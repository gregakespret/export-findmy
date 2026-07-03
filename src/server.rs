//! `--serve` mode: a localhost REST API that drives the export [`pipeline`] one
//! wizard step at a time, holding the Apple login session open between HTTP
//! requests. See docs in the airtag-tracker repo
//! (`docs/export-findmy-service/DESIGN.md`) for the contract.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{watch, Mutex};
use uuid::Uuid;

use crate::pipeline::{run_export, BeaconExport, DeviceInfo, ExportOpts, Interact, PipelineError};

const INPUT_TIMEOUT: Duration = Duration::from_secs(600); // pipeline waits on the user
const SESSION_TTL: Duration = Duration::from_secs(600);

/// Where the pipeline currently is; published on a watch channel so handlers can
/// await transitions.
#[derive(Debug, Clone)]
pub enum Step {
    /// Initial state, before login has determined whether 2FA is required.
    Starting,
    AwaitingTfa,
    AwaitingEscrow { devices: Vec<DeviceInfo> },
    Running,
    Done { beacons: Vec<BeaconExport> },
    Failed { error: &'static str, detail: String },
}

pub struct Session {
    pub step_rx: watch::Receiver<Step>,
    pub tfa_tx: Sender<String>,
    pub escrow_tx: Sender<(usize, String)>,
    pub task: tokio::task::JoinHandle<()>,
    pub last_touch: StdMutex<Instant>,
}

/// The [`Interact`] the server hands the pipeline: each input blocks on a channel
/// fed by the matching HTTP handler.
pub struct ServerInteract {
    step_tx: watch::Sender<Step>,
    tfa_rx: StdMutex<Receiver<String>>,
    escrow_rx: StdMutex<Receiver<(usize, String)>>,
    passcode: StdMutex<Option<String>>,
}

impl Interact for ServerInteract {
    fn get_2fa_code(&self) -> String {
        let _ = self.step_tx.send(Step::AwaitingTfa);
        tokio::task::block_in_place(|| {
            self.tfa_rx.lock().unwrap().recv_timeout(INPUT_TIMEOUT)
        })
        .unwrap_or_default()
    }

    fn choose_bottle(&self, devices: &[DeviceInfo]) -> Result<usize, PipelineError> {
        let _ = self.step_tx.send(Step::AwaitingEscrow { devices: devices.to_vec() });
        let (idx, passcode) = tokio::task::block_in_place(|| {
            self.escrow_rx.lock().unwrap().recv_timeout(INPUT_TIMEOUT)
        })
        .map_err(|_| PipelineError::Aborted)?;
        if idx >= devices.len() {
            return Err(PipelineError::BadDeviceIndex(format!(
                "Invalid device index {idx}. Must be 0-{}.",
                devices.len().saturating_sub(1)
            )));
        }
        *self.passcode.lock().unwrap() = Some(passcode);
        let _ = self.step_tx.send(Step::Running);
        Ok(idx)
    }

    fn get_passcode(&self) -> Result<String, PipelineError> {
        self.passcode.lock().unwrap().take().ok_or(PipelineError::Aborted)
    }
}

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<Session>>>>,
    expired: Arc<Mutex<HashSet<Uuid>>>,
    anisette_url: Arc<String>,
}

/// Spawn a session task driven by an arbitrary async runner. `spawn_session`
/// uses the real pipeline; tests inject a scripted runner over the same
/// [`ServerInteract`], so the channel/step plumbing is exercised without Apple.
pub fn spawn_session_with<F, Fut>(runner: F) -> (Uuid, Arc<Session>)
where
    F: FnOnce(Arc<ServerInteract>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<Vec<BeaconExport>, PipelineError>> + Send,
{
    let (step_tx, step_rx) = watch::channel(Step::Starting);
    let (tfa_tx, tfa_rx) = std::sync::mpsc::channel();
    let (escrow_tx, escrow_rx) = std::sync::mpsc::channel();
    let interact = Arc::new(ServerInteract {
        step_tx,
        tfa_rx: StdMutex::new(tfa_rx),
        escrow_rx: StdMutex::new(escrow_rx),
        passcode: StdMutex::new(None),
    });
    let task = tokio::spawn({
        let interact = interact.clone();
        async move {
            let final_step = match runner(interact.clone()).await {
                Ok(beacons) => Step::Done { beacons },
                Err(e) => Step::Failed { error: e.code(), detail: e.to_string() },
            };
            let _ = interact.step_tx.send(final_step);
        }
    });
    let session = Arc::new(Session {
        step_rx,
        tfa_tx,
        escrow_tx,
        task,
        last_touch: StdMutex::new(Instant::now()),
    });
    (Uuid::new_v4(), session)
}

fn spawn_session(opts: ExportOpts) -> (Uuid, Arc<Session>) {
    spawn_session_with(move |io| async move { run_export(opts, io.as_ref()).await })
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct StartBody {
    apple_id: String,
    password: String,
}

#[derive(Deserialize)]
struct TfaBody {
    code: String,
}

#[derive(Deserialize)]
struct EscrowBody {
    device_index: usize,
    passcode: String,
}

async fn healthz() -> Response {
    (StatusCode::OK, Json(json!({"status": "ok"}))).into_response()
}

async fn create_session(State(st): State<AppState>, Json(body): Json<StartBody>) -> Response {
    let opts = ExportOpts {
        apple_id: body.apple_id,
        password: body.password,
        anisette_url: (*st.anisette_url).clone(),
        debug: false,
    };
    let (id, session) = spawn_session(opts);
    // Wait until login has decided what's next: a 2FA challenge, or — if Apple
    // already trusts this session and skips 2FA — straight to device selection.
    // (Login → the device list can take a bit, so allow a generous window.)
    let mut rx = session.step_rx.clone();
    let outcome = wait_for(&mut rx, Duration::from_secs(180), |s| {
        !matches!(s, Step::Starting)
    })
    .await;
    let (keep, status, body) = start_outcome(id, outcome);
    if keep {
        st.sessions.lock().await.insert(id, session);
    } else {
        session.task.abort();
    }
    (status, Json(body)).into_response()
}

/// Decide the `POST /sessions` response from login's first real step: a 2FA
/// challenge, or — when Apple skips 2FA — the device list directly. Returns
/// `(keep_session, status, body)`. Pure, so the contract is unit-tested.
fn start_outcome(id: Uuid, outcome: Option<Step>) -> (bool, StatusCode, serde_json::Value) {
    match outcome {
        Some(Step::AwaitingTfa) => (
            true,
            StatusCode::CREATED,
            json!({"session_id": id, "state": "awaiting_2fa"}),
        ),
        Some(Step::AwaitingEscrow { devices }) => (
            true,
            StatusCode::CREATED,
            json!({"session_id": id, "state": "awaiting_passcode", "devices": devices}),
        ),
        Some(Step::Failed { error, detail }) => {
            (false, status_for(error), json!({"error": error, "detail": detail}))
        }
        _ => (
            false,
            status_for("apple_error"),
            json!({"error": "apple_error", "detail": "Timed out contacting Apple."}),
        ),
    }
}

async fn submit_2fa(
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<TfaBody>,
) -> Response {
    let session = match touch(&st, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let _ = session.tfa_tx.send(body.code);
    let mut rx = session.step_rx.clone();
    match wait_for(&mut rx, Duration::from_secs(180), |s| !matches!(s, Step::AwaitingTfa)).await {
        Some(Step::AwaitingEscrow { devices }) => {
            (StatusCode::OK, Json(json!({"state": "awaiting_passcode", "devices": devices})))
                .into_response()
        }
        Some(Step::Failed { error, detail }) => {
            remove(&st, id).await;
            error_response(error, detail)
        }
        _ => error_response("apple_error", "Timed out waiting for Apple.".into()),
    }
}

async fn submit_escrow(
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<EscrowBody>,
) -> Response {
    let session = match touch(&st, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let _ = session.escrow_tx.send((body.device_index, body.passcode));
    let mut rx = session.step_rx.clone();
    // The escrow join + CloudKit sync can take a while.
    let done = wait_for(&mut rx, Duration::from_secs(900), |s| {
        matches!(s, Step::Done { .. } | Step::Failed { .. })
    })
    .await;
    remove(&st, id).await;
    match done {
        Some(Step::Done { beacons }) => {
            let beacons: Vec<_> = beacons.iter().map(beacon_json).collect();
            (StatusCode::OK, Json(json!({"state": "done", "beacons": beacons}))).into_response()
        }
        Some(Step::Failed { error, detail }) => error_response(error, detail),
        _ => error_response("apple_error", "Timed out waiting for Apple.".into()),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn touch(st: &AppState, id: Uuid) -> Result<Arc<Session>, Response> {
    if let Some(s) = st.sessions.lock().await.get(&id) {
        *s.last_touch.lock().unwrap() = Instant::now();
        return Ok(s.clone());
    }
    if st.expired.lock().await.contains(&id) {
        return Err(error_response("session_expired", "This connection attempt expired.".into()));
    }
    Err(error_response("session_not_found", "Unknown connection attempt.".into()))
}

async fn remove(st: &AppState, id: Uuid) {
    st.sessions.lock().await.remove(&id);
}

async fn wait_for(
    rx: &mut watch::Receiver<Step>,
    timeout: Duration,
    pred: impl Fn(&Step) -> bool,
) -> Option<Step> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        {
            let cur = rx.borrow();
            if pred(&cur) {
                return Some(cur.clone());
            }
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => continue,
            _ => return None,
        }
    }
}

fn beacon_json(b: &BeaconExport) -> serde_json::Value {
    let b64 = |v: &[u8]| base64::engine::general_purpose::STANDARD.encode(v);
    let b64_opt = |v: &Option<Vec<u8>>| v.as_ref().map(|x| b64(x));
    json!({
        "identifier": b.identifier,
        "name": b.name,
        "emoji": b.emoji,
        "model": b.model,
        "private_key": b64(&b.private_key),
        "shared_secret": b64(&b.shared_secret),
        "secondary_shared_secret": b64_opt(&b.secondary_shared_secret),
        "secure_locations_shared_secret": b64_opt(&b.secure_locations_shared_secret),
        "public_key": b64_opt(&b.public_key),
        "pairing_date": b.pairing_date,
    })
}

fn status_for(code: &str) -> StatusCode {
    match code {
        "bad_credentials" => StatusCode::UNAUTHORIZED,
        "bad_2fa_code" | "bad_passcode" | "bad_device_index" | "no_bottles" => {
            StatusCode::BAD_REQUEST
        }
        "session_not_found" => StatusCode::NOT_FOUND,
        "session_expired" => StatusCode::GONE,
        _ => StatusCode::BAD_GATEWAY,
    }
}

fn error_response(code: &str, detail: String) -> Response {
    (status_for(code), Json(json!({"error": code, "detail": detail}))).into_response()
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/sessions", post(create_session))
        .route("/sessions/:id/2fa", post(submit_2fa))
        .route("/sessions/:id/escrow", post(submit_escrow))
        .with_state(state)
}

async fn reap_loop(st: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let mut dead = Vec::new();
        {
            let sessions = st.sessions.lock().await;
            for (id, s) in sessions.iter() {
                if s.last_touch.lock().unwrap().elapsed() > SESSION_TTL {
                    dead.push(*id);
                }
            }
        }
        if dead.is_empty() {
            continue;
        }
        let mut sessions = st.sessions.lock().await;
        let mut expired = st.expired.lock().await;
        for id in dead {
            if let Some(s) = sessions.remove(&id) {
                s.task.abort();
            }
            expired.insert(id);
        }
    }
}

pub async fn serve(port: u16, anisette_url: String) -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        expired: Arc::new(Mutex::new(HashSet::new())),
        anisette_url: Arc::new(anisette_url),
    };
    tokio::spawn(reap_loop(state.clone()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("export-findmy serving on http://127.0.0.1:{port}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt; // oneshot

    fn test_state() -> AppState {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            expired: Arc::new(Mutex::new(HashSet::new())),
            anisette_url: Arc::new("https://example".into()),
        }
    }

    fn test_device(serial: &str) -> DeviceInfo {
        DeviceInfo { serial: serial.into(), name: format!("{serial}-name"), model: "TestModel".into() }
    }

    fn sample_beacon() -> BeaconExport {
        BeaconExport {
            identifier: "2006~#abc".into(),
            name: "Keys".into(),
            emoji: "🔑".into(),
            model: "AirTag".into(),
            private_key: vec![1u8; 4],
            shared_secret: vec![2u8; 4],
            secondary_shared_secret: None,
            secure_locations_shared_secret: Some(vec![3u8; 4]),
            public_key: None,
            pairing_date: Some("2026-01-11T19:57:42Z".into()),
        }
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_ok() {
        let resp = router(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_session_is_not_found() {
        let st = test_state();
        let resp = router(st)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/sessions/{}/2fa", Uuid::new_v4()))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"code":"1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_scripted_session_reaches_done() {
        // A scripted runner drives the REAL ServerInteract, so the channel +
        // step-machine wiring is tested without touching Apple.
        let (id, session) = spawn_session_with(|io| async move {
            let code = io.get_2fa_code();
            assert_eq!(code, "123456");
            let idx = io.choose_bottle(&[test_device("GYK3003QMY"), test_device("J9NQHW229W")])?;
            assert_eq!(idx, 1);
            let pass = io.get_passcode()?;
            assert_eq!(pass, "0000");
            Ok(vec![sample_beacon()])
        });

        // AwaitingTfa -> feed code -> AwaitingEscrow.
        let mut rx = session.step_rx.clone();
        session.tfa_tx.send("123456".into()).unwrap();
        let step = wait_for(&mut rx, Duration::from_secs(5), |s| {
            matches!(s, Step::AwaitingEscrow { .. })
        })
        .await
        .expect("reached escrow");
        match step {
            Step::AwaitingEscrow { devices } => assert_eq!(devices.len(), 2),
            _ => panic!(),
        }

        // Feed the choice + passcode -> Done with the beacon.
        session.escrow_tx.send((1, "0000".into())).unwrap();
        let step = wait_for(&mut rx, Duration::from_secs(5), |s| matches!(s, Step::Done { .. }))
            .await
            .expect("reached done");
        match step {
            Step::Done { beacons } => {
                assert_eq!(beacons.len(), 1);
                assert_eq!(beacon_json(&beacons[0])["identifier"], "2006~#abc");
                // base64("\x03\x03\x03\x03") = "AwMDAw=="
                assert_eq!(beacons[0].secondary_shared_secret, None);
            }
            _ => panic!(),
        }
        let _ = id;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bad_device_index_fails_the_session() {
        let (_id, session) = spawn_session_with(|io| async move {
            io.get_2fa_code();
            let idx = io.choose_bottle(&[test_device("only")])?; // index 5 is out of range
            let _ = io.get_passcode()?;
            Ok(vec![BeaconExport {
                identifier: format!("idx-{idx}"),
                name: String::new(),
                emoji: String::new(),
                model: String::new(),
                private_key: vec![],
                shared_secret: vec![],
                secondary_shared_secret: None,
                secure_locations_shared_secret: None,
                public_key: None,
                pairing_date: None,
            }])
        });
        let mut rx = session.step_rx.clone();
        session.tfa_tx.send("1".into()).unwrap();
        wait_for(&mut rx, Duration::from_secs(5), |s| matches!(s, Step::AwaitingEscrow { .. }))
            .await
            .unwrap();
        session.escrow_tx.send((5, "0000".into())).unwrap();
        let step = wait_for(&mut rx, Duration::from_secs(5), |s| matches!(s, Step::Failed { .. }))
            .await
            .expect("failed");
        match step {
            Step::Failed { error, .. } => assert_eq!(error, "bad_device_index"),
            _ => panic!(),
        }
    }

    #[test]
    fn start_outcome_maps_each_first_step() {
        let id = Uuid::new_v4();

        // Normal: 2FA required.
        let (keep, status, body) = start_outcome(id, Some(Step::AwaitingTfa));
        assert!(keep && status == StatusCode::CREATED);
        assert_eq!(body["state"], "awaiting_2fa");
        assert!(body.get("devices").is_none());

        // 2FA skipped: device list returned directly so the client skips /2fa.
        let devices = vec![test_device("GYK3003QMY")];
        let (keep, status, body) = start_outcome(id, Some(Step::AwaitingEscrow { devices }));
        assert!(keep && status == StatusCode::CREATED);
        assert_eq!(body["state"], "awaiting_passcode");
        assert_eq!(body["devices"][0]["serial"], "GYK3003QMY");
        assert_eq!(body["devices"][0]["name"], "GYK3003QMY-name");

        // Bad credentials: don't keep the session, surface the error.
        let (keep, status, body) = start_outcome(
            id,
            Some(Step::Failed { error: "bad_credentials", detail: "nope".into() }),
        );
        assert!(!keep && status == StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "bad_credentials");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn skip_2fa_goes_straight_to_escrow() {
        // When login needs no 2FA (Apple already trusts the session), the runner
        // never calls get_2fa_code, so the step goes Starting -> AwaitingEscrow
        // directly and never becomes AwaitingTfa. This is what lets POST /sessions
        // report `awaiting_passcode` and the wizard skip the 2FA screen.
        let (_id, session) = spawn_session_with(|io| async move {
            let idx = io.choose_bottle(&[test_device("GYK3003QMY")])?;
            assert_eq!(idx, 0);
            let _ = io.get_passcode()?;
            Ok(vec![sample_beacon()])
        });
        let mut rx = session.step_rx.clone();
        let step = wait_for(&mut rx, Duration::from_secs(5), |s| !matches!(s, Step::Starting))
            .await
            .expect("left Starting");
        assert!(matches!(step, Step::AwaitingEscrow { .. }), "expected escrow, got {step:?}");
    }
}
