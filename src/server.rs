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
/// How long a handler waits on Apple for the next step. Named so the log lines
/// that quote them read from the same place the wait does — a prose "180s" beside
/// a separate literal states a duration that never elapsed the moment either moves.
const START_TIMEOUT: Duration = Duration::from_secs(180);
/// The escrow join plus the CloudKit sync, which can legitimately take minutes.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(900);

/// Short form of a session id, used as the log tag on both sides of the wire:
/// the pipeline prefixes its lines with it and the caller records the full id,
/// so one attempt can be followed across both logs.
pub fn tag(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

/// Server-side log line. The handlers used to be entirely silent, so everything
/// that goes wrong *around* the pipeline — a timeout waiting on Apple, a step
/// posted out of order, a session reaped mid-flow — reached the user as an
/// error string and left no trace at all.
macro_rules! slog {
    ($id:expr, $($arg:tt)*) => {
        eprintln!("[sess={}] {}", tag($id), format_args!($($arg)*))
    };
}

/// Why an input the pipeline was parked on never arrived. The two cases look
/// the same to the user (the attempt dies) but mean opposite things to us: a
/// timeout is a user who wandered off, a disconnect is the session being torn
/// down under them — by the reaper, an abort, or a restart.
fn why_no_input(e: std::sync::mpsc::RecvTimeoutError) -> String {
    match e {
        std::sync::mpsc::RecvTimeoutError::Timeout => {
            format!("nothing submitted within {}s", INPUT_TIMEOUT.as_secs())
        }
        std::sync::mpsc::RecvTimeoutError::Disconnected => {
            "the session was torn down while waiting".to_string()
        }
    }
}

/// Name for the step a session is parked on, for logs that report where a
/// request arrived relative to where the pipeline actually is.
fn step_name(s: &Step) -> &'static str {
    match s {
        Step::Starting => "starting",
        Step::AwaitingTfa => "awaiting_2fa",
        Step::AwaitingEscrow { .. } => "awaiting_passcode",
        Step::Running => "running",
        Step::Done { .. } => "done",
        Step::Failed { .. } => "failed",
    }
}

/// What a pipeline task's `JoinError` says. A panic (an `unwrap` on unexpected
/// Apple data) is reported to the user as "failed unexpectedly"; without the
/// payload here, nothing ties the panic printed by the runtime to the session
/// it killed.
fn join_failure(e: &tokio::task::JoinError) -> String {
    // JoinError's Display already carries the panic's own message ("task 12
    // panicked with message \"...\""), which is the only description of the
    // failure that can be tied back to the session it killed.
    if e.is_cancelled() {
        format!("cancelled ({e})")
    } else {
        format!("panicked ({e})")
    }
}

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
    /// Cancels the *pipeline* task, not the wrapper that awaits it. Aborting the
    /// wrapper would only drop its future — and dropping a `JoinHandle` detaches
    /// the task in tokio rather than cancelling it, so the export would carry on
    /// talking to Apple, holding extracted key material, for a session we had
    /// already told the user was dead.
    pub abort: tokio::task::AbortHandle,
    pub last_touch: StdMutex<Instant>,
}

/// The [`Interact`] the server hands the pipeline: each input blocks on a channel
/// fed by the matching HTTP handler.
pub struct ServerInteract {
    id: Uuid,
    step_tx: watch::Sender<Step>,
    tfa_rx: StdMutex<Receiver<String>>,
    escrow_rx: StdMutex<Receiver<(usize, String)>>,
    passcode: StdMutex<Option<String>>,
}

impl Interact for ServerInteract {
    fn get_2fa_code(&self) -> String {
        let _ = self.step_tx.send(Step::AwaitingTfa);
        match tokio::task::block_in_place(|| {
            self.tfa_rx.lock().unwrap().recv_timeout(INPUT_TIMEOUT)
        }) {
            Ok(code) => code,
            Err(e) => {
                // An empty code makes login fail as "bad credentials", so a user
                // who never got round to typing the code is reported as if they
                // had mistyped their password. Only this line separates them.
                slog!(self.id, "no 2FA code ({}) — login will fail as bad credentials",
                      why_no_input(e));
                String::new()
            }
        }
    }

    fn choose_bottle(&self, devices: &[DeviceInfo]) -> Result<usize, PipelineError> {
        let _ = self.step_tx.send(Step::AwaitingEscrow { devices: devices.to_vec() });
        let (idx, passcode) = tokio::task::block_in_place(|| {
            self.escrow_rx.lock().unwrap().recv_timeout(INPUT_TIMEOUT)
        })
        .map_err(|e| {
            slog!(self.id, "no device/passcode ({}) — abandoning the attempt", why_no_input(e));
            PipelineError::Aborted
        })?;
        if idx >= devices.len() {
            // This check, not the pipeline's identical one, is the one that
            // fires in server mode — so without this line a rejected index
            // leaves no record of what the client actually sent.
            slog!(self.id, "device_index {} out of range 0-{} — rejecting",
                  idx, devices.len().saturating_sub(1));
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

/// How `create_session` turns login options into a running session task. In
/// production this is `spawn_session` (the real pipeline); tests inject a
/// scripted spawner so the HTTP handlers can be driven end-to-end without Apple.
/// The id is minted by the caller and passed in, so the tag stamped into
/// `ExportOpts::session_id` and the id returned to the client cannot drift apart.
type Spawner = Arc<dyn Fn(Uuid, ExportOpts) -> Arc<Session> + Send + Sync>;

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<Session>>>>,
    expired: Arc<Mutex<HashSet<Uuid>>>,
    anisette_url: Arc<String>,
    spawn: Spawner,
}

/// Spawn a session task driven by an arbitrary async runner. `spawn_session`
/// uses the real pipeline; tests inject a scripted runner over the same
/// [`ServerInteract`], so the channel/step plumbing is exercised without Apple.
pub fn spawn_session_with<F, Fut>(id: Uuid, runner: F) -> Arc<Session>
where
    F: FnOnce(Arc<ServerInteract>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<Vec<BeaconExport>, PipelineError>> + Send + 'static,
{
    let (step_tx, step_rx) = watch::channel(Step::Starting);
    let (tfa_tx, tfa_rx) = std::sync::mpsc::channel();
    let (escrow_tx, escrow_rx) = std::sync::mpsc::channel();
    let interact = Arc::new(ServerInteract {
        id,
        step_tx,
        tfa_rx: StdMutex::new(tfa_rx),
        escrow_rx: StdMutex::new(escrow_rx),
        passcode: StdMutex::new(None),
    });
    let started = Instant::now();
    // Run the pipeline on its own task so a panic (e.g. an unwrap on unexpected
    // Apple/CloudKit data) becomes a JoinError the wrapper below can turn into
    // Failed — otherwise the panic unwinds past the step publish and every
    // waiting handler hangs to its timeout. The task also carries the session
    // tag, so rustpush's own log records are attributable to this attempt.
    let inner = tokio::spawn({
        let interact = interact.clone();
        crate::logging::SESSION.scope(tag(id), async move { runner(interact).await })
    });
    // Held by the Session: this, not the wrapper's handle, is what actually
    // stops the export.
    let abort = inner.abort_handle();
    tokio::spawn({
        let interact = interact.clone();
        async move {
            let final_step = match inner.await {
                Ok(Ok(beacons)) => {
                    slog!(id, "export finished: {} beacon(s) in {:.1}s",
                          beacons.len(), started.elapsed().as_secs_f32());
                    Step::Done { beacons }
                }
                Ok(Err(e)) => {
                    slog!(id, "export failed after {:.1}s: code={} detail={:?}",
                          started.elapsed().as_secs_f32(), e.code(), e.to_string());
                    Step::Failed { error: e.code(), detail: e.to_string() }
                }
                Err(e) => {
                    // The user gets a deliberately vague message here; the log
                    // is the only place the actual panic is recorded against
                    // the session it killed.
                    slog!(id, "export task {} after {:.1}s",
                          join_failure(&e), started.elapsed().as_secs_f32());
                    Step::Failed {
                        error: "apple_error",
                        detail: "The export failed unexpectedly.".into(),
                    }
                }
            };
            let _ = interact.step_tx.send(final_step);
        }
    });
    Arc::new(Session {
        step_rx,
        tfa_tx,
        escrow_tx,
        abort,
        last_touch: StdMutex::new(Instant::now()),
    })
}

fn spawn_session(id: Uuid, opts: ExportOpts) -> Arc<Session> {
    spawn_session_with(id, move |io| async move { run_export(opts, io.as_ref()).await })
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
    // Minted here, not inside the spawner, so the tag the pipeline logs and the
    // id the client is handed come from one value — the cross-log join rests on
    // them being the same and nothing downstream can make them differ.
    let id = Uuid::new_v4();
    let opts = ExportOpts {
        apple_id: body.apple_id,
        password: body.password,
        anisette_url: (*st.anisette_url).clone(),
        debug: false,
        session_id: tag(id),
    };
    let session = (st.spawn)(id, opts);
    // Track the session BEFORE waiting so that if the client disconnects during
    // the wait (dropping this handler), the task is still reachable by the reaper
    // rather than orphaned.
    let live = {
        let mut sessions = st.sessions.lock().await;
        sessions.insert(id, session.clone());
        // Counted after the insert, under the same lock: `len() + 1` beforehand
        // is a guess that two simultaneous creates make wrong.
        sessions.len()
    };
    slog!(id, "POST /sessions: new attempt (live sessions: {})", live);
    // Wait until login has decided what's next: a 2FA challenge, or — if Apple
    // already trusts this session and skips 2FA — straight to device selection.
    // (Login → the device list can take a bit, so allow a generous window.)
    let mut rx = session.step_rx.clone();
    let outcome = wait_for(&mut rx, START_TIMEOUT, |s| !matches!(s, Step::Starting)).await;
    match &outcome {
        Some(s) => slog!(id, "POST /sessions -> {}", step_name(s)),
        // A timeout here is reported to the user as "Timed out contacting
        // Apple", which reads like an Apple fault even when login is merely
        // slow; the log says how long we actually waited.
        None => slog!(id, "POST /sessions: still starting after {}s — giving up",
                      START_TIMEOUT.as_secs()),
    }
    let (keep, status, body) = start_outcome(id, outcome);
    if !keep {
        session.abort.abort();
        retire(&st, id).await;
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
    // Reject an out-of-order post: the code channel is only drained at
    // AwaitingTfa, so sending now would buffer a value that's consumed
    // sight-unseen later (or never).
    // One borrow feeds both the log and the guard. Taken separately, the
    // pipeline can publish a transition in between and the rejection line names
    // a step that isn't the one that caused it ("at awaiting_2fa, not
    // awaiting_2fa") — a self-contradiction in the record meant to settle it.
    let (current, ready) = {
        let step = session.step_rx.borrow();
        (step_name(&step), matches!(&*step, Step::AwaitingTfa))
    };
    // Never the code itself; its length is what tells an empty submit from a
    // mistyped one, and both reach Apple as the same rejection.
    slog!(id, "POST /2fa: code {} chars, session at {}", body.code.chars().count(), current);
    if !ready {
        slog!(id, "POST /2fa rejected: session is at {}, not awaiting_2fa", current);
        return wrong_step();
    }
    let _ = session.tfa_tx.send(body.code);
    let mut rx = session.step_rx.clone();
    match wait_for(&mut rx, START_TIMEOUT, |s| !matches!(s, Step::AwaitingTfa)).await {
        Some(Step::AwaitingEscrow { devices }) => {
            slog!(id, "POST /2fa -> awaiting_passcode with {} device(s)", devices.len());
            (StatusCode::OK, Json(json!({"state": "awaiting_passcode", "devices": devices})))
                .into_response()
        }
        Some(Step::Failed { error, detail }) => {
            slog!(id, "POST /2fa -> failed: code={error} detail={detail:?}");
            retire(&st, id).await;
            error_response(error, detail)
        }
        // `wait_for` returns None on a timeout *or* a dropped sender, and Some
        // for any other step — reporting all of them as a 180s timeout asserts
        // a cause this branch hasn't established.
        None => {
            slog!(id, "POST /2fa: no answer from Apple within {}s — aborting the attempt",
                  START_TIMEOUT.as_secs());
            session.abort.abort();
            retire(&st, id).await;
            error_response("apple_error", "Timed out waiting for Apple.".into())
        }
        Some(other) => {
            slog!(id, "POST /2fa: left awaiting_2fa for {} — aborting the attempt",
                  step_name(&other));
            session.abort.abort();
            retire(&st, id).await;
            error_response("apple_error", "Timed out waiting for Apple.".into())
        }
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
    // Reject an out-of-order post (e.g. /escrow before /2fa): sending now would
    // buffer a (device_index, passcode) tuple that choose_bottle later consumes
    // against a device the user never saw — burning an Apple escrow attempt.
    // One borrow for both the log and the guard — see the note in `submit_2fa`.
    let (current, ready) = {
        let step = session.step_rx.borrow();
        (step_name(&step), matches!(&*step, Step::AwaitingEscrow { .. }))
    };
    slog!(id, "POST /escrow: device_index={} passcode {} chars, session at {}",
          body.device_index, body.passcode.chars().count(), current);
    if !ready {
        slog!(id, "POST /escrow rejected: session is at {}, not awaiting_passcode", current);
        return wrong_step();
    }
    let escrow_started = Instant::now();
    let _ = session.escrow_tx.send((body.device_index, body.passcode));
    let mut rx = session.step_rx.clone();
    let done = wait_for(&mut rx, EXPORT_TIMEOUT, |s| {
        matches!(s, Step::Done { .. } | Step::Failed { .. })
    })
    .await;
    match done {
        Some(Step::Done { beacons }) => {
            slog!(id, "POST /escrow -> done: {} beacon(s) in {:.1}s",
                  beacons.len(), escrow_started.elapsed().as_secs_f32());
            remove(&st, id).await;
            let beacons: Vec<_> = beacons.iter().map(beacon_json).collect();
            (StatusCode::OK, Json(json!({"state": "done", "beacons": beacons}))).into_response()
        }
        Some(Step::Failed { error, detail }) => {
            slog!(id, "POST /escrow -> failed after {:.1}s: code={error} detail={detail:?}",
                  escrow_started.elapsed().as_secs_f32());
            retire(&st, id).await;
            error_response(error, detail)
        }
        _ => {
            slog!(id, "POST /escrow: still running after {}s — aborting (extraction \
                   never completed; the user sees an Apple timeout)", EXPORT_TIMEOUT.as_secs());
            // Still running past our budget — abort so the pipeline doesn't keep
            // running (holding extracted keys) with no one able to reach it.
            session.abort.abort();
            retire(&st, id).await;
            error_response("apple_error", "Timed out waiting for Apple.".into())
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn touch(st: &AppState, id: Uuid) -> Result<Arc<Session>, Response> {
    if let Some(s) = st.sessions.lock().await.get(&id) {
        *s.last_touch.lock().unwrap() = Instant::now();
        return Ok(s.clone());
    }
    // Both of these end the user's wizard with "start again" and no other
    // explanation. Expired means we had it and let it go (idle past the TTL, or
    // a failure retired it); not-found means this process never had it at all —
    // which is what a restart or a second service instance looks like.
    if st.expired.lock().await.contains(&id) {
        slog!(id, "request for an expired session -> 410");
        return Err(error_response("session_expired", "This connection attempt expired.".into()));
    }
    // Debug, not info: this is reachable by anyone who can reach the service
    // (on Railway's private network, any co-tenant), it carries no Apple ID, and
    // by construction it names a session this process has no other record of —
    // so it can never be joined to a user, and a client retry loop after a
    // redeploy would otherwise pour unbounded volume into the hosted log store.
    log::debug!("[sess={}] request for an unknown session -> 404 (restart, or never ours)", tag(id));
    Err(error_response("session_not_found", "Unknown connection attempt.".into()))
}

async fn remove(st: &AppState, id: Uuid) {
    st.sessions.lock().await.remove(&id);
}

/// Remove a session and remember it as expired, so a later request for it gets
/// a consistent 410 (rather than 404 depending on which teardown path ran).
async fn retire(st: &AppState, id: Uuid) {
    st.sessions.lock().await.remove(&id);
    st.expired.lock().await.insert(id);
}

/// 409 for a request that arrives at the wrong point in the flow.
fn wrong_step() -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": "wrong_step",
            "detail": "This connection isn't ready for that step — start over."
        })),
    )
        .into_response()
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
        "bad_passcode" | "bad_device_index" | "no_bottles" => StatusCode::BAD_REQUEST,
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

/// A session is reapable when it has been idle past the TTL AND is not actively
/// running the escrow/CloudKit work (which can legitimately exceed the TTL — we
/// must not abort a live export out from under the escrow handler's 900s wait).
fn is_reapable(s: &Session) -> bool {
    if matches!(&*s.step_rx.borrow(), Step::Running) {
        return false;
    }
    s.last_touch.lock().unwrap().elapsed() > SESSION_TTL
}

async fn reap_loop(st: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let mut dead = Vec::new();
        {
            let sessions = st.sessions.lock().await;
            for (id, s) in sessions.iter() {
                if is_reapable(s) {
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
            // Re-check under the lock: a session touched or become active between
            // the scan and now must not be aborted mid-flight.
            match sessions.get(&id) {
                Some(s) if !is_reapable(s) => continue,
                None => continue,
                _ => {}
            }
            if let Some(s) = sessions.remove(&id) {
                // The user was mid-wizard and just walked away for long enough;
                // their next step will 410 with no other trace of why.
                slog!(id, "reaped: idle {:.0}s at {} (TTL {}s)",
                      s.last_touch.lock().unwrap().elapsed().as_secs_f32(),
                      step_name(&s.step_rx.borrow()), SESSION_TTL.as_secs());
                s.abort.abort();
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
        spawn: Arc::new(spawn_session),
    };
    tokio::spawn(reap_loop(state.clone()));
    // Default to loopback so the security posture is unchanged for local use.
    // Set EXPORT_FINDMY_BIND to a non-loopback address (e.g. `::` for Railway's
    // IPv6 private network) to reach the service from another container.
    let bind_host = std::env::var("EXPORT_FINDMY_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let listener = tokio::net::TcpListener::bind((bind_host.as_str(), port)).await?;
    eprintln!("export-findmy serving on http://{bind_host}:{port}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt; // oneshot

    fn state_with(spawn: Spawner) -> AppState {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            expired: Arc::new(Mutex::new(HashSet::new())),
            anisette_url: Arc::new("https://example".into()),
            spawn,
        }
    }

    /// State whose spawner panics if used — for handler tests that never hit
    /// POST /sessions (healthz, unknown-session).
    fn test_state() -> AppState {
        state_with(Arc::new(|_, _| panic!("spawn should not be called in this test")))
    }

    /// Scripted spawner: normal 2FA flow → two devices → one beacon on Done.
    fn spawn_normal() -> Spawner {
        Arc::new(|id, _opts| {
            spawn_session_with(id, |io| async move {
                let _code = io.get_2fa_code(); // parks until POST /2fa
                let idx =
                    io.choose_bottle(&[test_device("GYK3003QMY"), test_device("J9NQHW229W")])?;
                assert!(idx < 2);
                let _pass = io.get_passcode()?;
                Ok(vec![sample_beacon()])
            })
        })
    }

    /// Scripted spawner: 2FA skipped → straight to device selection.
    fn spawn_skip_2fa() -> Spawner {
        Arc::new(|id, _opts| {
            spawn_session_with(id, |io| async move {
                let _idx = io.choose_bottle(&[test_device("GYK3003QMY")])?;
                let _pass = io.get_passcode()?;
                Ok(vec![sample_beacon()])
            })
        })
    }

    /// Scripted spawner: login fails before 2FA.
    fn spawn_err(mk: fn() -> PipelineError) -> Spawner {
        Arc::new(move |id, _opts| {
            spawn_session_with(id, move |_io| async move {
                Err::<Vec<BeaconExport>, PipelineError>(mk())
            })
        })
    }

    /// Drive one request through the real axum router against shared state.
    async fn req(
        st: &AppState,
        method: &str,
        uri: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let resp = router(st.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, json)
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

    #[test]
    fn log_tag_is_a_prefix_of_the_session_id_the_caller_gets() {
        // The whole point of the tag is cross-log correlation: the caller stores
        // the session id we return and greps our output for it. If the tag were
        // derived some other way (a counter, a hash) that join would silently
        // stop working.
        let id = Uuid::new_v4();
        let t = tag(id);
        assert_eq!(t.len(), 8);
        assert!(id.to_string().starts_with(&t), "{} should start with {}", id, t);
    }

    #[test]
    fn why_no_input_separates_a_slow_user_from_a_torn_down_session() {
        // Both end the attempt identically for the user; only this distinction
        // says whether to look at them or at us.
        use std::sync::mpsc::RecvTimeoutError;
        assert!(why_no_input(RecvTimeoutError::Timeout).contains("600s"));
        assert!(why_no_input(RecvTimeoutError::Disconnected).contains("torn down"));
    }

    #[test]
    fn step_name_uses_the_state_names_the_api_reports() {
        // A "wrong step" log line is only useful if the step it names is the one
        // the client was told it was on — the API calls AwaitingEscrow
        // "awaiting_passcode", so the log must too.
        assert_eq!(step_name(&Step::Starting), "starting");
        assert_eq!(step_name(&Step::AwaitingTfa), "awaiting_2fa");
        assert_eq!(step_name(&Step::AwaitingEscrow { devices: vec![] }), "awaiting_passcode");
        assert_eq!(step_name(&Step::Running), "running");
        assert_eq!(step_name(&Step::Done { beacons: vec![] }), "done");
        assert_eq!(
            step_name(&Step::Failed { error: "apple_error", detail: String::new() }),
            "failed"
        );
    }

    #[tokio::test]
    async fn join_failure_keeps_the_panic_message() {
        // A panicking pipeline is reported to the user as "failed unexpectedly";
        // this string is the only record of what actually blew up.
        let err = tokio::spawn(async { panic!("unexpected CloudKit record") })
            .await
            .expect_err("task panicked");
        let msg = join_failure(&err);
        assert!(msg.starts_with("panicked"), "{msg}");
        assert!(msg.contains("unexpected CloudKit record"), "{msg}");

        let handle = tokio::spawn(async { std::future::pending::<()>().await });
        handle.abort();
        let err = handle.await.expect_err("task cancelled");
        assert!(join_failure(&err).starts_with("cancelled"));
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
        let id = Uuid::new_v4();
        let session = spawn_session_with(id, |io| async move {
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
                assert_eq!(beacons[0].secondary_shared_secret, None);
            }
            _ => panic!(),
        }
        let _ = id;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bad_device_index_fails_the_session() {
        let session = spawn_session_with(Uuid::new_v4(), |io| async move {
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
        let session = spawn_session_with(Uuid::new_v4(), |io| async move {
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

    // ── Router-level integration tests (drive the real handlers) ────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_full_flow_start_2fa_escrow() {
        let st = state_with(spawn_normal());

        let (s1, b1) = req(&st, "POST", "/sessions", r#"{"apple_id":"me","password":"pw"}"#).await;
        assert_eq!(s1, StatusCode::CREATED);
        assert_eq!(b1["state"], "awaiting_2fa");
        let id = b1["session_id"].as_str().unwrap().to_string();

        let (s2, b2) = req(&st, "POST", &format!("/sessions/{id}/2fa"), r#"{"code":"123456"}"#).await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(b2["state"], "awaiting_passcode");
        assert_eq!(b2["devices"][0]["serial"], "GYK3003QMY");
        assert_eq!(b2["devices"][1]["serial"], "J9NQHW229W");

        let (s3, b3) = req(
            &st, "POST", &format!("/sessions/{id}/escrow"),
            r#"{"device_index":1,"passcode":"0000"}"#,
        ).await;
        assert_eq!(s3, StatusCode::OK);
        assert_eq!(b3["state"], "done");
        assert_eq!(b3["beacons"][0]["identifier"], "2006~#abc");
        assert_eq!(b3["beacons"][0]["private_key"], "AQEBAQ=="); // base64([1;4])

        // Session is gone after Done.
        let (s4, _) = req(&st, "POST", &format!("/sessions/{id}/2fa"), r#"{"code":"x"}"#).await;
        assert_eq!(s4, StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_session_stamps_the_tag_the_caller_can_grep_for() {
        // The whole cross-log join rests on the pipeline logging the same tag
        // the caller stores. Nothing else drives that stamping — the tag test
        // above checks `tag()` in isolation — so a refactor that dropped it
        // would leave `[sess=]` on every pipeline line and still pass green.
        let stamped: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let captured = stamped.clone();
        let st = state_with(Arc::new(move |id, opts: ExportOpts| {
            *captured.lock().unwrap() = Some(opts.session_id.clone());
            spawn_session_with(id, |io| async move {
                let _ = io.choose_bottle(&[test_device("GYK3003QMY")])?;
                let _ = io.get_passcode()?;
                Ok(vec![sample_beacon()])
            })
        }));

        let (_s, b) = req(&st, "POST", "/sessions", r#"{"apple_id":"me","password":"pw"}"#).await;
        let session_id = b["session_id"].as_str().expect("session_id returned");
        let stamped = stamped.lock().unwrap().clone().expect("spawner saw opts");
        assert_eq!(stamped.len(), 8);
        assert!(session_id.starts_with(&stamped), "{session_id} should start with {stamped}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_stops_the_pipeline_not_just_the_wrapper() {
        // Aborting the wrapper task would only DROP the pipeline's JoinHandle,
        // which detaches it in tokio rather than cancelling it — the export would
        // keep talking to Apple, holding extracted keys, for a session already
        // reported dead. The flag proves the pipeline itself stopped.
        let ran_on = Arc::new(StdMutex::new(false));
        let flag = ran_on.clone();
        let session = spawn_session_with(Uuid::new_v4(), move |_io| async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            *flag.lock().unwrap() = true; // only reached if the abort didn't land
            Ok(vec![sample_beacon()])
        });

        session.abort.abort();
        // Past the sleep the pipeline would have needed to set the flag.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!*ran_on.lock().unwrap(), "aborted pipeline kept running");
        // The wrapper still publishes the cancellation, so waiting handlers are
        // released instead of hanging to their timeout.
        assert!(matches!(&*session.step_rx.borrow(), Step::Failed { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_skip_2fa_returns_devices_from_post_sessions() {
        let st = state_with(spawn_skip_2fa());

        let (s1, b1) = req(&st, "POST", "/sessions", r#"{"apple_id":"me","password":"pw"}"#).await;
        assert_eq!(s1, StatusCode::CREATED);
        assert_eq!(b1["state"], "awaiting_passcode");
        assert_eq!(b1["devices"][0]["serial"], "GYK3003QMY");
        let id = b1["session_id"].as_str().unwrap().to_string();

        // Straight to escrow — no /2fa call.
        let (s2, b2) = req(
            &st, "POST", &format!("/sessions/{id}/escrow"),
            r#"{"device_index":0,"passcode":"0000"}"#,
        ).await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(b2["state"], "done");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_bad_credentials_returns_401_and_retires_session() {
        let st = state_with(spawn_err(|| PipelineError::BadCredentials("nope".into())));

        let (s1, b1) = req(&st, "POST", "/sessions", r#"{"apple_id":"me","password":"bad"}"#).await;
        assert_eq!(s1, StatusCode::UNAUTHORIZED);
        assert_eq!(b1["error"], "bad_credentials");
        let id = b1.get("session_id").and_then(|v| v.as_str());
        // create_session doesn't return an id on failure, but the reaper/retire
        // path is exercised: no session lingers in the map.
        assert!(id.is_none());
        assert!(st.sessions.lock().await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_escrow_before_2fa_is_rejected_wrong_step() {
        // An out-of-order /escrow must NOT buffer a passcode against the wrong
        // device — it returns 409 and the session stays usable for /2fa.
        let st = state_with(spawn_normal());
        let (_s1, b1) = req(&st, "POST", "/sessions", r#"{"apple_id":"me","password":"pw"}"#).await;
        let id = b1["session_id"].as_str().unwrap().to_string();

        let (s2, b2) = req(
            &st, "POST", &format!("/sessions/{id}/escrow"),
            r#"{"device_index":0,"passcode":"0000"}"#,
        ).await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert_eq!(b2["error"], "wrong_step");

        // The proper /2fa still works afterwards (nothing was consumed).
        let (s3, b3) = req(&st, "POST", &format!("/sessions/{id}/2fa"), r#"{"code":"123456"}"#).await;
        assert_eq!(s3, StatusCode::OK);
        assert_eq!(b3["state"], "awaiting_passcode");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_unknown_session_404_and_expired_410() {
        let st = state_with(spawn_err(|| PipelineError::BadCredentials("nope".into())));
        // Unknown id → 404.
        let random = Uuid::new_v4();
        let (s1, _) = req(&st, "POST", &format!("/sessions/{random}/escrow"),
                          r#"{"device_index":0,"passcode":"0"}"#).await;
        assert_eq!(s1, StatusCode::NOT_FOUND);

        // A failed start retires its id; but create_session doesn't expose it, so
        // assert the expired set is populated and yields 410 for that id.
        req(&st, "POST", "/sessions", r#"{"apple_id":"me","password":"bad"}"#).await;
        let expired: Vec<Uuid> = st.expired.lock().await.iter().copied().collect();
        assert_eq!(expired.len(), 1);
        let (s2, b2) = req(&st, "POST", &format!("/sessions/{}/2fa", expired[0]),
                           r#"{"code":"1"}"#).await;
        assert_eq!(s2, StatusCode::GONE);
        assert_eq!(b2["error"], "session_expired");
    }
}
