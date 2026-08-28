//! The Apple login -> keychain-circle join -> CloudKit fetch pipeline, factored
//! out of `main` so both the interactive CLI and the `--serve` HTTP API can drive
//! it. The three mid-flight inputs (2FA code, escrow-bottle choice, device
//! passcode) are supplied through the [`Interact`] trait: the CLI implements it
//! with stdin prompts, the server with channels parked on HTTP requests.

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteClient, ArcAnisetteClient};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use rustpush::cloudkit::{
    pcs_keys_for_record, should_reset, CloudKitClient, CloudKitState,
    FetchRecordChangesOperation, NO_ASSETS,
};
use rustpush::cloudkit_proto::CloudKitRecord;
use rustpush::findmy::{
    BeaconAccessory, BeaconNamingRecord, BeaconRatchet, KeyAlignmentRecord,
    MasterBeaconRecord, SharedBeaconRecord, FIND_MY_SERVICE, SEARCH_PARTY_CONTAINER,
};
use rustpush::keychain::{KeychainClient, KeychainClientState};
use rustpush::{
    login_apple_delegates, APSState, AppleAccount, DebugMutex, DebugRwLock, LoginDelegate,
    OSConfig, PushError, TokenProvider,
};

use crate::logging;
use crate::FakeIOSConfig;

/// The serial `FakeIOSConfig` registers for this tool's own device. Every run
/// leaves one such phantom escrow bottle behind; they can never be used to join,
/// so they're filtered out of the device picker.
pub const FAKE_SERIAL: &str = "F2LZN0FAKE00";

/// A trusted device the user can pick to unlock the escrow (by its passcode).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceInfo {
    pub serial: String,
    pub name: String,
    pub model: String,
}

impl DeviceInfo {
    /// Pull a friendly name/model out of Apple's SecureBackup `ClientMetadata`
    /// (keys `device_name`, `device_model_class`, `device_model`), falling back
    /// to the serial when a device didn't record a name.
    fn from_metadata(serial: &str, md: &plist::Value) -> Self {
        let get = |k: &str| {
            md.as_dictionary()
                .and_then(|d| d.get(k))
                .and_then(|v| v.as_string())
                .map(str::to_string)
        };
        DeviceInfo {
            serial: serial.to_string(),
            name: get("device_name").unwrap_or_else(|| serial.to_string()),
            model: get("device_model_class")
                .or_else(|| get("device_model"))
                .unwrap_or_default(),
        }
    }
}

/// One exported AirTag's key material. Key bytes are raw here; the server
/// base64-encodes them and the CLI writes them into plists.
#[derive(Debug, Clone)]
pub struct BeaconExport {
    pub identifier: String,
    pub name: String,
    pub emoji: String,
    pub model: String,
    pub private_key: Vec<u8>,
    pub shared_secret: Vec<u8>,
    pub secondary_shared_secret: Option<Vec<u8>>,
    pub secure_locations_shared_secret: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    /// RFC3339 with whole seconds (Apple's plist parser rejects fractional).
    pub pairing_date: Option<String>,
}

/// The code for [`PipelineError::TrustCircleSignature`]. Named separately
/// because the retry path reports it before any error value exists — the join
/// hasn't failed the *attempt*, it has failed this device.
pub const TRUST_CIRCLE_SIGNATURE: &str = "trust_circle_signature";

/// Failure at a specific pipeline stage, mapped to the API's error codes.
#[derive(Debug)]
pub enum PipelineError {
    /// SRP + 2FA both surface here — rustpush's login doesn't separate a bad
    /// password from a bad 2FA code, so this covers both step-1/step-2 failures.
    BadCredentials(String),
    BadPasscode(String),
    /// The trust-circle join failed a *signature* check, not the passcode. Kept
    /// apart from `BadPasscode` because the two need opposite advice: this one
    /// is reached only after the passcode has already unlocked the escrow
    /// bottle, so "check your passcode" sends the user round a loop that cannot
    /// terminate. Trying a different trusted device is the way out.
    TrustCircleSignature(String),
    BadDeviceIndex(String),
    NoBottles,
    Apple(String),
    Aborted,
}

impl PipelineError {
    /// The machine-readable code returned in the JSON error body.
    pub fn code(&self) -> &'static str {
        match self {
            PipelineError::BadCredentials(_) => "bad_credentials",
            PipelineError::BadPasscode(_) => "bad_passcode",
            PipelineError::TrustCircleSignature(_) => TRUST_CIRCLE_SIGNATURE,
            PipelineError::BadDeviceIndex(_) => "bad_device_index",
            PipelineError::NoBottles => "no_bottles",
            PipelineError::Apple(_) => "apple_error",
            // Aborted is a local input timeout/cancellation, not an Apple fault —
            // the attempt lapsed, so report it as an expired session (410).
            PipelineError::Aborted => "session_expired",
        }
    }
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::BadCredentials(m) => write!(f, "{m}"),
            PipelineError::BadPasscode(m) => write!(f, "{m}"),
            PipelineError::TrustCircleSignature(m) => write!(f, "{m}"),
            PipelineError::BadDeviceIndex(m) => write!(f, "{m}"),
            PipelineError::NoBottles => {
                write!(f, "No escrow bottles found. Make sure you have another trusted device.")
            }
            PipelineError::Apple(m) => write!(f, "{m}"),
            PipelineError::Aborted => write!(f, "The connection attempt was cancelled."),
        }
    }
}

impl std::error::Error for PipelineError {}

/// Shown when the sign-in failed *before* Apple ever judged the credentials —
/// an HTTP error from a GSA endpoint, an anisette outage, a response we could
/// not parse. Deliberately says what it is not: the whole point of splitting
/// these out is that the previous blanket `bad_credentials` told users with a
/// correct password to go and retype it.
const LOGIN_UPSTREAM: &str =
    "Could not reach Apple's sign-in service. This is not a problem with your \
     Apple ID or password — please wait a minute and try again.";

/// Which `PipelineError` a failed [`AppleAccount::login`] becomes.
///
/// `icloud_auth::Error` mixes three unrelated failures behind one type, and
/// mapping the lot to `bad_credentials` is what produced our commonest support
/// case: "it says my password is wrong, but it isn't".
///
/// The discriminator is the *raise site*, not the variant name. `AuthSrp` reads
/// like a rejected password and is not one: all five of its sites are
/// `if !res.status().is_success()` against a `gsa.apple.com` endpoint, i.e. a
/// non-2xx. Apple rejects a password with a **200** carrying `ec != 0`, which
/// arrives here as `AuthSrpWithMessage` — that is where -22406 "Enter the
/// correct password for this Apple Account" comes from. `PlistError` is the
/// same story one layer down: an HTML error page where a plist was promised.
fn login_error(e: &icloud_auth::Error) -> PipelineError {
    use icloud_auth::Error as E;
    match e {
        // Apple looked at the credentials and said no. Its own wording is more
        // specific than anything we would write (locked account, wrong
        // password, expired code), so it is passed through.
        E::AuthSrpWithMessage(..) | E::Bad2faCode => {
            PipelineError::BadCredentials(format!("Apple sign-in failed: {e}"))
        }
        // The credentials are fine; the *account* is in a state that blocks
        // this login, and each of these carries the action that clears it.
        // Not `bad_credentials`: re-typing the password cannot fix any of them.
        E::ExtraStep(_) | E::FailedGetting2FAConfig | E::HardwareKeyError => {
            PipelineError::Apple(format!("Apple sign-in failed: {e}"))
        }
        // Transport, provisioning, or a response we could not parse — nothing
        // about the user's input. The variant and its payload are in the log
        // line above; the user gets a sentence they can act on instead.
        _ => PipelineError::Apple(LOGIN_UPSTREAM.to_string()),
    }
}

/// Supplies the three inputs that arrive mid-login. Must be `Send + Sync` so the
/// server can drive the pipeline from a spawned task (`&dyn Interact` is captured
/// by the login closure). `get_2fa_code` returns `String` because rustpush's
/// login closure is `Fn() -> String`; an empty string makes login fail cleanly.
pub trait Interact: Send + Sync {
    fn get_2fa_code(&self) -> String;
    fn choose_bottle(&self, devices: &[DeviceInfo]) -> Result<usize, PipelineError>;
    fn get_passcode(&self) -> Result<String, PipelineError>;
    /// A join failed in a way a *different* device can get past, and the
    /// pipeline is about to ask again. Implementors show this to the user; the
    /// next `choose_bottle` is the retry. Defaulted to nothing so a driver that
    /// only ever offers one device needn't care.
    fn join_retryable(&self, _error: &'static str, _detail: &str) {}
}

/// How many devices the user may try before the attempt is spent. A signature
/// failure is a property of the device chosen, not of the login, so the user
/// gets to work down the list — but not forever: each try is a real escrow
/// recovery against Apple, and an unbounded loop would let a stuck client spend
/// them all.
const MAX_JOIN_ATTEMPTS: usize = 3;

pub struct ExportOpts {
    pub apple_id: String,
    pub password: String,
    pub anisette_url: String,
    pub debug: bool,
    /// Short tag identifying this run in the log. In `--serve` this is the
    /// session id the HTTP API handed the caller, so a line here can be joined
    /// to the caller's own record of the same attempt; the CLI passes "cli".
    /// One Apple ID can have two attempts in flight (a user who retries), and
    /// their lines interleave — the Apple ID prefix alone doesn't separate them.
    pub session_id: String,
}

pub async fn run_export(
    opts: ExportOpts,
    io: &dyn Interact,
) -> Result<Vec<BeaconExport>, PipelineError> {
    let debug = opts.debug;
    let config: Arc<dyn OSConfig> = Arc::new(FakeIOSConfig::new());
    let started = std::time::Instant::now();

    // `apple_id` arrives unvalidated from the caller's JSON body. Interpolated
    // raw, a newline in it forges a whole log record — including one carrying
    // another session's tag, which poisons exactly the cross-log join these
    // lines exist to support.
    let apple_id = sanitize(&opts.apple_id);

    // Every log line is prefixed with the Apple ID and the run's session tag so
    // concurrent `--serve` runs — including two attempts by the same account —
    // can be told apart in interleaved output.
    macro_rules! log {
        ($($arg:tt)*) => {
            eprintln!("[{}] [sess={}] {}", apple_id, opts.session_id, format_args!($($arg)*))
        };
    }

    // Until this existed, a failed export logged NOTHING: every `?` turned into
    // an HTTP error body for the caller and the log simply stopped at the last
    // step that had succeeded, so a user's screenshot could not be tied to the
    // step that produced it. Both `{}` and `{:?}` are logged on purpose —
    // rustpush's Display collapses unrelated failures onto the same words (the
    // "Bad message" users report is `PushError::BadMsg`), and only the Debug
    // form names the variant. The step number and elapsed time separate an
    // Apple rejection from a stall.
    macro_rules! step_failed {
        ($step:expr, $variant:path, $msg:literal, $e:expr) => {{
            let e = $e;
            log!("!! FAILED at {} after {:.1}s: {} [{:?}]", $step, started.elapsed().as_secs_f32(), e, e);
            $variant(format!(concat!($msg, ": {}"), e))
        }};
        // No underlying error — a response that is simply missing a field we
        // need. The `{:?}` form above earns its place only for a rustpush error
        // whose variant name it reveals; for a message we wrote ourselves it
        // would just print the same words twice, in the log and in the API's
        // `detail`.
        ($step:expr, $variant:path, $msg:literal) => {{
            log!("!! FAILED at {} after {:.1}s: {}", $step, started.elapsed().as_secs_f32(), $msg);
            $variant($msg.to_string())
        }};
    }

    // ── Step 1: Create anisette client ──────────────────────────────
    // The anisette server is third-party and has broken before; naming which
    // one this run used is the difference between "Apple rejected us" and "our
    // provisioning host was down".
    log!("[1/7] Connecting to anisette server ({})...", opts.anisette_url);
    let anisette_config_path = PathBuf::from_str("anisette_state").unwrap();
    std::fs::create_dir_all(&anisette_config_path).ok();

    let login_info = config.get_gsa_config(&APSState::default(), false);

    let anisette_client: ArcAnisetteClient<RemoteAnisetteProviderV3> =
        Arc::new(Mutex::new(AnisetteClient::new(RemoteAnisetteProviderV3::new(
            opts.anisette_url.clone(),
            login_info.clone(),
            anisette_config_path,
        ))));

    // ── Step 2: Login to Apple ──────────────────────────────────────
    log!("[2/7] Logging in to Apple ID...");
    let apple_id_clone = opts.apple_id.clone();
    let password_hash: Vec<u8> = Sha256::digest(opts.password.as_bytes()).to_vec();
    let appleid_closure = move || (apple_id_clone.clone(), password_hash.clone());
    let tfa_closure = || io.get_2fa_code();

    let account =
        AppleAccount::login(appleid_closure, tfa_closure, login_info, anisette_client.clone())
            .await
            .map_err(|e| {
                // Not `step_failed!`: the log keeps the full error (and its
                // variant, via `{:?}`) while the user-facing message depends on
                // which kind of failure it was — see `login_error`.
                log!("!! FAILED at [2/7] login after {:.1}s: {} [{:?}]",
                     started.elapsed().as_secs_f32(), e, e);
                login_error(&e)
            })?;

    // These three were `expect`/`unwrap`: a panic unwinding out of the pipeline
    // task, which the server can only report as "failed unexpectedly" with no
    // attribution. A login that returns no SPD is a real (if rare) Apple
    // response, so it gets a logged, attributable failure like any other.
    // `spd["DsPrsId"]` would be the same panic by another route — plist's
    // `Dictionary` indexes through `IndexMap`, which panics on an absent key
    // (rustpush's own code writes `.expect("no dsid???")` there, so a missing
    // key is the expected failure, not an impossible one) — hence `get`.
    let spd = account.spd.as_ref().ok_or_else(|| {
        step_failed!("[2/7] login", PipelineError::Apple, "No SPD after login")
    })?;
    let dsid = spd
        .get("DsPrsId")
        .and_then(|v| v.as_unsigned_integer())
        .ok_or_else(|| {
            step_failed!("[2/7] login", PipelineError::Apple, "No DsPrsId in SPD")
        })?
        .to_string();
    let adsid = spd
        .get("adsid")
        .and_then(|v| v.as_string())
        .ok_or_else(|| {
            step_failed!("[2/7] login", PipelineError::Apple, "No adsid in SPD")
        })?
        .to_string();
    log!("  Logged in (dsid={}) after {:.1}s", dsid, started.elapsed().as_secs_f32());

    // ── Step 3: Get MobileMe delegate ───────────────────────────────
    log!("[3/7] Fetching MobileMe delegate...");
    let delegates =
        login_apple_delegates(&account, None, config.as_ref(), &[LoginDelegate::MobileMe])
            .await
            .map_err(|e| {
                step_failed!("[3/7] MobileMe delegate", PipelineError::Apple, "MobileMe delegate failed", e)
            })?;
    let mobileme = delegates.mobileme.ok_or_else(|| {
        step_failed!("[3/7] MobileMe delegate", PipelineError::Apple, "No MobileMe delegate returned")
    })?;

    // ── Step 4: Create CloudKit + Keychain clients ──────────────────
    log!("[4/7] Setting up CloudKit & Keychain...");
    let keychain_state = KeychainClientState::new(dsid.clone(), adsid.clone(), &mobileme)
        .unwrap_or_else(|| {
            log!("  (escrowProxyUrl not in MobileMe config, using default)");
            KeychainClientState::new_with_host(
                dsid.clone(),
                adsid.clone(),
                "https://p97-escrowproxy.icloud.com:443".to_string(),
            )
        });

    let account_arc = Arc::new(DebugMutex::new(account));
    let token_provider = TokenProvider::new(account_arc.clone(), config.clone());
    token_provider.set_mme_delegate(mobileme).await;

    let cloudkit_state = CloudKitState::new(dsid.clone()).ok_or_else(|| {
        step_failed!("[4/7] CloudKit setup", PipelineError::Apple, "Failed to create CloudKitState")
    })?;
    let cloudkit = Arc::new(CloudKitClient {
        state: DebugRwLock::new(cloudkit_state),
        anisette: anisette_client.clone(),
        config: config.clone(),
        token_provider: token_provider.clone(),
    });

    let keychain = Arc::new(KeychainClient {
        anisette: anisette_client.clone(),
        token_provider: token_provider.clone(),
        state: DebugRwLock::new(keychain_state),
        config: config.clone(),
        update_state: Box::new(|_| {}),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    // ── Step 5: Join iCloud Keychain circle via escrow ────────────
    log!("[5/7] Joining iCloud Keychain trust circle...");
    let all_bottles = keychain
        .get_viable_bottles()
        .await
        .map_err(|e| {
            step_failed!("[5/7] fetch escrow bottles", PipelineError::Apple,
                         "Fetching escrow bottles failed", e)
        })?;
    let total_bottles = all_bottles.len();
    // Drop this tool's own phantom device (one per past run) so the picker only
    // offers real, usable trusted devices.
    let bottles: Vec<_> = all_bottles
        .into_iter()
        .filter(|(_, meta)| meta.serial != FAKE_SERIAL)
        .collect();
    // Both counts: "no usable devices" reads very differently when Apple
    // returned nothing at all than when every bottle we got was our own phantom.
    log!("  Escrow bottles: {} returned, {} usable (dropped {} of our own)",
         total_bottles, bottles.len(), total_bottles - bottles.len());
    if bottles.is_empty() {
        log!("!! FAILED at [5/7] escrow bottles after {:.1}s: no usable bottles",
             started.elapsed().as_secs_f32());
        return Err(PipelineError::NoBottles);
    }
    let devices: Vec<DeviceInfo> = bottles
        .iter()
        .map(|(_, meta)| DeviceInfo::from_metadata(&meta.serial, &meta.client_metadata))
        .collect();
    log!("  Found {} usable device(s):", devices.len());
    for (i, d) in devices.iter().enumerate() {
        // Device names come from Apple, i.e. from whatever the user typed into
        // Settings — the same forged-record hole as `apple_id`, from the other
        // direction.
        log!("    [{}] {} ({}) [{}]", i, sanitize(&d.name), sanitize(&d.model), sanitize(&d.serial));
    }
    // A signature failure is a property of the device the user picked, not of
    // the login: the escrow bottle decrypted, so the passcode was right, and the
    // circle's own signed data is what didn't verify. The way through is another
    // device — so ask again rather than failing the attempt, which would cost
    // the user their password and 2FA to retry the one thing the error tells
    // them to do.
    for attempt in 1..=MAX_JOIN_ATTEMPTS {
        let bottle_idx = io.choose_bottle(&devices).inspect_err(|e| {
            log!("!! FAILED at [5/7] device choice after {:.1}s: {} [{:?}]",
                 started.elapsed().as_secs_f32(), e, e);
        })?;
        if bottle_idx >= bottles.len() {
            log!("!! FAILED at [5/7] device choice: index {} out of range 0-{}",
                 bottle_idx, bottles.len().saturating_sub(1));
            return Err(PipelineError::BadDeviceIndex(format!(
                "Invalid device index {bottle_idx}. Must be 0-{}.",
                bottles.len().saturating_sub(1)
            )));
        }
        let (bottle, _) = &bottles[bottle_idx];
        let passcode = io.get_passcode().inspect_err(|e| {
            log!("!! FAILED at [5/7] passcode input after {:.1}s: {} [{:?}]",
                 started.elapsed().as_secs_f32(), e, e);
        })?;
        // The passcode's length, never the passcode: a Mac wants its login
        // password while a phone wants 4/6 digits, and the commonest support case
        // is someone typing the wrong one of those for the device they picked.
        // Characters, not `len()`'s UTF-8 bytes — an accented Mac password would
        // otherwise report a length the user never typed, undercutting the one
        // thing the line is for.
        log!("  Attempt {}/{} — using device [{}]: {} ({}) [{}], passcode {} chars",
             attempt, MAX_JOIN_ATTEMPTS, bottle_idx,
             sanitize(&devices[bottle_idx].name), sanitize(&devices[bottle_idx].model),
             sanitize(&devices[bottle_idx].serial), passcode.chars().count());

        let join_started = std::time::Instant::now();
        let Err(e) = keychain
            .join_clique_from_escrow(bottle, passcode.as_bytes(), b"findmy-export")
            .await
        else {
            log!("  Joined keychain trust circle in {:.1}s!", join_started.elapsed().as_secs_f32());
            break;
        };

        log!("!! FAILED at [5/7] join trust circle after {:.1}s ({:.1}s in the join): {} [{:?}]",
             started.elapsed().as_secs_f32(), join_started.elapsed().as_secs_f32(), e, e);
        // This call fails for several unrelated reasons and only some of them
        // are the passcode. `PushError::BadMsg` in particular is a *signature*
        // verification failure, reached only after the passcode has already
        // unlocked the bottle — a genuinely wrong passcode fails earlier, in the
        // escrow SRP exchange, as an escrow/HTTP error. So BadMsg gets its own
        // message: telling that user to re-check their passcode sends them round
        // a loop that cannot terminate.
        //
        // rustpush logs the identical "Signature verification failed" at all
        // four sites, so which one it was comes from `logging`'s checkpoint —
        // available here at the default log level, with no keychain contents
        // spilled to get it. See `logging::CHECKPOINTS`.
        if !matches!(e, PushError::BadMsg) {
            return Err(PipelineError::BadPasscode(format!(
                "Joining the keychain trust circle failed (wrong passcode?): {e}"
            )));
        }
        let failing = match logging::last_checkpoint() {
            Some(c) => {
                log!("   last keychain checkpoint: {:?}", c.prefix());
                c.verifies()
            }
            // Nothing reached: the first check in the join is the bottle's own
            // escrowed-key signature, which rustpush verifies before the peer
            // lookup that logs the first checkpoint.
            None => Some("the escrow bottle's own escrowed-key signature"),
        };
        match failing {
            Some(what) => log!("   => signature check failed on {what} — NOT a rejected \
                                passcode (the bottle had already decrypted)"),
            // A checkpoint with no check after it. Saying which signature failed
            // would be a guess, and the guess is the thing this whole path
            // exists to stop.
            None => log!("   => BadMsg at a point with no expected signature check; \
                          not one of the known join sites"),
        }
        let detail = format!(
            "Joining the keychain trust circle failed a signature check on {}. \
             This is not a wrong passcode — the device passcode already worked. \
             Try connecting with a different trusted device.",
            failing.unwrap_or("an unidentified signature")
        );
        // Retrying needs somewhere to go. With one device the user would just be
        // asked for the same one again — and the CLI, which auto-picks when
        // there is only one, would silently re-run it to the attempt limit.
        if attempt == MAX_JOIN_ATTEMPTS || devices.len() < 2 {
            log!("   => no retry ({}); ending the attempt",
                 if devices.len() < 2 { "only one trusted device" } else { "attempts spent" });
            return Err(PipelineError::TrustCircleSignature(detail));
        }
        // Round again: `join_retryable` lets the driver report this, and the
        // next `choose_bottle` collects another device.
        log!("   => asking for another device (attempt {}/{})", attempt + 1, MAX_JOIN_ATTEMPTS);
        io.join_retryable(TRUST_CIRCLE_SIGNATURE, &detail);
    }

    // ── Step 6: Fetch BeaconStore records from CloudKit ─────────────
    log!("[6/7] Fetching FindMy accessories from CloudKit...");
    let container = SEARCH_PARTY_CONTAINER
        .init(cloudkit.clone())
        .await
        .map_err(|e| {
            step_failed!("[6/7] CloudKit container init", PipelineError::Apple,
                         "CloudKit container init failed", e)
        })?;
    let beacon_zone = container.private_zone("BeaconStore".to_string());
    let key = container
        .get_zone_encryption_config(&beacon_zone, &keychain, &FIND_MY_SERVICE)
        .await
        .map_err(|e| {
            step_failed!("[6/7] zone encryption config", PipelineError::Apple,
                         "Zone encryption config failed", e)
        })?;

    let mut beacon_records: HashMap<String, MasterBeaconRecord> = HashMap::new();
    let mut naming_records: HashMap<String, (String, BeaconNamingRecord)> = HashMap::new();
    let mut alignment_records: HashMap<String, (String, KeyAlignmentRecord)> = HashMap::new();

    let mut result =
        FetchRecordChangesOperation::do_sync(&container, &[(beacon_zone.clone(), None)], &NO_ASSETS)
            .await;
    if should_reset(result.as_ref().err()) {
        // A retried sync that then succeeds looks identical to a first-try
        // success, and a second failure looks like a single one.
        log!("  CloudKit sync asked for a reset; retrying once");
        result = FetchRecordChangesOperation::do_sync(
            &container,
            &[(beacon_zone.clone(), None)],
            &NO_ASSETS,
        )
        .await;
    }

    // `.remove(0)` and the per-change field accesses below were unwraps on data
    // Apple controls — the least predictable input in the whole pipeline, and
    // the panic source `spawn_session_with` names when it explains why the
    // pipeline runs on its own task. A panic here reaches the user as "The
    // export failed unexpectedly." with no step attribution at all, which is
    // the failure class this instrumentation exists to remove.
    let mut zones = result.map_err(|e| {
        step_failed!("[6/7] CloudKit fetch", PipelineError::Apple, "CloudKit fetch failed", e)
    })?;
    if zones.is_empty() {
        return Err(step_failed!("[6/7] CloudKit fetch", PipelineError::Apple,
                                "CloudKit returned no BeaconStore zone"));
    }
    let (_, changes, _) = zones.remove(0);

    log!("  CloudKit returned {} change(s)", changes.len());

    let mut skipped = 0usize;
    for change in changes {
        // A single malformed change must not kill an otherwise good export, but
        // it must not vanish either: the count below is what says whether a
        // short export is Apple's doing or ours.
        let Some(identifier) = change
            .identifier
            .as_ref()
            .and_then(|i| i.value.as_ref())
            .map(|v| v.name().to_string())
        else {
            log!("  skipping a change with no record identifier");
            skipped += 1;
            continue;
        };
        let Some(record) = change.record else { continue };
        let Some(record_type) = record.r#type.as_ref().map(|t| t.name().to_string()) else {
            log!("  skipping change {}: record has no type", sanitize(&identifier));
            skipped += 1;
            continue;
        };

        if record_type == MasterBeaconRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)
                .map_err(|e| {
                    step_failed!("[6/7] PCS record keys", PipelineError::Apple, "PCS keys failed", e)
                })?;
            let item = MasterBeaconRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            beacon_records.insert(identifier, item);
        } else if record_type == BeaconNamingRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)
                .map_err(|e| {
                    step_failed!("[6/7] PCS record keys", PipelineError::Apple, "PCS keys failed", e)
                })?;
            let item = BeaconNamingRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            naming_records.insert(item.associated_beacon.clone(), (identifier, item));
        } else if record_type == KeyAlignmentRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)
                .map_err(|e| {
                    step_failed!("[6/7] PCS record keys", PipelineError::Apple, "PCS keys failed", e)
                })?;
            let item = KeyAlignmentRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            alignment_records.insert(item.beacon_identifier.clone(), (identifier, item));
        } else if debug && record_type == SharedBeaconRecord::record_type() {
            log!("  [debug] Shared beacon id={} (not exported)", sanitize(&identifier));
        }
    }
    if skipped > 0 {
        log!("  Skipped {} malformed change(s) from CloudKit", skipped);
    }

    // An export that "succeeds" with nothing in it is the hardest failure to
    // read from outside — the wizard finishes and the user's map stays empty.
    // The per-type counts say whether CloudKit gave us no beacons at all or we
    // dropped them while assembling.
    log!("  Records decrypted: {} master, {} naming, {} alignment",
         beacon_records.len(), naming_records.len(), alignment_records.len());

    // ── Assemble accessories ────────────────────────────────────────
    let mut accessories: HashMap<String, BeaconAccessory> = HashMap::new();
    for (id, master) in beacon_records {
        let stable_id = master.stable_identifier.clone();
        // associated_beacon / beacon_identifier hold the master's CloudKit UUID
        // (`id`), not its stable_identifier — see the CLI's long-form note.
        let naming = naming_records.remove(&id).unwrap_or_else(|| {
            (
                String::new(),
                BeaconNamingRecord {
                    emoji: "".to_string(),
                    name: format!("Unknown-{}", stable_id),
                    associated_beacon: id.clone(),
                    role_id: 0,
                },
            )
        });
        let alignment = alignment_records.remove(&id).unwrap_or_default();
        accessories.insert(
            id,
            BeaconAccessory {
                master_record: master,
                naming: naming.1,
                naming_id: naming.0,
                naming_prot_tag: None,
                alignment: alignment.1.clone(),
                alignment_id: alignment.0,
                aligment_prot_tag: None,
                local_alignment: alignment.1,
                last_report: None,
                primary_ratchet: BeaconRatchet::default(),
                secondary_ratchet: BeaconRatchet::default(),
            },
        );
    }

    log!("[7/7] Assembling {} accessory export(s)... (total {:.1}s)",
         accessories.len(), started.elapsed().as_secs_f32());
    if accessories.is_empty() {
        log!("!! WARNING: export succeeded with zero accessories — the caller will \
              report a connected account with no tags");
    }
    // Move the accessories (and their secret key bytes) into the exports rather
    // than cloning — accessories is dropped right after.
    Ok(accessories.into_values().map(beacon_export).collect())
}

fn beacon_export(acc: BeaconAccessory) -> BeaconExport {
    let m = acc.master_record;
    BeaconExport {
        identifier: m.stable_identifier,
        name: acc.naming.name,
        emoji: acc.naming.emoji,
        model: m.model,
        private_key: m.private_key,
        shared_secret: m.shared_secret,
        secondary_shared_secret: m.shared_secret_2,
        secure_locations_shared_secret: m.secure_locations_shared_secret,
        public_key: Some(m.public_key),
        pairing_date: m.pairing_date.map(rfc3339_secs),
    }
}

/// Strip control characters from anything interpolated into a log line. The
/// Apple ID comes straight from the caller's JSON body and device names come
/// from Apple; a newline in either ends the current record and starts one the
/// attacker writes, which is enough to forge a `[sess=…]`-tagged success line
/// for somebody else's attempt.
fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '\u{fffd}' } else { c }).collect()
}

/// Whole-second RFC3339 (`2026-01-11T19:57:42Z`). Apple's plist parser and
/// `datetime.fromisoformat` both reject the nanosecond precision CloudKit carries.
fn rfc3339_secs(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    chrono::DateTime::<chrono::Utc>::from(UNIX_EPOCH + Duration::from_secs(secs))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md(pairs: &[(&str, &str)]) -> plist::Value {
        let mut d = plist::Dictionary::new();
        for (k, v) in pairs {
            d.insert((*k).into(), plist::Value::String((*v).into()));
        }
        plist::Value::Dictionary(d)
    }

    #[test]
    fn device_info_prefers_name_and_model_class() {
        let info = DeviceInfo::from_metadata(
            "GYK3003QMY",
            &md(&[
                ("device_name", "Grega's MacBook Air"),
                ("device_model_class", "MacBook Air"),
                ("device_model", "Mac17,4"),
            ]),
        );
        assert_eq!(info.serial, "GYK3003QMY");
        assert_eq!(info.name, "Grega's MacBook Air");
        assert_eq!(info.model, "MacBook Air"); // class preferred over device_model
    }

    #[test]
    fn device_info_falls_back_to_model_then_serial() {
        // No model_class → device_model; no device_name → serial.
        let info = DeviceInfo::from_metadata("J9NQHW229W", &md(&[("device_model", "iPhone 16")]));
        assert_eq!(info.name, "J9NQHW229W");
        assert_eq!(info.model, "iPhone 16");

        // Empty metadata → serial as name, empty model.
        let info = DeviceInfo::from_metadata("SER", &md(&[]));
        assert_eq!(info.name, "SER");
        assert_eq!(info.model, "");
    }

    #[test]
    fn rfc3339_secs_truncates_to_whole_seconds() {
        assert_eq!(rfc3339_secs(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // Sub-second precision is dropped — Apple's plist parser rejects it.
        let t = UNIX_EPOCH + Duration::from_millis(1_500);
        assert_eq!(rfc3339_secs(t), "1970-01-01T00:00:01Z");
        let t = UNIX_EPOCH + Duration::from_nanos(1_736_625_462_920_991_898);
        let s = rfc3339_secs(t);
        assert!(!s.contains('.') && s.ends_with('Z'), "no fractional seconds: {s}");
    }

    #[test]
    fn sanitize_stops_a_caller_forging_a_log_record() {
        // The Apple ID is caller-supplied. A newline in it would close our line
        // and open one attributed to another session — defeating the cross-log
        // join the tag exists for.
        let forged = "a@b.com\n[victim@icloud.com] [sess=3f2a1b8c]   Joined trust circle!";
        let clean = sanitize(forged);
        assert!(!clean.contains('\n'), "{clean}");
        assert!(!clean.contains('\r'));
        assert!(clean.starts_with("a@b.com"));
        // Ordinary text, including non-ASCII, is untouched.
        assert_eq!(sanitize("Grega's MacBook Air"), "Grega's MacBook Air");
        assert_eq!(sanitize("iPhone de José"), "iPhone de José");
    }

    #[test]
    fn passcode_length_counts_characters_not_bytes() {
        // The log reports a passcode's length to tell a Mac login password from
        // a 4/6-digit phone passcode. Counting UTF-8 bytes would report 10 for
        // an 8-character accented password and send support down the wrong path.
        assert_eq!("pässwörd".chars().count(), 8);
        assert_eq!("pässwörd".len(), 10);
    }

    /// The bug this file's `login_error` exists to stop: five sessions in one
    /// eight-minute window were told "Apple sign-in failed: Failed to parse a
    /// plist Serde(invalid type: string "<html>", expected a map)" under
    /// `bad_credentials` — i.e. a user whose password was never even checked
    /// was told to check their password. If any arm here starts returning
    /// `bad_credentials` again, that support case is back.
    #[test]
    fn login_error_does_not_blame_the_password_for_an_upstream_failure() {
        use icloud_auth::Error as E;

        // Exactly what production hit: an HTML error page where a plist was
        // promised, which `?` converts into `Error::PlistError`.
        let html: E = plist::from_bytes::<plist::Dictionary>(b"<html>Bad Gateway</html>")
            .unwrap_err()
            .into();
        // Reads like a rejected password; is not one. Every `AuthSrp` site in
        // icloud_auth is `if !res.status().is_success()` against a GSA endpoint.
        for e in [html, E::AuthSrp, E::Parse, E::HappyBirthdayError] {
            let mapped = login_error(&e);
            assert_ne!(mapped.code(), "bad_credentials", "{e:?} must not blame the password");
            assert_eq!(mapped.code(), "apple_error");
            assert_eq!(mapped.to_string(), LOGIN_UPSTREAM);
        }

        // Account state: the credentials are right, so re-typing them is not the
        // way out. Apple's own wording carries the action that is.
        for e in [E::ExtraStep("repair".into()), E::FailedGetting2FAConfig, E::HardwareKeyError] {
            let mapped = login_error(&e);
            assert_ne!(mapped.code(), "bad_credentials", "{e:?} must not blame the password");
            assert_eq!(mapped.code(), "apple_error");
            assert!(mapped.to_string().contains(&e.to_string()), "{mapped} drops Apple's advice");
        }
    }

    /// The other half: a genuinely wrong password must still say so, or the fix
    /// above has simply moved the confusion to the users who *did* mistype.
    #[test]
    fn login_error_keeps_apples_own_verdict_on_the_credentials() {
        use icloud_auth::Error as E;

        // Apple rejects a password with HTTP 200 and `ec != 0` — this variant,
        // not `AuthSrp`. -22406 is the code our reporters actually saw.
        let rejected = E::AuthSrpWithMessage(
            -22406,
            "Enter the correct password for this Apple Account".into(),
        );
        let mapped = login_error(&rejected);
        assert_eq!(mapped.code(), "bad_credentials");
        assert!(mapped.to_string().contains("-22406"), "{mapped}");
        assert!(mapped.to_string().contains("Enter the correct password"), "{mapped}");

        assert_eq!(login_error(&E::Bad2faCode).code(), "bad_credentials");
    }

    #[test]
    fn pipeline_error_codes_and_messages() {
        assert_eq!(PipelineError::BadCredentials("x".into()).code(), "bad_credentials");
        assert_eq!(PipelineError::BadPasscode("x".into()).code(), "bad_passcode");
        // Distinct from bad_passcode on purpose: a client that tells the user to
        // re-enter their passcode here would be telling them to retry the one
        // thing that already worked.
        assert_eq!(
            PipelineError::TrustCircleSignature("x".into()).code(),
            "trust_circle_signature"
        );
        assert_eq!(PipelineError::BadDeviceIndex("x".into()).code(), "bad_device_index");
        assert_eq!(PipelineError::NoBottles.code(), "no_bottles");
        assert_eq!(PipelineError::Apple("x".into()).code(), "apple_error");
        // A local input timeout is not Apple's fault.
        assert_eq!(PipelineError::Aborted.code(), "session_expired");
        // Display is never empty — it becomes the JSON `detail`.
        assert!(!PipelineError::NoBottles.to_string().is_empty());
        assert!(!PipelineError::Aborted.to_string().is_empty());
    }
}
