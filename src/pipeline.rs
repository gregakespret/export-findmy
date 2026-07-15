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
    OSConfig, TokenProvider,
};

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

/// Failure at a specific pipeline stage, mapped to the API's error codes.
#[derive(Debug)]
pub enum PipelineError {
    /// SRP + 2FA both surface here — rustpush's login doesn't separate a bad
    /// password from a bad 2FA code, so this covers both step-1/step-2 failures.
    BadCredentials(String),
    BadPasscode(String),
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

/// Supplies the three inputs that arrive mid-login. Must be `Send + Sync` so the
/// server can drive the pipeline from a spawned task (`&dyn Interact` is captured
/// by the login closure). `get_2fa_code` returns `String` because rustpush's
/// login closure is `Fn() -> String`; an empty string makes login fail cleanly.
pub trait Interact: Send + Sync {
    fn get_2fa_code(&self) -> String;
    fn choose_bottle(&self, devices: &[DeviceInfo]) -> Result<usize, PipelineError>;
    fn get_passcode(&self) -> Result<String, PipelineError>;
}

pub struct ExportOpts {
    pub apple_id: String,
    pub password: String,
    pub anisette_url: String,
    pub debug: bool,
}

pub async fn run_export(
    opts: ExportOpts,
    io: &dyn Interact,
) -> Result<Vec<BeaconExport>, PipelineError> {
    let debug = opts.debug;
    let config: Arc<dyn OSConfig> = Arc::new(FakeIOSConfig::new());

    // Every log line is prefixed with the Apple ID so concurrent `--serve` runs
    // (each driving a different account) can be told apart in interleaved output.
    macro_rules! log {
        ($($arg:tt)*) => {
            eprintln!("[{}] {}", opts.apple_id, format_args!($($arg)*))
        };
    }

    // ── Step 1: Create anisette client ──────────────────────────────
    log!("[1/7] Connecting to anisette server...");
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
            .map_err(|e| PipelineError::BadCredentials(format!("Apple sign-in failed: {e}")))?;

    let spd = account.spd.as_ref().expect("No SPD after login");
    let dsid = spd["DsPrsId"].as_unsigned_integer().unwrap().to_string();
    let adsid = spd["adsid"].as_string().unwrap().to_string();
    log!("  Logged in (dsid={})", dsid);

    // ── Step 3: Get MobileMe delegate ───────────────────────────────
    log!("[3/7] Fetching MobileMe delegate...");
    let delegates =
        login_apple_delegates(&account, None, config.as_ref(), &[LoginDelegate::MobileMe])
            .await
            .map_err(|e| PipelineError::Apple(format!("MobileMe delegate failed: {e}")))?;
    let mobileme = delegates.mobileme.expect("No MobileMe delegate returned");

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

    let cloudkit_state =
        CloudKitState::new(dsid.clone()).expect("Failed to create CloudKitState");
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
        .map_err(|e| PipelineError::Apple(format!("Fetching escrow bottles failed: {e}")))?;
    // Drop this tool's own phantom device (one per past run) so the picker only
    // offers real, usable trusted devices.
    let bottles: Vec<_> = all_bottles
        .into_iter()
        .filter(|(_, meta)| meta.serial != FAKE_SERIAL)
        .collect();
    if bottles.is_empty() {
        return Err(PipelineError::NoBottles);
    }
    let devices: Vec<DeviceInfo> = bottles
        .iter()
        .map(|(_, meta)| DeviceInfo::from_metadata(&meta.serial, &meta.client_metadata))
        .collect();
    log!("  Found {} usable device(s):", devices.len());
    for (i, d) in devices.iter().enumerate() {
        log!("    [{}] {} ({}) [{}]", i, d.name, d.model, d.serial);
    }
    let bottle_idx = io.choose_bottle(&devices)?;
    if bottle_idx >= bottles.len() {
        return Err(PipelineError::BadDeviceIndex(format!(
            "Invalid device index {bottle_idx}. Must be 0-{}.",
            bottles.len().saturating_sub(1)
        )));
    }
    let (bottle, _) = &bottles[bottle_idx];
    log!("  Using device: {} [{}]", devices[bottle_idx].name, devices[bottle_idx].serial);
    let passcode = io.get_passcode()?;

    keychain
        .join_clique_from_escrow(bottle, passcode.as_bytes(), b"findmy-export")
        .await
        .map_err(|e| {
            PipelineError::BadPasscode(format!(
                "Joining the keychain trust circle failed (wrong passcode?): {e}"
            ))
        })?;
    log!("  Joined keychain trust circle!");

    // ── Step 6: Fetch BeaconStore records from CloudKit ─────────────
    log!("[6/7] Fetching FindMy accessories from CloudKit...");
    let container = SEARCH_PARTY_CONTAINER
        .init(cloudkit.clone())
        .await
        .map_err(|e| PipelineError::Apple(format!("CloudKit container init failed: {e}")))?;
    let beacon_zone = container.private_zone("BeaconStore".to_string());
    let key = container
        .get_zone_encryption_config(&beacon_zone, &keychain, &FIND_MY_SERVICE)
        .await
        .map_err(|e| PipelineError::Apple(format!("Zone encryption config failed: {e}")))?;

    let mut beacon_records: HashMap<String, MasterBeaconRecord> = HashMap::new();
    let mut naming_records: HashMap<String, (String, BeaconNamingRecord)> = HashMap::new();
    let mut alignment_records: HashMap<String, (String, KeyAlignmentRecord)> = HashMap::new();

    let mut result =
        FetchRecordChangesOperation::do_sync(&container, &[(beacon_zone.clone(), None)], &NO_ASSETS)
            .await;
    if should_reset(result.as_ref().err()) {
        result = FetchRecordChangesOperation::do_sync(
            &container,
            &[(beacon_zone.clone(), None)],
            &NO_ASSETS,
        )
        .await;
    }

    let (_, changes, _) = result
        .map_err(|e| PipelineError::Apple(format!("CloudKit fetch failed: {e}")))?
        .remove(0);

    if debug {
        log!("  [debug] total CloudKit changes returned: {}", changes.len());
    }

    for change in changes {
        let identifier = change
            .identifier
            .as_ref()
            .unwrap()
            .value
            .as_ref()
            .unwrap()
            .name()
            .to_string();
        let Some(record) = change.record else { continue };
        let record_type = record.r#type.as_ref().unwrap().name().to_string();

        if record_type == MasterBeaconRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)
                .map_err(|e| PipelineError::Apple(format!("PCS keys failed: {e}")))?;
            let item = MasterBeaconRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            beacon_records.insert(identifier, item);
        } else if record_type == BeaconNamingRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)
                .map_err(|e| PipelineError::Apple(format!("PCS keys failed: {e}")))?;
            let item = BeaconNamingRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            naming_records.insert(item.associated_beacon.clone(), (identifier, item));
        } else if record_type == KeyAlignmentRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)
                .map_err(|e| PipelineError::Apple(format!("PCS keys failed: {e}")))?;
            let item = KeyAlignmentRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            alignment_records.insert(item.beacon_identifier.clone(), (identifier, item));
        } else if debug && record_type == SharedBeaconRecord::record_type() {
            log!("  [debug] Shared beacon id={} (not exported)", identifier);
        }
    }

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

    log!("[7/7] Assembling {} accessory export(s)...", accessories.len());
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
    fn pipeline_error_codes_and_messages() {
        assert_eq!(PipelineError::BadCredentials("x".into()).code(), "bad_credentials");
        assert_eq!(PipelineError::BadPasscode("x".into()).code(), "bad_passcode");
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
