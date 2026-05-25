use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use keystore::{init_keystore, software::{NoEncryptor, SoftwareKeystore}};
use sha2::{Sha256, Digest};
use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteClient, ArcAnisetteClient};
use plist::Dictionary;
use tokio::sync::Mutex;

use rustpush::cloudkit::{
    pcs_keys_for_record, should_reset, CloudKitClient, CloudKitState,
    FetchRecordChangesOperation, NO_ASSETS,
};
use rustpush::cloudkit_proto::CloudKitRecord;
use rustpush::findmy::{
    BeaconAccessory, BeaconNamingRecord, BeaconRatchet,
    KeyAlignmentRecord, MasterBeaconRecord, SharedBeaconRecord,
    SEARCH_PARTY_CONTAINER, FIND_MY_SERVICE,
};
use rustpush::keychain::{KeychainClient, KeychainClientState};
use rustpush::{
    login_apple_delegates, APSState, ActivationInfo, AppleAccount, DebugMutex, DebugRwLock,
    LoginDelegate, OSConfig, PushError, TokenProvider,
};
use rustpush::{DebugMeta, RegisterMeta};

// ── Fake OSConfig (presents as iPhone to avoid NAS validation) ───────

struct FakeIOSConfig {
    device_uuid: String,
    serial: String,
    udid: String,
}

impl FakeIOSConfig {
    fn new() -> Self {
        FakeIOSConfig {
            device_uuid: uuid::Uuid::new_v4().to_string().to_uppercase(),
            serial: "F2LZN0FAKE00".to_string(),
            udid: format!("{:032X}", rand::random::<u128>()),
        }
    }
}

#[async_trait]
impl OSConfig for FakeIOSConfig {
    fn build_activation_info(&self, _csr: Vec<u8>) -> ActivationInfo {
        unreachable!("activation not needed for FindMy export")
    }

    fn get_activation_device(&self) -> String {
        "iPhone".to_string()
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        Ok(vec![])
    }

    fn get_protocol_version(&self) -> u32 {
        1640
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: "iPhone15,2".to_string(),
            os_version: "iPhone OS,17.4,21E219".to_string(),
            software_version: "21E219".to_string(),
        }
    }

    fn get_normal_ua(&self, item: &str) -> String {
        format!("{item} CFNetwork/1494.0.7 Darwin/23.4.0")
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<iPhone15,2> <iPhone OS;17.4;21E219> <{}>", for_item)
    }

    fn get_version_ua(&self) -> String {
        "[iPhone OS,17.4,21E219,iPhone15,2]".to_string()
    }

    fn get_device_name(&self) -> String {
        "iPhone".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_uuid.clone()
    }

    fn get_private_data(&self) -> Dictionary {
        Dictionary::new()
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: "17.4".to_string(),
            hardware_version: "iPhone15,2".to_string(),
            serial_number: self.serial.clone(),
        }
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
    }

    fn get_serial_number(&self) -> String {
        self.serial.clone()
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn get_aoskit_version(&self) -> String {
        "com.apple.AuthKit/1 (com.apple.akd/1.0)".to_string()
    }

    fn get_udid(&self) -> String {
        self.udid.clone()
    }
}

// ── Plist generation ────────────────────────────────────────────────────

fn accessory_to_plist(acc: &BeaconAccessory) -> plist::Value {
    let mut dict = Dictionary::new();

    dict.insert(
        "privateKey".to_string(),
        plist::Value::Data(acc.master_record.private_key.clone()),
    );
    dict.insert(
        "sharedSecret".to_string(),
        plist::Value::Data(acc.master_record.shared_secret.clone()),
    );
    if let Some(ref ss2) = acc.master_record.shared_secret_2 {
        dict.insert(
            "secondarySharedSecret".to_string(),
            plist::Value::Data(ss2.clone()),
        );
    }
    if let Some(ref slss) = acc.master_record.secure_locations_shared_secret {
        dict.insert(
            "secureLocationsSharedSecret".to_string(),
            plist::Value::Data(slss.clone()),
        );
    }
    dict.insert(
        "publicKey".to_string(),
        plist::Value::Data(acc.master_record.public_key.clone()),
    );
    dict.insert(
        "identifier".to_string(),
        plist::Value::String(acc.master_record.stable_identifier.clone()),
    );
    dict.insert(
        "model".to_string(),
        plist::Value::String(acc.master_record.model.clone()),
    );
    if let Some(pairing_date) = acc.master_record.pairing_date {
        // Apple's plistlib (and CFPropertyList) parses <date> with a strict regex
        // that rejects fractional seconds. SystemTime here carries nanosecond
        // precision from CloudKit and the plist crate serialises it verbatim
        // (e.g. `2026-01-11T19:57:42.920991898Z`), making the resulting plist
        // unreadable by `plutil`, FindMy.py, and any other tool using Apple's
        // parser. Truncate to whole seconds.
        let secs = pairing_date
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let truncated = UNIX_EPOCH + Duration::from_secs(secs);
        dict.insert(
            "pairingDate".to_string(),
            plist::Value::Date(truncated.into()),
        );
    }
    dict.insert(
        "name".to_string(),
        plist::Value::String(acc.naming.name.clone()),
    );
    dict.insert(
        "emoji".to_string(),
        plist::Value::String(acc.naming.emoji.clone()),
    );

    plist::Value::Dictionary(dict)
}

// ── Password reading ────────────────────────────────────────────────────

fn read_password() -> String {
    if std::io::stdin().is_terminal() {
        let pass = disable_echo_read();
        eprintln!();
        pass
    } else {
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass).unwrap();
        pass.trim().to_string()
    }
}

#[cfg(unix)]
fn disable_echo_read() -> String {
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios: libc::termios = std::mem::zeroed();
        libc::tcgetattr(fd, &mut termios);
        let old = termios;
        termios.c_lflag &= !libc::ECHO;
        libc::tcsetattr(fd, libc::TCSANOW, &termios);
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass).unwrap();
        libc::tcsetattr(fd, libc::TCSANOW, &old);
        pass.trim().to_string()
    }
}

#[cfg(not(unix))]
fn disable_echo_read() -> String {
    let mut pass = String::new();
    std::io::stdin().read_line(&mut pass).unwrap();
    pass.trim().to_string()
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    init_keystore(SoftwareKeystore {
        state: plist::from_file("keystore.plist").unwrap_or_default(),
        update_state: Box::new(|state| {
            plist::to_file_xml("keystore.plist", state).unwrap();
        }),
        encryptor: NoEncryptor,
    });

    let args: Vec<String> = std::env::args().collect();

    let mut apple_id = String::new();
    let mut anisette_url = "https://ani.sidestore.io".to_string();
    let mut output_dir = PathBuf::from(".");
    let mut debug = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--apple-id" => {
                i += 1;
                apple_id = args[i].clone();
            }
            "--anisette-url" => {
                i += 1;
                anisette_url = args[i].clone();
            }
            "--output-dir" => {
                i += 1;
                output_dir = PathBuf::from(&args[i]);
            }
            "--debug" => {
                debug = true;
            }
            "--help" | "-h" => {
                eprintln!("Usage: export_findmy [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --apple-id <email>       Apple ID email");
                eprintln!("  --anisette-url <url>     Anisette server URL (default: https://ani.sidestore.io)");
                eprintln!("  --output-dir <dir>       Output directory for plist files (default: .)");
                eprintln!("  --debug                  Print CloudKit record-type breakdown and per-record details");
                eprintln!();
                eprintln!("WARNING: Output plist files contain private key material.");
                return Ok(());
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                return Ok(());
            }
        }
        i += 1;
    }

    if apple_id.is_empty() {
        eprint!("Apple ID: ");
        std::io::stdin().read_line(&mut apple_id)?;
        apple_id = apple_id.trim().to_string();
    }

    eprint!("Password: ");
    let password = read_password();

    std::fs::create_dir_all(&output_dir)?;

    let config: Arc<dyn OSConfig> = Arc::new(FakeIOSConfig::new());

    // ── Step 1: Create anisette client ──────────────────────────────
    eprintln!("[1/7] Connecting to anisette server...");
    let anisette_config_path = PathBuf::from_str("anisette_state").unwrap();
    std::fs::create_dir_all(&anisette_config_path).ok();

    let login_info = config.get_gsa_config(&APSState::default(), false);

    let anisette_client: ArcAnisetteClient<RemoteAnisetteProviderV3> =
        Arc::new(Mutex::new(AnisetteClient::new(
            RemoteAnisetteProviderV3::new(
                anisette_url.clone(),
                login_info.clone(),
                anisette_config_path,
            ),
        )));

    // ── Step 2: Login to Apple ──────────────────────────────────────
    eprintln!("[2/7] Logging in to Apple ID...");
    let apple_id_clone = apple_id.clone();
    let password_hash: Vec<u8> = Sha256::digest(password.as_bytes()).to_vec();
    let appleid_closure = move || (apple_id_clone.clone(), password_hash.clone());
    let tfa_closure = || {
        eprint!("2FA code: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    };

    let account = AppleAccount::login(
        appleid_closure,
        tfa_closure,
        login_info,
        anisette_client.clone(),
    )
    .await?;

    let spd = account.spd.as_ref().expect("No SPD after login");
    let dsid = spd["DsPrsId"]
        .as_unsigned_integer()
        .unwrap()
        .to_string();
    let adsid = spd["adsid"].as_string().unwrap().to_string();

    eprintln!("  Logged in (dsid={})", dsid);

    // ── Step 3: Get MobileMe delegate ───────────────────────────────
    eprintln!("[3/7] Fetching MobileMe delegate...");
    let delegates = login_apple_delegates(
        &account,
        None,
        config.as_ref(),
        &[LoginDelegate::MobileMe],
    )
    .await?;
    let mobileme = delegates
        .mobileme
        .expect("No MobileMe delegate returned");

    // ── Step 4: Create CloudKit + Keychain clients ──────────────────
    eprintln!("[4/7] Setting up CloudKit & Keychain...");

    let keychain_state = KeychainClientState::new(dsid.clone(), adsid.clone(), &mobileme)
        .unwrap_or_else(|| {
            eprintln!("  (escrowProxyUrl not in MobileMe config, using default)");
            KeychainClientState::new_with_host(dsid.clone(), adsid.clone(), "https://p97-escrowproxy.icloud.com:443".to_string())
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
    eprintln!("[5/7] Joining iCloud Keychain trust circle...");
    let bottles = keychain.get_viable_bottles().await?;
    if bottles.is_empty() {
        return Err("No escrow bottles found. Make sure you have another trusted device.".into());
    }
    eprintln!("  Found {} escrow bottle(s):", bottles.len());
    for (i, (_, meta)) in bottles.iter().enumerate() {
        eprintln!("    [{}] {}", i, meta.serial);
    }
    let bottle_idx = if bottles.len() == 1 {
        0
    } else {
        eprint!("  Choose bottle [0]: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let idx = input.trim().parse::<usize>().unwrap_or(0);
        if idx >= bottles.len() {
            return Err(format!("Invalid bottle index {}. Must be 0-{}.", idx, bottles.len() - 1).into());
        }
        idx
    };
    let (bottle, meta) = &bottles[bottle_idx];
    eprintln!("  Using escrow bottle from device: {}", meta.serial);
    eprint!("  Enter the passcode of that device: ");
    let passcode = read_password();

    keychain
        .join_clique_from_escrow(bottle, passcode.as_bytes(), b"findmy-export")
        .await?;
    eprintln!("  Joined keychain trust circle!");

    // ── Step 6: Fetch BeaconStore records from CloudKit ─────────────
    eprintln!("[6/7] Fetching FindMy accessories from CloudKit...");

    let container = SEARCH_PARTY_CONTAINER
        .init(cloudkit.clone())
        .await?;
    let beacon_zone = container.private_zone("BeaconStore".to_string());
    let key = container
        .get_zone_encryption_config(&beacon_zone, &keychain, &FIND_MY_SERVICE)
        .await?;

    let mut beacon_records: HashMap<String, MasterBeaconRecord> = HashMap::new();
    let mut naming_records: HashMap<String, (String, BeaconNamingRecord)> = HashMap::new();
    let mut alignment_records: HashMap<String, (String, KeyAlignmentRecord)> = HashMap::new();

    let mut result = FetchRecordChangesOperation::do_sync(
        &container,
        &[(beacon_zone.clone(), None)],
        &NO_ASSETS,
    )
    .await;
    if should_reset(result.as_ref().err()) {
        result = FetchRecordChangesOperation::do_sync(
            &container,
            &[(beacon_zone.clone(), None)],
            &NO_ASSETS,
        )
        .await;
    }

    let (_, changes, _) = result?.remove(0);

    if debug {
        eprintln!("  [debug] total CloudKit changes returned: {}", changes.len());
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        for change in &changes {
            if let Some(record) = &change.record {
                if let Some(t) = record.r#type.as_ref() {
                    *type_counts.entry(t.name().to_string()).or_insert(0) += 1;
                }
            }
        }
        eprintln!("  [debug] record type breakdown:");
        let mut sorted: Vec<_> = type_counts.iter().collect();
        sorted.sort();
        for (t, n) in &sorted {
            eprintln!("  [debug]   {} = {}", t, n);
        }
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
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                MasterBeaconRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            if debug {
                eprintln!(
                    "  [debug] Master id={} model={:?} stable={}",
                    identifier, item.model, item.stable_identifier,
                );
            }
            beacon_records.insert(identifier, item);
        } else if record_type == BeaconNamingRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                BeaconNamingRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            if debug {
                eprintln!(
                    "  [debug] Naming id={} name={:?} assoc={}",
                    identifier, item.name, item.associated_beacon,
                );
            }
            naming_records.insert(
                item.associated_beacon.clone(),
                (identifier, item),
            );
        } else if record_type == KeyAlignmentRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                KeyAlignmentRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            alignment_records.insert(
                item.beacon_identifier.clone(),
                (identifier, item),
            );
        } else if debug && record_type == SharedBeaconRecord::record_type() {
            // Shared beacons are not used by export-findmy (no private keys), but
            // surfacing them helps users understand why an item visible in Find My
            // doesn't appear in the output: items shared TO you arrive as
            // SharedBeaconRecord, not MasterBeaconRecord.
            match pcs_keys_for_record(&record, &key) {
                Ok(pcs) => {
                    let item = SharedBeaconRecord::from_record_encrypted(
                        &record.record_field,
                        Some(&pcs),
                    );
                    eprintln!(
                        "  [debug] Shared id={} model={:?} owner={} accepted={}",
                        identifier, item.model, item.owner_handle, item.accepted,
                    );
                }
                Err(e) => eprintln!("  [debug] Shared id={} (pcs error: {})", identifier, e),
            }
        }
    }

    // ── Assemble accessories ────────────────────────────────────────
    let mut accessories: HashMap<String, BeaconAccessory> = HashMap::new();

    for (id, master) in beacon_records {
        let stable_id = master.stable_identifier.clone();
        // BeaconNamingRecord.associated_beacon and KeyAlignmentRecord.beacon_identifier
        // both hold the master's CloudKit record UUID (i.e. `id`), not its
        // `stable_identifier`. Looking up by stable_identifier silently misses every
        // match, causing all accessories to fall through to the "Unknown-…" fallback
        // and — because multiple AirTags share the same `2006~#…` prefix — collide
        // onto the same output filename, overwriting each other's keys.
        let naming = naming_records
            .remove(&id)
            .unwrap_or_else(|| {
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
        let alignment = alignment_records
            .remove(&id)
            .map(|(id, rec)| (id, rec))
            .unwrap_or_default();
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

    // ── Step 7: Write plist files ───────────────────────────────────
    eprintln!("[7/7] Writing plist files...");

    if accessories.is_empty() {
        eprintln!("  No accessories found!");
        return Ok(());
    }

    for acc in accessories.values() {
        let safe_name: String = acc
            .naming
            .name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let filename = format!("{}.plist", safe_name);
        let path = output_dir.join(&filename);

        let plist_val = accessory_to_plist(acc);
        plist::to_file_xml(&path, &plist_val)?;

        eprintln!(
            "  {} {} ({}) -> {}",
            acc.naming.emoji,
            acc.naming.name,
            acc.master_record.model,
            path.display()
        );
    }

    eprintln!();
    eprintln!(
        "Done! Exported {} accessory plist file(s) to {}",
        accessories.len(),
        output_dir.display()
    );

    Ok(())
}
