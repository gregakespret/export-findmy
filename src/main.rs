mod pipeline;
mod server;

use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::PathBuf;

use async_trait::async_trait;
use keystore::{init_keystore, software::{NoEncryptor, SoftwareKeystore}};
use plist::Dictionary;

use rustpush::{ActivationInfo, DebugMeta, OSConfig, PushError, RegisterMeta};

use pipeline::{run_export, BeaconExport, DeviceInfo, ExportOpts, Interact, PipelineError};

// ── Fake OSConfig (presents as iPhone to avoid NAS validation) ───────

pub struct FakeIOSConfig {
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

fn beacon_to_plist(b: &BeaconExport) -> plist::Value {
    let mut dict = Dictionary::new();

    dict.insert("privateKey".to_string(), plist::Value::Data(b.private_key.clone()));
    dict.insert("sharedSecret".to_string(), plist::Value::Data(b.shared_secret.clone()));
    if let Some(ref ss2) = b.secondary_shared_secret {
        dict.insert("secondarySharedSecret".to_string(), plist::Value::Data(ss2.clone()));
    }
    if let Some(ref slss) = b.secure_locations_shared_secret {
        dict.insert("secureLocationsSharedSecret".to_string(), plist::Value::Data(slss.clone()));
    }
    if let Some(ref pk) = b.public_key {
        dict.insert("publicKey".to_string(), plist::Value::Data(pk.clone()));
    }
    dict.insert("identifier".to_string(), plist::Value::String(b.identifier.clone()));
    dict.insert("model".to_string(), plist::Value::String(b.model.clone()));
    if let Some(ref pd) = b.pairing_date {
        // pipeline already truncated to whole seconds (Apple's plist parser
        // rejects fractional); parse the RFC3339 string back to a plist date.
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(pd) {
            let st: std::time::SystemTime = dt.into();
            dict.insert("pairingDate".to_string(), plist::Value::Date(st.into()));
        }
    }
    dict.insert("name".to_string(), plist::Value::String(b.name.clone()));
    dict.insert("emoji".to_string(), plist::Value::String(b.emoji.clone()));

    plist::Value::Dictionary(dict)
}

// ── Interactive CLI input ───────────────────────────────────────────────

struct CliInteract;

impl Interact for CliInteract {
    fn get_2fa_code(&self) -> String {
        eprint!("2FA code: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }

    fn choose_bottle(&self, devices: &[DeviceInfo]) -> Result<usize, PipelineError> {
        if devices.len() == 1 {
            return Ok(0);
        }
        eprint!("  Choose device [0]: ");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| PipelineError::Apple(e.to_string()))?;
        Ok(input.trim().parse::<usize>().unwrap_or(0))
    }

    fn get_passcode(&self) -> Result<String, PipelineError> {
        eprint!("  Enter the passcode of that device: ");
        Ok(read_password())
    }
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

fn arg_err(flag: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Missing value for {flag}");
    Ok(())
}

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
    let mut serve = false;
    let mut port: u16 = 5301;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--apple-id" => {
                i += 1;
                match args.get(i) {
                    Some(v) => apple_id = v.clone(),
                    None => return arg_err("--apple-id"),
                }
            }
            "--anisette-url" => {
                i += 1;
                match args.get(i) {
                    Some(v) => anisette_url = v.clone(),
                    None => return arg_err("--anisette-url"),
                }
            }
            "--output-dir" => {
                i += 1;
                match args.get(i) {
                    Some(v) => output_dir = PathBuf::from(v),
                    None => return arg_err("--output-dir"),
                }
            }
            "--debug" => {
                debug = true;
            }
            "--serve" => {
                serve = true;
            }
            "--port" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u16>().ok()) {
                    Some(p) => port = p,
                    None => {
                        eprintln!("--port needs a valid port number (1-65535)");
                        return Ok(());
                    }
                }
            }
            "--help" | "-h" => {
                eprintln!("Usage: export_findmy [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --apple-id <email>       Apple ID email");
                eprintln!("  --anisette-url <url>     Anisette server URL (default: https://ani.sidestore.io)");
                eprintln!("  --output-dir <dir>       Output directory for plist files (default: .)");
                eprintln!("  --debug                  Print CloudKit record-type breakdown and per-record details");
                eprintln!("  --serve                  Run the localhost REST API instead of the CLI export");
                eprintln!("  --port <n>               Port for --serve (default: 5301, binds 127.0.0.1 only)");
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

    if serve {
        return server::serve(port, anisette_url).await;
    }

    if apple_id.is_empty() {
        eprint!("Apple ID: ");
        std::io::stdin().read_line(&mut apple_id)?;
        apple_id = apple_id.trim().to_string();
    }

    eprint!("Password: ");
    let password = read_password();

    std::fs::create_dir_all(&output_dir)?;

    let beacons = run_export(
        ExportOpts { apple_id, password, anisette_url, debug },
        &CliInteract,
    )
    .await?;

    // ── Write plist files ───────────────────────────────────────────
    if beacons.is_empty() {
        eprintln!("  No accessories found!");
        return Ok(());
    }

    for b in &beacons {
        let safe_name: String = b
            .name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let path = output_dir.join(format!("{}.plist", safe_name));
        plist::to_file_xml(&path, &beacon_to_plist(b))?;
        eprintln!("  {} {} ({}) -> {}", b.emoji, b.name, b.model, path.display());
    }

    eprintln!();
    eprintln!(
        "Done! Exported {} accessory plist file(s) to {}",
        beacons.len(),
        output_dir.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon(pairing: Option<&str>, public: Option<Vec<u8>>) -> BeaconExport {
        BeaconExport {
            identifier: "2006~#abc".into(),
            name: "Keys".into(),
            emoji: "🔑".into(),
            model: "AirTag".into(),
            private_key: vec![1, 2, 3],
            shared_secret: vec![4, 5, 6],
            secondary_shared_secret: None,
            secure_locations_shared_secret: Some(vec![7, 8]),
            public_key: public,
            pairing_date: pairing.map(|s| s.to_string()),
        }
    }

    #[test]
    fn beacon_to_plist_has_expected_keys() {
        let v = beacon_to_plist(&beacon(Some("2026-01-11T19:57:42Z"), Some(vec![9])));
        let d = v.as_dictionary().unwrap();
        assert_eq!(d.get("identifier").unwrap().as_string(), Some("2006~#abc"));
        assert_eq!(d.get("name").unwrap().as_string(), Some("Keys"));
        assert_eq!(d.get("emoji").unwrap().as_string(), Some("🔑"));
        assert_eq!(d.get("model").unwrap().as_string(), Some("AirTag"));
        assert!(matches!(d.get("privateKey"), Some(plist::Value::Data(_))));
        assert!(matches!(d.get("sharedSecret"), Some(plist::Value::Data(_))));
        assert!(matches!(d.get("secureLocationsSharedSecret"), Some(plist::Value::Data(_))));
        assert!(matches!(d.get("publicKey"), Some(plist::Value::Data(_))));
        assert!(matches!(d.get("pairingDate"), Some(plist::Value::Date(_))));
        // Absent optional is omitted, not written as null.
        assert!(d.get("secondarySharedSecret").is_none());
    }

    #[test]
    fn beacon_to_plist_omits_absent_optionals() {
        let v = beacon_to_plist(&beacon(None, None));
        let d = v.as_dictionary().unwrap();
        assert!(d.get("publicKey").is_none());
        assert!(d.get("pairingDate").is_none());
    }

    #[test]
    fn beacon_to_plist_drops_unparseable_pairing_date() {
        // A malformed date must not crash or write garbage — the key is dropped.
        let v = beacon_to_plist(&beacon(Some("not-a-date"), None));
        assert!(v.as_dictionary().unwrap().get("pairingDate").is_none());
    }
}
