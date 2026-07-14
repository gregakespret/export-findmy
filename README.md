# export-findmy

Export AirTag/FindMy accessory private keys from iCloud, producing `.plist` files compatible with [FindMy.py](https://github.com/malmeloo/FindMy.py).

Should works on any platform? --- Tested on MacOS 26

## Prerequisites

- [Rust toolchain](https://rustup.rs/)
- `openssl` CLI (for building — generates dummy FairPlay certs needed by rustpush)
- `protoc` (protobuf compiler) — `brew install protobuf` on macOS

## Build

```bash
git clone https://github.com/thisiscam/export-findmy.git
cd export-findmy
cargo build --release
```

## Usage

```bash
./target/release/export-findmy \
  --apple-id you@example.com \
  --output-dir ./keys
```

The tool will prompt for:
1. **Password** (hidden input)
2. **2FA code** — enter the **SMS code** sent to your phone, not the code shown on other devices
3. **Device passcode** — the screen lock passcode (iPhone PIN) or login password (Mac) of the device listed

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--apple-id <email>` | Apple ID email | prompted if omitted |
| `--anisette-url <url>` | Anisette v3 server URL | `https://ani.sidestore.io` |
| `--output-dir <dir>` | Where to write plist files | `.` |
| `--serve` | Run the localhost REST API instead of the CLI export (see below) | off |
| `--port <n>` | Port for `--serve` (binds `127.0.0.1` only) | `5301` |

### Example

```
$ ./target/release/export-findmy --apple-id xxxx@xxx --output-dir ./keys
Password:
[1/7] Connecting to anisette server...
[2/7] Logging in to Apple ID...
2FA code: 123456
  Logged in (dsid=......)
[3/7] Fetching MobileMe delegate...
[4/7] Setting up CloudKit & Keychain...
[5/7] Joining iCloud Keychain trust circle...
  Found 1 escrow bottle(s):
    [0] ......
  Using escrow bottle from device: L2MPKH342P
  Enter the passcode of that device:
  Joined keychain trust circle!
[6/7] Fetching FindMy accessories from CloudKit...
[7/7] Writing plist files...
  🎧 Wilbur's AirTag (AirTag) -> ./keys/Wilbur_s_AirTag.plist

Done! Exported 1 accessory plist file(s) to ./keys
```

## Server mode (`--serve`)

For driving the export from a web UI (rather than a terminal), `--serve`
exposes the same login → escrow → CloudKit pipeline as a small REST API. It
holds the Apple login session open between requests so the 2FA code, device
choice, and passcode can arrive one HTTP call at a time. The server binds
`127.0.0.1` by default (set `EXPORT_FINDMY_BIND`, e.g. `::`, to listen on
another interface such as a private container network) and keeps all session
state in memory (10-minute idle TTL); credentials are never written to disk or
logged.

```bash
./target/release/export-findmy --serve --port 5301
```

| Method & path | Body | Response |
|---|---|---|
| `POST /sessions` | `{"apple_id","password"}` | `201 {"session_id","state":"awaiting_2fa"}` — or `"awaiting_passcode"` + `devices` if Apple already trusts the session and skips 2FA |
| `POST /sessions/{id}/2fa` | `{"code"}` | `200 {"state":"awaiting_passcode","devices":[{"serial","name","model"},…]}` |
| `POST /sessions/{id}/escrow` | `{"device_index","passcode"}` | `200 {"state":"done","beacons":[…]}` |
| `GET /healthz` | — | `200 {"status":"ok"}` |

When Apple already trusts the session (a recent successful login from the same
anisette identity), the login skips 2FA — then `POST /sessions` returns
`awaiting_passcode` with the `devices` list directly, and the client goes
straight to `/escrow` without calling `/2fa`.

`devices` are the account's trusted devices (this tool's own phantom
`F2LZN0FAKE00` bottles are filtered out), each `{serial, name, model}` — e.g.
`{"serial":"GYK3003QMY","name":"Grega's MacBook Air","model":"MacBook Air"}` —
so a UI can show a name rather than a serial. `device_index` in the escrow call
is the position in this list.

Each `beacon` returns the same key material as the plist output, base64-encoded
(`private_key`, `shared_secret`, `secondary_shared_secret`,
`secure_locations_shared_secret`, `public_key`) plus `identifier`, `name`,
`emoji`, `model`, and `pairing_date` (RFC3339). Errors are
`{"error":"<code>","detail":"<message>"}` with codes `bad_credentials`
(covers a wrong password *or* a wrong 2FA code — rustpush's login doesn't
distinguish them), `bad_passcode`, `bad_device_index`, `no_bottles`,
`wrong_step`, `session_not_found`, `session_expired`, `apple_error`.

## Output format

Each accessory produces a `.plist` file containing:

| Key | Description |
|-----|-------------|
| `privateKey` | EC private key (for deriving rolling BLE keys) |
| `sharedSecret` | Primary shared secret |
| `secondarySharedSecret` | Secondary shared secret (if present) |
| `publicKey` | EC public key |
| `identifier` | Stable accessory identifier |
| `name` | User-assigned name |
| `emoji` | User-assigned emoji |
| `model` | Hardware model |
| `pairingDate` | When the accessory was paired |

These files can be used directly with [FindMy.py](https://github.com/malmeloo/FindMy.py) for tracking AirTag locations.

## Security notes

- **Output plist files contain private key material.** Treat them like passwords.
- Your Apple ID password and device passcode are never written to disk.
- `anisette_state/` and `keystore.plist` are created in the working directory at runtime — these contain device provisioning state and keychain crypto keys. Delete them after use if you don't plan to run the tool again.
- The anisette server only sees OTP header requests from your IP. It never sees your Apple ID, password, or iCloud data.

## How it works

1. Authenticates to Apple via SRP (using remote anisette for device identity tokens)
2. Fetches MobileMe delegate tokens via the iOS `iosbuddy` login endpoint
3. Joins the iCloud Keychain trust circle via escrow recovery (using your device passcode)
4. Fetches encrypted `BeaconStore` records from CloudKit
5. Decrypts records using PCS (Protected CloudStorage) keys from the keychain
6. Writes accessory data to plist files

## Deployment

In production this runs as a private `--serve` service on Railway, reachable only
by the airtag-tracker backend over Railway's internal network. It builds with
Rust 1.89 (see `rust-toolchain.toml`), needs `protoc` at build time, and binds
`EXPORT_FINDMY_BIND=::`. Every push to `main` auto-deploys.

Built on [rustpush](https://github.com/OpenBubbles/rustpush) by the OpenBubbles project.
