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
[xxxx@xxx] [sess=cli] [1/7] Connecting to anisette server (https://ani.sidestore.io)...
[xxxx@xxx] [sess=cli] [2/7] Logging in to Apple ID...
2FA code: 123456
[xxxx@xxx] [sess=cli]   Logged in (dsid=......) after 4.2s
[xxxx@xxx] [sess=cli] [3/7] Fetching MobileMe delegate...
[xxxx@xxx] [sess=cli] [4/7] Setting up CloudKit & Keychain...
[xxxx@xxx] [sess=cli] [5/7] Joining iCloud Keychain trust circle...
[xxxx@xxx] [sess=cli]   Escrow bottles: 2 returned, 1 usable (dropped 1 of our own)
[xxxx@xxx] [sess=cli]   Found 1 usable device(s):
[xxxx@xxx] [sess=cli]     [0] Wilbur's Mac (MacBook Air) [L2MPKH342P]
  Enter the passcode of that device:
[xxxx@xxx] [sess=cli]   Using device [0]: Wilbur's Mac (MacBook Air) [L2MPKH342P], passcode 6 chars
[xxxx@xxx] [sess=cli]   Joined keychain trust circle in 11.3s!
[xxxx@xxx] [sess=cli] [6/7] Fetching FindMy accessories from CloudKit...
[xxxx@xxx] [sess=cli]   CloudKit returned 7 change(s)
[xxxx@xxx] [sess=cli]   Records decrypted: 1 master, 1 naming, 1 alignment
[xxxx@xxx] [sess=cli] [7/7] Assembling 1 accessory export(s)... (total 21.7s)
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

### Reading the logs

Everything goes to stderr, prefixed with the Apple ID and a session tag — the
first 8 characters of the `session_id` returned by `POST /sessions`, so one
attempt can be followed through interleaved output and joined to whatever the
caller recorded for the same session:

```
[sess=3f2a1b8c] POST /escrow: device_index=0 passcode 14 chars, session at awaiting_passcode
[wilbur@icloud.com] [sess=3f2a1b8c]   Using device [0]: Wilbur's Mac (MacBook Air) [L2MPKH342P], passcode 14 chars
[wilbur@icloud.com] [sess=3f2a1b8c] !! FAILED at [5/7] join trust circle after 31.4s (9.2s in the join): Bad message [BadMsg]
```

Failures are logged where they happen, with the step, the elapsed time, and the
error in both its `Display` and `Debug` forms. The Debug form is the useful one:
rustpush collapses unrelated failures onto the same words, and only the variant
name tells them apart. In particular **`Bad message` / `BadMsg` is a signature
check inside escrow recovery, not a rejected passcode** — it is reached after
the passcode has already opened the bottle, so the "(wrong passcode?)" wording
in the user-facing message is misleading for that one. A genuinely wrong
passcode fails earlier, in the SRP exchange, as an escrow/HTTP error.

Passwords, passcodes and 2FA codes are never logged — only their lengths, which
is what distinguishes an empty field, or a Mac login password typed where a
phone passcode was wanted, from a real Apple rejection.

`RUST_LOG` controls rustpush's own logging, which carries the reason behind
several of the opaque errors above (`Signature verification failed` for
`BadMsg`). Those records are stamped with the same `[sess=…]` tag as the lines
around them, so a warning can be tied to the attempt that produced it even with
two exports in flight:

```
[sess=3f2a1b8c] WARN  rustpush::icloud::keychain > Signature verification failed
```

It defaults to `warn,export_findmy=info,rustpush::icloud::keychain=info`; an
empty `RUST_LOG` counts as unset (a cleared-but-present env var would otherwise
silence everything). The filter in force is logged at startup.

The keychain module is turned up because it is the only place that says *why* a
trust-circle join stopped where it did, and the only place that reports what
became of the escrow bottles. Everything it logs below `warn` is dropped unless
it is on the allowlist in `src/logging.rs` — the join checkpoints, and the
escrow-lookup counts. That allowlist is a redaction guard, not a verbosity
setting: it outranks `RUST_LOG`, because the same module `info!`s decrypted
keychain contents as hex. The other half of the escrow diagnosis, the metadata
schema mismatch, is a `warn!` and prints without it.

**Do not widen the filter to `rustpush=debug` on a deployed instance:** the
allowlist covers only `rustpush::icloud::keychain`, and rustpush debug-logs the
whole SPD after login, which contains every Apple service token for the session,
including the IDMS PET.

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
(a wrong password *or* a wrong 2FA code — Apple judged what was typed and
rejected it), `bad_passcode`, `trust_circle_signature`, `escrow_club`,
`bad_device_index`, `no_bottles`, `wrong_step`, `session_not_found`,
`session_expired`, `apple_error`.

A sign-in that fails *without* Apple ever judging the credentials — a non-2xx
from a GSA endpoint, an anisette outage, an HTML error page where a plist was
promised — is `apple_error` (HTTP 502), **not** `bad_credentials`. Clients
must not treat every `POST /sessions` failure as a wrong password: the whole
point of the split is that `detail` now tells the user whether retyping the
password can possibly help, so surface `detail` rather than a message of your
own.

`trust_circle_signature` (HTTP 409) is deliberately separate from
`bad_passcode`: it means the escrow bottle decrypted — so the device passcode
was correct — and the join then failed verifying one of the trust circle's
signatures. Prompting for the passcode again cannot resolve it. The server log
names which signature failed, and `detail` names the way out, which depends on
the account: with another trusted device, try that one; with only one, there is
nothing to switch to and `detail` says so instead of asking for a device that
does not exist.

`escrow_club` (HTTP 502) is separate from `bad_passcode` for the same reason and
with more certainty. Apple's escrow proxy serves two stages: `srp_init` /
`recover`, which is where the device passcode is actually checked, and
`get_club_cert` / `enroll`, which deposit the *new* escrow record this tool
creates once it is already inside the circle. A failure in the second — Apple
labels them `CLUBH ERROR`, commonly with status `-6015` — is by construction
past the passcode check, so the passcode was right. It is usually transient:
the user should start the connection again rather than re-enter anything.
Because nothing about the request was wrong, it is reported as an upstream 502;
a 4xx here is what sends clients back to blaming the user's input.

**It is also the one error that does not end the attempt.** When another device
is available, `POST /escrow` answers with the session still live and the body
carries `"retryable": true`, `"state": "awaiting_passcode"` and the `devices`
list again — the login and 2FA are still held, so the client should re-render
device selection and post to the same session rather than starting over. Up to
three devices may be tried per attempt; the last failure comes back without
`retryable` and retires the session as any other failure does. A client that
ignores `retryable` and treats the 409 as fatal still behaves correctly, just
less kindly.

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
