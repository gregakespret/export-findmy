//! Logger wiring shared by the CLI and `--serve`.
//!
//! rustpush carries the *reason* behind several of the opaque errors we surface
//! — "Signature verification failed" is what stands behind the "Bad message" a
//! user sees — but only through the `log` crate, and its records know nothing
//! about which export produced them. In `--serve` two attempts can be in flight
//! at once and their lines interleave, so an untagged `WARN` is unattributable
//! exactly when it matters most: the operator cannot tell which join failed its
//! signature check. Every pipeline task runs inside [`scope`], and the format
//! below stamps that tag onto every record, rustpush's included.
//!
//! The tag alone still doesn't say *which* signature failed. rustpush verifies
//! four different signatures on the way through a trust-circle join and logs the
//! same six words for all of them, so a `BadMsg` is unattributable to a site.
//! The lines that would separate them are `info!`s in `rustpush::icloud::keychain`
//! — but that module also logs decrypted keychain material (`info!("data {hex}")`),
//! so simply raising the level on it would spill secrets into a hosted log store.
//! [`CHECKPOINTS`] is the way out: that one module is raised to `info`, an
//! allowlist drops every record that isn't a known-safe checkpoint, and the last
//! checkpoint reached is remembered per session so the pipeline can name the
//! failing signature at the default `warn` level.

use std::future::Future;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

tokio::task_local! {
    /// Session tag of the export running on this task. Set by [`scope`] for
    /// each server session and for the CLI's single run (as `cli`). Private on
    /// purpose: scoping this alone would tag the lines but leave the checkpoint
    /// slot unset, so every join failure would report as unexplained.
    static SESSION: String;
    /// Last [`CHECKPOINTS`] index reached on this task, biased by one so that
    /// zero means "none yet". Shared rather than plain because the logger
    /// writes it and the pipeline reads it.
    static CHECKPOINT: Arc<AtomicUsize>;
}

/// The rustpush module whose records get the allowlist treatment below.
const KEYCHAIN_TARGET: &str = "rustpush::icloud::keychain";

/// One known-safe `info!` line from rustpush's keychain module, and the
/// signature check (if any) that immediately follows it in a trust-circle join.
///
/// The join's verification sites all report `PushError::BadMsg` and log the
/// identical "Signature verification failed", so the site is only recoverable
/// from position: each of these lines is the last thing printed before a
/// specific check. Matching is by prefix — the suffixes are peer hashes and
/// service names, which we keep out of the log.
pub struct Checkpoint {
    prefix: &'static str,
    verifies: Option<&'static str>,
}

impl Checkpoint {
    /// The rustpush message that was matched, for the operator's log line.
    pub fn prefix(&self) -> &'static str {
        self.prefix
    }
    /// What a `BadMsg` raised straight after this checkpoint means, or `None`
    /// where the join does no signature check — a `BadMsg` there is unexplained
    /// and should be reported as such rather than guessed at.
    pub fn verifies(&self) -> Option<&'static str> {
        self.verifies
    }
}

/// In the order `join_clique_from_escrow` walks them. Only these get printed;
/// see the module docs for why the rest of the module is dropped.
const CHECKPOINTS: &[Checkpoint] = &[
    // `recover_bottle`: the escrow blob decrypted, so the passcode was right.
    // Two checks follow back to back — the bottle's peer-key signature and that
    // same peer's dynamic info — with no line between them, so they share a
    // bucket. Both mean the same thing for the user.
    Checkpoint {
        prefix: "Available as ",
        verifies: Some(
            "the escrow bottle's owning peer (its peer-key signature, or that peer's dynamic info)",
        ),
    },
    // Vouching only signs; nothing is verified between here and the share fetch.
    Checkpoint { prefix: "Self vouching as ", verifies: None },
    // `fetch_shares_for`: printed once per share, immediately before that
    // share's signature is checked against the peer that sent it.
    Checkpoint {
        prefix: "Entering on key ",
        verifies: Some("a TLK share's signature, from the peer that sent it"),
    },
    Checkpoint { prefix: "Joining with ", verifies: None },
    // `derive_trust_from_included_peer`, on the way into `join_clique`.
    Checkpoint {
        prefix: "Deriving trust from peer ",
        verifies: Some("the sponsoring peer's dynamic info, while deriving trust"),
    },
    Checkpoint { prefix: "Synced Trust!", verifies: None },
    Checkpoint { prefix: "Joining clique", verifies: None },
];

/// The session tag of the export we're running under, or `-` outside one
/// (startup, server plumbing, the reaper).
fn current_session() -> String {
    SESSION.try_with(|s| s.clone()).unwrap_or_else(|_| "-".to_string())
}

/// Run `fut` as one export: its own session tag and its own checkpoint slot.
/// Both must be scoped together — a tagged run with no slot would silently
/// discard every checkpoint and report a join failure as unexplained.
pub fn scope<F: Future>(tag: String, fut: F) -> impl Future<Output = F::Output> {
    CHECKPOINT.scope(Arc::new(AtomicUsize::new(0)), SESSION.scope(tag, fut))
}

/// The last checkpoint this export reached, or `None` if it reached none.
///
/// `None` is itself informative: the first verification in the join is the
/// bottle's own escrowed-key signature, which rustpush checks *before* the
/// peer lookup that prints "Available as" — and which fails with a bare
/// `BadMsg` and no warning at all.
pub fn last_checkpoint() -> Option<&'static Checkpoint> {
    let biased = CHECKPOINT.try_with(|c| c.load(Ordering::Relaxed)).unwrap_or(0);
    biased.checked_sub(1).map(|i| &CHECKPOINTS[i])
}

/// Record that `idx` was reached, if we're inside an export. Outside one there
/// is nowhere to put it and nothing that would read it.
fn note_checkpoint(idx: usize) {
    let _ = CHECKPOINT.try_with(|c| c.store(idx + 1, Ordering::Relaxed));
}

/// Whether a record is subject to the keychain allowlist: that module, below
/// `warn`. Its warnings are the reasons we turned logging up in the first place
/// and are always kept; it is the chattier levels that carry key material.
fn is_keychain_detail(target: &str, level: log::Level) -> bool {
    target.starts_with(KEYCHAIN_TARGET) && level > log::Level::Warn
}

/// The checkpoint this message is, or `None` if it isn't one. Deliberately an
/// allowlist: a denylist would leak any sensitive line a future rustpush adds,
/// and this module already has one (`info!("data {}", encode_hex(&data))` over
/// decrypted keychain contents).
fn classify(message: &str) -> Option<usize> {
    CHECKPOINTS.iter().position(|c| message.starts_with(c.prefix))
}

/// Lines from the keychain module that are safe to print but say nothing about
/// *where* a join is. Kept apart from [`CHECKPOINTS`] on purpose: these are
/// emitted by `get_viable_bottles`, which runs before the join starts, so
/// filing them as checkpoints would leave a bogus position in the slot a join
/// failure reads to name its failing signature.
///
/// They are the discriminator for a `no_bottles` failure, which is otherwise
/// unanswerable. Our own count is taken *after* rustpush has already discarded
/// every bottle whose metadata would not deserialize, so "0 returned" reads
/// identically whether Apple sent nothing at all or we threw away everything it
/// sent — the exact question a user with a trusted iPhone and iCloud Keychain
/// on leaves us with. Together with the module's `warn!`s (which were never
/// filtered) they separate the two:
///
/// | metadata records | viable bottles | what it means                        |
/// |------------------|----------------|--------------------------------------|
/// | 0                | 0              | the account really has no escrow      |
/// | >0               | >0, discarded  | our deserialization, and our bug      |
/// | 0                | >0             | escrow-proxy / shard mismatch         |
/// | >0               | 0              | Cuttlefish rejected them, not us      |
///
/// Both carry counts, a serde error and plist key *names* with their value
/// *types* — never a metadata value and never key material. (rustpush 96c1228.)
const SAFE_PREFIXES: &[&str] = &[
    "Escrow lookup returned ",
    "Escrow metadata schema mismatch: ",
];

/// Whether a non-checkpoint keychain line is nonetheless safe to print.
fn is_safe_diagnostic(message: &str) -> bool {
    SAFE_PREFIXES.iter().any(|p| message.starts_with(p))
}

/// Dependencies stay at `warn` — that is the level rustpush reports its reasons
/// at, and anything lower is noise. Our own crate's `log` records are `info`, so
/// a bare `warn` would silence them. The keychain module is the one exception,
/// raised to `debug` for [`CHECKPOINTS`] and [`SAFE_PREFIXES`]; everything it
/// logs at those levels that is on neither allowlist is dropped before it
/// reaches the output.
///
/// `debug` rather than `info` because the line naming *which* escrow-metadata
/// field a bottle was thrown away over is a `debug!` upstream, and that line is
/// the whole difference between "some bottles were discarded" and a fix. The
/// level is safe to raise precisely because the allowlist is not a verbosity
/// setting: it runs at every level above `warn`, so turning the module up
/// admits the two lines named there and nothing else.
const DEFAULT_FILTER: &str = "warn,export_findmy=info,rustpush::icloud::keychain=debug";

/// The filter to run with. `RUST_LOG` overrides the default, but a variable that
/// exists and is *empty* — a Railway variable cleared rather than deleted —
/// parses to zero directives and silently drops the whole process back to
/// error-only, so blank counts as unset.
fn filter_from_env(var: Option<&str>) -> &str {
    match var {
        Some(v) if !v.trim().is_empty() => v,
        _ => DEFAULT_FILTER,
    }
}

/// Render one record. Named rather than inline so the tests can drive it
/// through a real `env_logger` and prove that a dropped record produces no
/// output — the assumption the whole allowlist rests on.
///
/// Same `[sess=…]` prefix our own lines carry, so a rustpush warning and the
/// pipeline failure it explains can be grepped together.
fn format_record(
    buf: &mut pretty_env_logger::env_logger::fmt::Formatter,
    record: &log::Record,
) -> std::io::Result<()> {
    if is_keychain_detail(record.target(), record.level()) {
        // The allowlist runs regardless of `RUST_LOG`: it is a redaction guard,
        // not a verbosity setting, and an operator raising the level to debug a
        // join must not thereby dump keychain contents into a hosted log store.
        // Writing nothing emits nothing.
        let message = record.args().to_string();
        match classify(&message) {
            Some(idx) => note_checkpoint(idx),
            // Printed, but deliberately not recorded as a position — see
            // [`SAFE_PREFIXES`].
            None if is_safe_diagnostic(&message) => {}
            None => return Ok(()),
        }
    }
    writeln!(
        buf,
        "[sess={}] {:<5} {} > {}",
        current_session(),
        record.level(),
        record.target(),
        record.args()
    )
}

/// Install the logger. Returns the filter in force, which the caller logs — a
/// filter that silently isn't what you think it is turns "no reason in the log"
/// into an unanswerable question.
pub fn init() -> String {
    let var = std::env::var("RUST_LOG").ok();
    let filter = filter_from_env(var.as_deref()).to_string();
    pretty_env_logger::formatted_builder()
        .parse_filters(&filter)
        .format(format_record)
        .init();
    filter
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn blank_rust_log_falls_back_to_the_default_filter() {
        // A cleared-but-present env var parses to no directives, which would
        // leave the process error-only and drop the very reasons this exists
        // to surface.
        assert_eq!(filter_from_env(None), DEFAULT_FILTER);
        assert_eq!(filter_from_env(Some("")), DEFAULT_FILTER);
        assert_eq!(filter_from_env(Some("   ")), DEFAULT_FILTER);
        assert_eq!(filter_from_env(Some("rustpush=debug")), "rustpush=debug");
    }

    #[test]
    fn default_filter_keeps_our_own_lines() {
        // `warn` alone would silence every info! we emit; the export_findmy
        // directive is what keeps the pipeline's own record.
        assert!(DEFAULT_FILTER.contains("export_findmy=info"));
    }

    #[test]
    fn default_filter_admits_the_keychain_checkpoints_and_diagnostics() {
        // Without this directive the checkpoints never reach the format
        // closure and every join failure reports as unexplained. It has to be
        // `debug`, not `info`: the escrow schema mismatch — the line that says
        // which metadata field cost us a bottle — is a debug! upstream, and at
        // `info` env_logger drops it before the allowlist ever sees it.
        assert!(DEFAULT_FILTER.contains("rustpush::icloud::keychain=debug"));
    }

    #[tokio::test]
    async fn session_tag_is_scoped_to_the_task() {
        assert_eq!(current_session(), "-");
        scope("3f2a1b8c".to_string(), async {
            assert_eq!(current_session(), "3f2a1b8c");
        })
        .await;
        assert_eq!(current_session(), "-");
    }

    #[test]
    fn checkpoints_are_recognised_with_their_real_suffixes() {
        // The messages as rustpush actually formats them, hashes and all.
        let cases = [
            ("Available as SHA256:abc123 [\"SHA256:def\"]", 0),
            ("Self vouching as SHA256:abc123 [\"SHA256:def\"]", 1),
            ("Entering on key MasterKey", 2),
            ("Joining with 4 shared keys.", 3),
            ("Deriving trust from peer SHA256:abc123 [\"SHA256:def\"]", 4),
        ];
        for (message, expected) in cases {
            assert_eq!(classify(message), Some(expected), "{message}");
        }
    }

    #[test]
    fn non_checkpoint_keychain_lines_are_dropped() {
        // The reason the allowlist exists: this one is decrypted keychain
        // contents. `classify` returning None is what stops it being printed.
        assert_eq!(classify("data 62706c6973743030d4010203"), None);
        assert_eq!(classify("Insert key uuid 5A2B"), None);
        assert_eq!(classify("Peer SHA256:abc clique trust state:"), None);
    }

    #[test]
    fn only_the_keychain_module_below_warn_is_filtered() {
        // Warnings from the module are the reasons we surface, and other
        // modules are governed by the filter alone — neither may be dropped.
        assert!(is_keychain_detail(KEYCHAIN_TARGET, log::Level::Info));
        assert!(is_keychain_detail(KEYCHAIN_TARGET, log::Level::Debug));
        assert!(!is_keychain_detail(KEYCHAIN_TARGET, log::Level::Warn));
        assert!(!is_keychain_detail(KEYCHAIN_TARGET, log::Level::Error));
        assert!(!is_keychain_detail("rustpush::icloud::cloudkit", log::Level::Info));
        assert!(!is_keychain_detail("export_findmy::pipeline", log::Level::Info));
    }

    #[tokio::test]
    async fn the_last_checkpoint_reached_is_what_is_reported() {
        scope("t".to_string(), async {
            assert!(last_checkpoint().is_none());

            note_checkpoint(classify("Available as SHA256:abc []").unwrap());
            assert_eq!(
                last_checkpoint().map(|c| c.prefix()),
                Some("Available as ")
            );

            // A share fetch that gets through several shares still reports the
            // site, not the share.
            note_checkpoint(classify("Entering on key MasterKey").unwrap());
            note_checkpoint(classify("Entering on key TLK").unwrap());
            let last = last_checkpoint().expect("checkpoint recorded");
            assert_eq!(last.prefix(), "Entering on key ");
            assert!(last.verifies().unwrap().contains("TLK share"));
        })
        .await;
    }

    #[tokio::test]
    async fn checkpoints_do_not_leak_between_sessions() {
        // Two concurrent attempts is the case the session tag exists for; a
        // shared slot would name the wrong signature for one of them.
        scope("a".to_string(), async {
            note_checkpoint(classify("Entering on key TLK").unwrap());
            assert!(last_checkpoint().is_some());
        })
        .await;
        scope("b".to_string(), async {
            assert!(last_checkpoint().is_none());
        })
        .await;
    }

    /// A logger wired exactly as `init()` wires it, but piped somewhere we can
    /// read. Everything below goes through the real `env_logger`, so the filter
    /// and the drop behaviour are the ones production gets.
    fn piped_logger(filter: &str) -> (pretty_env_logger::env_logger::Logger, Arc<Mutex<Vec<u8>>>) {
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Arc::new(Mutex::new(Vec::new()));
        let logger = pretty_env_logger::env_logger::Builder::new()
            .parse_filters(filter)
            .format(format_record)
            .target(pretty_env_logger::env_logger::Target::Pipe(Box::new(Sink(sink.clone()))))
            .build();
        (logger, sink)
    }

    fn emit(logger: &impl log::Log, target: &str, level: log::Level, message: &str) {
        logger.log(
            &log::Record::builder()
                .args(format_args!("{message}"))
                .level(level)
                .target(target)
                .build(),
        );
    }

    fn written(sink: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(sink.lock().unwrap().clone()).unwrap()
    }

    #[tokio::test]
    async fn a_dropped_record_reaches_the_output_as_nothing_at_all() {
        // The load-bearing assumption: `format_record` returning without
        // writing must emit no bytes — not a blank line, not a prefix. If
        // env_logger ever framed records itself, the decrypted keychain dump
        // would appear in the log with its message merely blanked.
        let (logger, sink) = piped_logger(DEFAULT_FILTER);
        scope("t".to_string(), async {
            emit(&logger, KEYCHAIN_TARGET, log::Level::Info, "data 62706c69737430");
            assert_eq!(written(&sink), "", "dropped record produced output");

            // And the hex never appears even in part.
            emit(&logger, KEYCHAIN_TARGET, log::Level::Debug, "Insert key uuid 5A2B");
            assert_eq!(written(&sink), "");
        })
        .await;
    }

    #[tokio::test]
    async fn checkpoints_and_warnings_do_reach_the_output() {
        let (logger, sink) = piped_logger(DEFAULT_FILTER);
        scope("7b2f1fa7".to_string(), async {
            emit(&logger, KEYCHAIN_TARGET, log::Level::Info, "Entering on key MasterKey");
            emit(&logger, KEYCHAIN_TARGET, log::Level::Warn, "Signature verification failed");
            let out = written(&sink);
            assert!(out.contains("Entering on key MasterKey"), "{out}");
            assert!(out.contains("Signature verification failed"), "{out}");
            // Tagged, so two concurrent attempts stay separable.
            assert_eq!(out.matches("[sess=7b2f1fa7]").count(), 2, "{out}");
            // And the record was recorded, not just printed.
            assert_eq!(last_checkpoint().map(|c| c.prefix()), Some("Entering on key "));
        })
        .await;
    }

    #[tokio::test]
    async fn rust_log_cannot_re_enable_the_redacted_lines() {
        // An operator turning the module up to debug to chase a join is exactly
        // when the keychain dump would land in a hosted log store, so the
        // allowlist deliberately outranks the filter.
        let (logger, sink) = piped_logger("rustpush::icloud::keychain=trace");
        scope("t".to_string(), async {
            emit(&logger, KEYCHAIN_TARGET, log::Level::Trace, "data 62706c69737430");
            assert_eq!(written(&sink), "");
        })
        .await;
    }

    #[test]
    fn the_escrow_diagnostics_are_matched_as_rustpush_formats_them() {
        // Verbatim from rustpush 96c1228 — an allowlist that matched a
        // paraphrase would be config matching nothing, which reads as healthy.
        assert!(is_safe_diagnostic(
            "Escrow lookup returned 3 metadata record(s) and 0 viable Cuttlefish bottle(s)"
        ));
        assert!(is_safe_diagnostic(
            "Escrow metadata schema mismatch: missing field `passcodeGeneration`; \
             top-level shape: [bottleId:string, escrowedSPKI:data]"
        ));
        // Prefix, not substring: a future line whose *contents* happen to
        // mention escrow is not thereby cleared to print.
        assert!(!is_safe_diagnostic("Insert key for Escrow lookup returned"));
        assert!(!is_safe_diagnostic("data 62706c69737430"));
    }

    #[tokio::test]
    async fn the_escrow_diagnostics_print_without_claiming_a_join_position() {
        // Both lines are emitted by `get_viable_bottles`, before the join
        // starts. Recording them as checkpoints would make a later failure
        // name a signature it never got as far as verifying.
        let (logger, sink) = piped_logger(DEFAULT_FILTER);
        scope("t".to_string(), async {
            emit(
                &logger,
                KEYCHAIN_TARGET,
                log::Level::Info,
                "Escrow lookup returned 3 metadata record(s) and 0 viable Cuttlefish bottle(s)",
            );
            emit(
                &logger,
                KEYCHAIN_TARGET,
                log::Level::Debug,
                "Escrow metadata schema mismatch: missing field `passcodeGeneration`; \
                 top-level shape: [bottleId:string, escrowedSPKI:data]",
            );
            let out = written(&sink);
            // The counts are the discriminator for a `no_bottles` failure…
            assert!(out.contains("3 metadata record(s) and 0 viable"), "{out}");
            // …and the field name is what turns it into a fix.
            assert!(out.contains("missing field `passcodeGeneration`"), "{out}");
            assert!(last_checkpoint().is_none(), "diagnostic recorded as a checkpoint");
        })
        .await;
    }

    #[test]
    fn a_checkpoint_outside_an_export_is_harmless() {
        // The logger runs before any session is scoped (and for the reaper's
        // own records); recording must not panic there.
        note_checkpoint(0);
        assert!(last_checkpoint().is_none());
    }
}
