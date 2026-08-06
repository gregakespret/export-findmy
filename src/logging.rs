//! Logger wiring shared by the CLI and `--serve`.
//!
//! rustpush carries the *reason* behind several of the opaque errors we surface
//! — "Signature verification failed" is what stands behind the "Bad message" a
//! user sees — but only through the `log` crate, and its records know nothing
//! about which export produced them. In `--serve` two attempts can be in flight
//! at once and their lines interleave, so an untagged `WARN` is unattributable
//! exactly when it matters most: the operator cannot tell which join failed its
//! signature check. Every pipeline task runs inside [`SESSION`], and the format
//! below stamps that tag onto every record, rustpush's included.

use std::io::Write;

tokio::task_local! {
    /// Session tag of the export running on this task. Set by the server for
    /// each session and by the CLI (as `cli`) for its single run.
    pub static SESSION: String;
}

/// The session tag of the export we're running under, or `-` outside one
/// (startup, server plumbing, the reaper).
fn current_session() -> String {
    SESSION.try_with(|s| s.clone()).unwrap_or_else(|_| "-".to_string())
}

/// Dependencies stay at `warn` — that is the level rustpush reports its reasons
/// at, and anything lower is noise. Our own crate's `log` records are `info`, so
/// a bare `warn` would silence them.
const DEFAULT_FILTER: &str = "warn,export_findmy=info";

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

/// Install the logger. Returns the filter in force, which the caller logs — a
/// filter that silently isn't what you think it is turns "no reason in the log"
/// into an unanswerable question.
pub fn init() -> String {
    let var = std::env::var("RUST_LOG").ok();
    let filter = filter_from_env(var.as_deref()).to_string();
    pretty_env_logger::formatted_builder()
        .parse_filters(&filter)
        // Same `[sess=…]` prefix our own lines carry, so a rustpush warning and
        // the pipeline failure it explains can be grepped together.
        .format(|buf, record| {
            writeln!(
                buf,
                "[sess={}] {:<5} {} > {}",
                current_session(),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn session_tag_is_scoped_to_the_task() {
        assert_eq!(current_session(), "-");
        SESSION
            .scope("3f2a1b8c".to_string(), async {
                assert_eq!(current_session(), "3f2a1b8c");
            })
            .await;
        assert_eq!(current_session(), "-");
    }
}
