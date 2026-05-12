//! Telemetry event log (§21.1).
//!
//! Writes one JSON line per verdict to `~/.cache/nyx/dynamic/events.jsonl`.
//! `NYX_NO_TELEMETRY=1` silently disables all writes (§21.4).
//!
//! Schema (§21.1 minimal fields):
//! ```json
//! {
//!   "ts": "<RFC-3339>",
//!   "finding_id": "...",
//!   "spec_hash": "...",
//!   "lang": "python",
//!   "cap": "SQL_QUERY",
//!   "status": "Confirmed",
//!   "toolchain_id": "python-3.11",
//!   "toolchain_match": "exact",
//!   "duration_ms": 312,
//!   "build_attempts": 1
//! }
//! ```

use crate::dynamic::spec::HarnessSpec;
use crate::evidence::{InconclusiveReason, VerifyStatus};
use directories::ProjectDirs;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::Duration;

/// One telemetry event per verdict.
#[derive(Debug, serde::Serialize)]
pub struct TelemetryEvent {
    pub ts: String,
    pub finding_id: String,
    pub spec_hash: String,
    pub lang: String,
    pub cap: String,
    pub status: String,
    pub toolchain_id: String,
    pub toolchain_match: String,
    pub duration_ms: u64,
    pub build_attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inconclusive_reason: Option<String>,
}

impl TelemetryEvent {
    pub fn new(
        spec: &HarnessSpec,
        status: VerifyStatus,
        inconclusive_reason: Option<InconclusiveReason>,
        toolchain_match: &str,
        duration: Duration,
        build_attempts: u32,
    ) -> Self {
        Self {
            ts: chrono::Utc::now().to_rfc3339(),
            finding_id: spec.finding_id.clone(),
            spec_hash: spec.spec_hash.clone(),
            lang: format!("{:?}", spec.lang).to_ascii_lowercase(),
            cap: format!("{:?}", spec.expected_cap),
            status: format!("{status:?}"),
            toolchain_id: spec.toolchain_id.clone(),
            toolchain_match: toolchain_match.to_owned(),
            duration_ms: duration.as_millis() as u64,
            build_attempts,
            inconclusive_reason: inconclusive_reason.map(|r| format!("{r:?}")),
        }
    }
}

/// Write a telemetry event to the events log.
///
/// Silently no-ops when:
/// - `NYX_NO_TELEMETRY=1`
/// - The log directory cannot be created
/// - The write fails (telemetry must never affect verdict)
pub fn emit(event: &TelemetryEvent) {
    if std::env::var("NYX_NO_TELEMETRY").as_deref() == Ok("1") {
        return;
    }

    let Some(path) = events_log_path() else {
        return;
    };

    let Ok(line) = serde_json::to_string(event) else {
        return;
    };

    // Best-effort: ignore all errors.
    let _ = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            // Ensure the directory is private (0700).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        writeln!(f, "{line}")?;
        Ok(())
    })();
}

fn events_log_path() -> Option<std::path::PathBuf> {
    // Respect explicit override for testing.
    if let Ok(p) = std::env::var("NYX_TELEMETRY_PATH") {
        return Some(std::path::PathBuf::from(p));
    }
    let dirs = ProjectDirs::from("", "", "nyx")?;
    Some(dirs.cache_dir().join("dynamic").join("events.jsonl"))
}

/// Return the path to the events log (for tests and verification).
pub fn log_path() -> Option<std::path::PathBuf> {
    events_log_path()
}

// ── Rank delta telemetry ──────────────────────────────────────────────────────

/// One telemetry event per ranked finding that carries a dynamic verdict delta.
///
/// Emitted by `rank::rank_diags` for every diag whose dynamic verdict shifts
/// its rank score (delta != 0). Used by the M7 calibration pipeline to tune
/// the N/M boost/penalty constants from real-world verdict distributions.
#[derive(Debug, serde::Serialize)]
pub struct RankDeltaEvent {
    pub ts: String,
    /// Always `"rank_delta"` — distinguishes from verdict events in the log.
    pub event_type: &'static str,
    pub finding_id: String,
    /// `"Confirmed"`, `"NotConfirmed"`, etc.
    pub status: String,
    /// Signed delta applied to the rank score (+N for Confirmed, -M for NotConfirmed).
    pub delta: f64,
}

/// Write a rank-delta telemetry event to the events log.
///
/// Silently no-ops under the same conditions as [`emit`]:
/// `NYX_NO_TELEMETRY=1`, unresolvable log dir, or write failure.
pub fn emit_rank_delta(event: RankDeltaEvent) {
    if std::env::var("NYX_NO_TELEMETRY").as_deref() == Ok("1") {
        return;
    }

    let Some(path) = events_log_path() else {
        return;
    };

    let Ok(line) = serde_json::to_string(&event) else {
        return;
    };

    let _ = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        writeln!(f, "{line}")?;
        Ok(())
    })();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;
    use tempfile::TempDir;

    fn make_spec() -> HarnessSpec {
        HarnessSpec {
            finding_id: "0000000000000001".into(),
            entry_file: "handler.py".into(),
            entry_name: "handle".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "python-3.11".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "handler.py".into(),
            sink_line: 5,
            spec_hash: "abcd1234abcd1234".into(),
        }
    }

    #[test]
    fn emit_writes_valid_json() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("events.jsonl");
        unsafe { std::env::set_var("NYX_TELEMETRY_PATH", log.to_str().unwrap()) };

        let event = TelemetryEvent::new(
            &make_spec(),
            VerifyStatus::Confirmed,
            None,
            "exact",
            Duration::from_millis(200),
            1,
        );
        emit(&event);

        let content = std::fs::read_to_string(&log).unwrap();
        assert!(!content.is_empty());
        let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(v["status"], "Confirmed");
        assert_eq!(v["toolchain_match"], "exact");

        unsafe { std::env::remove_var("NYX_TELEMETRY_PATH") };
    }

    #[test]
    fn nyx_no_telemetry_suppresses_writes() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("events.jsonl");
        unsafe {
            std::env::set_var("NYX_TELEMETRY_PATH", log.to_str().unwrap());
            std::env::set_var("NYX_NO_TELEMETRY", "1");
        }

        let event = TelemetryEvent::new(
            &make_spec(),
            VerifyStatus::Confirmed,
            None,
            "exact",
            Duration::from_millis(100),
            1,
        );
        emit(&event);

        assert!(!log.exists(), "log must not be created when NYX_NO_TELEMETRY=1");

        unsafe {
            std::env::remove_var("NYX_NO_TELEMETRY");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }
    }
}
