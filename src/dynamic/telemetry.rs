//! Telemetry event log.
//!
//! Writes one JSON line per verdict to `~/.cache/nyx/dynamic/events.jsonl`.
//! `NYX_NO_TELEMETRY=1` silently disables all writes.
//!
//! # Schema
//!
//! Every record starts with three envelope fields so the on-disk format can
//! evolve across releases without silently mixing incompatible records:
//!
//! - `schema_version`: integer, bumped on any breaking shape change.
//! - `nyx_version`: the Cargo package version that wrote the record.
//! - `corpus_version`: the payload-corpus version active at write time.
//!
//! Followed by a `kind` discriminator (`"verdict"` or `"rank_delta"`). All
//! readers require `schema_version == SCHEMA_VERSION`; mismatched records
//! produce [`TelemetryReadError::SchemaMismatch`] instead of being silently
//! parsed as if they matched.
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "nyx_version": "0.7.0",
//!   "corpus_version": "4",
//!   "kind": "verdict",
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

use crate::commands::scan::Diag;
use crate::dynamic::spec::HarnessSpec;
use crate::evidence::{InconclusiveReason, VerifyStatus};
use directories::ProjectDirs;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// On-disk telemetry schema version.  Bump on any breaking shape change to
/// the JSON record.  Readers reject any record whose `schema_version` does
/// not match this constant.
pub const SCHEMA_VERSION: u32 = 1;

/// Cargo package version of the Nyx build that wrote the record.
pub const NYX_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Corpus-version label written into every record.  Kept as a `&'static str`
/// so it can sit on a `Serialize`-derived struct alongside the other envelope
/// fields without an allocation.  Mirrors
/// [`crate::dynamic::corpus::CORPUS_VERSION`]; the compile-time assertion
/// below + the [`corpus_version_const_matches_corpus_module`] runtime test
/// jointly guard drift.
pub const CORPUS_VERSION: &str = "15";

/// Compile-time guard that pins [`CORPUS_VERSION`] (this module) to the
/// textual form of [`crate::dynamic::corpus::CORPUS_VERSION`].  Bumping the
/// `u32` constant without updating the `&str` here (or vice versa) fails
/// the build, so the manual-bookkeeping risk the Phase 27 follow-up flagged
/// is caught at `cargo build` rather than at test time.
const _: () = assert_corpus_version_str_matches_u32();

const fn assert_corpus_version_str_matches_u32() {
    let int_val = crate::dynamic::corpus::CORPUS_VERSION;
    let bytes = CORPUS_VERSION.as_bytes();

    // Render `int_val` into a 10-byte buffer (u32::MAX is 10 digits).
    let mut buf = [0u8; 10];
    let mut len: usize = 0;
    if int_val == 0 {
        buf[0] = b'0';
        len = 1;
    } else {
        let mut v = int_val;
        while v > 0 {
            buf[len] = b'0' + (v % 10) as u8;
            v /= 10;
            len += 1;
        }
        // Reverse the first `len` bytes so the most-significant digit lands first.
        let mut i: usize = 0;
        while i < len / 2 {
            let tmp = buf[i];
            buf[i] = buf[len - 1 - i];
            buf[len - 1 - i] = tmp;
            i += 1;
        }
    }

    if bytes.len() != len {
        panic!(
            "CORPUS_VERSION &str length disagrees with crate::dynamic::corpus::CORPUS_VERSION u32; update both in lockstep"
        );
    }
    let mut i: usize = 0;
    while i < len {
        if bytes[i] != buf[i] {
            panic!(
                "CORPUS_VERSION &str differs from crate::dynamic::corpus::CORPUS_VERSION u32; update both in lockstep"
            );
        }
        i += 1;
    }
}

/// One telemetry event per verdict.
///
/// `lang` is `"unknown"` for findings whose language could not be resolved
/// (e.g. spec derivation failed before `HarnessSpec::lang` was set).  Counting
/// these is the `lang_unknown_count` Phase 02 acceptance asks for:
/// `grep '"lang":"unknown"' events.jsonl | wc -l`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TelemetryEvent {
    pub schema_version: u32,
    pub nyx_version: &'static str,
    pub corpus_version: &'static str,
    pub kind: &'static str,
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
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub inconclusive_reason: Option<String>,
    /// Path of the finding's source file, populated for spec-derivation
    /// failures so downstream consumers can map `lang="unknown"` events back
    /// to a file.  Skipped on successful verdicts (the spec already carries
    /// `entry_file`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,
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
            schema_version: SCHEMA_VERSION,
            nyx_version: NYX_VERSION,
            corpus_version: CORPUS_VERSION,
            kind: "verdict",
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
            path: None,
        }
    }

    /// Telemetry event for findings that never got a `HarnessSpec`.
    ///
    /// Used by `verify_finding` when spec derivation fails (lang unresolvable,
    /// path empty, sink redacted, etc.). Without this path the events log
    /// silently drops every spec-derivation failure, which breaks the
    /// `lang_unknown_count` aggregation acceptance.
    ///
    /// `lang` is best-effort sniffed from `diag.path`'s extension via
    /// [`crate::symbol::Lang::from_extension`]. When the extension is
    /// unknown or absent, `lang` is the literal string `"unknown"`.
    pub fn no_spec(
        diag: &Diag,
        status: VerifyStatus,
        inconclusive_reason: Option<InconclusiveReason>,
    ) -> Self {
        let cap = diag
            .evidence
            .as_ref()
            .map(|e| format!("{:?}", e.sink_caps))
            .unwrap_or_else(|| "0".to_owned());
        Self {
            schema_version: SCHEMA_VERSION,
            nyx_version: NYX_VERSION,
            corpus_version: CORPUS_VERSION,
            kind: "verdict",
            ts: chrono::Utc::now().to_rfc3339(),
            finding_id: format!("{:016x}", diag.stable_hash),
            spec_hash: String::new(),
            lang: lang_from_path(&diag.path),
            cap,
            status: format!("{status:?}"),
            toolchain_id: String::new(),
            toolchain_match: String::new(),
            duration_ms: 0,
            build_attempts: 0,
            inconclusive_reason: inconclusive_reason.map(|r| format!("{r:?}")),
            path: Some(diag.path.clone()),
        }
    }

    /// Telemetry event for a verdict reached without a [`Diag`] handle.
    ///
    /// Used by `verify_finding` when emitting an
    /// `Inconclusive(EntryKindUnsupported)` from inside `build_verdict`.
    /// The diag is not threaded that far, but the spec's `entry_file` and
    /// the inconclusive reason carry enough signal to populate the event.
    /// `cap` and `finding_id` default to empty / `0`; downstream consumers
    /// already handle that path for `no_spec` events.
    pub fn no_spec_for_path(
        path: &str,
        status: VerifyStatus,
        inconclusive_reason: Option<InconclusiveReason>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            nyx_version: NYX_VERSION,
            corpus_version: CORPUS_VERSION,
            kind: "verdict",
            ts: chrono::Utc::now().to_rfc3339(),
            finding_id: String::new(),
            spec_hash: String::new(),
            lang: lang_from_path(path),
            cap: "0".to_owned(),
            status: format!("{status:?}"),
            toolchain_id: String::new(),
            toolchain_match: String::new(),
            duration_ms: 0,
            build_attempts: 0,
            inconclusive_reason: inconclusive_reason.map(|r| format!("{r:?}")),
            path: Some(path.to_owned()),
        }
    }
}

/// Sniff a language slug from a file extension. Returns `"unknown"` when
/// the extension is missing or unrecognized.
fn lang_from_path(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .and_then(crate::symbol::Lang::from_extension)
        .map(|l| l.as_str().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Sampling decision for telemetry writes.
///
/// Confirmed and Inconclusive verdicts are kept for calibration. Other verdict
/// statuses can be downsampled to bound log growth on high-volume scans.
///
/// The decision is seeded by `spec_hash` so the *same* finding makes the *same*
/// keep-or-drop call across reruns. Without this, two scans of the same project
/// would produce non-comparable event logs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SamplingPolicy {
    /// Always keep Confirmed verdicts.  Default `true`.
    pub keep_all_confirmed: bool,
    /// Always keep Inconclusive verdicts.  Default `true`.
    pub keep_all_inconclusive: bool,
    /// Probability of keeping any other verdict (NotConfirmed, Unsupported).
    /// `0.0` drops all non-retained; `1.0` keeps all.  Default `1.0`.
    pub sample_rate_other: f32,
}

impl Default for SamplingPolicy {
    fn default() -> Self {
        Self {
            keep_all_confirmed: true,
            keep_all_inconclusive: true,
            sample_rate_other: 1.0,
        }
    }
}

impl SamplingPolicy {
    /// Keep every record regardless of status.  Equivalent to the pre-Phase-27
    /// behaviour and the right default for unit tests.
    pub fn keep_all() -> Self {
        Self::default()
    }

    /// Build the runtime policy from `[telemetry]` in `nyx.toml`.
    pub fn from_config(cfg: &crate::utils::config::TelemetryConfig) -> Self {
        Self {
            keep_all_confirmed: cfg.keep_all_confirmed,
            keep_all_inconclusive: cfg.keep_all_inconclusive,
            sample_rate_other: cfg.sample_rate_other,
        }
    }

    /// Decide whether an event with the given status / spec_hash should be
    /// written.  Deterministic for a fixed `(self, status, spec_hash)`.
    pub fn should_sample(&self, status: VerifyStatus, spec_hash: &str) -> bool {
        if matches!(status, VerifyStatus::Confirmed) && self.keep_all_confirmed {
            return true;
        }
        if matches!(status, VerifyStatus::Inconclusive) && self.keep_all_inconclusive {
            return true;
        }
        // Clamp the configured rate into [0, 1] and short-circuit the extremes
        // so we never hash a record we already know the answer for.
        let rate = self.sample_rate_other.clamp(0.0, 1.0);
        if rate >= 1.0 {
            return true;
        }
        if rate <= 0.0 {
            return false;
        }
        // Hash the spec_hash with a fixed key so the bucket is stable across
        // releases.  blake3 is already in the dep tree; the first 8 bytes
        // give a uniform u64.
        let h = blake3::hash(spec_hash.as_bytes());
        let bytes: [u8; 8] = h.as_bytes()[..8].try_into().unwrap();
        let bucket = (u64::from_le_bytes(bytes) % 1_000_000) as f32 / 1_000_000.0;
        bucket < rate
    }
}

/// Write a telemetry event to the events log.
///
/// Silently no-ops when:
/// - `NYX_NO_TELEMETRY=1`
/// - The log directory cannot be created
/// - The write fails (telemetry must never affect verdict)
///
/// Applies the default-`keep_all` sampling policy (every event is written).
/// Call sites that want sampling go through [`emit_with_policy`] instead.
pub fn emit(event: &TelemetryEvent) {
    emit_with_policy(event, &SamplingPolicy::keep_all());
}

/// Like [`emit`] but consults `policy` before writing.
///
/// Drops the record when `policy.should_sample(...)` returns `false`.  The
/// decision is keyed on `event.spec_hash`, so the same finding produces the
/// same keep-or-drop call across reruns.
pub fn emit_with_policy(event: &TelemetryEvent, policy: &SamplingPolicy) {
    if std::env::var("NYX_NO_TELEMETRY").as_deref() == Ok("1") {
        return;
    }

    // Map the &str status back into the VerifyStatus enum for the policy
    // check.  Falls through to "keep" on any unrecognised string so we never
    // accidentally drop a record because of a future status variant.
    let status = parse_status(&event.status).unwrap_or(VerifyStatus::Confirmed);
    if !policy.should_sample(status, &event.spec_hash) {
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

fn parse_status(s: &str) -> Option<VerifyStatus> {
    match s {
        "Confirmed" => Some(VerifyStatus::Confirmed),
        "NotConfirmed" => Some(VerifyStatus::NotConfirmed),
        "Inconclusive" => Some(VerifyStatus::Inconclusive),
        "Unsupported" => Some(VerifyStatus::Unsupported),
        _ => None,
    }
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

// Reading events back

/// Structured error returned by [`read_events`].
///
/// Returned when a log mixes records from incompatible schema versions.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryReadError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "schema mismatch in {path} line {line}: expected schema_version={expected}, found {found}"
    )]
    SchemaMismatch {
        path: PathBuf,
        line: usize,
        expected: u32,
        found: u32,
    },
    #[error("missing schema_version in {path} line {line}")]
    MissingSchemaVersion { path: PathBuf, line: usize },
    #[error("malformed JSON in {path} line {line}: {source}")]
    Json {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
}

/// Read every event record from the JSONL log at `path`.
///
/// Returns each line as a `serde_json::Value` so callers can dispatch on the
/// `kind` discriminator themselves.  Rejects any record whose `schema_version`
/// does not match [`SCHEMA_VERSION`]. A v0 record from an older release must
/// not silently parse as if the schema had never changed.
///
/// Blank lines are skipped. Any malformed JSON or missing `schema_version`
/// fails the whole read; partial recovery is not the contract for telemetry
/// logs.
pub fn read_events(path: &Path) -> Result<Vec<serde_json::Value>, TelemetryReadError> {
    let file = std::fs::File::open(path).map_err(|e| TelemetryReadError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line_no = idx + 1;
        let line = line.map_err(|e| TelemetryReadError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| TelemetryReadError::Json {
                path: path.to_path_buf(),
                line: line_no,
                source: e,
            })?;
        let found = value
            .get("schema_version")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| TelemetryReadError::MissingSchemaVersion {
                path: path.to_path_buf(),
                line: line_no,
            })?;
        if found != SCHEMA_VERSION as u64 {
            return Err(TelemetryReadError::SchemaMismatch {
                path: path.to_path_buf(),
                line: line_no,
                expected: SCHEMA_VERSION,
                found: found as u32,
            });
        }
        out.push(value);
    }
    Ok(out)
}

/// Scan the `verify_feedback` records in an events log for the given
/// finding id and return the matching `VerifyResult::wrong` value.
///
/// * `Some(true)`: most-recent feedback for this finding was
///   `wrong:<reason>`.
/// * `Some(false)`: most-recent feedback was `right`.
/// * `None`: no feedback recorded for this finding.
///
/// Multiple records for the same finding collapse to the **last** one
/// in file order: callers run `nyx verify-feedback` more than once when
/// they correct an earlier judgment, and the latest reading is the
/// authoritative one. The events log is read via the raw JSONL path
/// (NOT [`read_events`]) because `verify_feedback` rows were written
/// before the `schema_version`-envelope migration and may legitimately
/// pre-date the schema bump; a missing `schema_version` here is not
/// fatal.
pub fn feedback_wrong_for_finding(path: &Path, finding_id: &str) -> Option<bool> {
    let file = std::fs::File::open(path).ok()?;
    let reader = BufReader::new(file);
    let mut latest: Option<bool> = None;
    for line in reader.lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if value.get("event").and_then(|v| v.as_str()) != Some("verify_feedback") {
            continue;
        }
        if value.get("finding_id").and_then(|v| v.as_str()) != Some(finding_id) {
            continue;
        }
        let Some(feedback) = value.get("feedback").and_then(|v| v.as_str()) else {
            continue;
        };
        if feedback.starts_with("wrong:") || feedback == "wrong" {
            latest = Some(true);
        } else if feedback == "right" {
            latest = Some(false);
        }
    }
    latest
}

// ── Rank delta telemetry ──────────────────────────────────────────────────────

/// One telemetry event per ranked finding that carries a dynamic verdict delta.
///
/// Emitted by `rank::rank_diags` for every diag whose dynamic verdict shifts
/// its rank score (delta != 0). Used to tune the N/M boost/penalty constants
/// from real-world verdict distributions.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RankDeltaEvent {
    pub schema_version: u32,
    pub nyx_version: &'static str,
    pub corpus_version: &'static str,
    /// Always `"rank_delta"`. Distinguishes from verdict events in the log.
    pub kind: &'static str,
    pub ts: String,
    pub finding_id: String,
    /// `"Confirmed"`, `"NotConfirmed"`, etc.
    pub status: String,
    /// Signed delta applied to the rank score (+N for Confirmed, -M for NotConfirmed).
    pub delta: f64,
}

impl RankDeltaEvent {
    pub fn new(finding_id: String, status: String, delta: f64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            nyx_version: NYX_VERSION,
            corpus_version: CORPUS_VERSION,
            kind: "rank_delta",
            ts: chrono::Utc::now().to_rfc3339(),
            finding_id,
            status,
            delta,
        }
    }
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
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn feedback_wrong_for_finding_returns_latest_record() {
        use std::io::Write;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("events.jsonl");
        let mut f = std::fs::File::create(&log).unwrap();
        // Three records for the same finding: initial wrong, later
        // overridden by right.  The latest wins.
        writeln!(
            f,
            r#"{{"event":"verify_feedback","finding_id":"abc1","feedback":"wrong:sample"}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"event":"verify_feedback","finding_id":"abc2","feedback":"wrong:other"}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"event":"verify_feedback","finding_id":"abc1","feedback":"right"}}"#
        )
        .unwrap();
        // Non-feedback rows are ignored.
        writeln!(f, r#"{{"event":"verify","finding_id":"abc1"}}"#).unwrap();
        f.flush().unwrap();
        assert_eq!(feedback_wrong_for_finding(&log, "abc1"), Some(false));
        assert_eq!(feedback_wrong_for_finding(&log, "abc2"), Some(true));
        assert_eq!(feedback_wrong_for_finding(&log, "missing"), None);
    }

    #[test]
    fn feedback_wrong_for_finding_tolerates_missing_file() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("nonexistent.jsonl");
        assert_eq!(feedback_wrong_for_finding(&log, "abc1"), None);
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
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert_eq!(v["nyx_version"], NYX_VERSION);
        assert_eq!(v["corpus_version"], CORPUS_VERSION);
        assert_eq!(v["kind"], "verdict");
        assert_eq!(v["status"], "Confirmed");
        assert_eq!(v["toolchain_match"], "exact");

        unsafe { std::env::remove_var("NYX_TELEMETRY_PATH") };
    }

    fn make_diag(path: &str) -> Diag {
        Diag {
            stable_hash: 0xdeadbeef_cafebabe,
            path: path.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn no_spec_event_records_lang_unknown_for_missing_extension() {
        let diag = make_diag("/tmp/some_script_no_ext");
        let event = TelemetryEvent::no_spec(&diag, VerifyStatus::Unsupported, None);
        assert_eq!(event.lang, "unknown");
        assert_eq!(event.path.as_deref(), Some("/tmp/some_script_no_ext"));
        assert!(event.spec_hash.is_empty());
        assert_eq!(event.status, "Unsupported");
        assert_eq!(event.schema_version, SCHEMA_VERSION);
        assert_eq!(event.kind, "verdict");
    }

    #[test]
    fn no_spec_event_sniffs_lang_from_extension_when_present() {
        let diag = make_diag("/tmp/handler.py");
        let event = TelemetryEvent::no_spec(&diag, VerifyStatus::Inconclusive, None);
        assert_eq!(event.lang, "python");
        assert_eq!(event.path.as_deref(), Some("/tmp/handler.py"));
        assert!(event.spec_hash.is_empty());
    }

    #[test]
    fn no_spec_event_serialises_inconclusive_reason() {
        use crate::evidence::SpecDerivationStrategy;
        let diag = make_diag("/tmp/x.kt");
        let reason = InconclusiveReason::SpecDerivationFailed {
            tried: vec![SpecDerivationStrategy::FromFlowSteps],
            hint: "kotlin source".to_owned(),
        };
        let event = TelemetryEvent::no_spec(&diag, VerifyStatus::Inconclusive, Some(reason));
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"lang\":\"java\""));
        assert!(json.contains("SpecDerivationFailed"));
        assert!(json.contains("\"path\":\"/tmp/x.kt\""));
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

    #[test]
    fn corpus_version_const_matches_corpus_module() {
        assert_eq!(
            CORPUS_VERSION,
            crate::dynamic::corpus::CORPUS_VERSION.to_string()
        );
    }

    #[test]
    fn read_events_rejects_schema_zero() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("events.jsonl");
        std::fs::write(
            &log,
            "{\"schema_version\":0,\"kind\":\"verdict\",\"status\":\"Confirmed\"}\n",
        )
        .unwrap();
        let err = read_events(&log).expect_err("schema 0 must be rejected");
        match err {
            TelemetryReadError::SchemaMismatch { expected, found, .. } => {
                assert_eq!(expected, SCHEMA_VERSION);
                assert_eq!(found, 0);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn read_events_accepts_current_schema() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("events.jsonl");
        let event = TelemetryEvent::new(
            &make_spec(),
            VerifyStatus::Confirmed,
            None,
            "exact",
            Duration::from_millis(1),
            1,
        );
        let line = serde_json::to_string(&event).unwrap();
        std::fs::write(&log, format!("{line}\n\n")).unwrap();
        let events = read_events(&log).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "verdict");
    }

    #[test]
    fn read_events_rejects_missing_schema() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("events.jsonl");
        std::fs::write(&log, "{\"kind\":\"verdict\"}\n").unwrap();
        match read_events(&log).unwrap_err() {
            TelemetryReadError::MissingSchemaVersion { .. } => {}
            other => panic!("expected MissingSchemaVersion, got {other:?}"),
        }
    }

    #[test]
    fn read_events_rejects_malformed_json() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("events.jsonl");
        std::fs::write(&log, "{not json\n").unwrap();
        match read_events(&log).unwrap_err() {
            TelemetryReadError::Json { .. } => {}
            other => panic!("expected Json, got {other:?}"),
        }
    }

    #[test]
    fn sampling_policy_keeps_confirmed_and_inconclusive() {
        let policy = SamplingPolicy {
            keep_all_confirmed: true,
            keep_all_inconclusive: true,
            sample_rate_other: 0.0,
        };
        assert!(policy.should_sample(VerifyStatus::Confirmed, "any"));
        assert!(policy.should_sample(VerifyStatus::Inconclusive, "any"));
        assert!(!policy.should_sample(VerifyStatus::NotConfirmed, "any"));
        assert!(!policy.should_sample(VerifyStatus::Unsupported, "any"));
    }

    #[test]
    fn sampling_policy_is_deterministic_per_spec_hash() {
        let policy = SamplingPolicy {
            keep_all_confirmed: true,
            keep_all_inconclusive: true,
            sample_rate_other: 0.5,
        };
        let first = policy.should_sample(VerifyStatus::NotConfirmed, "deadbeef");
        for _ in 0..100 {
            assert_eq!(
                first,
                policy.should_sample(VerifyStatus::NotConfirmed, "deadbeef")
            );
        }
    }

    #[test]
    fn sampling_policy_rate_one_keeps_everything() {
        let policy = SamplingPolicy {
            keep_all_confirmed: false,
            keep_all_inconclusive: false,
            sample_rate_other: 1.0,
        };
        for hash in &["a", "b", "c", "deadbeef", ""] {
            assert!(policy.should_sample(VerifyStatus::NotConfirmed, hash));
        }
    }

    #[test]
    fn sampling_policy_rate_zero_drops_everything_else() {
        let policy = SamplingPolicy {
            keep_all_confirmed: true,
            keep_all_inconclusive: true,
            sample_rate_other: 0.0,
        };
        for hash in &["a", "b", "c", "deadbeef"] {
            assert!(!policy.should_sample(VerifyStatus::NotConfirmed, hash));
            assert!(!policy.should_sample(VerifyStatus::Unsupported, hash));
        }
    }

    #[test]
    fn sampling_policy_rate_half_buckets_roughly_evenly() {
        let policy = SamplingPolicy {
            keep_all_confirmed: true,
            keep_all_inconclusive: true,
            sample_rate_other: 0.5,
        };
        let kept = (0..1000)
            .filter(|i| {
                let h = format!("hash-{i:06x}");
                policy.should_sample(VerifyStatus::NotConfirmed, &h)
            })
            .count();
        // Loose envelope around 500/1000.  Tight enough to catch a "always
        // keep" or "always drop" regression, wide enough to avoid flakes.
        assert!(
            kept > 350 && kept < 650,
            "expected ~500/1000 kept at rate 0.5, got {kept}"
        );
    }

    #[test]
    fn emit_with_policy_drops_when_unsampled() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("events.jsonl");
        unsafe { std::env::set_var("NYX_TELEMETRY_PATH", log.to_str().unwrap()) };

        let mut spec = make_spec();
        spec.spec_hash = "drop-me".into();
        let event = TelemetryEvent::new(
            &spec,
            VerifyStatus::NotConfirmed,
            None,
            "exact",
            Duration::from_millis(1),
            1,
        );
        let policy = SamplingPolicy {
            keep_all_confirmed: true,
            keep_all_inconclusive: true,
            sample_rate_other: 0.0,
        };
        emit_with_policy(&event, &policy);

        assert!(!log.exists(), "event must not be written when policy drops");

        unsafe { std::env::remove_var("NYX_TELEMETRY_PATH") };
    }

    #[test]
    fn rank_delta_carries_envelope_fields() {
        let event = RankDeltaEvent::new("abc".into(), "Confirmed".into(), 2.5);
        assert_eq!(event.schema_version, SCHEMA_VERSION);
        assert_eq!(event.nyx_version, NYX_VERSION);
        assert_eq!(event.corpus_version, CORPUS_VERSION);
        assert_eq!(event.kind, "rank_delta");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.starts_with("{\"schema_version\":1"));
    }
}
