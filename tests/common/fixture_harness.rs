//! Golden-verdict regression harness for dynamic-verification fixtures.
//!
//! Replaces the original hand-rolled `assert_eq!(status, Confirmed)` style
//! with a "current verdict is the golden" model: each fixture's first run
//! (under `NYX_UPDATE_GOLDENS=1`) records its current verdict shape into a
//! `.golden.json` file checked in beside the fixture; subsequent runs diff
//! against that golden and fail on regression.
//!
//! The contract is intentionally agnostic to the verdict's polarity. A
//! fixture stuck at `Inconclusive(BuildFailed)` because of a missing
//! toolchain is locked at that shape until someone consciously refreshes the
//! golden via `scripts/update_dynamic_goldens.sh`. A flip to `Confirmed` is
//! also a "regression" in the harness's sense and surfaces as a test
//! failure, prompting an explicit golden update.

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
use nyx_scanner::evidence::{
    Confidence, Evidence, FlowStep, FlowStepKind, InconclusiveReason, UnsupportedReason,
    VerifyResult, VerifyStatus,
};
use nyx_scanner::labels::Cap;
use nyx_scanner::patterns::{FindingCategory, Severity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::TempDir;

/// Serialise-once lock guarding the process-global env vars
/// (`NYX_REPRO_BASE`, `NYX_TELEMETRY_PATH`) and the shared build cache dir.
/// Shared across `python_fixtures` / `rust_fixtures` to prevent cross-suite
/// races when nextest runs them in parallel within the same test binary.
pub static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

/// How the fixture source should land relative to the harness's tempdir
/// before [`verify_finding`] is invoked. Mirrors the original per-language
/// behaviour: Python copies the file beside its sibling-import siblings;
/// Rust lays it out as `src/entry.rs` so the Cargo project emitter finds it.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Each test binary uses only one variant; the other is dead per-crate.
pub enum CopyStrategy {
    /// Copy the fixture to `tempdir/{fixture_basename}`. The synthesised Diag
    /// points at the copy so the Python harness can import it directly.
    PreserveName,
    /// Copy the fixture to `tempdir/src/entry.rs`. The synthesised Diag
    /// points at the original fixture path (the Rust emitter reads source via
    /// the absolute Diag path, not via the temp-dir layout).
    RustEntry,
}

/// Per-fixture specification.
pub struct FixtureSpec<'a> {
    /// Subdirectory under `tests/dynamic_fixtures/` (e.g. `"python"`, `"rust"`).
    pub lang_dir: &'a str,
    /// Fixture filename within `lang_dir`.
    pub fixture: &'a str,
    /// Entry-point function name passed in the synthesised flow-step.
    pub func: &'a str,
    /// Sink capability bits to set on `Evidence.sink_caps`.
    pub cap: Cap,
    /// Sink line for the synthesised flow-step. Adversarial fixtures pass a
    /// line that does not exist in the source (e.g. 999) so the probe cannot
    /// fire while the oracle marker still prints.
    pub sink_line: u32,
    /// Confidence stamp on the Diag. `Confidence::Low` short-circuits to
    /// `Unsupported(ConfidenceTooLow)` before the harness executes.
    pub confidence: Confidence,
    /// File-layout strategy for the temp-dir copy.
    pub copy: CopyStrategy,
}

/// Trimmed verdict shape persisted in the `.golden.json` file.
///
/// Captures the fields a regression test must pin: status + typed reasons
/// + whether a payload triggered. Excludes machine-dependent fields
/// (`finding_id`, `detail`, `attempts`, `toolchain_match`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenVerdict {
    pub status: VerifyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<UnsupportedReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inconclusive_reason: Option<InconclusiveReason>,
    #[serde(default)]
    pub triggered: bool,
}

impl From<&VerifyResult> for GoldenVerdict {
    fn from(v: &VerifyResult) -> Self {
        Self {
            status: v.status,
            reason: v.reason.clone(),
            inconclusive_reason: v.inconclusive_reason.clone(),
            triggered: v.triggered_payload.is_some(),
        }
    }
}

/// Run the fixture through `verify_finding` and either compare against the
/// stored golden or — when `NYX_UPDATE_GOLDENS=1` — overwrite the golden
/// with the current verdict.
pub fn run_fixture_and_compare_to_golden(spec: &FixtureSpec<'_>) {
    let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let fixture_root = fixture_dir(spec.lang_dir);
    let fixture_src = fixture_root.join(spec.fixture);
    let golden_path = fixture_root.join(format!("{}.golden.json", spec.fixture));

    let tmp = TempDir::new().expect("create tempdir");
    let diag_path = stage_fixture(&fixture_src, &tmp, spec.copy);

    // SAFETY: env mutation is serialised by FIXTURE_LOCK and the vars are
    // cleared before the lock guard drops at end of function.
    unsafe {
        std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
        std::env::set_var(
            "NYX_TELEMETRY_PATH",
            tmp.path().join("events.jsonl").to_str().unwrap(),
        );
    }

    let mut diag = make_diag(&diag_path, spec.func, spec.cap, spec.sink_line);
    diag.confidence = Some(spec.confidence);

    let opts = VerifyOptions::default();
    let result = verify_finding(&diag, &opts);

    unsafe {
        std::env::remove_var("NYX_REPRO_BASE");
        std::env::remove_var("NYX_TELEMETRY_PATH");
    }

    let current = GoldenVerdict::from(&result);
    let mut current_json =
        serde_json::to_string_pretty(&current).expect("serialise golden verdict");
    current_json.push('\n');

    if std::env::var("NYX_UPDATE_GOLDENS").is_ok_and(|v| v == "1") {
        std::fs::write(&golden_path, &current_json).unwrap_or_else(|e| {
            panic!("write golden {}: {e}", golden_path.display())
        });
        return;
    }

    let expected_json = std::fs::read_to_string(&golden_path).unwrap_or_else(|e| {
        panic!(
            "missing golden {}: {e}\n\
             current verdict:\n{current_json}\n\
             rerun with NYX_UPDATE_GOLDENS=1 ./scripts/update_dynamic_goldens.sh to seed it.",
            golden_path.display()
        )
    });
    let expected: GoldenVerdict = serde_json::from_str(&expected_json)
        .unwrap_or_else(|e| panic!("parse golden {}: {e}", golden_path.display()));

    if current != expected {
        panic!(
            "golden regression for {}:\n\
             expected: {expected_json}\n\
             actual:   {current_json}\n\
             detail: {:?}\n\
             rerun with NYX_UPDATE_GOLDENS=1 ./scripts/update_dynamic_goldens.sh if intended.",
            spec.fixture, result.detail
        );
    }
}

fn fixture_dir(lang_dir: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dynamic_fixtures")
        .join(lang_dir)
}

fn stage_fixture(src: &Path, tmp: &TempDir, copy: CopyStrategy) -> PathBuf {
    match copy {
        CopyStrategy::PreserveName => {
            let dst = tmp.path().join(src.file_name().expect("fixture has filename"));
            std::fs::copy(src, &dst).expect("copy fixture into tempdir");
            dst
        }
        CopyStrategy::RustEntry => {
            let dst_dir = tmp.path().join("src");
            std::fs::create_dir_all(&dst_dir).expect("create src/ in tempdir");
            let dst = dst_dir.join("entry.rs");
            std::fs::copy(src, &dst).expect("copy fixture into tempdir/src/entry.rs");
            // The Rust harness emitter reads source via the Diag's absolute path,
            // not via the temp-dir layout, so the Diag must point at the original
            // fixture file. The temp-dir copy is only consulted by the harness
            // builder for the workdir-relative `src/entry.rs` view.
            src.to_path_buf()
        }
    }
}

fn make_diag(path: &Path, func: &str, cap: Cap, sink_line: u32) -> Diag {
    let path_str = path.to_string_lossy().into_owned();
    let evidence = Evidence {
        flow_steps: vec![
            FlowStep {
                step: 1,
                kind: FlowStepKind::Source,
                file: path_str.clone(),
                line: 1,
                col: 0,
                snippet: None,
                variable: Some("payload".into()),
                callee: None,
                function: Some(func.to_owned()),
                is_cross_file: false,
            },
            FlowStep {
                step: 2,
                kind: FlowStepKind::Sink,
                file: path_str.clone(),
                line: sink_line,
                col: 4,
                snippet: None,
                variable: None,
                callee: None,
                function: None,
                is_cross_file: false,
            },
        ],
        sink_caps: cap.bits(),
        ..Default::default()
    };
    Diag {
        path: path_str,
        line: sink_line as usize,
        col: 0,
        severity: Severity::High,
        id: "taint-unsanitised-flow".into(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: Some(Confidence::High),
        evidence: Some(evidence),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: vec![],
        stable_hash: 0,
    }
}
