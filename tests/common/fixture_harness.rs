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
    Confidence, EntryKind, Evidence, FlowStep, FlowStepKind, InconclusiveReason,
    UnsupportedReason, VerifyResult, VerifyStatus,
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

/// Phase 29 (Track I): host-environment prerequisite a fixture needs in
/// order to run. The harness consults the list before staging the
/// fixture; any unsatisfied prerequisite triggers a structured skip
/// rather than a panic, so non-applicable matrix rows (process-only
/// macOS, dockerless CI, missing static libc) still see green ticks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Prerequisite {
    /// A binary must resolve on `PATH` and respond to `--version` with
    /// exit code 0 (e.g. `python3`, `node`, `go`, `cargo`).
    CommandAvailable(&'static str),
    /// A specific env var must be set (used to gate feature-flagged
    /// suites — e.g. `NYX_ENABLE_FLAKY_FIXTURES=1`).
    EnvVar(&'static str),
    /// The docker daemon must be reachable.  Equivalent to
    /// `docker info` returning exit 0.
    DockerAvailable,
    /// A static C library archive (e.g. `libc.a`) must be linkable.
    /// Used by the Phase-17/20 hardening probe fixtures.
    StaticLib(&'static str),
    /// A Node.js module must be importable via `require.resolve`.  Used
    /// by the JavaScript / TypeScript framework-bound shape suites
    /// (express / koa / next / jsdom) so a host without the package on
    /// the resolution path skips with a structured reason instead of
    /// failing the test.
    NodeModuleAvailable(&'static str),
    /// A binary must resolve on `PATH` and respond to `--version` with
    /// exit code 0, but the binary name can be overridden via an env
    /// var.  Used by the C / C++ fixture suites where `cc` / `c++` can
    /// be swapped in for `clang` / `gcc` via `NYX_CC_BIN` / `NYX_CXX_BIN`.
    /// The env var's *value* (when set) names the binary to probe;
    /// otherwise `default` is used.
    CommandAvailableEnvOverride {
        env_var: &'static str,
        default: &'static str,
    },
}

/// Phase 29 (Track I): why the harness skipped a fixture.  Carried by
/// every skip so callers can distinguish "host did not have python3" from
/// "host has docker but daemon refused" from "intentional env-var gate".
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SkipReason {
    MissingCommand(&'static str),
    MissingEnvVar(&'static str),
    DockerUnavailable,
    MissingStaticLib(&'static str),
    MissingNodeModule(&'static str),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::MissingCommand(c) => write!(f, "missing command on PATH: {c}"),
            SkipReason::MissingEnvVar(v) => write!(f, "env var not set: {v}"),
            SkipReason::DockerUnavailable => write!(f, "docker daemon unavailable"),
            SkipReason::MissingStaticLib(l) => write!(f, "static lib not linkable: {l}"),
            SkipReason::MissingNodeModule(m) => {
                write!(f, "Node module not resolvable via require.resolve: {m}")
            }
        }
    }
}

/// Returns the first unsatisfied prerequisite, or `Ok(())` when every
/// requirement holds. Exposed for tests that want to gate their own
/// per-shape helpers without going through `FixtureSpec`.
#[allow(dead_code)]
pub fn check_prerequisites(reqs: &[Prerequisite]) -> Result<(), SkipReason> {
    for req in reqs {
        match req {
            Prerequisite::CommandAvailable(cmd) => {
                let ok = std::process::Command::new(cmd)
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !ok {
                    return Err(SkipReason::MissingCommand(cmd));
                }
            }
            Prerequisite::CommandAvailableEnvOverride { env_var, default } => {
                // Resolve binary name from the env var when set; fall
                // back to `default` so an unset override stays
                // transparent to the existing acceptance contract.  The
                // suite under test reads the SAME env var to pick the
                // binary it will execute, so the prereq probe lines up
                // with the actual invocation.
                let env_value = std::env::var(env_var).ok();
                let bin: &str = match env_value.as_deref() {
                    Some(v) if !v.is_empty() => v,
                    _ => default,
                };
                let ok = std::process::Command::new(bin)
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !ok {
                    return Err(SkipReason::MissingCommand(default));
                }
            }
            Prerequisite::EnvVar(var) => {
                if std::env::var(var).is_err() {
                    return Err(SkipReason::MissingEnvVar(var));
                }
            }
            Prerequisite::DockerAvailable => {
                let ok = std::process::Command::new("docker")
                    .arg("info")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !ok {
                    return Err(SkipReason::DockerUnavailable);
                }
            }
            Prerequisite::NodeModuleAvailable(name) => {
                let probe = format!("require.resolve('{name}')");
                let ok = std::process::Command::new("node")
                    .arg("-e")
                    .arg(&probe)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !ok {
                    return Err(SkipReason::MissingNodeModule(name));
                }
            }
            Prerequisite::StaticLib(lib) => {
                // Treat the lib as linkable iff `cc -static -l<lib>` on
                // an empty TU succeeds.  Slow but reliable; only called
                // by the small Phase-17 hardening suite.
                let probe = match tempfile::NamedTempFile::new() {
                    Ok(f) => f,
                    Err(_) => return Err(SkipReason::MissingStaticLib(lib)),
                };
                use std::io::Write;
                let mut handle = match std::fs::OpenOptions::new()
                    .write(true)
                    .open(probe.path())
                {
                    Ok(h) => h,
                    Err(_) => return Err(SkipReason::MissingStaticLib(lib)),
                };
                let _ = writeln!(handle, "int main(void) {{ return 0; }}");
                drop(handle);
                let out = tempfile::Builder::new()
                    .prefix("nyx-prereq-")
                    .tempfile()
                    .map(|f| f.path().to_path_buf())
                    .ok();
                let out = match out {
                    Some(p) => p,
                    None => return Err(SkipReason::MissingStaticLib(lib)),
                };
                let status = std::process::Command::new("cc")
                    .args([
                        "-x", "c", "-static",
                        probe.path().to_str().unwrap_or(""),
                        "-o",
                        out.to_str().unwrap_or(""),
                        &format!("-l{lib}"),
                    ])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                let _ = std::fs::remove_file(&out);
                if !status {
                    return Err(SkipReason::MissingStaticLib(lib));
                }
            }
        }
    }
    Ok(())
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
    /// Phase 29 (Track I): host-environment prerequisites. Empty means
    /// "always runs"; otherwise the harness checks each entry before
    /// staging the fixture and skips with a structured [`SkipReason`]
    /// when any prerequisite is unmet.
    pub requires: Vec<Prerequisite>,
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
    if let Err(reason) = check_prerequisites(&spec.requires) {
        eprintln!(
            "SKIP {}/{}: prerequisite unmet — {reason}",
            spec.lang_dir, spec.fixture
        );
        return;
    }

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

/// Phase 12 — Python-specific per-shape acceptance helper.
///
/// Thin wrapper over [`run_shape_fixture_lang`] pinning the lang dir
/// to `tests/dynamic_fixtures/python/` and [`Lang::Python`].
#[allow(clippy::too_many_arguments)]
pub fn run_shape_fixture(
    shape_dir: &str,
    file: &str,
    func: &str,
    cap: Cap,
    sink_line: u32,
    entry_kind: EntryKind,
    payload_slot: nyx_scanner::dynamic::spec::PayloadSlot,
) -> VerifyResult {
    run_shape_fixture_lang(
        nyx_scanner::symbol::Lang::Python,
        "python",
        shape_dir,
        file,
        func,
        cap,
        sink_line,
        entry_kind,
        payload_slot,
    )
}

/// Phase 13 — lang-aware per-shape acceptance helper.
///
/// Stages `tests/dynamic_fixtures/<lang_dir>/<shape>/<file>` into a
/// tempdir, builds a [`HarnessSpec`] with the caller's `entry_kind` /
/// `payload_slot` / [`Lang`], then executes it through
/// [`nyx_scanner::dynamic::runner::run_spec`] directly.  Returns a
/// [`VerifyResult`]-shaped summary so callers can reuse the same
/// `assert_confirmed` / `assert_not_confirmed` helpers across Python /
/// JS / TS / etc. shape suites.
///
/// Bypasses [`verify_finding`] for the same reason as [`run_shape_fixture`]:
/// the public verifier always lands on
/// [`nyx_scanner::dynamic::spec::PayloadSlot::Param`].
#[allow(clippy::too_many_arguments)]
pub fn run_shape_fixture_lang(
    lang: nyx_scanner::symbol::Lang,
    lang_dir: &str,
    shape_dir: &str,
    file: &str,
    func: &str,
    cap: Cap,
    sink_line: u32,
    entry_kind: EntryKind,
    payload_slot: nyx_scanner::dynamic::spec::PayloadSlot,
) -> VerifyResult {
    use nyx_scanner::dynamic::runner::{run_spec, RunError};
    use nyx_scanner::dynamic::sandbox::SandboxOptions;
    use nyx_scanner::dynamic::spec::{HarnessSpec, SpecDerivationStrategy};

    let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dynamic_fixtures")
        .join(lang_dir)
        .join(shape_dir);
    let fixture_src = fixture_root.join(file);

    let tmp = TempDir::new().expect("create tempdir");
    let dst = tmp.path().join(file);
    std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

    // SAFETY: env mutation is serialised by FIXTURE_LOCK and cleared at end.
    unsafe {
        std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
        std::env::set_var(
            "NYX_TELEMETRY_PATH",
            tmp.path().join("events.jsonl").to_str().unwrap(),
        );
    }

    let entry_file = dst.to_string_lossy().into_owned();
    // Per-fixture stable hash so workdir layout / cache key stays
    // distinct between langs / shapes / vuln-vs-benign fixtures.
    let mut digest = blake3::Hasher::new();
    digest.update(lang_dir.as_bytes());
    digest.update(b"|");
    digest.update(shape_dir.as_bytes());
    digest.update(b"|");
    digest.update(file.as_bytes());
    let spec_hash = format!("{:016x}", {
        let bytes = digest.finalize();
        u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
    });

    let toolchain_id = nyx_scanner::dynamic::spec::default_toolchain_id(lang);

    let spec = HarnessSpec {
        finding_id: spec_hash.clone(),
        entry_file: entry_file.clone(),
        entry_name: func.to_owned(),
        entry_kind,
        lang,
        toolchain_id: toolchain_id.into(),
        payload_slot,
        expected_cap: cap,
        constraint_hints: vec![],
        sink_file: entry_file,
        sink_line,
        spec_hash: spec_hash.clone(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
    };

    // Phase 14: Java shape fixtures bundle annotation / type stubs as
    // sibling `*.java` files alongside `Vuln.java` / `Benign.java`.
    // The harness builder owns `/tmp/nyx-harness/<spec_hash>/` and only
    // copies the entry file + extra_files — it never walks the entry
    // file's parent dir.  Pre-create the workdir and stage every
    // sibling stub there so the build sandbox's `javac *.java` step
    // resolves the annotation / type references without pulling in any
    // Maven deps.  Skip the alternate Vuln/Benign file to keep public
    // class declarations from colliding with the running variant.
    if matches!(lang, nyx_scanner::symbol::Lang::Java) {
        let workdir = std::path::PathBuf::from("/tmp/nyx-harness").join(&spec.spec_hash);
        // Wipe any prior contents so stale `.java` / `.class` files
        // from previous emitter revisions cannot bleed into this run.
        // `prepare_java` globs every `*.java` in the workdir — leaving
        // an obsolete `Entry.java` next to the new `Vuln.java` produces
        // a duplicate-class compile error.
        let _ = std::fs::remove_dir_all(&workdir);
        let _ = std::fs::create_dir_all(&workdir);
        let alt_file = if file == "Vuln.java" {
            "Benign.java"
        } else if file == "Benign.java" {
            "Vuln.java"
        } else {
            ""
        };
        if let Ok(entries) = std::fs::read_dir(&fixture_root) {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = match p.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_owned(),
                    None => continue,
                };
                if name == file || name == alt_file {
                    continue;
                }
                if p.extension().map(|e| e == "java").unwrap_or(false) {
                    let _ = std::fs::copy(&p, workdir.join(&name));
                }
            }
        }
    }

    let opts = SandboxOptions::default();
    let outcome = run_spec(&spec, &opts);

    unsafe {
        std::env::remove_var("NYX_REPRO_BASE");
        std::env::remove_var("NYX_TELEMETRY_PATH");
    }

    // Project the [`RunOutcome`] / [`RunError`] back onto a
    // [`VerifyResult`] shape so callers can assert against
    // [`VerifyStatus`] directly without learning the runner's API.
    match outcome {
        Ok(run) => {
            let (status, inconclusive_reason) = if run.triggered_by.is_some() {
                (VerifyStatus::Confirmed, None)
            } else if run.oracle_collision {
                (
                    VerifyStatus::Inconclusive,
                    Some(nyx_scanner::evidence::InconclusiveReason::OracleCollisionSuspected),
                )
            } else if run.unrelated_crash {
                // Mirror the runner's downgrade in
                // `src/dynamic/runner.rs:425-432`: a process-level crash
                // outside the sink probe routes to
                // `Inconclusive(UnrelatedCrash)`.  Shape suites that
                // exercise SinkCrash oracles pin this branch instead of
                // recreating `run_spec` plumbing inline.
                (
                    VerifyStatus::Inconclusive,
                    Some(nyx_scanner::evidence::InconclusiveReason::UnrelatedCrash),
                )
            } else {
                (VerifyStatus::NotConfirmed, None)
            };
            VerifyResult {
                finding_id: spec.finding_id.clone(),
                status,
                triggered_payload: run
                    .triggered_by
                    .and_then(|i| run.attempts.get(i))
                    .map(|a| a.payload_label.to_owned()),
                reason: None,
                inconclusive_reason,
                detail: None,
                attempts: vec![],
                toolchain_match: None,
                differential: None,
                replay_stable: None,
                wrong: None,
                hardening_outcome: None,
            }
        }
        Err(RunError::NoPayloadsForCap) => VerifyResult {
            finding_id: spec.finding_id.clone(),
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some(UnsupportedReason::NoPayloadsForCap),
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
        Err(e) => VerifyResult {
            finding_id: spec.finding_id.clone(),
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: Some(format!("{e:?}")),
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
    }
}

/// Phase 29 (Track I) — `run_shape_fixture_lang` with structured
/// prerequisite gating.
///
/// Checks `requires` against the host before staging the fixture; when
/// a prerequisite is unmet, eprintln-skips with a [`SkipReason`] (so
/// `cargo nextest` surfaces the line in test output) and returns
/// `None`.  Callers migrate from the bespoke
/// `python3_available()` / `go_available()` / etc. helpers + per-test
/// `eprintln!("SKIP ...") ; return;` blocks to a single
/// `let Some(r) = run_shape_fixture_lang_or_skip(...) else { return; };`
/// at the call site.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn run_shape_fixture_lang_or_skip(
    requires: &[Prerequisite],
    lang: nyx_scanner::symbol::Lang,
    lang_dir: &str,
    shape_dir: &str,
    file: &str,
    func: &str,
    cap: Cap,
    sink_line: u32,
    entry_kind: EntryKind,
    payload_slot: nyx_scanner::dynamic::spec::PayloadSlot,
) -> Option<VerifyResult> {
    if let Err(reason) = check_prerequisites(requires) {
        eprintln!("SKIP {lang_dir}/{shape_dir}/{file}: {reason}");
        return None;
    }
    Some(run_shape_fixture_lang(
        lang,
        lang_dir,
        shape_dir,
        file,
        func,
        cap,
        sink_line,
        entry_kind,
        payload_slot,
    ))
}

/// Phase 29 (Track I) — `run_harness_snapshot_lang` with structured
/// prerequisite gating.  Returns `false` and eprintln-skips when a
/// prerequisite is unmet; otherwise runs the snapshot to completion
/// and returns `true`.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn run_harness_snapshot_lang_or_skip(
    requires: &[Prerequisite],
    lang: nyx_scanner::symbol::Lang,
    lang_dir: &str,
    snapshot_ext: &str,
    shape_dir: &str,
    file: &str,
    func: &str,
    cap: Cap,
    sink_line: u32,
    entry_kind: EntryKind,
    payload_slot: nyx_scanner::dynamic::spec::PayloadSlot,
) -> bool {
    if let Err(reason) = check_prerequisites(requires) {
        eprintln!("SKIP {lang_dir}/{shape_dir}/{file}: {reason}");
        return false;
    }
    run_harness_snapshot_lang(
        lang,
        lang_dir,
        snapshot_ext,
        shape_dir,
        file,
        func,
        cap,
        sink_line,
        entry_kind,
        payload_slot,
    );
    true
}

/// Phase 12 — Python-specific harness snapshot wrapper.
///
/// Pins lang to [`Lang::Python`] and the lang dir to `python` so legacy
/// Python tests can keep their original two-axis signature.
#[allow(clippy::too_many_arguments)]
pub fn run_harness_snapshot(
    shape_dir: &str,
    file: &str,
    func: &str,
    cap: Cap,
    sink_line: u32,
    entry_kind: EntryKind,
    payload_slot: nyx_scanner::dynamic::spec::PayloadSlot,
) {
    run_harness_snapshot_lang(
        nyx_scanner::symbol::Lang::Python,
        "python",
        "py",
        shape_dir,
        file,
        func,
        cap,
        sink_line,
        entry_kind,
        payload_slot,
    )
}

/// Phase 13 — lang-aware golden harness snapshot.
///
/// Stages `tests/dynamic_fixtures/<lang_dir>/<shape>/<file>` into a
/// tempdir, builds a [`HarnessSpec`] for the supplied lang / entry kind
/// / payload slot, emits the per-shape harness via
/// [`nyx_scanner::dynamic::lang::emit`], and either writes the resulting
/// source to `<shape>/<file>.golden_harness.<ext>` (under
/// `NYX_UPDATE_GOLDENS=1`) or diffs against the existing snapshot.
#[allow(clippy::too_many_arguments)]
pub fn run_harness_snapshot_lang(
    lang: nyx_scanner::symbol::Lang,
    lang_dir: &str,
    snapshot_ext: &str,
    shape_dir: &str,
    file: &str,
    func: &str,
    cap: Cap,
    sink_line: u32,
    entry_kind: EntryKind,
    payload_slot: nyx_scanner::dynamic::spec::PayloadSlot,
) {
    use nyx_scanner::dynamic::lang as lang_emit;
    use nyx_scanner::dynamic::spec::{HarnessSpec, SpecDerivationStrategy};

    let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dynamic_fixtures")
        .join(lang_dir)
        .join(shape_dir);
    let fixture_src = fixture_root.join(file);
    let snapshot_path = fixture_root.join(format!("{file}.golden_harness.{snapshot_ext}"));

    // Stage into tempdir so the spec.entry_file path matches what the
    // verifier sees at runtime.
    let tmp = TempDir::new().expect("create tempdir");
    let dst = tmp.path().join(file);
    std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");
    let entry_file = dst.to_string_lossy().into_owned();

    let toolchain_id = nyx_scanner::dynamic::spec::default_toolchain_id(lang);

    let spec = HarnessSpec {
        finding_id: "0000000000000001".into(),
        entry_file: entry_file.clone(),
        entry_name: func.to_owned(),
        entry_kind,
        lang,
        toolchain_id: toolchain_id.into(),
        payload_slot,
        expected_cap: cap,
        constraint_hints: vec![],
        sink_file: entry_file,
        sink_line,
        // Snapshot uses a fixed spec_hash so the emitted source stays
        // stable; the runner regenerates the real hash at verify time.
        spec_hash: "snapshotsnapshot".into(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
    };

    let harness = lang_emit::emit(&spec).expect("emitter must produce a harness");

    // Strip the tempdir prefix so the snapshot is stable across runs.
    let tmp_prefix = tmp.path().to_string_lossy().into_owned();
    let normalised = harness
        .source
        .replace(&tmp_prefix, "<TMPDIR>")
        .replace(file, "<ENTRY_FILE>");

    if std::env::var("NYX_UPDATE_GOLDENS").is_ok_and(|v| v == "1") {
        std::fs::write(&snapshot_path, &normalised).unwrap_or_else(|e| {
            panic!("write harness snapshot {}: {e}", snapshot_path.display())
        });
        return;
    }

    let expected = std::fs::read_to_string(&snapshot_path).unwrap_or_else(|e| {
        panic!(
            "missing harness snapshot {}: {e}\n\
             current harness source:\n{normalised}\n\
             rerun with NYX_UPDATE_GOLDENS=1 to seed it.",
            snapshot_path.display()
        )
    });

    if expected != normalised {
        panic!(
            "harness snapshot drift for {shape_dir}/{file}:\n\
             ---- expected ----\n{expected}\n\
             ---- actual ----\n{normalised}\n\
             rerun with NYX_UPDATE_GOLDENS=1 if intended."
        );
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
