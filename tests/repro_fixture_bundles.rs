//! Tree-committed dynamic repro bundles for the bare-CI replay matrix.
//!
//! These tests gate the artefacts under `tests/repro_fixtures/` so a future
//! schema bump or harness rewrite breaks the build before it surfaces in
//! `repro-bare.yml`.  Each fixture is a self-contained bundle written by
//! [`nyx_scanner::dynamic::repro::write`] for a real, hand-verified finding.
//! The committed copy is the artefact the bare-image workflow replays via
//! `reproduce.sh --docker`; the structural-invariants tests below ensure the
//! committed copy stays in sync with the writer's current output shape.
//!
//! Regenerating a fixture: run the matching `regen_*` test with `--ignored`,
//! e.g.
//!
//! ```sh
//! cargo nextest run --features dynamic --test repro_fixture_bundles \
//!     -E 'test(regen_python_3_11_flask_eval_bundle)' --run-ignored=only
//! ```
//!
//! Commit the resulting tree changes.  The structural-invariants test runs in
//! the default cargo nextest pass and asserts the bundle stays well-formed.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::repro::{self, replay_bundle, ReplayResult};
use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions, SandboxOutcome};
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use nyx_scanner::dynamic::spec::SpecDerivationStrategy;
use nyx_scanner::evidence::{AttemptSummary, VerifyResult, VerifyStatus};
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Spec hash used as the bundle directory name.  The bundle lives at
/// `tests/repro_fixtures/python-3.11/<SPEC_HASH>/` and
/// [`nyx_scanner::dynamic::repro::write`] joins this onto `NYX_REPRO_BASE`.
const FLASK_EVAL_SPEC_HASH: &str = "repro";

const FLASK_EVAL_TOOLCHAIN_ID: &str = "python-3.11";

const FLASK_EVAL_HARNESS_SOURCE: &str = "\
import os
import sys


def main() -> int:
    payload = os.environ.get('NYX_PAYLOAD', '')
    if not payload:
        sys.stderr.write('error: NYX_PAYLOAD missing\\n')
        return 2
    try:
        result = eval(payload)  # noqa: S307 sink under sandbox
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f'__NYX_SINK_ERROR__ {type(exc).__name__}: {exc}\\n')
        return 1
    sys.stdout.write('__NYX_SINK_HIT__\\n')
    sys.stdout.write(f'eval-result={result}\\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
";

const FLASK_EVAL_ENTRY_SOURCE: &str = "\
import flask

app = flask.Flask(__name__)


@app.route('/run', methods=['POST'])
def run():
    cmd = flask.request.json.get('cmd')
    return {'out': eval(cmd)}
";

const FLASK_EVAL_PAYLOAD_LABEL: &str = "eval-rce-arith";

/// Payload that is a pure-expression eval target.  `1 + 1` proves the eval
/// reached arbitrary code without any I/O side-effects beyond the harness's
/// own stdout writes.
const FLASK_EVAL_PAYLOAD: &[u8] = b"1 + 1";

fn flask_eval_spec() -> HarnessSpec {
    HarnessSpec {
        finding_id: "flask_eval_python_311".into(),
        entry_file: "app.py".into(),
        entry_name: "run".into(),
        entry_kind: EntryKind::Function,
        lang: Lang::Python,
        toolchain_id: FLASK_EVAL_TOOLCHAIN_ID.into(),
        payload_slot: PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        expected_cap: Cap::CODE_EXEC,
        constraint_hints: vec![],
        sink_file: "app.py".into(),
        sink_line: 27,
        spec_hash: FLASK_EVAL_SPEC_HASH.into(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
    }
}

fn flask_eval_outcome() -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(0),
        stdout: b"__NYX_SINK_HIT__\neval-result=2\n".to_vec(),
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: true,
        duration: Duration::from_millis(120),
        hardening_outcome: None,
    }
}

fn flask_eval_verdict() -> VerifyResult {
    VerifyResult {
        finding_id: "flask_eval_python_311".into(),
        status: VerifyStatus::Confirmed,
        triggered_payload: Some(FLASK_EVAL_PAYLOAD_LABEL.into()),
        reason: None,
        inconclusive_reason: None,
        detail: Some(
            "flask_eval chain composer fixture: eval(NYX_PAYLOAD) under python-3.11"
                .into(),
        ),
        attempts: vec![AttemptSummary {
            payload_label: FLASK_EVAL_PAYLOAD_LABEL.into(),
            exit_code: Some(0),
            timed_out: false,
            triggered: true,
            sink_hit: true,
        }],
        toolchain_match: Some("exact".into()),
        differential: None,
        replay_stable: Some(true),
        wrong: None,
        hardening_outcome: None,
    }
}

fn flask_eval_sandbox_options() -> SandboxOptions {
    let mut opts = SandboxOptions::default();
    opts.backend = SandboxBackend::Docker;
    opts.env_passthrough = vec!["NYX_PAYLOAD".into()];
    opts.timeout = Duration::from_secs(30);
    opts.memory_mib = 256;
    opts
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn flask_eval_base_dir() -> PathBuf {
    workspace_root()
        .join("tests")
        .join("repro_fixtures")
        .join(FLASK_EVAL_TOOLCHAIN_ID)
}

fn flask_eval_bundle_root() -> PathBuf {
    flask_eval_base_dir().join(FLASK_EVAL_SPEC_HASH)
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Regenerate the committed flask_eval bundle.  Run with `--ignored` to
/// refresh the tree-checked-in artefacts when the schema (manifest layout,
/// reproduce.sh template, toolchain.lock format) changes.
#[test]
#[ignore = "regenerates tree-committed fixture; run with --ignored after schema bumps"]
fn regen_python_3_11_flask_eval_bundle() {
    let base = flask_eval_base_dir();
    std::fs::create_dir_all(&base).unwrap();
    let bundle_root = base.join(FLASK_EVAL_SPEC_HASH);
    if bundle_root.exists() {
        std::fs::remove_dir_all(&bundle_root).unwrap();
    }

    unsafe {
        std::env::set_var("NYX_REPRO_BASE", base.as_os_str());
    }
    let artifact = repro::write(
        &flask_eval_spec(),
        &flask_eval_sandbox_options(),
        &flask_eval_outcome(),
        &flask_eval_verdict(),
        FLASK_EVAL_HARNESS_SOURCE,
        FLASK_EVAL_ENTRY_SOURCE,
        FLASK_EVAL_PAYLOAD,
        FLASK_EVAL_PAYLOAD_LABEL,
        None,
    )
    .expect("repro::write");
    unsafe {
        std::env::remove_var("NYX_REPRO_BASE");
    }

    assert_eq!(
        artifact.root,
        bundle_root,
        "bundle wrote to unexpected path",
    );
}

/// Structural invariants for the tree-committed flask_eval bundle.  Asserts
/// every file the bare-CI replay path depends on is present and well-formed.
#[test]
fn python_3_11_flask_eval_bundle_structural_invariants() {
    let root = flask_eval_bundle_root();
    assert!(
        root.exists(),
        "committed bundle missing at {} (regenerate via `cargo nextest run --features dynamic \
         --test repro_fixture_bundles -E 'test(regen_python_3_11_flask_eval_bundle)' \
         --run-ignored=only`)",
        root.display(),
    );

    for rel in [
        "manifest.json",
        "entry/extracted_source.py",
        "harness/harness.py",
        "harness/Dockerfile.harness",
        "payload/payload.bin",
        "payload/payload.meta.json",
        "sandbox/options.json",
        "sandbox/env.allowlist.json",
        "expected/outcome.json",
        "expected/verdict.json",
        "toolchain.lock",
        "reproduce.sh",
        "README.md",
    ] {
        let path = root.join(rel);
        assert!(path.exists(), "bundle missing {}", path.display());
    }

    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["toolchain_id"], FLASK_EVAL_TOOLCHAIN_ID);
    assert_eq!(manifest["lang"], "python");
    assert_eq!(manifest["entry_name"], "run");

    let harness = std::fs::read_to_string(root.join("harness/harness.py")).unwrap();
    assert!(
        harness.contains("eval(payload)"),
        "harness missing eval() sink",
    );
    assert!(
        harness.contains("__NYX_SINK_HIT__"),
        "harness missing sentinel print",
    );

    let dockerfile = std::fs::read_to_string(root.join("harness/Dockerfile.harness")).unwrap();
    assert!(
        dockerfile.contains("FROM python:3.11"),
        "dockerfile missing pinned FROM line",
    );

    let payload = std::fs::read(root.join("payload/payload.bin")).unwrap();
    assert_eq!(payload, FLASK_EVAL_PAYLOAD);

    let outcome = read_json(&root.join("expected/outcome.json"));
    assert_eq!(outcome["sink_hit"], true);
    assert_eq!(outcome["exit_code"], 0);

    let verdict = read_json(&root.join("expected/verdict.json"));
    assert_eq!(verdict["status"], "Confirmed");
    assert_eq!(verdict["finding_id"], "flask_eval_python_311");

    let lock = read_json(&root.join("toolchain.lock"));
    assert_eq!(lock["toolchain_id"], FLASK_EVAL_TOOLCHAIN_ID);
    assert_eq!(lock["spec_hash"], FLASK_EVAL_SPEC_HASH);
    assert_eq!(lock["lock_version"], 1);
    let files = lock["files"].as_object().expect("files map");
    for rel in [
        "harness/Dockerfile.harness",
        "harness/harness.py",
        "entry/extracted_source.py",
        "payload/payload.bin",
    ] {
        assert!(
            files.contains_key(rel),
            "toolchain.lock missing hash for {rel}",
        );
    }

    let reproduce = std::fs::read_to_string(root.join("reproduce.sh")).unwrap();
    assert!(
        reproduce.contains("EXPECTED_TOOLCHAIN=\"python-3.11\""),
        "reproduce.sh missing expected toolchain line",
    );
    assert!(
        reproduce.contains("--docker"),
        "reproduce.sh missing docker branch",
    );
}

/// Replay the committed bundle via docker.  Skips when docker is not reachable
/// on the host; the bare-CI workflow guarantees coverage of the docker path.
#[test]
fn python_3_11_flask_eval_bundle_replays_via_docker_when_available() {
    let root = flask_eval_bundle_root();
    if !root.exists() {
        // Structural-invariants test surfaces this with a clearer message;
        // skip here so a missing bundle does not double-fail.
        eprintln!("skip: bundle missing at {}", root.display());
        return;
    }

    let docker_reachable = std::process::Command::new("docker")
        .args(["info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !docker_reachable {
        eprintln!("skip: docker daemon not reachable");
        return;
    }

    match replay_bundle(&root, &["--docker"]) {
        ReplayResult::Pass => {}
        ReplayResult::DockerUnavailable => {
            eprintln!("skip: docker became unavailable mid-test");
        }
        other => panic!("expected ReplayResult::Pass; got {other:?}"),
    }
}
