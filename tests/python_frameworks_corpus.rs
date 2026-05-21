//! Phase 12 (Track L.10) — Python framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/python_frameworks/`, asserting
//! that the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` + per-formal
//! `request_params` match the brief's contract.  Benign fixtures
//! must produce the same adapter binding shape as the vuln fixtures
//! — the adapter only models the route, the differential outcome of
//! a verifier run is what distinguishes the two.
//!
//! The `e2e_phase_12` submodule drives `run_spec` on the vuln fixture
//! per framework and asserts `DifferentialVerdict::Confirmed`.  These
//! tests rely on `prepare_python` installing the requirements.txt the
//! per-shape emitter stages (Flask / FastAPI+httpx / Django /
//! Starlette+httpx); on hosts where `python3 -m venv` + `pip install`
//! cannot reach a registry the harness build fails and the test
//! silently SKIPs via the established `BuildFailed` pattern.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::framework::{detect_binding, HttpMethod, ParamSource};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_python(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "python".into(),
        ..Default::default()
    }
}

#[test]
fn flask_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/python_frameworks/flask/vuln.py";
    let bytes = std::fs::read(path).expect("flask vuln fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("flask adapter must bind");
    assert_eq!(binding.adapter, "python-flask");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn flask_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/python_frameworks/flask/benign.py";
    let bytes = std::fs::read(path).expect("flask benign fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("flask adapter must bind benign fixture");
    assert_eq!(binding.adapter, "python-flask");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn fastapi_vuln_fixture_binds_route_with_query_param() {
    let path = "tests/dynamic_fixtures/python_frameworks/fastapi/vuln.py";
    let bytes = std::fs::read(path).expect("fastapi vuln fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("fastapi adapter must bind");
    assert_eq!(binding.adapter, "python-fastapi");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    let cmd_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "cmd")
        .expect("cmd formal");
    assert!(matches!(cmd_binding.source, ParamSource::QueryParam(_)));
}

#[test]
fn fastapi_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/python_frameworks/fastapi/benign.py";
    let bytes = std::fs::read(path).expect("fastapi benign fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("fastapi adapter must bind benign fixture");
    assert_eq!(binding.adapter, "python-fastapi");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn django_vuln_fixture_binds_route_via_urlconf() {
    let path = "tests/dynamic_fixtures/python_frameworks/django/vuln.py";
    let bytes = std::fs::read(path).expect("django vuln fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("django adapter must bind");
    assert_eq!(binding.adapter, "python-django");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "run/");
    let request_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "request")
        .expect("request formal");
    assert!(matches!(request_binding.source, ParamSource::Implicit));
}

#[test]
fn django_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/python_frameworks/django/benign.py";
    let bytes = std::fs::read(path).expect("django benign fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("django adapter must bind benign fixture");
    assert_eq!(binding.adapter, "python-django");
    assert_eq!(binding.route.as_ref().unwrap().path, "run/");
}

#[test]
fn starlette_vuln_fixture_binds_route_via_routes_list() {
    let path = "tests/dynamic_fixtures/python_frameworks/starlette/vuln.py";
    let bytes = std::fs::read(path).expect("starlette vuln fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("starlette adapter must bind");
    assert_eq!(binding.adapter, "python-starlette");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn starlette_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/python_frameworks/starlette/benign.py";
    let bytes = std::fs::read(path).expect("starlette benign fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("starlette adapter must bind benign fixture");
    assert_eq!(binding.adapter, "python-starlette");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
}

#[test]
fn fastapi_adapter_runs_before_starlette_for_fastapi_files() {
    // Regression: a FastAPI file imports starlette transitively via
    // `from starlette.responses import ...`, so the Starlette adapter
    // would otherwise fire for it.  Registration order
    // (python-fastapi before python-starlette alphabetically) +
    // the FastAPI adapter's tighter import check protect against
    // mis-routing.
    let src: &[u8] = b"from fastapi import FastAPI\nfrom starlette.responses import PlainTextResponse\napp = FastAPI()\n@app.get(\"/x\")\ndef handler(q: str = \"\"):\n    return q\n";
    let tree = parse_python(src);
    let summary = summary_for("handler", "phantom.py");
    let binding =
        detect_binding(&summary, tree.root_node(), src, Lang::Python).expect("adapter fires");
    assert_eq!(binding.adapter, "python-fastapi");
}

// ── End-to-end Phase 12 acceptance via run_spec ─────────────────────────────
//
// Drives `run_spec` on the per-framework vuln fixtures with
// `Cap::CODE_EXEC` and asserts `DifferentialVerdict::Confirmed`.  The
// Python harness emitter writes a `requirements.txt` carrying Flask /
// FastAPI+httpx / Django / Starlette+httpx; `prepare_python` runs
// `pip install -r requirements.txt` inside the per-spec venv before
// the harness boots.  Hosts without network access or with pip
// install failures trip the established `RunError::BuildFailed`
// branch and the test silently SKIPs.

#[cfg(feature = "dynamic")]
mod e2e_phase_12 {
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::dynamic::runner::{run_spec, RunError, RunOutcome};
    use nyx_scanner::dynamic::sandbox::SandboxOptions;
    use nyx_scanner::dynamic::spec::{
        default_toolchain_id, EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy,
    };
    use nyx_scanner::evidence::DifferentialVerdict;
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    fn command_available(bin: &str) -> bool {
        Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn build_spec(fixture_subdir: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/python_frameworks")
            .join(fixture_subdir)
            .join("vuln.py");
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("vuln.py");
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase12-e2e-python-framework|");
        digest.update(fixture_subdir.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: "run_cmd".to_owned(),
            entry_kind: EntryKind::HttpRoute,
            lang: Lang::Python,
            toolchain_id: default_toolchain_id(Lang::Python).into(),
            payload_slot: PayloadSlot::QueryParam("cmd".to_owned()),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 1,
            spec_hash: spec_hash.clone(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
        };

        (spec, tmp)
    }

    fn run(fixture_subdir: &str) -> Option<RunOutcome> {
        if !command_available("python3") {
            eprintln!("SKIP {fixture_subdir}: missing python3");
            return None;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_spec(fixture_subdir);
        let opts = SandboxOptions {
            backend: nyx_scanner::dynamic::sandbox::SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        match run_spec(&spec, &opts) {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP {fixture_subdir}: harness build failed after {attempts} attempts: {stderr}",
                );
                None
            }
            Err(e) => panic!("run_spec({fixture_subdir}) errored: {e:?}"),
        }
    }

    fn assert_confirmed(fixture_subdir: &str) {
        let Some(outcome) = run(fixture_subdir) else { return };
        assert!(
            outcome.triggered_by.is_some(),
            "{fixture_subdir} CODE_EXEC vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(
            diff.verdict,
            DifferentialVerdict::Confirmed,
            "differential verdict must be Confirmed: {diff:?}",
        );
    }

    #[test]
    fn flask_vuln_confirms_via_run_spec() {
        assert_confirmed("flask");
    }

    #[test]
    fn fastapi_vuln_confirms_via_run_spec() {
        assert_confirmed("fastapi");
    }

    #[test]
    fn django_vuln_confirms_via_run_spec() {
        assert_confirmed("django");
    }

    #[test]
    fn starlette_vuln_confirms_via_run_spec() {
        assert_confirmed("starlette");
    }
}
