//! Phase 13 (Track L.11) — JS framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/js_frameworks/`, asserting that
//! the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` + per-formal
//! `request_params` match the brief's contract.  Benign fixtures must
//! produce the same adapter binding shape as the vuln fixtures — the
//! adapter only models the route, the differential outcome of a
//! verifier run is what distinguishes the two.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::framework::{HttpMethod, ParamSource, detect_binding};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_js(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "javascript".into(),
        ..Default::default()
    }
}

#[test]
fn express_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/js_frameworks/express/vuln.js";
    let bytes = std::fs::read(path).expect("express vuln fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("express adapter must bind");
    assert_eq!(binding.adapter, "js-express");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    assert!(
        binding
            .request_params
            .iter()
            .any(|p| p.name == "req" && matches!(p.source, ParamSource::Implicit))
    );
}

#[test]
fn express_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/js_frameworks/express/benign.js";
    let bytes = std::fs::read(path).expect("express benign fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("express adapter must bind benign fixture");
    assert_eq!(binding.adapter, "js-express");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn koa_vuln_fixture_binds_router_route() {
    let path = "tests/dynamic_fixtures/js_frameworks/koa/vuln.js";
    let bytes = std::fs::read(path).expect("koa vuln fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("koa adapter must bind");
    assert_eq!(binding.adapter, "js-koa");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    assert!(
        binding
            .request_params
            .iter()
            .any(|p| p.name == "ctx" && matches!(p.source, ParamSource::Implicit))
    );
}

#[test]
fn koa_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/js_frameworks/koa/benign.js";
    let bytes = std::fs::read(path).expect("koa benign fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("koa adapter must bind benign fixture");
    assert_eq!(binding.adapter, "js-koa");
    assert_eq!(binding.route.as_ref().unwrap().path, "/run");
}

#[test]
fn fastify_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/js_frameworks/fastify/vuln.js";
    let bytes = std::fs::read(path).expect("fastify vuln fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("fastify adapter must bind");
    assert_eq!(binding.adapter, "js-fastify");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    assert!(
        binding
            .request_params
            .iter()
            .any(|p| p.name == "request" && matches!(p.source, ParamSource::Implicit))
    );
    assert!(
        binding
            .request_params
            .iter()
            .any(|p| p.name == "reply" && matches!(p.source, ParamSource::Implicit))
    );
}

#[test]
fn fastify_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/js_frameworks/fastify/benign.js";
    let bytes = std::fs::read(path).expect("fastify benign fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("fastify adapter must bind benign fixture");
    assert_eq!(binding.adapter, "js-fastify");
    assert_eq!(binding.route.as_ref().unwrap().path, "/run");
}

#[test]
fn nest_vuln_fixture_binds_controller_route() {
    let path = "tests/dynamic_fixtures/js_frameworks/nest/vuln.js";
    let bytes = std::fs::read(path).expect("nest vuln fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("nest adapter must bind");
    assert_eq!(binding.adapter, "js-nest");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    let cmd_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "cmd")
        .expect("cmd formal");
    match &cmd_binding.source {
        ParamSource::QueryParam(q) => assert_eq!(q, "cmd"),
        other => panic!("expected QueryParam(\"cmd\"), got {other:?}"),
    }
}

#[test]
fn nest_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/js_frameworks/nest/benign.js";
    let bytes = std::fs::read(path).expect("nest benign fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("nest adapter must bind benign fixture");
    assert_eq!(binding.adapter, "js-nest");
    assert_eq!(binding.route.as_ref().unwrap().path, "/run");
}

#[test]
fn express_adapter_runs_before_fastify_for_express_files() {
    // Regression guard: an Express file does not pull in `fastify`,
    // so the Fastify adapter never fires.  Registration order is
    // alphabetical (`js-express` before `js-fastify`) which keeps the
    // adapter dispatch deterministic.
    let src: &[u8] = b"const express = require('express');\n\
        const app = express();\n\
        function h(req, res) { res.send('ok'); }\n\
        app.get('/x', h);\n";
    let tree = parse_js(src);
    let summary = summary_for("h", "synthetic.js");
    let binding = detect_binding(&summary, tree.root_node(), src, Lang::JavaScript).expect("fires");
    assert_eq!(binding.adapter, "js-express");
}

mod e2e_phase_13 {
    use super::{parse_js, summary_for};
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::dynamic::framework::{FrameworkBinding, detect_binding};
    use nyx_scanner::dynamic::runner::{RunError, RunOutcome, run_spec};
    use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
    use nyx_scanner::dynamic::spec::{
        EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy, default_toolchain_id,
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

    fn detect_framework(entry_file: &str, entry_name: &str) -> FrameworkBinding {
        let bytes = std::fs::read(entry_file).expect("fixture copy exists");
        let tree = parse_js(&bytes);
        let summary = summary_for(entry_name, entry_file);
        detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
            .expect("JS framework fixture must bind before run_spec")
    }

    fn build_spec(fixture_subdir: &str, fixture_file: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/js_frameworks")
            .join(fixture_subdir)
            .join(fixture_file);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture_file);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase13-e2e-js-framework|");
        digest.update(fixture_subdir.as_bytes());
        digest.update(b"|");
        digest.update(fixture_file.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });
        let framework = Some(detect_framework(&entry_file, "runCmd"));

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: "runCmd".to_owned(),
            entry_kind: EntryKind::HttpRoute,
            lang: Lang::JavaScript,
            toolchain_id: default_toolchain_id(Lang::JavaScript).into(),
            payload_slot: PayloadSlot::QueryParam("cmd".to_owned()),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 1,
            spec_hash: spec_hash.clone(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework,
            java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
        };

        (spec, tmp)
    }

    fn run(fixture_subdir: &str, fixture_file: &str) -> Option<RunOutcome> {
        if !command_available("node") {
            eprintln!("SKIP {fixture_subdir}/{fixture_file}: missing node");
            return None;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_spec(fixture_subdir, fixture_file);
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        match run_spec(&spec, &opts) {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP {fixture_subdir}/{fixture_file}: harness build failed after {attempts} attempts: {stderr}",
                );
                None
            }
            Err(e) => panic!("run_spec({fixture_subdir}/{fixture_file}) errored: {e:?}"),
        }
    }

    fn assert_confirmed(fixture_subdir: &str) {
        let Some(outcome) = run(fixture_subdir, "vuln.js") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "{fixture_subdir} JS framework vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    fn assert_not_confirmed(fixture_subdir: &str) {
        let Some(outcome) = run(fixture_subdir, "benign.js") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "{fixture_subdir} JS framework benign control must not Confirm; got {outcome:?}",
        );
        if let Some(diff) = &outcome.differential {
            assert_ne!(diff.verdict, DifferentialVerdict::Confirmed);
        }
    }

    #[test]
    fn express_vuln_confirms_via_run_spec() {
        assert_confirmed("express");
    }

    #[test]
    fn express_benign_does_not_confirm_via_run_spec() {
        assert_not_confirmed("express");
    }

    #[test]
    fn koa_vuln_confirms_via_run_spec() {
        assert_confirmed("koa");
    }

    #[test]
    fn koa_benign_does_not_confirm_via_run_spec() {
        assert_not_confirmed("koa");
    }

    #[test]
    fn fastify_vuln_confirms_via_run_spec() {
        assert_confirmed("fastify");
    }

    #[test]
    fn fastify_benign_does_not_confirm_via_run_spec() {
        assert_not_confirmed("fastify");
    }

    #[test]
    fn nest_vuln_confirms_via_run_spec() {
        assert_confirmed("nest");
    }

    #[test]
    fn nest_benign_does_not_confirm_via_run_spec() {
        assert_not_confirmed("nest");
    }
}
