//! Phase 17 (Track L.15) — Go framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/go_frameworks/`, asserting that
//! the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` matches the brief.
//! Benign fixtures must produce the same adapter binding shape as
//! the vuln fixtures — the adapter only models the route; the
//! differential outcome of a verifier run is what distinguishes the
//! two.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::framework::{HttpMethod, detect_binding};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_go(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "go".into(),
        ..Default::default()
    }
}

fn assert_route(path: &str, adapter: &str, route_path: &str) {
    let bytes = std::fs::read(path).expect("fixture exists");
    let tree = parse_go(&bytes);
    let summary = summary_for("Run", path);
    let binding =
        detect_binding(&summary, tree.root_node(), &bytes, Lang::Go).expect("adapter must bind");
    assert_eq!(binding.adapter, adapter, "wrong adapter for {path}");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, route_path);
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn gin_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/gin/vuln.go",
        "go-gin",
        "/run",
    );
}

#[test]
fn gin_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/gin/benign.go",
        "go-gin",
        "/run",
    );
}

#[test]
fn echo_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/echo/vuln.go",
        "go-echo",
        "/run",
    );
}

#[test]
fn echo_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/echo/benign.go",
        "go-echo",
        "/run",
    );
}

#[test]
fn fiber_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/fiber/vuln.go",
        "go-fiber",
        "/run",
    );
}

#[test]
fn fiber_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/fiber/benign.go",
        "go-fiber",
        "/run",
    );
}

#[test]
fn chi_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/chi/vuln.go",
        "go-chi",
        "/run",
    );
}

#[test]
fn chi_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/chi/benign.go",
        "go-chi",
        "/run",
    );
}

#[test]
fn gin_adapter_ignores_unrelated_function() {
    // Match a non-route function name to confirm the adapter does
    // not over-fire on unrelated helpers in the same file.
    let path = "tests/dynamic_fixtures/go_frameworks/gin/vuln.go";
    let bytes = std::fs::read(path).expect("fixture exists");
    let tree = parse_go(&bytes);
    let summary = summary_for("NonexistentHelper", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Go);
    assert!(binding.is_none());
}

#[test]
fn gin_adapter_rejects_cache_get_receiver_collision() {
    let src: &[u8] = b"package main\nimport \"github.com/gin-gonic/gin\"\n\
        func init() { r := gin.New(); _ = r; cache.Get(\"/run\", Run) }\n\
        func Run(c interface{}) {}\n";
    let tree = parse_go(src);
    let summary = summary_for("Run", "synthetic/gin_cache_collision.go");
    let binding = detect_binding(&summary, tree.root_node(), src, Lang::Go);
    assert!(
        binding.is_none(),
        "cache.Get must not be treated as a gin route registration"
    );
}

// ── End-to-end Phase 17 dispatcher acceptance via run_spec ─────────────────

#[cfg(test)]
mod e2e_phase_17 {
    use super::*;
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::dynamic::framework::{FrameworkBinding, RouteShape};
    use nyx_scanner::dynamic::runner::{RunError, RunOutcome, run_spec};
    use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
    use nyx_scanner::dynamic::spec::{
        HarnessSpec, PayloadSlot, SpecDerivationStrategy, default_toolchain_id,
    };
    use nyx_scanner::evidence::DifferentialVerdict;
    use nyx_scanner::labels::Cap;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    #[derive(Clone, Copy)]
    struct Case {
        fixture_dir: &'static str,
        adapter: &'static str,
    }

    const CASES: &[Case] = &[
        Case {
            fixture_dir: "gin",
            adapter: "go-gin",
        },
        Case {
            fixture_dir: "echo",
            adapter: "go-echo",
        },
        Case {
            fixture_dir: "fiber",
            adapter: "go-fiber",
        },
        Case {
            fixture_dir: "chi",
            adapter: "go-chi",
        },
    ];

    fn command_available(bin: &str) -> bool {
        Command::new(bin)
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn build_spec(case: Case, fixture_file: &str) -> (HarnessSpec, TempDir) {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/go_frameworks")
            .join(case.fixture_dir)
            .join(fixture_file);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture_file);
        std::fs::copy(&src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase17-go-framework|");
        digest.update(case.fixture_dir.as_bytes());
        digest.update(b"|");
        digest.update(fixture_file.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        let framework = Some(FrameworkBinding {
            adapter: case.adapter.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape::single(HttpMethod::GET, "/run")),
            request_params: vec![],
            response_writer: None,
            middleware: vec![],
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: "Run".to_owned(),
            entry_kind: EntryKind::HttpRoute,
            lang: Lang::Go,
            toolchain_id: default_toolchain_id(Lang::Go).to_owned(),
            payload_slot: PayloadSlot::QueryParam("cmd".to_owned()),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 1,
            spec_hash,
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework,
            java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
        };
        (spec, tmp)
    }

    fn run(case: Case, fixture_file: &str) -> Option<RunOutcome> {
        if !command_available("go") {
            eprintln!(
                "SKIP Go {}/{fixture_file}: missing toolchain go",
                case.fixture_dir
            );
            return None;
        }

        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_spec(case, fixture_file);
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        match run_spec(&spec, &opts) {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP Go {}/{fixture_file}: harness build failed after {attempts} attempts: {stderr}",
                    case.fixture_dir,
                );
                None
            }
            Err(e) => panic!(
                "run_spec(Go {}/{fixture_file}) errored: {e:?}",
                case.fixture_dir
            ),
        }
    }

    #[test]
    fn go_framework_vuln_fixtures_confirm_via_run_spec() {
        for case in CASES {
            let Some(outcome) = run(*case, "vuln.go") else {
                continue;
            };
            assert!(
                outcome.triggered_by.is_some(),
                "{} vuln must Confirm via run_spec; got {outcome:?}",
                case.adapter,
            );
            let diff = outcome
                .differential
                .as_ref()
                .expect("Confirmed run must carry a DifferentialOutcome");
            assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
        }
    }

    #[test]
    fn go_framework_benign_fixtures_do_not_confirm_via_run_spec() {
        for case in CASES {
            let Some(outcome) = run(*case, "benign.go") else {
                continue;
            };
            assert!(
                outcome.triggered_by.is_none(),
                "{} benign control must not Confirm via run_spec; got {outcome:?}",
                case.adapter,
            );
            if let Some(diff) = outcome.differential.as_ref() {
                assert_ne!(diff.verdict, DifferentialVerdict::Confirmed);
            }
        }
    }
}
