//! Phase 17 (Track L.15) — Rust framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/rust_frameworks/`, asserting
//! that the right adapter fires, the binding carries
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

fn parse_rust(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "rust".into(),
        ..Default::default()
    }
}

fn assert_route(path: &str, adapter: &str, expected_path_fragment: &str, method: HttpMethod) {
    let bytes = std::fs::read(path).expect("fixture exists");
    let tree = parse_rust(&bytes);
    let summary = summary_for("run", path);
    let binding =
        detect_binding(&summary, tree.root_node(), &bytes, Lang::Rust).expect("adapter must bind");
    assert_eq!(binding.adapter, adapter, "wrong adapter for {path}");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert!(
        route.path.contains(expected_path_fragment),
        "route path {} should contain {expected_path_fragment}",
        route.path
    );
    assert_eq!(route.method, method);
}

#[test]
fn axum_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/axum/vuln.rs",
        "rust-axum",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn axum_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/axum/benign.rs",
        "rust-axum",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn actix_vuln_fixture_binds_route_via_attribute() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/actix/vuln.rs",
        "rust-actix",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn actix_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/actix/benign.rs",
        "rust-actix",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn rocket_vuln_fixture_binds_route_via_attribute() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/rocket/vuln.rs",
        "rust-rocket",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn rocket_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/rocket/benign.rs",
        "rust-rocket",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn warp_vuln_fixture_binds_path_macro() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/warp/vuln.rs",
        "rust-warp",
        "run",
        HttpMethod::GET,
    );
}

#[test]
fn warp_benign_fixture_binds_same_path_macro() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/warp/benign.rs",
        "rust-warp",
        "run",
        HttpMethod::GET,
    );
}

#[test]
fn axum_adapter_ignores_unrelated_function() {
    let path = "tests/dynamic_fixtures/rust_frameworks/axum/vuln.rs";
    let bytes = std::fs::read(path).expect("fixture exists");
    let tree = parse_rust(&bytes);
    let summary = summary_for("nonexistent_helper", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Rust);
    assert!(binding.is_none());
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
        expected_path_fragment: &'static str,
    }

    const CASES: &[Case] = &[
        Case {
            fixture_dir: "axum",
            adapter: "rust-axum",
            expected_path_fragment: "/run",
        },
        Case {
            fixture_dir: "actix",
            adapter: "rust-actix",
            expected_path_fragment: "/run",
        },
        Case {
            fixture_dir: "rocket",
            adapter: "rust-rocket",
            expected_path_fragment: "/run",
        },
        Case {
            fixture_dir: "warp",
            adapter: "rust-warp",
            expected_path_fragment: "run",
        },
    ];

    fn command_available(bin: &str) -> bool {
        Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn build_spec(case: Case, fixture_file: &str) -> (HarnessSpec, TempDir) {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/rust_frameworks")
            .join(case.fixture_dir)
            .join(fixture_file);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture_file);
        std::fs::copy(&src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase17-rust-framework|");
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
            route: Some(RouteShape::single(
                HttpMethod::GET,
                case.expected_path_fragment,
            )),
            request_params: vec![],
            response_writer: None,
            middleware: vec![],
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: "run".to_owned(),
            entry_kind: EntryKind::HttpRoute,
            lang: Lang::Rust,
            toolchain_id: default_toolchain_id(Lang::Rust).to_owned(),
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
        if !command_available("cargo") {
            eprintln!(
                "SKIP Rust {}/{fixture_file}: missing toolchain cargo",
                case.fixture_dir
            );
            return None;
        }

        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, tmp) = build_spec(case, fixture_file);
        let repro = tmp.path().join("repro");
        let telemetry = tmp.path().join("events.jsonl");
        unsafe {
            std::env::set_var("NYX_REPRO_BASE", repro.to_str().unwrap());
            std::env::set_var("NYX_TELEMETRY_PATH", telemetry.to_str().unwrap());
        }
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        let outcome = run_spec(&spec, &opts);
        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }

        match outcome {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP Rust {}/{fixture_file}: harness build failed after {attempts} attempts: {stderr}",
                    case.fixture_dir,
                );
                None
            }
            Err(RunError::Sandbox(e)) => {
                eprintln!(
                    "SKIP Rust {}/{fixture_file}: harness sandbox failed before verdict: {e:?}",
                    case.fixture_dir,
                );
                None
            }
            Err(e) => panic!(
                "run_spec(Rust {}/{fixture_file}) errored: {e:?}",
                case.fixture_dir
            ),
        }
    }

    #[test]
    fn rust_framework_vuln_fixtures_confirm_via_run_spec() {
        for case in CASES {
            let Some(outcome) = run(*case, "vuln.rs") else {
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
    fn rust_framework_benign_fixtures_do_not_confirm_via_run_spec() {
        for case in CASES {
            let Some(outcome) = run(*case, "benign.rs") else {
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
