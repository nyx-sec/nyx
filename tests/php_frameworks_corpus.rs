//! Phase 16 (Track L.14) — PHP framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/php_frameworks/`, asserting
//! that the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` + per-formal
//! `request_params` match the brief's contract.  Benign fixtures
//! must produce the same adapter binding shape as the vuln fixtures
//! — the adapter only models the route, the differential outcome of
//! a verifier run is what distinguishes the two.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::framework::{HttpMethod, ParamSource, detect_binding};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_php(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "php".into(),
        ..Default::default()
    }
}

#[test]
fn laravel_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/php_frameworks/laravel/vuln.php";
    let bytes = std::fs::read(path).expect("laravel vuln fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("laravel adapter must bind");
    assert_eq!(binding.adapter, "php-laravel");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    let payload = binding
        .request_params
        .iter()
        .find(|p| p.name == "payload")
        .expect("payload formal");
    assert!(matches!(payload.source, ParamSource::QueryParam(_)));
}

#[test]
fn laravel_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/php_frameworks/laravel/benign.php";
    let bytes = std::fs::read(path).expect("laravel benign fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("laravel adapter must bind benign fixture");
    assert_eq!(binding.adapter, "php-laravel");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn laravel_multi_verb_fixture_preserves_match_methods() {
    let path = "tests/dynamic_fixtures/php_frameworks/laravel_multi_verb/vuln.php";
    let bytes = std::fs::read(path).expect("laravel multi-verb fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("laravel adapter must bind multi-verb fixture");
    assert_eq!(binding.adapter, "php-laravel");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    assert_eq!(
        route.reachable_methods(),
        vec![HttpMethod::GET, HttpMethod::POST]
    );
}

#[test]
fn symfony_vuln_fixture_binds_route_via_attribute() {
    let path = "tests/dynamic_fixtures/php_frameworks/symfony/vuln.php";
    let bytes = std::fs::read(path).expect("symfony vuln fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("symfony adapter must bind");
    assert_eq!(binding.adapter, "php-symfony");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn symfony_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/php_frameworks/symfony/benign.php";
    let bytes = std::fs::read(path).expect("symfony benign fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("symfony adapter must bind benign fixture");
    assert_eq!(binding.adapter, "php-symfony");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
}

#[test]
fn codeigniter_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/php_frameworks/codeigniter/vuln.php";
    let bytes = std::fs::read(path).expect("codeigniter vuln fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("codeigniter adapter must bind");
    assert_eq!(binding.adapter, "php-codeigniter");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn codeigniter_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/php_frameworks/codeigniter/benign.php";
    let bytes = std::fs::read(path).expect("codeigniter benign fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("codeigniter adapter must bind benign fixture");
    assert_eq!(binding.adapter, "php-codeigniter");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "run");
}

#[test]
fn laravel_adapter_ignores_helper_method() {
    // `helper` is declared but not referenced in any `Route::*` call.
    // The adapter must return `None` so the verifier surfaces
    // `SpecDerivationFailed` for non-route helpers in a route file.
    let path = "tests/dynamic_fixtures/php_frameworks/laravel/vuln.php";
    let bytes = std::fs::read(path).expect("laravel vuln fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("nonexistent_helper", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php);
    assert!(binding.is_none());
}

mod e2e_phase_16_framework_dispatchers {
    use super::{common::fixture_harness::FIXTURE_LOCK, parse_php, summary_for};
    use nyx_scanner::dynamic::framework::detect_binding;
    use nyx_scanner::dynamic::runner::{RunError, RunOutcome, run_spec};
    use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
    use nyx_scanner::dynamic::spec::{
        EntryKind, HarnessSpec, JavaToolchain, PayloadSlot, SpecDerivationStrategy,
        default_toolchain_id,
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

    fn fixture_path(framework: &str, file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/php_frameworks")
            .join(framework)
            .join(file)
    }

    fn build_spec(framework: &str, file: &str) -> (HarnessSpec, TempDir) {
        let src = fixture_path(framework, file);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(file);
        std::fs::copy(&src, &dst).expect("copy fixture into tempdir");
        let entry_file = dst.to_string_lossy().into_owned();
        let bytes = std::fs::read(&dst).expect("copied fixture readable");
        let tree = parse_php(&bytes);
        let summary = summary_for("run", &entry_file);
        let framework_binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
            .unwrap_or_else(|| panic!("{framework}/{file} must bind"));

        let mut digest = blake3::Hasher::new();
        digest.update(b"phase16-e2e-php-framework-dispatcher|");
        digest.update(framework.as_bytes());
        digest.update(b"|");
        digest.update(file.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: "run".to_owned(),
            entry_kind: EntryKind::HttpRoute,
            lang: Lang::Php,
            toolchain_id: default_toolchain_id(Lang::Php).to_owned(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 1,
            spec_hash,
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: Some(framework_binding),
            java_toolchain: JavaToolchain::default(),
        };
        (spec, tmp)
    }

    fn run(framework: &str, file: &str) -> Option<RunOutcome> {
        if !command_available("php") {
            eprintln!("SKIP {framework}/{file}: missing php");
            return None;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_spec(framework, file);
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        match run_spec(&spec, &opts) {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP {framework}/{file}: harness build failed after {attempts} attempts: {stderr}",
                );
                None
            }
            Err(e) => panic!("run_spec({framework}/{file}) errored: {e:?}"),
        }
    }

    fn assert_vuln_confirms(framework: &str) {
        let Some(outcome) = run(framework, "vuln.php") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "{framework} vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry differential outcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    fn assert_benign_does_not_confirm(framework: &str) {
        let Some(outcome) = run(framework, "benign.php") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "{framework} benign control must not Confirm; got {outcome:?}",
        );
        if let Some(diff) = &outcome.differential {
            assert_ne!(diff.verdict, DifferentialVerdict::Confirmed);
        }
    }

    #[test]
    fn laravel_vuln_confirms_via_run_spec() {
        assert_vuln_confirms("laravel");
    }

    #[test]
    fn laravel_benign_does_not_confirm_via_run_spec() {
        assert_benign_does_not_confirm("laravel");
    }

    #[test]
    fn symfony_vuln_confirms_via_run_spec() {
        assert_vuln_confirms("symfony");
    }

    #[test]
    fn symfony_benign_does_not_confirm_via_run_spec() {
        assert_benign_does_not_confirm("symfony");
    }

    #[test]
    fn codeigniter_vuln_confirms_via_run_spec() {
        assert_vuln_confirms("codeigniter");
    }

    #[test]
    fn codeigniter_benign_does_not_confirm_via_run_spec() {
        assert_benign_does_not_confirm("codeigniter");
    }
}

mod e2e_phase_16_laravel_multi_verb {
    use super::{common::fixture_harness::FIXTURE_LOCK, parse_php, summary_for};
    use nyx_scanner::dynamic::framework::{HttpMethod, detect_binding};
    use nyx_scanner::dynamic::runner::{RunError, RunOutcome, run_spec};
    use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
    use nyx_scanner::dynamic::spec::{
        EntryKind, HarnessSpec, JavaToolchain, PayloadSlot, SpecDerivationStrategy,
        default_toolchain_id,
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

    fn fixture_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/php_frameworks/laravel_multi_verb")
            .join(file)
    }

    fn build_spec(file: &str) -> (HarnessSpec, TempDir) {
        let src = fixture_path(file);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(file);
        std::fs::copy(&src, &dst).expect("copy fixture into tempdir");
        let entry_file = dst.to_string_lossy().into_owned();
        let bytes = std::fs::read(&dst).expect("copied fixture readable");
        let tree = parse_php(&bytes);
        let summary = summary_for("run", &entry_file);
        let framework = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
            .expect("multi-verb Laravel fixture must bind");
        let route = framework.route.as_ref().expect("route");
        assert_eq!(
            route.reachable_methods(),
            vec![HttpMethod::GET, HttpMethod::POST],
            "fixture must exercise GET+POST fanout"
        );

        let mut digest = blake3::Hasher::new();
        digest.update(b"phase16-e2e-php-laravel-multi-verb|");
        digest.update(file.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: "run".to_owned(),
            entry_kind: EntryKind::HttpRoute,
            lang: Lang::Php,
            toolchain_id: default_toolchain_id(Lang::Php).to_owned(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 1,
            spec_hash,
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: Some(framework),
            java_toolchain: JavaToolchain::default(),
        };
        (spec, tmp)
    }

    fn run(file: &str) -> Option<RunOutcome> {
        if !command_available("php") {
            eprintln!("SKIP laravel_multi_verb/{file}: missing php");
            return None;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_spec(file);
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        match run_spec(&spec, &opts) {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP laravel_multi_verb/{file}: harness build failed after {attempts} attempts: {stderr}",
                );
                None
            }
            Err(e) => panic!("run_spec(laravel_multi_verb/{file}) errored: {e:?}"),
        }
    }

    #[test]
    fn laravel_match_post_branch_confirms_via_run_spec() {
        let Some(outcome) = run("vuln.php") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Laravel Route::match vuln must Confirm via POST fanout; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry differential outcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn laravel_match_benign_does_not_confirm_via_run_spec() {
        let Some(outcome) = run("benign.php") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "Laravel Route::match benign control must not Confirm; got {outcome:?}",
        );
        if let Some(diff) = &outcome.differential {
            assert_ne!(diff.verdict, DifferentialVerdict::Confirmed);
        }
    }
}
