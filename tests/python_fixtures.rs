//! Python fixture integration tests (§15 Pillar B acceptance gate).
//!
//! Each fixture is run through the dynamic verification pipeline; its
//! verdict is then compared against the per-fixture golden under
//! `tests/dynamic_fixtures/python/{name}.golden.json`. Refresh the goldens
//! via `NYX_UPDATE_GOLDENS=1 ./scripts/update_dynamic_goldens.sh`.
//!
//! Tests that need python3 on PATH skip with an `eprintln!` when it is
//! missing; `Confidence::Low` rows do not need python3 because the verifier
//! short-circuits before harness execution.

mod common;

#[cfg(feature = "dynamic")]
mod python_fixture_tests {
    use crate::common::fixture_harness::{
        run_fixture_and_compare_to_golden, run_harness_snapshot, run_shape_fixture,
        CopyStrategy, FixtureSpec,
    };
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
    use nyx_scanner::evidence::{
        Confidence, EntryKind, Evidence, FlowStep, FlowStepKind, UnsupportedReason,
        VerifyStatus,
    };
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// `python3` available on PATH? Tests that need an interpreter return
    /// early with an `eprintln!` when this is false.
    fn python3_available() -> bool {
        std::process::Command::new("python3")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn spec(fixture: &'static str, func: &'static str, cap: Cap, sink_line: u32) -> FixtureSpec<'static> {
        FixtureSpec {
            lang_dir: "python",
            fixture,
            func,
            cap,
            sink_line,
            confidence: Confidence::High,
            copy: CopyStrategy::PreserveName,
        }
    }

    fn low_spec(
        fixture: &'static str,
        func: &'static str,
        cap: Cap,
        sink_line: u32,
    ) -> FixtureSpec<'static> {
        FixtureSpec {
            lang_dir: "python",
            fixture,
            func,
            cap,
            sink_line,
            confidence: Confidence::Low,
            copy: CopyStrategy::PreserveName,
        }
    }

    // ── SQLi ─────────────────────────────────────────────────────────────────

    #[test]
    fn sqli_positive_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("sqli_positive.py", "login", Cap::SQL_QUERY, 17));
    }

    #[test]
    fn sqli_negative_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("sqli_negative.py", "login", Cap::SQL_QUERY, 12));
    }

    #[test]
    fn sqli_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec(
            "sqli_unsupported.py",
            "find_user",
            Cap::SQL_QUERY,
            10,
        ));
    }

    #[test]
    fn sqli_adversarial_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("sqli_adversarial.py", "get_value", Cap::SQL_QUERY, 999));
    }

    // ── Command injection ────────────────────────────────────────────────────

    #[test]
    fn cmdi_positive_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("cmdi_positive.py", "run_ping", Cap::CODE_EXEC, 13));
    }

    #[test]
    fn cmdi_negative_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("cmdi_negative.py", "run_ping", Cap::CODE_EXEC, 17));
    }

    #[test]
    fn cmdi_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec(
            "cmdi_unsupported.py",
            "process_request",
            Cap::CODE_EXEC,
            9,
        ));
    }

    #[test]
    fn cmdi_adversarial_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec(
            "cmdi_adversarial.py",
            "process_input",
            Cap::CODE_EXEC,
            999,
        ));
    }

    // ── File I/O ─────────────────────────────────────────────────────────────

    #[test]
    fn fileio_positive_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("fileio_positive.py", "read_file", Cap::FILE_IO, 11));
    }

    #[test]
    fn fileio_negative_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("fileio_negative.py", "read_file", Cap::FILE_IO, 18));
    }

    #[test]
    fn fileio_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec(
            "fileio_unsupported.py",
            "read_config",
            Cap::FILE_IO,
            7,
        ));
    }

    #[test]
    fn fileio_adversarial_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("fileio_adversarial.py", "read_file", Cap::FILE_IO, 999));
    }

    // ── SSRF ─────────────────────────────────────────────────────────────────

    #[test]
    fn ssrf_positive_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("ssrf_positive.py", "fetch_url", Cap::SSRF, 11));
    }

    #[test]
    fn ssrf_negative_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("ssrf_negative.py", "fetch_url", Cap::SSRF, 26));
    }

    #[test]
    fn ssrf_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec("ssrf_unsupported.py", "fetch", Cap::SSRF, 9));
    }

    #[test]
    fn ssrf_adversarial_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec("ssrf_adversarial.py", "fetch_url", Cap::SSRF, 999));
    }

    // ── XSS ──────────────────────────────────────────────────────────────────

    #[test]
    fn xss_positive_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec(
            "xss_positive.py",
            "render_comment",
            Cap::HTML_ESCAPE,
            9,
        ));
    }

    #[test]
    fn xss_negative_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec(
            "xss_negative.py",
            "render_comment",
            Cap::HTML_ESCAPE,
            11,
        ));
    }

    #[test]
    fn xss_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec(
            "xss_unsupported.py",
            "render",
            Cap::HTML_ESCAPE,
            7,
        ));
    }

    #[test]
    fn xss_adversarial_matches_golden() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        run_fixture_and_compare_to_golden(&spec(
            "xss_adversarial.py",
            "render_comment",
            Cap::HTML_ESCAPE,
            999,
        ));
    }

    // ── Cross-cutting tests retained verbatim ────────────────────────────────

    /// Telemetry must not contain literal secret strings from the fixture.
    /// Independent of the golden contract: it inspects the side-channel.
    #[test]
    fn secret_not_in_telemetry_after_verify() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }

        let _guard = crate::common::fixture_harness::FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = TempDir::new().unwrap();
        let telemetry_path = tmp.path().join("events.jsonl");
        unsafe {
            std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
            std::env::set_var("NYX_TELEMETRY_PATH", telemetry_path.to_str().unwrap());
        }

        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/python/sqli_positive.py");
        let tmp_fix = tmp.path().join("sqli_positive.py");
        let _ = std::fs::copy(&fixture, &tmp_fix);

        let diag = make_diag(&tmp_fix, "login", Cap::SQL_QUERY, 17);
        let opts = VerifyOptions::default();
        let _ = verify_finding(&diag, &opts);

        if telemetry_path.exists() {
            let content = std::fs::read_to_string(&telemetry_path).unwrap_or_default();
            assert!(
                !content.contains("AKIAFAKETEST00000000"),
                "telemetry must not contain fake AWS key; got: {content}"
            );
        }

        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }
    }

    // ── Phase 12 — per-shape acceptance ──────────────────────────────────────
    //
    // For each shape the suite asserts:
    //   1. The vuln fixture confirms (oracle fires, sink hit).
    //   2. The benign fixture does NOT confirm.
    //   3. The emitted harness source matches the per-shape golden
    //      snapshot under `tests/dynamic_fixtures/python/<shape>/`.
    //
    // Framework-bound shapes (Flask / FastAPI / Django / Celery) skip
    // with an `eprintln!` when the framework is unimportable in the
    // host's `python3` (and therefore unavailable to the harness's
    // built venv without a successful pip install).

    fn python_module_available(module: &'static str) -> bool {
        std::process::Command::new("python3")
            .arg("-c")
            .arg(format!("import {module}"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn assert_confirmed(shape: &str, result: &nyx_scanner::evidence::VerifyResult) {
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "{shape}/vuln.py: expected Confirmed, got {:?} ({:?})",
            result.status,
            result.detail,
        );
    }

    fn assert_not_confirmed(shape: &str, result: &nyx_scanner::evidence::VerifyResult) {
        assert!(
            matches!(
                result.status,
                VerifyStatus::NotConfirmed | VerifyStatus::Inconclusive
            ),
            "{shape}/benign.py: expected NotConfirmed (or Inconclusive), got {:?} ({:?})",
            result.status,
            result.detail,
        );
        // Tighter check: a benign fixture must never light up `Confirmed`.
        assert_ne!(
            result.status,
            VerifyStatus::Confirmed,
            "{shape}/benign.py: must not confirm",
        );
    }

    // ── generic ─────────────────────────────────────────────────────────────

    #[test]
    fn generic_vuln_is_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        let r = run_shape_fixture(
            "generic", "vuln.py", "run_ping", Cap::CODE_EXEC, 12,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("generic", &r);
    }

    #[test]
    fn generic_benign_not_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        let r = run_shape_fixture(
            "generic", "benign.py", "run_ping", Cap::CODE_EXEC, 20,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("generic", &r);
    }

    #[test]
    fn generic_harness_snapshot_matches_golden() {
        run_harness_snapshot(
            "generic", "vuln.py", "run_ping", Cap::CODE_EXEC, 12,
            EntryKind::Function, PayloadSlot::Param(0),
        );
    }

    // ── cli ─────────────────────────────────────────────────────────────────

    #[test]
    fn cli_vuln_is_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        let r = run_shape_fixture(
            "cli", "vuln.py", "main", Cap::CODE_EXEC, 14,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        );
        assert_confirmed("cli", &r);
    }

    #[test]
    fn cli_benign_not_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        let r = run_shape_fixture(
            "cli", "benign.py", "main", Cap::CODE_EXEC, 11,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        );
        assert_not_confirmed("cli", &r);
    }

    #[test]
    fn cli_harness_snapshot_matches_golden() {
        run_harness_snapshot(
            "cli", "vuln.py", "main", Cap::CODE_EXEC, 14,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        );
    }

    // ── pytest ──────────────────────────────────────────────────────────────

    #[test]
    fn pytest_vuln_is_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        let r = run_shape_fixture(
            "pytest", "vuln.py", "test_run_ping", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        );
        assert_confirmed("pytest", &r);
    }

    #[test]
    fn pytest_benign_not_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        let r = run_shape_fixture(
            "pytest", "benign.py", "test_run_ping", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        );
        assert_not_confirmed("pytest", &r);
    }

    #[test]
    fn pytest_harness_snapshot_matches_golden() {
        run_harness_snapshot(
            "pytest", "vuln.py", "test_run_ping", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        );
    }

    // ── async ───────────────────────────────────────────────────────────────

    #[test]
    fn async_vuln_is_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        let r = run_shape_fixture(
            "async", "vuln.py", "run_ping", Cap::CODE_EXEC, 13,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("async", &r);
    }

    #[test]
    fn async_benign_not_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        let r = run_shape_fixture(
            "async", "benign.py", "run_ping", Cap::CODE_EXEC, 14,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("async", &r);
    }

    #[test]
    fn async_harness_snapshot_matches_golden() {
        run_harness_snapshot(
            "async", "vuln.py", "run_ping", Cap::CODE_EXEC, 13,
            EntryKind::Function, PayloadSlot::Param(0),
        );
    }

    // ── celery ──────────────────────────────────────────────────────────────

    #[test]
    fn celery_vuln_is_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        if !python_module_available("celery") {
            eprintln!("SKIP: celery not importable");
            return;
        }
        let r = run_shape_fixture(
            "celery", "vuln.py", "run_job", Cap::CODE_EXEC, 17,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_confirmed("celery", &r);
    }

    #[test]
    fn celery_benign_not_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        if !python_module_available("celery") {
            eprintln!("SKIP: celery not importable");
            return;
        }
        let r = run_shape_fixture(
            "celery", "benign.py", "run_job", Cap::CODE_EXEC, 17,
            EntryKind::Function, PayloadSlot::Param(0),
        );
        assert_not_confirmed("celery", &r);
    }

    #[test]
    fn celery_harness_snapshot_matches_golden() {
        run_harness_snapshot(
            "celery", "vuln.py", "run_job", Cap::CODE_EXEC, 17,
            EntryKind::Function, PayloadSlot::Param(0),
        );
    }

    // ── flask ───────────────────────────────────────────────────────────────

    #[test]
    fn flask_vuln_is_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        if !python_module_available("flask") {
            eprintln!("SKIP: flask not importable");
            return;
        }
        let r = run_shape_fixture(
            "flask", "vuln.py", "ping", Cap::CODE_EXEC, 18,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_confirmed("flask", &r);
    }

    #[test]
    fn flask_benign_not_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        if !python_module_available("flask") {
            eprintln!("SKIP: flask not importable");
            return;
        }
        let r = run_shape_fixture(
            "flask", "benign.py", "ping", Cap::CODE_EXEC, 17,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_not_confirmed("flask", &r);
    }

    #[test]
    fn flask_harness_snapshot_matches_golden() {
        run_harness_snapshot(
            "flask", "vuln.py", "ping", Cap::CODE_EXEC, 18,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
    }

    // ── fastapi ─────────────────────────────────────────────────────────────

    #[test]
    fn fastapi_vuln_is_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        if !python_module_available("fastapi") {
            eprintln!("SKIP: fastapi not importable");
            return;
        }
        let r = run_shape_fixture(
            "fastapi", "vuln.py", "ping", Cap::CODE_EXEC, 16,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_confirmed("fastapi", &r);
    }

    #[test]
    fn fastapi_benign_not_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        if !python_module_available("fastapi") {
            eprintln!("SKIP: fastapi not importable");
            return;
        }
        let r = run_shape_fixture(
            "fastapi", "benign.py", "ping", Cap::CODE_EXEC, 16,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_not_confirmed("fastapi", &r);
    }

    #[test]
    fn fastapi_harness_snapshot_matches_golden() {
        run_harness_snapshot(
            "fastapi", "vuln.py", "ping", Cap::CODE_EXEC, 16,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
    }

    // ── django ──────────────────────────────────────────────────────────────

    #[test]
    fn django_vuln_is_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        if !python_module_available("django") {
            eprintln!("SKIP: django not importable");
            return;
        }
        let r = run_shape_fixture(
            "django", "vuln.py", "ping", Cap::CODE_EXEC, 15,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_confirmed("django", &r);
    }

    #[test]
    fn django_benign_not_confirmed() {
        if !python3_available() { eprintln!("SKIP: python3 not available"); return; }
        if !python_module_available("django") {
            eprintln!("SKIP: django not importable");
            return;
        }
        let r = run_shape_fixture(
            "django", "benign.py", "ping", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
        assert_not_confirmed("django", &r);
    }

    #[test]
    fn django_harness_snapshot_matches_golden() {
        run_harness_snapshot(
            "django", "vuln.py", "ping", Cap::CODE_EXEC, 15,
            EntryKind::HttpRoute, PayloadSlot::QueryParam("host".into()),
        );
    }

    /// Sensitive-filename gate fires before any harness execution; no
    /// python3 needed.
    #[test]
    fn sensitive_entry_file_is_unsupported() {
        let tmp = TempDir::new().unwrap();
        let entry = tmp.path().join("id_rsa.py");
        std::fs::write(&entry, "def run(x): pass\n").unwrap();

        let diag = make_diag(&entry, "run", Cap::SQL_QUERY, 2);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        assert_eq!(result.status, VerifyStatus::Unsupported);
        match &result.reason {
            Some(UnsupportedReason::RequiredFileRedactedForSecrets(_)) => {}
            other => panic!("expected RequiredFileRedactedForSecrets, got {other:?}"),
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
}
