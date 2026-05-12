//! Python fixture integration tests (§15 Pillar B acceptance gate).
//!
//! Runs the dynamic verification pipeline against each Python fixture and
//! asserts the expected verdict. Requires `--features dynamic` and Python3
//! to be available on PATH.
//!
//! Verdicts under test:
//! - positive  → Confirmed
//! - negative  → NotConfirmed
//! - unsupported → Unsupported(ConfidenceTooLow) [spec-level rejection]
//! - adversarial → Inconclusive(OracleCollisionSuspected)
//!
//! Tests are skipped when Python3 is not available.

#[cfg(feature = "dynamic")]
mod python_fixture_tests {
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
    use nyx_scanner::evidence::{
        Confidence, Evidence, FlowStep, FlowStepKind, InconclusiveReason, UnsupportedReason,
        VerifyStatus,
    };
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// Returns `true` if `python3` is available.
    fn python3_available() -> bool {
        std::process::Command::new("python3")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/python")
            .join(name)
    }

    /// Run a fixture and return the verdict.
    fn run_fixture(fixture: &str, func: &str, cap: Cap, sink_line: u32) -> nyx_scanner::evidence::VerifyResult {
        let path = fixture_path(fixture);
        // Copy fixture to a temp dir so the harness can import it.
        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join(Path::new(fixture).file_name().unwrap());
        std::fs::copy(&path, &dst).expect("fixture file must exist");

        // Set up repro and telemetry to temp dirs to avoid side effects.
        unsafe {
            std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
            std::env::set_var("NYX_TELEMETRY_PATH", tmp.path().join("events.jsonl").to_str().unwrap());
        }

        // Use the temp dir copy as the fixture path.
        let diag = make_diag(&dst, func, cap, sink_line);

        // Change CWD to the temp dir so the harness can find the module.
        let original_dir = std::env::current_dir().ok();
        let _ = std::env::set_current_dir(tmp.path());

        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        if let Some(dir) = original_dir {
            let _ = std::env::set_current_dir(dir);
        }

        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }

        result
    }

    // ── SQLi fixtures ────────────────────────────────────────────────────────

    #[test]
    fn sqli_positive_is_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("sqli_positive.py", "login", Cap::SQL_QUERY, 17);
        assert_eq!(
            result.status, VerifyStatus::Confirmed,
            "sqli_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status, result.detail
        );
    }

    #[test]
    fn sqli_negative_is_not_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("sqli_negative.py", "login", Cap::SQL_QUERY, 12);
        assert_eq!(
            result.status, VerifyStatus::NotConfirmed,
            "sqli_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn sqli_unsupported_is_unsupported() {
        // Low-confidence Diag → Unsupported(ConfidenceTooLow) without execution.
        let path = fixture_path("sqli_unsupported.py");
        let mut d = make_diag(&path, "find_user", Cap::SQL_QUERY, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn sqli_adversarial_is_inconclusive_collision() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        // The adversarial fixture prints the oracle marker WITHOUT going through
        // any SQL sink — so the oracle fires but the probe at the (nonexistent)
        // SQL execute line does not.
        // We point the sink line at a line that doesn't exist in the file (999)
        // so the settrace probe can't fire.
        let result = run_fixture("sqli_adversarial.py", "get_value", Cap::SQL_QUERY, 999);
        // Oracle fires (prints "NYX_SQL_CONFIRMED") but probe doesn't (line 999 missing).
        assert_eq!(
            result.status, VerifyStatus::Inconclusive,
            "sqli_adversarial must be Inconclusive; got {:?}",
            result.status
        );
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected),
            "adversarial must be OracleCollisionSuspected"
        );
    }

    // ── Command injection fixtures ───────────────────────────────────────────

    #[test]
    fn cmdi_positive_is_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("cmdi_positive.py", "run_ping", Cap::CODE_EXEC, 13);
        assert_eq!(
            result.status, VerifyStatus::Confirmed,
            "cmdi_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status, result.detail
        );
    }

    #[test]
    fn cmdi_negative_is_not_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("cmdi_negative.py", "run_ping", Cap::CODE_EXEC, 17);
        assert_eq!(
            result.status, VerifyStatus::NotConfirmed,
            "cmdi_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn cmdi_unsupported_is_unsupported() {
        let path = fixture_path("cmdi_unsupported.py");
        let mut d = make_diag(&path, "process_request", Cap::CODE_EXEC, 9);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn cmdi_adversarial_is_inconclusive_collision() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("cmdi_adversarial.py", "process_input", Cap::CODE_EXEC, 999);
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    // ── File I/O fixtures ────────────────────────────────────────────────────

    #[test]
    fn fileio_positive_is_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("fileio_positive.py", "read_file", Cap::FILE_IO, 11);
        assert_eq!(
            result.status, VerifyStatus::Confirmed,
            "fileio_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status, result.detail
        );
    }

    #[test]
    fn fileio_negative_is_not_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("fileio_negative.py", "read_file", Cap::FILE_IO, 18);
        assert_eq!(
            result.status, VerifyStatus::NotConfirmed,
            "fileio_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn fileio_unsupported_is_unsupported() {
        let path = fixture_path("fileio_unsupported.py");
        let mut d = make_diag(&path, "read_config", Cap::FILE_IO, 7);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn fileio_adversarial_is_inconclusive_collision() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("fileio_adversarial.py", "read_file", Cap::FILE_IO, 999);
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    // ── SSRF fixtures ────────────────────────────────────────────────────────

    #[test]
    fn ssrf_positive_is_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("ssrf_positive.py", "fetch_url", Cap::SSRF, 11);
        assert_eq!(
            result.status, VerifyStatus::Confirmed,
            "ssrf_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status, result.detail
        );
    }

    #[test]
    fn ssrf_negative_is_not_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("ssrf_negative.py", "fetch_url", Cap::SSRF, 26);
        // Blocked by host validation — oracle won't fire.
        assert_eq!(
            result.status, VerifyStatus::NotConfirmed,
            "ssrf_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn ssrf_unsupported_is_unsupported() {
        let path = fixture_path("ssrf_unsupported.py");
        let mut d = make_diag(&path, "fetch", Cap::SSRF, 9);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn ssrf_adversarial_is_inconclusive_collision() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("ssrf_adversarial.py", "fetch_url", Cap::SSRF, 999);
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    // ── XSS fixtures ─────────────────────────────────────────────────────────

    #[test]
    fn xss_positive_is_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("xss_positive.py", "render_comment", Cap::HTML_ESCAPE, 9);
        assert_eq!(
            result.status, VerifyStatus::Confirmed,
            "xss_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status, result.detail
        );
    }

    #[test]
    fn xss_negative_is_not_confirmed() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("xss_negative.py", "render_comment", Cap::HTML_ESCAPE, 11);
        assert_eq!(
            result.status, VerifyStatus::NotConfirmed,
            "xss_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn xss_unsupported_is_unsupported() {
        let path = fixture_path("xss_unsupported.py");
        let mut d = make_diag(&path, "render", Cap::HTML_ESCAPE, 7);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn xss_adversarial_is_inconclusive_collision() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }
        let result = run_fixture("xss_adversarial.py", "render_comment", Cap::HTML_ESCAPE, 999);
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    // ── Secrets fixture ───────────────────────────────────────────────────────

    #[test]
    fn secret_not_in_telemetry_after_verify() {
        if !python3_available() {
            eprintln!("SKIP: python3 not available");
            return;
        }

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

        let original_dir = std::env::current_dir().ok();
        let _ = std::env::set_current_dir(tmp.path());

        let diag = make_diag(&tmp_fix, "login", Cap::SQL_QUERY, 17);
        let opts = VerifyOptions::default();
        let _ = verify_finding(&diag, &opts);

        if let Some(dir) = original_dir {
            let _ = std::env::set_current_dir(dir);
        }

        // Check telemetry doesn't contain any secret patterns.
        if telemetry_path.exists() {
            let content = std::fs::read_to_string(&telemetry_path).unwrap_or_default();
            // Telemetry must not contain the fake AWS key.
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
