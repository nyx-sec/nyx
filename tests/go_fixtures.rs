//! Go fixture integration tests (Phase 05 acceptance gate).
//!
//! Runs the dynamic verification pipeline against each Go fixture and asserts
//! the expected verdict. Requires `--features dynamic` and `go` on PATH.
//!
//! Entry points follow: `func FuncName(payload string)` in package `entry`.
//! The harness wraps each fixture in a generated `main.go` that reads
//! `NYX_PAYLOAD` and calls `entry.FuncName(payload)`.
//!
//! Run with: `cargo nextest run --features dynamic --test go_fixtures`

#[cfg(feature = "dynamic")]
mod go_fixture_tests {
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
    use nyx_scanner::evidence::{
        Confidence, Evidence, FlowStep, FlowStepKind, InconclusiveReason, UnsupportedReason,
        VerifyStatus,
    };
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tempfile::TempDir;

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn go_available() -> bool {
        std::process::Command::new("go")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/go")
            .join(name)
    }

    fn run_fixture(
        fixture: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
    ) -> nyx_scanner::evidence::VerifyResult {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !go_available() {
            return nyx_scanner::evidence::VerifyResult {
                finding_id: String::new(),
                status: VerifyStatus::Unsupported,
                triggered_payload: None,
                reason: Some(UnsupportedReason::BackendUnavailable),
                inconclusive_reason: None,
                detail: None,
                attempts: vec![],
                toolchain_match: None,
            };
        }

        let path = fixture_path(fixture);
        let tmp = TempDir::new().unwrap();

        unsafe {
            std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
            std::env::set_var(
                "NYX_TELEMETRY_PATH",
                tmp.path().join("events.jsonl").to_str().unwrap(),
            );
        }

        let diag = make_diag(&path, func, cap, sink_line);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }

        result
    }

    // ── SQLi fixtures ────────────────────────────────────────────────────────

    #[test]
    fn go_sqli_positive_is_confirmed() {
        let result = run_fixture("sqli_positive.go", "Login", Cap::SQL_QUERY, 13);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "sqli_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn go_sqli_negative_is_not_confirmed() {
        let result = run_fixture("sqli_negative.go", "Login", Cap::SQL_QUERY, 12);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "sqli_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn go_sqli_adversarial_is_oracle_collision() {
        let result = run_fixture("sqli_adversarial.go", "Login", Cap::SQL_QUERY, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn go_sqli_unsupported_is_confidence_too_low() {
        let path = fixture_path("sqli_unsupported.go");
        let mut d = make_diag(&path, "FindUser", Cap::SQL_QUERY, 12);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── Command injection fixtures ───────────────────────────────────────────

    #[test]
    fn go_cmdi_positive_is_confirmed() {
        let result = run_fixture("cmdi_positive.go", "RunPing", Cap::CODE_EXEC, 15);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "cmdi_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn go_cmdi_negative_is_not_confirmed() {
        let result = run_fixture("cmdi_negative.go", "RunPing", Cap::CODE_EXEC, 14);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "cmdi_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn go_cmdi_adversarial_is_oracle_collision() {
        let result = run_fixture("cmdi_adversarial.go", "RunPing", Cap::CODE_EXEC, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn go_cmdi_unsupported_is_confidence_too_low() {
        let path = fixture_path("cmdi_unsupported.go");
        let mut d = make_diag(&path, "Execute", Cap::CODE_EXEC, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── File I/O fixtures ────────────────────────────────────────────────────

    #[test]
    fn go_fileio_positive_is_confirmed() {
        let result = run_fixture("fileio_positive.go", "ReadFile", Cap::FILE_IO, 17);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "fileio_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn go_fileio_negative_is_not_confirmed() {
        let result = run_fixture("fileio_negative.go", "ReadFile", Cap::FILE_IO, 20);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "fileio_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn go_fileio_adversarial_is_oracle_collision() {
        let result = run_fixture("fileio_adversarial.go", "ReadFile", Cap::FILE_IO, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn go_fileio_unsupported_is_confidence_too_low() {
        let path = fixture_path("fileio_unsupported.go");
        let mut d = make_diag(&path, "Serve", Cap::FILE_IO, 13);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── SSRF fixtures ────────────────────────────────────────────────────────

    #[test]
    fn go_ssrf_positive_is_confirmed() {
        let result = run_fixture("ssrf_positive.go", "FetchURL", Cap::SSRF, 21);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "ssrf_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn go_ssrf_negative_is_not_confirmed() {
        let result = run_fixture("ssrf_negative.go", "FetchURL", Cap::SSRF, 18);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "ssrf_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn go_ssrf_adversarial_is_oracle_collision() {
        let result = run_fixture("ssrf_adversarial.go", "FetchURL", Cap::SSRF, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn go_ssrf_unsupported_is_confidence_too_low() {
        let path = fixture_path("ssrf_unsupported.go");
        let mut d = make_diag(&path, "Fetch", Cap::SSRF, 11);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── XSS fixtures ─────────────────────────────────────────────────────────

    #[test]
    fn go_xss_positive_is_confirmed() {
        let result = run_fixture("xss_positive.go", "RenderPage", Cap::HTML_ESCAPE, 12);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "xss_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn go_xss_negative_is_not_confirmed() {
        let result = run_fixture("xss_negative.go", "RenderPage", Cap::HTML_ESCAPE, 12);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "xss_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn go_xss_adversarial_is_oracle_collision() {
        let result = run_fixture("xss_adversarial.go", "RenderPage", Cap::HTML_ESCAPE, 999);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return;
        }
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    #[test]
    fn go_xss_unsupported_is_confidence_too_low() {
        let path = fixture_path("xss_unsupported.go");
        let mut d = make_diag(&path, "Render", Cap::HTML_ESCAPE, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

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
