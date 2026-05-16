//! JavaScript/Node.js fixture integration tests (Phase 05 acceptance gate).
//!
//! Runs the dynamic verification pipeline against each JS fixture and asserts
//! the expected verdict. Requires `--features dynamic` and `node` on PATH.
//!
//! Entry points follow: `function funcName(payload)` + `module.exports = { funcName }`.
//! The harness emitter wraps each fixture in a generated `harness.js` that
//! reads `NYX_PAYLOAD` from the environment and calls `_entry.funcName(payload)`.
//!
//! Run with: `cargo nextest run --features dynamic --test js_fixtures`

#[cfg(feature = "dynamic")]
mod js_fixture_tests {
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

    fn node_available() -> bool {
        std::process::Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/js")
            .join(name)
    }

    /// Run a JS fixture through the full dynamic verification pipeline.
    ///
    /// The fixture file is copied to a temp dir as `entry.js`.
    fn run_fixture(
        fixture: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
    ) -> nyx_scanner::evidence::VerifyResult {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !node_available() {
            return nyx_scanner::evidence::VerifyResult {
                finding_id: String::new(),
                status: VerifyStatus::Unsupported,
                triggered_payload: None,
                reason: Some(UnsupportedReason::BackendUnavailable),
                inconclusive_reason: None,
                detail: None,
                attempts: vec![],
                toolchain_match: None,
                differential: None,
                replay_stable: None,
                wrong: None,
                hardening_outcome: None,
            };
        }

        let path = fixture_path(fixture);
        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("entry.js");
        std::fs::copy(&path, &dst).expect("fixture file must exist");

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
    fn js_sqli_positive_is_confirmed() {
        let result = run_fixture("sqli_positive.js", "login", Cap::SQL_QUERY, 12);
        if result.status == VerifyStatus::Unsupported
            && result.reason == Some(UnsupportedReason::BackendUnavailable)
        {
            return; // node not available
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
    fn js_sqli_negative_is_not_confirmed() {
        let result = run_fixture("sqli_negative.js", "login", Cap::SQL_QUERY, 13);
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
    fn js_sqli_adversarial_is_oracle_collision() {
        let result = run_fixture("sqli_adversarial.js", "login", Cap::SQL_QUERY, 999);
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
    fn js_sqli_unsupported_is_confidence_too_low() {
        let path = fixture_path("sqli_unsupported.js");
        let mut d = make_diag(&path, "findUser", Cap::SQL_QUERY, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── Command injection fixtures ───────────────────────────────────────────

    #[test]
    fn js_cmdi_positive_is_confirmed() {
        let result = run_fixture("cmdi_positive.js", "runPing", Cap::CODE_EXEC, 11);
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
    fn js_cmdi_negative_is_not_confirmed() {
        let result = run_fixture("cmdi_negative.js", "runPing", Cap::CODE_EXEC, 11);
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
    fn js_cmdi_adversarial_is_oracle_collision() {
        let result = run_fixture("cmdi_adversarial.js", "runPing", Cap::CODE_EXEC, 999);
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
    fn js_cmdi_unsupported_is_confidence_too_low() {
        let path = fixture_path("cmdi_unsupported.js");
        let mut d = make_diag(&path, "runCommand", Cap::CODE_EXEC, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── File I/O fixtures ────────────────────────────────────────────────────

    #[test]
    fn js_fileio_positive_is_confirmed() {
        let result = run_fixture("fileio_positive.js", "readFile", Cap::FILE_IO, 13);
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
    fn js_fileio_negative_is_not_confirmed() {
        let result = run_fixture("fileio_negative.js", "readFile", Cap::FILE_IO, 16);
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
    fn js_fileio_adversarial_is_oracle_collision() {
        let result = run_fixture("fileio_adversarial.js", "readFile", Cap::FILE_IO, 999);
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
    fn js_fileio_unsupported_is_confidence_too_low() {
        let path = fixture_path("fileio_unsupported.js");
        let mut d = make_diag(&path, "processUpload", Cap::FILE_IO, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── SSRF fixtures ────────────────────────────────────────────────────────

    #[test]
    fn js_ssrf_positive_is_confirmed() {
        let result = run_fixture("ssrf_positive.js", "fetchUrl", Cap::SSRF, 21);
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
    fn js_ssrf_negative_is_not_confirmed() {
        let result = run_fixture("ssrf_negative.js", "fetchUrl", Cap::SSRF, 16);
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
    fn js_ssrf_adversarial_is_oracle_collision() {
        let result = run_fixture("ssrf_adversarial.js", "fetchUrl", Cap::SSRF, 999);
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
    fn js_ssrf_unsupported_is_confidence_too_low() {
        let path = fixture_path("ssrf_unsupported.js");
        let mut d = make_diag(&path, "fetchParsed", Cap::SSRF, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── XSS fixtures ─────────────────────────────────────────────────────────

    #[test]
    fn js_xss_positive_is_confirmed() {
        let result = run_fixture("xss_positive.js", "renderPage", Cap::HTML_ESCAPE, 10);
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
    fn js_xss_negative_is_not_confirmed() {
        let result = run_fixture("xss_negative.js", "renderPage", Cap::HTML_ESCAPE, 14);
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
    fn js_xss_adversarial_is_oracle_collision() {
        let result = run_fixture("xss_adversarial.js", "renderPage", Cap::HTML_ESCAPE, 999);
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
    fn js_xss_unsupported_is_confidence_too_low() {
        let path = fixture_path("xss_unsupported.js");
        let mut d = make_diag(&path, "render", Cap::HTML_ESCAPE, 10);
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
