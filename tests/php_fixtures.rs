//! PHP fixture integration tests (Phase 05 acceptance gate).
//!
//! Runs the dynamic verification pipeline against each PHP fixture and asserts
//! the expected verdict. Requires `--features dynamic` and `php` on PATH.
//!
//! Entry points follow: `function funcName($payload)` at top level.
//! The harness wraps each fixture in a generated runner that reads
//! `NYX_PAYLOAD` and calls `funcName($payload)`.
//!
//! Run with: `cargo nextest run --features dynamic --test php_fixtures`

mod common;

#[cfg(feature = "dynamic")]
mod php_fixture_tests {
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::verify::{VerifyOptions, verify_finding};
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

    fn php_available() -> bool {
        std::process::Command::new("php")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/php")
            .join(name)
    }

    fn run_fixture(
        fixture: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
    ) -> nyx_scanner::evidence::VerifyResult {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !php_available() {
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
    fn php_sqli_positive_is_confirmed() {
        let result = run_fixture("sqli_positive.php", "login", Cap::SQL_QUERY, 9);
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
    fn php_sqli_negative_is_not_confirmed() {
        let result = run_fixture("sqli_negative.php", "login", Cap::SQL_QUERY, 10);
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
    fn php_sqli_adversarial_is_oracle_collision() {
        let result = run_fixture("sqli_adversarial.php", "login", Cap::SQL_QUERY, 999);
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
    fn php_sqli_unsupported_is_confidence_too_low() {
        let path = fixture_path("sqli_unsupported.php");
        let mut d = make_diag(&path, "findUser", Cap::SQL_QUERY, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── Command injection fixtures ───────────────────────────────────────────

    #[test]
    fn php_cmdi_positive_is_confirmed() {
        let result = run_fixture("cmdi_positive.php", "runPing", Cap::CODE_EXEC, 8);
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
    fn php_cmdi_negative_is_not_confirmed() {
        let result = run_fixture("cmdi_negative.php", "runPing", Cap::CODE_EXEC, 10);
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
    fn php_cmdi_adversarial_is_oracle_collision() {
        let result = run_fixture("cmdi_adversarial.php", "runPing", Cap::CODE_EXEC, 999);
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
    fn php_cmdi_unsupported_is_confidence_too_low() {
        let path = fixture_path("cmdi_unsupported.php");
        let mut d = make_diag(&path, "execute", Cap::CODE_EXEC, 8);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── File I/O fixtures ────────────────────────────────────────────────────

    #[test]
    fn php_fileio_positive_is_confirmed() {
        let result = run_fixture("fileio_positive.php", "runReadFile", Cap::FILE_IO, 9);
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
    fn php_fileio_negative_is_not_confirmed() {
        let result = run_fixture("fileio_negative.php", "runReadFile", Cap::FILE_IO, 14);
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
    fn php_fileio_adversarial_is_oracle_collision() {
        let result = run_fixture("fileio_adversarial.php", "runReadFile", Cap::FILE_IO, 999);
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
    fn php_fileio_unsupported_is_confidence_too_low() {
        let path = fixture_path("fileio_unsupported.php");
        let mut d = make_diag(&path, "serve", Cap::FILE_IO, 8);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── SSRF fixtures ────────────────────────────────────────────────────────

    #[test]
    fn php_ssrf_positive_is_confirmed() {
        let result = run_fixture("ssrf_positive.php", "fetchUrl", Cap::SSRF, 9);
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
    fn php_ssrf_negative_is_not_confirmed() {
        let result = run_fixture("ssrf_negative.php", "fetchUrl", Cap::SSRF, 14);
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
    fn php_ssrf_adversarial_is_oracle_collision() {
        let result = run_fixture("ssrf_adversarial.php", "fetchUrl", Cap::SSRF, 999);
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
    fn php_ssrf_unsupported_is_confidence_too_low() {
        let path = fixture_path("ssrf_unsupported.php");
        let mut d = make_diag(&path, "fetch", Cap::SSRF, 8);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    // ── XSS fixtures ─────────────────────────────────────────────────────────

    #[test]
    fn php_xss_positive_is_confirmed() {
        let result = run_fixture("xss_positive.php", "renderPage", Cap::HTML_ESCAPE, 8);
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
    fn php_xss_negative_is_not_confirmed() {
        let result = run_fixture("xss_negative.php", "renderPage", Cap::HTML_ESCAPE, 9);
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
    fn php_xss_adversarial_is_oracle_collision() {
        let result = run_fixture("xss_adversarial.php", "renderPage", Cap::HTML_ESCAPE, 999);
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
    fn php_xss_unsupported_is_confidence_too_low() {
        let path = fixture_path("xss_unsupported.php");
        let mut d = make_diag(&path, "render", Cap::HTML_ESCAPE, 8);
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

// ── Phase 15: per-shape acceptance ───────────────────────────────────────────

#[cfg(feature = "dynamic")]
mod phase15_shape_tests {
    use crate::common::fixture_harness::{Prerequisite, run_shape_fixture_lang_or_skip};
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::evidence::{EntryKind, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;

    fn assert_confirmed(shape: &str, result: &VerifyResult) {
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "{shape}/vuln: expected Confirmed, got {:?} ({:?})",
            result.status,
            result.detail,
        );
    }

    fn assert_not_confirmed(shape: &str, result: &VerifyResult) {
        assert!(
            matches!(
                result.status,
                VerifyStatus::NotConfirmed | VerifyStatus::Inconclusive
            ),
            "{shape}/benign: expected NotConfirmed (or Inconclusive), got {:?} ({:?})",
            result.status,
            result.detail,
        );
        assert_ne!(
            result.status,
            VerifyStatus::Confirmed,
            "{shape}/benign: must not confirm",
        );
    }

    fn run(
        shape: &str,
        file: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
        kind: EntryKind,
        slot: PayloadSlot,
    ) -> Option<VerifyResult> {
        // Phase 29 (Track I): replace the bespoke `php_available()` +
        // per-test `eprintln!("SKIP ..."); return;` blocks with the
        // structured `Prerequisite::CommandAvailable("php")` gate.  The
        // helper emits the same SKIP line and returns `None` so each
        // test can short-circuit via `let Some(r) = run(...) else {
        // return; };`.
        run_shape_fixture_lang_or_skip(
            &[Prerequisite::CommandAvailable("php")],
            Lang::Php,
            "php",
            shape,
            file,
            func,
            cap,
            sink_line,
            kind,
            slot,
        )
    }

    // ── route_closure ────────────────────────────────────────────────────────

    #[test]
    fn route_closure_vuln_is_confirmed() {
        let Some(r) = run(
            "route_closure",
            "vuln.php",
            "run",
            Cap::CODE_EXEC,
            10,
            EntryKind::HttpRoute,
            PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("route_closure", &r);
    }

    #[test]
    fn route_closure_benign_not_confirmed() {
        let Some(r) = run(
            "route_closure",
            "benign.php",
            "run",
            Cap::CODE_EXEC,
            11,
            EntryKind::HttpRoute,
            PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("route_closure", &r);
    }

    // ── cli_script ───────────────────────────────────────────────────────────

    #[test]
    fn cli_script_vuln_is_confirmed() {
        let Some(r) = run(
            "cli_script",
            "vuln.php",
            "main",
            Cap::CODE_EXEC,
            8,
            EntryKind::CliSubcommand,
            PayloadSlot::Argv(0),
        ) else {
            return;
        };
        assert_confirmed("cli_script", &r);
    }

    #[test]
    fn cli_script_benign_not_confirmed() {
        let Some(r) = run(
            "cli_script",
            "benign.php",
            "main",
            Cap::CODE_EXEC,
            11,
            EntryKind::CliSubcommand,
            PayloadSlot::Argv(0),
        ) else {
            return;
        };
        assert_not_confirmed("cli_script", &r);
    }

    // ── top_level_script ─────────────────────────────────────────────────────

    #[test]
    fn top_level_script_vuln_is_confirmed() {
        let Some(r) = run(
            "top_level_script",
            "vuln.php",
            "",
            Cap::CODE_EXEC,
            8,
            EntryKind::Function,
            PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        ) else {
            return;
        };
        assert_confirmed("top_level_script", &r);
    }

    #[test]
    fn top_level_script_benign_not_confirmed() {
        let Some(r) = run(
            "top_level_script",
            "benign.php",
            "",
            Cap::CODE_EXEC,
            10,
            EntryKind::Function,
            PayloadSlot::EnvVar("NYX_PAYLOAD".into()),
        ) else {
            return;
        };
        assert_not_confirmed("top_level_script", &r);
    }
}
