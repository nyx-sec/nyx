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

mod common;

#[cfg(feature = "dynamic")]
mod go_fixture_tests {
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::sandbox::SandboxBackend;
    use nyx_scanner::dynamic::verify::{VerifyOptions, verify_finding};
    use nyx_scanner::evidence::{
        Confidence, Evidence, FlowStep, FlowStepKind, InconclusiveReason, UnsupportedReason,
        VerifyStatus,
    };
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

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
            std::env::set_var(
                "NYX_BUILD_CACHE",
                tmp.path().join("build-cache").to_str().unwrap(),
            );
            std::env::set_var("GOCACHE", tmp.path().join("gocache").to_str().unwrap());
        }

        let diag = make_diag(&path, func, cap, sink_line);
        let mut opts = VerifyOptions::default();
        opts.sandbox.backend = SandboxBackend::Process;
        let result = verify_finding(&diag, &opts);

        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
            std::env::remove_var("NYX_BUILD_CACHE");
            std::env::remove_var("GOCACHE");
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
            "cmdi_negative must be NotConfirmed; got {:?} (detail: {:?}, inconclusive: {:?}, differential: {:?})",
            result.status,
            result.detail,
            result.inconclusive_reason,
            result.differential
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
            triage_state: "open".to_string(),
            triage_note: String::new(),
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
        // Phase 29 (Track I): replace the bespoke `go_available()` +
        // per-test `eprintln!("SKIP ..."); return;` blocks with the
        // structured `Prerequisite::CommandAvailable("go")` gate.  The
        // helper emits the same SKIP line and returns `None` so each
        // test can short-circuit via `let Some(r) = run(...) else {
        // return; };`.
        run_shape_fixture_lang_or_skip(
            &[Prerequisite::CommandAvailable("go")],
            Lang::Go,
            "go",
            shape,
            file,
            func,
            cap,
            sink_line,
            kind,
            slot,
        )
    }

    // ── handler_func ─────────────────────────────────────────────────────────

    #[test]
    fn handler_func_vuln_is_confirmed() {
        let Some(r) = run(
            "handler_func",
            "vuln.go",
            "Handle",
            Cap::CODE_EXEC,
            17,
            EntryKind::HttpRoute,
            PayloadSlot::QueryParam("payload".into()),
        ) else {
            return;
        };
        assert_confirmed("handler_func", &r);
    }

    #[test]
    fn handler_func_benign_not_confirmed() {
        let Some(r) = run(
            "handler_func",
            "benign.go",
            "Handle",
            Cap::CODE_EXEC,
            14,
            EntryKind::HttpRoute,
            PayloadSlot::QueryParam("payload".into()),
        ) else {
            return;
        };
        assert_not_confirmed("handler_func", &r);
    }

    // ── gin_handler ──────────────────────────────────────────────────────────

    #[test]
    fn gin_handler_vuln_is_confirmed() {
        let Some(r) = run(
            "gin_handler",
            "vuln.go",
            "Handle",
            Cap::CODE_EXEC,
            16,
            EntryKind::HttpRoute,
            PayloadSlot::QueryParam("payload".into()),
        ) else {
            return;
        };
        assert_confirmed("gin_handler", &r);
    }

    #[test]
    fn gin_handler_benign_not_confirmed() {
        let Some(r) = run(
            "gin_handler",
            "benign.go",
            "Handle",
            Cap::CODE_EXEC,
            14,
            EntryKind::HttpRoute,
            PayloadSlot::QueryParam("payload".into()),
        ) else {
            return;
        };
        assert_not_confirmed("gin_handler", &r);
    }

    // ── flag_cli ─────────────────────────────────────────────────────────────

    #[test]
    fn flag_cli_vuln_is_confirmed() {
        let Some(r) = run(
            "flag_cli",
            "vuln.go",
            "Run",
            Cap::CODE_EXEC,
            19,
            EntryKind::CliSubcommand,
            PayloadSlot::Argv(0),
        ) else {
            return;
        };
        assert_confirmed("flag_cli", &r);
    }

    #[test]
    fn flag_cli_benign_not_confirmed() {
        let Some(r) = run(
            "flag_cli",
            "benign.go",
            "Run",
            Cap::CODE_EXEC,
            15,
            EntryKind::CliSubcommand,
            PayloadSlot::Argv(0),
        ) else {
            return;
        };
        assert_not_confirmed("flag_cli", &r);
    }

    // ── fuzz_variadic ────────────────────────────────────────────────────────

    #[test]
    fn fuzz_variadic_vuln_is_confirmed() {
        let Some(r) = run(
            "fuzz_variadic",
            "vuln.go",
            "FuzzHandle",
            Cap::CODE_EXEC,
            14,
            EntryKind::Function,
            PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_confirmed("fuzz_variadic", &r);
    }

    #[test]
    fn fuzz_variadic_benign_not_confirmed() {
        let Some(r) = run(
            "fuzz_variadic",
            "benign.go",
            "FuzzHandle",
            Cap::CODE_EXEC,
            14,
            EntryKind::Function,
            PayloadSlot::Param(0),
        ) else {
            return;
        };
        assert_not_confirmed("fuzz_variadic", &r);
    }
}
