//! Rust fixture integration tests (Phase 04 acceptance gate).
//!
//! Runs the dynamic verification pipeline against each Rust fixture and
//! asserts the expected verdict. Requires `--features dynamic` and a
//! working `cargo` toolchain on PATH.
//!
//! Fixture entry points follow the convention:
//!   `pub fn run(payload: &str)` in `tests/dynamic_fixtures/rust/{name}.rs`
//!
//! The harness emitter wraps each fixture in a generated `src/main.rs` that
//! reads `NYX_PAYLOAD` from the environment and calls `entry::run(&payload)`.
//!
//! Build note: the first run per capability compiles a Cargo project; subsequent
//! runs with differing entry files hit the build cache only when Cargo.toml and
//! src/entry.rs are identical (the cache key includes the entry file hash).
//! Expect 2-4 compilations per full test run (one per unique dependency set).
//!
//! Run with: `cargo nextest run --features dynamic --test rust_fixtures`

#[cfg(feature = "dynamic")]
mod rust_fixture_tests {
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

    // Serialize all fixture tests: prevents races on process-global env vars
    // (NYX_REPRO_BASE, NYX_TELEMETRY_PATH) and the shared build cache dir.
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/rust")
            .join(name)
    }

    /// Run a Rust fixture through the full dynamic verification pipeline.
    ///
    /// The fixture file is copied to a temp dir as `src/entry.rs`.
    /// `NYX_REPRO_BASE` and `NYX_TELEMETRY_PATH` are redirected to temp dirs.
    fn run_fixture(
        fixture: &str,
        func: &str,
        cap: Cap,
        sink_line: u32,
    ) -> nyx_scanner::evidence::VerifyResult {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let path = fixture_path(fixture);

        let tmp = TempDir::new().unwrap();
        // Rust fixtures live at src/entry.rs inside the harness workdir;
        // the Diag's entry_file points to the fixture source on disk.
        let dst_dir = tmp.path().join("src");
        std::fs::create_dir_all(&dst_dir).unwrap();
        let dst = dst_dir.join("entry.rs");
        std::fs::copy(&path, &dst).expect("fixture file must exist");

        unsafe {
            std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
            std::env::set_var(
                "NYX_TELEMETRY_PATH",
                tmp.path().join("events.jsonl").to_str().unwrap(),
            );
        }

        // Point the Diag at the original fixture path (absolute), not the copy.
        // The harness emitter reads the file at entry_file to extract source.
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
    fn sqli_positive_is_confirmed() {
        let result = run_fixture("sqli_positive.rs", "run", Cap::SQL_QUERY, 18);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "sqli_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
        assert!(
            result.triggered_payload.is_some(),
            "Confirmed result must have triggered_payload"
        );
    }

    #[test]
    fn sqli_negative_is_not_confirmed() {
        let result = run_fixture("sqli_negative.rs", "run", Cap::SQL_QUERY, 22);
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "sqli_negative must be NotConfirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn sqli_unsupported_is_unsupported() {
        let path = fixture_path("sqli_unsupported.rs");
        let mut d = make_diag(&path, "find_user", Cap::SQL_QUERY, 10);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn sqli_adversarial_is_inconclusive_collision() {
        // Adversarial prints oracle marker without __NYX_SINK_HIT__:
        //   oracle_fired = true, sink_hit = false → OracleCollisionSuspected.
        let result = run_fixture("sqli_adversarial.rs", "run", Cap::SQL_QUERY, 999);
        assert_eq!(
            result.status,
            VerifyStatus::Inconclusive,
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
        let result = run_fixture("cmdi_positive.rs", "run", Cap::CODE_EXEC, 17);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "cmdi_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn cmdi_negative_is_not_confirmed() {
        let result = run_fixture("cmdi_negative.rs", "run", Cap::CODE_EXEC, 17);
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "cmdi_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn cmdi_unsupported_is_unsupported() {
        let path = fixture_path("cmdi_unsupported.rs");
        let mut d = make_diag(&path, "execute", Cap::CODE_EXEC, 9);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn cmdi_adversarial_is_inconclusive_collision() {
        let result = run_fixture("cmdi_adversarial.rs", "run", Cap::CODE_EXEC, 999);
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    // ── File I/O fixtures ────────────────────────────────────────────────────

    #[test]
    fn fileio_positive_is_confirmed() {
        let result = run_fixture("fileio_positive.rs", "run", Cap::FILE_IO, 7);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "fileio_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn fileio_negative_is_not_confirmed() {
        let result = run_fixture("fileio_negative.rs", "run", Cap::FILE_IO, 17);
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "fileio_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn fileio_unsupported_is_unsupported() {
        let path = fixture_path("fileio_unsupported.rs");
        let mut d = make_diag(&path, "read", Cap::FILE_IO, 8);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn fileio_adversarial_is_inconclusive_collision() {
        let result = run_fixture("fileio_adversarial.rs", "run", Cap::FILE_IO, 999);
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    // ── SSRF fixtures ────────────────────────────────────────────────────────

    #[test]
    fn ssrf_positive_is_confirmed() {
        let result = run_fixture("ssrf_positive.rs", "run", Cap::SSRF, 7);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "ssrf_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn ssrf_negative_is_not_confirmed() {
        let result = run_fixture("ssrf_negative.rs", "run", Cap::SSRF, 13);
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "ssrf_negative must be NotConfirmed; got {:?}",
            result.status
        );
    }

    #[test]
    fn ssrf_unsupported_is_unsupported() {
        let path = fixture_path("ssrf_unsupported.rs");
        let mut d = make_diag(&path, "get", Cap::SSRF, 8);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn ssrf_adversarial_is_inconclusive_collision() {
        let result = run_fixture("ssrf_adversarial.rs", "run", Cap::SSRF, 999);
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected)
        );
    }

    // ── XSS fixtures ─────────────────────────────────────────────────────────

    #[test]
    fn xss_positive_is_confirmed() {
        let result = run_fixture("xss_positive.rs", "run", Cap::HTML_ESCAPE, 11);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "xss_positive must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
        assert!(
            result.triggered_payload.is_some(),
            "Confirmed result must have triggered_payload"
        );
    }

    #[test]
    fn xss_negative_is_not_confirmed() {
        let result = run_fixture("xss_negative.rs", "run", Cap::HTML_ESCAPE, 15);
        assert_eq!(
            result.status,
            VerifyStatus::NotConfirmed,
            "xss_negative must be NotConfirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn xss_unsupported_is_unsupported() {
        let path = fixture_path("xss_unsupported.rs");
        let mut d = make_diag(&path, "render", Cap::HTML_ESCAPE, 14);
        d.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&d, &opts);
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    #[test]
    fn xss_adversarial_is_inconclusive_collision() {
        let result = run_fixture("xss_adversarial.rs", "run", Cap::HTML_ESCAPE, 999);
        assert_eq!(
            result.status,
            VerifyStatus::Inconclusive,
            "xss_adversarial must be Inconclusive; got {:?}",
            result.status
        );
        assert_eq!(
            result.inconclusive_reason,
            Some(InconclusiveReason::OracleCollisionSuspected),
            "adversarial must be OracleCollisionSuspected"
        );
    }

    // ── Variant fixtures (smoke-test second positive paths) ──────────────────

    #[test]
    fn cmdi_positive2_is_confirmed() {
        let result = run_fixture("cmdi_positive2.rs", "run", Cap::CODE_EXEC, 17);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "cmdi_positive2 must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn fileio_positive2_is_confirmed() {
        let result = run_fixture("fileio_positive2.rs", "run", Cap::FILE_IO, 11);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "fileio_positive2 must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    #[test]
    fn ssrf_positive2_is_confirmed() {
        let result = run_fixture("ssrf_positive2.rs", "run", Cap::SSRF, 7);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "ssrf_positive2 must be Confirmed; got {:?} (detail: {:?})",
            result.status,
            result.detail
        );
    }

    // ── Harness architecture: non-Python-specific gate ───────────────────────

    /// Rust fixture must produce a VerifyResult (not panic or ICE).
    /// This is the Phase 04 acceptance gate: the dynamic pipeline handles
    /// a compiled-language finding without Python-specific assumptions.
    #[test]
    fn rust_pipeline_does_not_panic() {
        let result = run_fixture("sqli_positive.rs", "run", Cap::SQL_QUERY, 18);
        // Any verdict is acceptable; the test asserts non-panic only.
        let _ = result;
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
