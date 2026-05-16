//! Rust fixture integration tests (Phase 04 acceptance gate).
//!
//! Each fixture is run through the dynamic verification pipeline; its
//! verdict is then compared against the per-fixture golden under
//! `tests/dynamic_fixtures/rust/{name}.golden.json`. Refresh the goldens
//! via `NYX_UPDATE_GOLDENS=1 ./scripts/update_dynamic_goldens.sh`.
//!
//! Run with: `cargo nextest run --features dynamic --test rust_fixtures`.

mod common;

#[cfg(feature = "dynamic")]
mod rust_fixture_tests {
    use crate::common::fixture_harness::{
        run_fixture_and_compare_to_golden, CopyStrategy, FixtureSpec, Prerequisite,
    };
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
    use nyx_scanner::evidence::{
        Confidence, Evidence, FlowStep, FlowStepKind,
    };
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use std::path::{Path, PathBuf};

    fn spec(fixture: &'static str, func: &'static str, cap: Cap, sink_line: u32) -> FixtureSpec<'static> {
        FixtureSpec {
            lang_dir: "rust",
            fixture,
            func,
            cap,
            sink_line,
            confidence: Confidence::High,
            copy: CopyStrategy::RustEntry,
            // Phase 29 (Track I): the Rust harness emitter shells out
            // to `cargo` during verify, so the host must have a Rust
            // toolchain on PATH.  Missing cargo triggers a structured
            // skip rather than a panic.
            requires: vec![Prerequisite::CommandAvailable("cargo")],
        }
    }

    fn low_spec(
        fixture: &'static str,
        func: &'static str,
        cap: Cap,
        sink_line: u32,
    ) -> FixtureSpec<'static> {
        FixtureSpec {
            lang_dir: "rust",
            fixture,
            func,
            cap,
            sink_line,
            confidence: Confidence::Low,
            copy: CopyStrategy::RustEntry,
            // Low-confidence rows short-circuit to
            // `Unsupported(ConfidenceTooLow)` before the harness ever
            // shells out to cargo.
            requires: vec![],
        }
    }

    // ── SQLi ─────────────────────────────────────────────────────────────────

    #[test]
    fn sqli_positive_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("sqli_positive.rs", "run", Cap::SQL_QUERY, 18));
    }

    #[test]
    fn sqli_negative_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("sqli_negative.rs", "run", Cap::SQL_QUERY, 22));
    }

    #[test]
    fn sqli_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec(
            "sqli_unsupported.rs",
            "find_user",
            Cap::SQL_QUERY,
            10,
        ));
    }

    #[test]
    fn sqli_adversarial_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("sqli_adversarial.rs", "run", Cap::SQL_QUERY, 999));
    }

    // ── Command injection ────────────────────────────────────────────────────

    #[test]
    fn cmdi_positive_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("cmdi_positive.rs", "run", Cap::CODE_EXEC, 17));
    }

    #[test]
    fn cmdi_negative_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("cmdi_negative.rs", "run", Cap::CODE_EXEC, 17));
    }

    #[test]
    fn cmdi_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec(
            "cmdi_unsupported.rs",
            "execute",
            Cap::CODE_EXEC,
            9,
        ));
    }

    #[test]
    fn cmdi_adversarial_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("cmdi_adversarial.rs", "run", Cap::CODE_EXEC, 999));
    }

    // ── File I/O ─────────────────────────────────────────────────────────────

    #[test]
    fn fileio_positive_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("fileio_positive.rs", "run", Cap::FILE_IO, 7));
    }

    #[test]
    fn fileio_negative_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("fileio_negative.rs", "run", Cap::FILE_IO, 17));
    }

    #[test]
    fn fileio_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec(
            "fileio_unsupported.rs",
            "read",
            Cap::FILE_IO,
            8,
        ));
    }

    #[test]
    fn fileio_adversarial_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("fileio_adversarial.rs", "run", Cap::FILE_IO, 999));
    }

    // ── SSRF ─────────────────────────────────────────────────────────────────

    #[test]
    fn ssrf_positive_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("ssrf_positive.rs", "run", Cap::SSRF, 7));
    }

    #[test]
    fn ssrf_negative_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("ssrf_negative.rs", "run", Cap::SSRF, 13));
    }

    #[test]
    fn ssrf_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec("ssrf_unsupported.rs", "get", Cap::SSRF, 8));
    }

    #[test]
    fn ssrf_adversarial_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("ssrf_adversarial.rs", "run", Cap::SSRF, 999));
    }

    // ── XSS ──────────────────────────────────────────────────────────────────

    #[test]
    fn xss_positive_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("xss_positive.rs", "run", Cap::HTML_ESCAPE, 11));
    }

    #[test]
    fn xss_negative_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("xss_negative.rs", "run", Cap::HTML_ESCAPE, 15));
    }

    #[test]
    fn xss_unsupported_matches_golden() {
        run_fixture_and_compare_to_golden(&low_spec(
            "xss_unsupported.rs",
            "render",
            Cap::HTML_ESCAPE,
            14,
        ));
    }

    #[test]
    fn xss_adversarial_matches_golden() {
        run_fixture_and_compare_to_golden(&spec(
            "xss_adversarial.rs",
            "run",
            Cap::HTML_ESCAPE,
            999,
        ));
    }

    // ── Smoke-test second positive paths ─────────────────────────────────────

    #[test]
    fn cmdi_positive2_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("cmdi_positive2.rs", "run", Cap::CODE_EXEC, 17));
    }

    #[test]
    fn fileio_positive2_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("fileio_positive2.rs", "run", Cap::FILE_IO, 11));
    }

    #[test]
    fn ssrf_positive2_matches_golden() {
        run_fixture_and_compare_to_golden(&spec("ssrf_positive2.rs", "run", Cap::SSRF, 7));
    }

    // ── Pipeline non-panic gate ──────────────────────────────────────────────

    /// Confirms the Rust pipeline produces a VerifyResult (not a panic/ICE).
    /// Independent of the golden contract: this is a structural assertion.
    #[test]
    fn rust_pipeline_does_not_panic() {
        let _guard = crate::common::fixture_harness::FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/rust/sqli_positive.rs");
        let diag = make_diag(&path, "run", Cap::SQL_QUERY, 18);
        let opts = VerifyOptions::default();
        let _ = verify_finding(&diag, &opts);
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

// ── Phase 16: per-shape acceptance ───────────────────────────────────────────

#[cfg(feature = "dynamic")]
mod phase16_shape_tests {
    use crate::common::fixture_harness::run_shape_fixture_lang;
    use nyx_scanner::dynamic::spec::PayloadSlot;
    use nyx_scanner::evidence::{EntryKind, VerifyResult, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;

    fn rust_available() -> bool {
        std::process::Command::new("cargo")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

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
    ) -> VerifyResult {
        run_shape_fixture_lang(
            Lang::Rust, "rust", shape, file, func, cap, sink_line, kind, slot,
        )
    }

    // ── actix_route ─────────────────────────────────────────────────────────

    #[test]
    fn actix_route_vuln_is_confirmed() {
        if !rust_available() {
            eprintln!("SKIP: cargo not available");
            return;
        }
        let r = run(
            "actix_route", "vuln.rs", "handler", Cap::CODE_EXEC, 16,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        );
        assert_confirmed("actix_route", &r);
    }

    #[test]
    fn actix_route_benign_not_confirmed() {
        if !rust_available() {
            eprintln!("SKIP: cargo not available");
            return;
        }
        let r = run(
            "actix_route", "benign.rs", "handler", Cap::CODE_EXEC, 14,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        );
        assert_not_confirmed("actix_route", &r);
    }

    // ── axum_handler ────────────────────────────────────────────────────────

    #[test]
    fn axum_handler_vuln_is_confirmed() {
        if !rust_available() {
            eprintln!("SKIP: cargo not available");
            return;
        }
        let r = run(
            "axum_handler", "vuln.rs", "handler", Cap::CODE_EXEC, 15,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        );
        assert_confirmed("axum_handler", &r);
    }

    #[test]
    fn axum_handler_benign_not_confirmed() {
        if !rust_available() {
            eprintln!("SKIP: cargo not available");
            return;
        }
        let r = run(
            "axum_handler", "benign.rs", "handler", Cap::CODE_EXEC, 13,
            EntryKind::HttpRoute, PayloadSlot::Param(0),
        );
        assert_not_confirmed("axum_handler", &r);
    }

    // ── clap_cli ────────────────────────────────────────────────────────────

    #[test]
    fn clap_cli_vuln_is_confirmed() {
        if !rust_available() {
            eprintln!("SKIP: cargo not available");
            return;
        }
        let r = run(
            "clap_cli", "vuln.rs", "run", Cap::CODE_EXEC, 17,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        );
        assert_confirmed("clap_cli", &r);
    }

    #[test]
    fn clap_cli_benign_not_confirmed() {
        if !rust_available() {
            eprintln!("SKIP: cargo not available");
            return;
        }
        let r = run(
            "clap_cli", "benign.rs", "run", Cap::CODE_EXEC, 13,
            EntryKind::CliSubcommand, PayloadSlot::Argv(0),
        );
        assert_not_confirmed("clap_cli", &r);
    }

    // ── libfuzzer_target ────────────────────────────────────────────────────

    #[test]
    fn libfuzzer_target_vuln_is_confirmed() {
        if !rust_available() {
            eprintln!("SKIP: cargo not available");
            return;
        }
        let r = run(
            "libfuzzer_target", "vuln.rs", "fuzz_target", Cap::CODE_EXEC, 15,
            EntryKind::LibraryApi, PayloadSlot::Param(0),
        );
        assert_confirmed("libfuzzer_target", &r);
    }

    #[test]
    fn libfuzzer_target_benign_not_confirmed() {
        if !rust_available() {
            eprintln!("SKIP: cargo not available");
            return;
        }
        let r = run(
            "libfuzzer_target", "benign.rs", "fuzz_target", Cap::CODE_EXEC, 13,
            EntryKind::LibraryApi, PayloadSlot::Param(0),
        );
        assert_not_confirmed("libfuzzer_target", &r);
    }
}
