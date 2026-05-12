//! End-to-end integration test for the `--verify` / `verify: true` path.
//!
//! Phase M1 has no harness builder (`harness::build` returns `Unimplemented`),
//! so every finding that reaches `verify_finding` collapses to
//! `VerifyStatus::Unsupported` with `reason = BackendUnavailable`. These tests
//! confirm that:
//!
//! 1. `verify_finding` returns the expected `VerifyResult` shape.
//! 2. The JSON serialization of `VerifyResult` contains the expected fields.
//! 3. Findings that cannot derive a spec produce `Unsupported` with a typed
//!    reason (not `BackendUnavailable`), confirming the two code paths are
//!    distinct.
//!
//! Tests are gated on `#[cfg(feature = "dynamic")]` because `verify_finding`
//! lives in the `dynamic` module. Run with `cargo nextest run --features
//! dynamic` to exercise them.

#[cfg(feature = "dynamic")]
mod verify_e2e {
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
    use nyx_scanner::evidence::{Confidence, Evidence, FlowStep, FlowStepKind, UnsupportedReason, VerifyStatus};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};

    fn source_step(file: &str, function: &str) -> FlowStep {
        FlowStep {
            step: 1,
            kind: FlowStepKind::Source,
            file: file.into(),
            line: 1,
            col: 0,
            snippet: None,
            variable: Some("x".into()),
            callee: None,
            function: Some(function.into()),
            is_cross_file: false,
        }
    }

    fn sink_step(file: &str) -> FlowStep {
        FlowStep {
            step: 2,
            kind: FlowStepKind::Sink,
            file: file.into(),
            line: 10,
            col: 0,
            snippet: None,
            variable: None,
            callee: None,
            function: None,
            is_cross_file: false,
        }
    }

    fn taint_diag_with_cap(cap: Cap) -> Diag {
        Diag {
            path: "src/handler.rs".into(),
            line: 10,
            col: 0,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: Some(Confidence::High),
            evidence: Some(Evidence {
                flow_steps: vec![
                    source_step("src/handler.rs", "handle_request"),
                    sink_step("src/handler.rs"),
                ],
                sink_caps: cap.bits(),
                ..Default::default()
            }),
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

    /// Same as `taint_diag_with_cap` but uses a C source file so that
    /// `HarnessSpec::from_finding` derives `Lang::C`, which has no emitter.
    fn taint_diag_c_lang(cap: Cap) -> Diag {
        Diag {
            path: "src/handler.c".into(),
            line: 10,
            col: 0,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: Some(Confidence::High),
            evidence: Some(Evidence {
                flow_steps: vec![
                    source_step("src/handler.c", "handle_request"),
                    sink_step("src/handler.c"),
                ],
                sink_caps: cap.bits(),
                ..Default::default()
            }),
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

    /// A finding with a supported cap (SQL_QUERY) and a derivable spec reaches
    /// `harness::build`. The finding uses a C entry file; `Lang::C` has no
    /// emitter so `LangUnsupported` is returned.
    #[test]
    fn verify_finding_rust_lang_returns_lang_unsupported() {
        let diag = taint_diag_c_lang(Cap::SQL_QUERY);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::LangUnsupported));
        assert!(result.triggered_payload.is_none());
        assert!(result.attempts.is_empty());
    }

    /// A finding with an unsupported cap (CRYPTO has no payload corpus) reaches
    /// `run_spec`, which returns `RunError::NoPayloadsForCap`, producing
    /// `VerifyStatus::Unsupported` with `reason = NoPayloadsForCap`.
    /// This is distinct from `BackendUnavailable` and tests the two code paths.
    #[test]
    fn verify_finding_with_unsupported_cap_returns_no_payloads() {
        let diag = taint_diag_with_cap(Cap::CRYPTO);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::NoPayloadsForCap));
    }

    /// A low-confidence finding is rejected before spec derivation with
    /// `reason = ConfidenceTooLow`.
    #[test]
    fn verify_finding_low_confidence_returns_confidence_too_low() {
        let mut diag = taint_diag_with_cap(Cap::SQL_QUERY);
        diag.confidence = Some(Confidence::Low);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::ConfidenceTooLow));
    }

    /// The JSON shape of `VerifyResult` for a C finding (lang unsupported)
    /// matches the documented contract: `status`, `reason` present;
    /// `triggered_payload`, `detail`, `attempts` absent (skipped by serde).
    #[test]
    fn verify_result_json_shape_lang_unsupported() {
        let diag = taint_diag_c_lang(Cap::SQL_QUERY);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        let json = serde_json::to_string(&result).expect("VerifyResult must serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

        assert_eq!(v["status"], "Unsupported");
        assert_eq!(v["reason"], "LangUnsupported");
        assert!(v.get("triggered_payload").is_none(), "triggered_payload must be absent");
        assert!(v.get("detail").is_none(), "detail must be absent");
        assert!(v.get("attempts").is_none(), "attempts must be absent (empty vec skipped)");
        assert!(v["finding_id"].is_string());
    }
}
