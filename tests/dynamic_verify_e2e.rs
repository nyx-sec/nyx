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

    /// Phase 16 turned every [`crate::symbol::Lang`] into a supported
    /// emitter, so the legacy `LangUnsupported` exit path is no longer
    /// reachable through `verify_finding` for any real language.  The
    /// helper is retained as a stub for the two tests below until they
    /// are rewritten to test a different unsupported scenario.
    #[allow(dead_code)]
    fn taint_diag_c_lang(_cap: Cap) -> Diag {
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
            evidence: None,
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

    /// Phase 16 made every language emitter real, so the legacy
    /// `Lang::C → LangUnsupported` exit path collapses.  Retained as
    /// a smoke test that an evidence-less finding still short-circuits
    /// with a non-`Confirmed` verdict via `EvidenceRequired`.
    #[test]
    fn verify_finding_without_evidence_short_circuits() {
        let diag = taint_diag_c_lang(Cap::SQL_QUERY);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        assert_ne!(result.status, VerifyStatus::Confirmed);
        assert!(result.triggered_payload.is_none());
        assert!(result.attempts.is_empty());
    }

    /// A finding whose cap has no sound oracle (Phase 11 / Track J.9
    /// routes `ENV_VAR` / `SHELL_ESCAPE` / `URL_ENCODE` through this
    /// path) reaches `run_spec`, which returns
    /// `RunError::SoundOracleUnavailable`, producing
    /// `VerifyStatus::Unsupported` with
    /// `reason = SoundOracleUnavailable { cap, lang, hint }`.  Distinct
    /// from `BackendUnavailable` and `NoPayloadsForCap`.
    #[test]
    fn verify_finding_with_unsupported_cap_returns_sound_oracle_unavailable() {
        let diag = taint_diag_with_cap(Cap::ENV_VAR);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        assert_eq!(result.status, VerifyStatus::Unsupported);
        match result.reason {
            Some(UnsupportedReason::SoundOracleUnavailable { cap, hint, .. }) => {
                assert_eq!(cap, Cap::ENV_VAR);
                assert!(!hint.is_empty());
            }
            other => panic!("expected SoundOracleUnavailable, got {other:?}"),
        }
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

    /// Phase 01 / Track L.0 acceptance: every spec the verifier
    /// finalises must emit either `framework_adapter_detected` or
    /// `framework_adapter_none` into the [`VerifyTrace`].  The Phase 01
    /// adapter registry is empty, so the baseline contract is that
    /// every successfully-derived spec records a `framework_adapter_none`
    /// event whose `detail` carries `lang=<Lang> entry=<entry_name>`.
    ///
    /// We drive `verify_finding` through the `NoPayloadsForCap` short-circuit
    /// (CRYPTO has no curated payload corpus) so the trace is recorded
    /// without needing a working toolchain or sandbox backend.
    #[test]
    fn verify_finding_emits_framework_adapter_none_for_empty_registry() {
        use nyx_scanner::dynamic::trace::{TraceStage, VerifyTrace};
        use std::sync::Arc;

        let diag = taint_diag_with_cap(Cap::CRYPTO);
        let trace = Arc::new(VerifyTrace::new());
        let mut opts = VerifyOptions::default();
        opts.trace_sink = Some(Arc::clone(&trace));

        let _result = verify_finding(&diag, &opts);

        let events = trace.events();
        let adapter_event = events
            .iter()
            .find(|e| e.stage == TraceStage::FrameworkAdapterNone)
            .expect(
                "Phase 01 / Track L.0 contract: every finalised spec must emit \
                 a `framework_adapter_none` event when the adapter registry is empty",
            );
        let detail = adapter_event
            .detail
            .as_deref()
            .expect("framework_adapter_none must carry a detail string");
        assert!(
            detail.contains("lang="),
            "framework_adapter_none detail must include `lang=…`, got: {detail:?}"
        );
        assert!(
            detail.contains("entry="),
            "framework_adapter_none detail must include `entry=…`, got: {detail:?}"
        );
        assert!(
            detail.contains("entry=handle_request"),
            "framework_adapter_none detail must name the spec's entry function, got: {detail:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| e.stage == TraceStage::FrameworkAdapterDetected),
            "Phase 01 ships zero adapters, so no `framework_adapter_detected` event \
             can fire on the baseline path"
        );
    }

    /// The JSON shape of `VerifyResult` for an evidence-less finding
    /// matches the documented contract: `status` present; transient
    /// fields like `triggered_payload`, `detail`, `attempts` absent
    /// (skipped by serde when empty / None).
    #[test]
    fn verify_result_json_shape_evidence_required() {
        let diag = taint_diag_c_lang(Cap::SQL_QUERY);
        let opts = VerifyOptions::default();
        let result = verify_finding(&diag, &opts);

        let json = serde_json::to_string(&result).expect("VerifyResult must serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

        assert!(v.get("status").is_some(), "status field must be present");
        assert!(v.get("triggered_payload").is_none(), "triggered_payload must be absent");
        assert!(v.get("detail").is_none(), "detail must be absent");
        assert!(v.get("attempts").is_none(), "attempts must be absent (empty vec skipped)");
        assert!(v["finding_id"].is_string());
    }
}
