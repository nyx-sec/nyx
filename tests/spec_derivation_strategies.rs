#![allow(clippy::field_reassign_with_default)]
//! Phase 01, Track A.1: integration coverage for
//! `HarnessSpec::from_finding_opts` strategy fall-through.
//!
//! Exercises each `SpecDerivationStrategy` end-to-end:
//!
//! 1. [`FromFlowSteps`]              — explicit flow_steps in evidence.
//! 2. [`FromRuleNamespace`]          — rule id namespace + sink_caps.
//! 3. [`FromFuncSummaryWalk`]        — walking `FuncSummary::tainted_sink_params`.
//! 4. [`FromCallgraphEntry`]         — `*.http.*` rule id → HttpRoute entry.
//!
//! Also asserts that
//! [`crate::evidence::InconclusiveReason::SpecDerivationFailed`] is surfaced
//! when no strategy succeeds but the finding had derivable signal.
//!
//! Gated on `--features dynamic`; the strategy types live in
//! `dynamic::spec` but the `InconclusiveReason` payload is always-present.

#[cfg(feature = "dynamic")]
mod spec_strategies {
    use nyx_scanner::commands::scan::Diag;
    use nyx_scanner::dynamic::spec::{
        EntryKind, EntryKindTag, HarnessSpec, PayloadSlot, SpecDerivationStrategy,
        derive_from_callgraph_entry, derive_from_func_summary, derive_from_rule_namespace,
    };
    use nyx_scanner::dynamic::verify::{VerifyOptions, verify_finding};
    use nyx_scanner::evidence::{
        Confidence, Evidence, FlowStep, FlowStepKind, InconclusiveReason, UnsupportedReason,
        VerifyStatus,
    };
    use nyx_scanner::labels::Cap;
    use nyx_scanner::patterns::{FindingCategory, Severity};
    use nyx_scanner::summary::FuncSummary;

    fn make_diag(id: &str, path: &str, line: usize) -> Diag {
        Diag {
            path: path.into(),
            line,
            col: 0,
            severity: Severity::High,
            id: id.into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: Some(Confidence::High),
            evidence: Some(Evidence::default()),
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

    fn source_step(file: &str, function: &str) -> FlowStep {
        FlowStep {
            step: 1,
            kind: FlowStepKind::Source,
            file: file.into(),
            line: 4,
            col: 0,
            snippet: None,
            variable: Some("payload".into()),
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
            line: 6,
            col: 0,
            snippet: Some("os.system".into()),
            variable: None,
            callee: Some("os.system".into()),
            function: None,
            is_cross_file: false,
        }
    }

    // ── Strategy 1: FromFlowSteps ────────────────────────────────────────────

    #[test]
    fn from_flow_steps_strategy_drives_taint_finding() {
        let mut diag = make_diag(
            "taint-unsanitised-flow (source 4:0)",
            "tests/dynamic_fixtures/spec_strategies/flow_steps_taint.py",
            6,
        );
        let mut ev = Evidence::default();
        ev.flow_steps = vec![
            source_step(
                "tests/dynamic_fixtures/spec_strategies/flow_steps_taint.py",
                "handle_request",
            ),
            sink_step("tests/dynamic_fixtures/spec_strategies/flow_steps_taint.py"),
        ];
        ev.sink_caps = Cap::SHELL_ESCAPE.bits();
        diag.evidence = Some(ev);

        let spec = HarnessSpec::from_finding(&diag).expect("flow_steps strategy must succeed");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromFlowSteps);
        assert_eq!(spec.entry_name, "handle_request");
        assert_eq!(spec.expected_cap, Cap::SHELL_ESCAPE);
    }

    // ── Strategy 2: FromRuleNamespace ────────────────────────────────────────

    #[test]
    fn from_rule_namespace_strategy_drives_ast_finding() {
        let mut diag = make_diag(
            "py.cmdi.os_system",
            "tests/dynamic_fixtures/spec_strategies/rule_namespace_cmdi.py",
            6,
        );
        // Empty flow_steps, but sink_caps set on evidence.
        let mut ev = Evidence::default();
        ev.sink_caps = Cap::SHELL_ESCAPE.bits();
        diag.evidence = Some(ev);

        let spec = HarnessSpec::from_finding(&diag).expect("rule-namespace strategy must succeed");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.expected_cap, Cap::SHELL_ESCAPE);
        assert_eq!(spec.toolchain_id, "python-3");
    }

    #[test]
    fn from_rule_namespace_called_directly_returns_some() {
        let mut diag = make_diag("java.deser.readobject", "src/Main.java", 12);
        let mut ev = Evidence::default();
        ev.sink_caps = Cap::DESERIALIZE.bits();
        diag.evidence = Some(ev.clone());
        let spec = derive_from_rule_namespace(&diag, &ev).expect("must succeed");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.expected_cap, Cap::DESERIALIZE);
    }

    #[test]
    fn from_rule_namespace_pins_rs_auth_to_unauthorized_id() {
        // Regression: `rs.auth.missing_ownership_check.taint` must derive a
        // Rust + UNAUTHORIZED_ID spec via the rule-namespace strategy. The
        // phase 01 deliverables called out `rs.auth.*` as an exemplar but
        // shipped without a regression test pinning the `auth → UNAUTHORIZED_ID`
        // mapping.
        let mut diag = make_diag(
            "rs.auth.missing_ownership_check.taint",
            "src/handler.rs",
            14,
        );
        let mut ev = Evidence::default();
        ev.sink_caps = Cap::UNAUTHORIZED_ID.bits();
        diag.evidence = Some(ev.clone());

        let spec = derive_from_rule_namespace(&diag, &ev)
            .expect("rs.auth rule namespace must derive a spec");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, nyx_scanner::symbol::Lang::Rust);
        assert_eq!(spec.expected_cap, Cap::UNAUTHORIZED_ID);
        assert_eq!(spec.sink_line, 14);
        assert_eq!(spec.toolchain_id, "rust-stable");

        // End-to-end through `HarnessSpec::from_finding` (no flow_steps).
        let spec_end_to_end =
            HarnessSpec::from_finding(&diag).expect("end-to-end derivation must succeed");
        assert_eq!(
            spec_end_to_end.derivation,
            SpecDerivationStrategy::FromRuleNamespace
        );
        assert_eq!(spec_end_to_end.expected_cap, Cap::UNAUTHORIZED_ID);
    }

    // ── Strategy 3: FromFuncSummaryWalk ──────────────────────────────────────

    #[test]
    fn from_func_summary_strategy_picks_first_tainted_param() {
        let mut diag = make_diag(
            "cfg-unguarded-sink",
            "tests/dynamic_fixtures/spec_strategies/func_summary_walk.rs",
            5,
        );
        diag.evidence = Some(Evidence::default());
        let summary = FuncSummary {
            name: "read_path".into(),
            file_path: "tests/dynamic_fixtures/spec_strategies/func_summary_walk.rs".into(),
            lang: "rust".into(),
            param_count: 2,
            param_names: vec!["root".into(), "name".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps: Cap::FILE_IO.bits(),
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: vec![1],
            param_to_sink: vec![],
            callees: vec![],
            container: String::new(),
            disambig: None,
            kind: Default::default(),
            module_path: None,
            rust_use_map: None,
            rust_wildcards: None,
            hierarchy_edges: vec![],
            entry_kind: None,
        };
        let spec = derive_from_func_summary(&diag, diag.evidence.as_ref().unwrap(), Some(&summary))
            .expect("summary strategy must succeed");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromFuncSummaryWalk);
        assert!(matches!(spec.payload_slot, PayloadSlot::Param(1)));
        assert_eq!(spec.entry_name, "read_path");
    }

    // ── Strategy 4: FromCallgraphEntry ───────────────────────────────────────

    #[test]
    fn from_callgraph_entry_strategy_marks_http_route() {
        let mut diag = make_diag(
            "py.http.flask_route",
            "tests/dynamic_fixtures/spec_strategies/callgraph_entry_http.py",
            8,
        );
        let mut ev = Evidence::default();
        ev.sink_caps = Cap::SSRF.bits();
        diag.evidence = Some(ev);

        let spec = HarnessSpec::from_finding(&diag).expect("callgraph-entry strategy must succeed");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromCallgraphEntry);
        assert!(matches!(spec.entry_kind, EntryKind::HttpRoute));
    }

    #[test]
    fn from_callgraph_entry_called_directly_returns_some() {
        let mut diag = make_diag("rs.cli.subcommand_parse", "src/main.rs", 10);
        let mut ev = Evidence::default();
        ev.sink_caps = Cap::SHELL_ESCAPE.bits();
        diag.evidence = Some(ev.clone());

        let spec = derive_from_callgraph_entry(&diag, &ev).expect("must succeed");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromCallgraphEntry);
        assert!(matches!(spec.entry_kind, EntryKind::CliSubcommand));
    }

    // ── Failure path: Inconclusive(SpecDerivationFailed) ─────────────────────

    #[test]
    fn verify_finding_surfaces_inconclusive_when_strategies_exhaust_signal() {
        // Rule namespace identifies a known sink class (`cmdi`), but the path
        // language disagrees with the rule's language and there are no
        // flow_steps to fall back on. Every strategy bails — but the finding
        // had usable signal, so the verifier reports Inconclusive.
        let mut diag = make_diag("py.cmdi.os_system", "src/Main.java", 5);
        let mut ev = Evidence::default();
        ev.sink_caps = Cap::SHELL_ESCAPE.bits();
        diag.evidence = Some(ev);

        let result = verify_finding(&diag, &VerifyOptions::default());
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        match result.inconclusive_reason {
            Some(InconclusiveReason::SpecDerivationFailed { tried, hint }) => {
                assert_eq!(tried.len(), 4);
                assert!(!hint.is_empty(), "hint must summarise the failed inputs");
            }
            other => panic!("expected SpecDerivationFailed, got {other:?}"),
        }
    }

    #[test]
    fn verify_finding_surfaces_unsupported_when_no_signal_at_all() {
        // No evidence struct, no rule namespace, no path. Genuinely
        // unmodellable → Unsupported(NoFlowSteps).
        let diag = make_diag("", "", 0);
        let diag = Diag {
            evidence: None,
            ..diag
        };
        let result = verify_finding(&diag, &VerifyOptions::default());
        assert_eq!(result.status, VerifyStatus::Unsupported);
        assert_eq!(result.reason, Some(UnsupportedReason::NoFlowSteps));
    }

    // ── Strategy ordering ────────────────────────────────────────────────────

    #[test]
    fn strategy_priority_flow_steps_wins_over_rule_namespace() {
        // Both signals present: flow_steps wins because it's first in
        // `HarnessSpec::derivation_strategies()`.
        let mut diag = make_diag(
            "py.cmdi.os_system",
            "tests/dynamic_fixtures/spec_strategies/flow_steps_taint.py",
            6,
        );
        let mut ev = Evidence::default();
        ev.flow_steps = vec![
            source_step(
                "tests/dynamic_fixtures/spec_strategies/flow_steps_taint.py",
                "handle_request",
            ),
            sink_step("tests/dynamic_fixtures/spec_strategies/flow_steps_taint.py"),
        ];
        ev.sink_caps = Cap::SHELL_ESCAPE.bits();
        diag.evidence = Some(ev);
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromFlowSteps);
    }

    // ── Phase 03 acceptance: entry-kind gate produces Inconclusive ───────────

    /// Phase 03 promised that findings whose [`EntryKind`] is not in the
    /// emitter's supported list surface as
    /// `Inconclusive(EntryKindUnsupported { lang, attempted, supported, hint })`
    /// rather than `Unsupported`. End-to-end coverage:
    ///   - construct an HttpRoute spec against a language whose emitter
    ///     does not advertise `HttpRoute` (C, after Phase 16 — the C
    ///     emitter supports `Function`, `CliSubcommand`, `LibraryApi` but
    ///     not `HttpRoute`);
    ///   - drive it through `verify_finding`;
    ///   - assert the verdict shape matches the promise.
    #[test]
    fn entry_kind_gate_promotes_unsupported_to_inconclusive_with_hint() {
        let mut diag = make_diag(
            "c.http.handler",
            "tests/dynamic_fixtures/spec_strategies/callgraph_entry_http.c",
            8,
        );
        let mut ev = Evidence::default();
        ev.sink_caps = Cap::SSRF.bits();
        diag.evidence = Some(ev);

        // Sanity: the spec really does carry an HttpRoute entry kind.
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert!(matches!(spec.entry_kind, EntryKind::HttpRoute));

        let result = verify_finding(&diag, &VerifyOptions::default());
        assert_eq!(
            result.status,
            VerifyStatus::Inconclusive,
            "entry-kind gate must emit Inconclusive; got {:?}",
            result.status
        );
        assert!(
            result.reason.is_none(),
            "Inconclusive verdicts carry inconclusive_reason, not reason; got {:?}",
            result.reason
        );
        match result.inconclusive_reason {
            Some(InconclusiveReason::EntryKindUnsupported {
                lang,
                attempted,
                supported,
                hint,
            }) => {
                assert_eq!(lang, nyx_scanner::symbol::Lang::C);
                assert!(matches!(attempted, EntryKindTag::HttpRoute));
                assert!(
                    !supported.is_empty(),
                    "supported list must be non-empty so operators can triage"
                );
                assert!(
                    supported.contains(&EntryKindTag::Function),
                    "C emitter must advertise Function support; got {supported:?}"
                );
                assert!(
                    !hint.is_empty(),
                    "hint must guide the operator toward the gap"
                );
                assert!(
                    hint.contains("HttpRoute"),
                    "hint must name the attempted entry kind; got {hint:?}"
                );
            }
            other => panic!("expected InconclusiveReason::EntryKindUnsupported, got {other:?}"),
        }
    }
}
