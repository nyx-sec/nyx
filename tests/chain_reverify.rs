//! Phase 26 — Track G.3 integration tests.
//!
//! Exercises the composite re-verification surface end-to-end with a
//! stubbed reverifier so the test runs without a live sandbox backend.
//! Two scenarios:
//!
//! 1. **Composite Confirms**: the stub returns `VerifyStatus::Confirmed`;
//!    the chain's severity is preserved and `reverify_reason` stays
//!    empty.
//! 2. **Composite Inconclusive-downgrades**: the stub returns
//!    `VerifyStatus::Inconclusive`; the chain drops one severity bucket
//!    and records a typed reason on `reverify_reason`.
//!
//! Also covers the `reverify_top_n` cost-control gate and verifies the
//! per-language `compose_chain_step` API surface bottoms out on
//! [`ChainStepHarness::PREV_OUTPUT_ENV`] for every registered emitter.

#![cfg(feature = "dynamic")]

use nyx_scanner::chain::edges::FindingRef;
use nyx_scanner::chain::finding::{ChainFinding, ChainSeverity, ChainSink};
use nyx_scanner::chain::impact::ImpactCategory;
use nyx_scanner::chain::reverify::{
    CompositeReverifier, chain_step_specs, reverify_chain_with, reverify_top_chains_with,
};
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::dynamic::lang::{ChainStepHarness, compose_chain_step};
use nyx_scanner::dynamic::verify::VerifyOptions;
use nyx_scanner::evidence::{InconclusiveReason, UnsupportedReason, VerifyResult, VerifyStatus};
use nyx_scanner::surface::{SourceLocation, SurfaceMap};
use nyx_scanner::symbol::Lang;

fn loc(file: &str, line: u32) -> SourceLocation {
    SourceLocation::new(file, line, 1)
}

fn make_chain(
    hash: u64,
    severity: ChainSeverity,
    impact: ImpactCategory,
    score: f64,
) -> ChainFinding {
    ChainFinding {
        stable_hash: hash,
        members: vec![FindingRef {
            finding_id: format!("f-{hash}"),
            stable_hash: hash,
            location: loc("app.py", 10),
            rule_id: "taint-shell-exec".into(),
            cap_bits: 0,
        }],
        sink: ChainSink {
            file: "app.py".into(),
            line: 30,
            col: 1,
            function_name: "shell.exec".into(),
            cap_bits: 0,
        },
        implied_impact: impact,
        severity,
        score,
        dynamic_verdict: None,
        reverify_reason: None,
    }
}

fn verdict(status: VerifyStatus, reason: Option<InconclusiveReason>) -> VerifyResult {
    VerifyResult {
        finding_id: "f-0".into(),
        status,
        triggered_payload: None,
        reason: None,
        inconclusive_reason: reason,
        detail: None,
        attempts: vec![],
        toolchain_match: None,
        differential: None,
        replay_stable: None,
        wrong: None,
        hardening_outcome: None,
    }
}

struct StubReverifier(VerifyResult);
impl CompositeReverifier for StubReverifier {
    fn reverify(
        &self,
        _chain: &ChainFinding,
        _member_diags: &[Diag],
        _surface: &SurfaceMap,
        _opts: &VerifyOptions,
    ) -> VerifyResult {
        self.0.clone()
    }
}

#[test]
fn composite_confirms_keeps_severity_and_attaches_verdict() {
    let mut chain = make_chain(0xAA, ChainSeverity::Critical, ImpactCategory::Rce, 100.0);
    let surface = SurfaceMap::new();
    let opts = VerifyOptions::default();
    let stub = StubReverifier(verdict(VerifyStatus::Confirmed, None));

    let result = reverify_chain_with(&mut chain, &[], &surface, &opts, &stub);
    assert!(!result.was_downgraded(), "Confirmed must not downgrade");
    assert_eq!(result.severity_before, ChainSeverity::Critical);
    assert_eq!(result.severity_after, ChainSeverity::Critical);
    assert_eq!(chain.severity, ChainSeverity::Critical);
    let attached = chain.dynamic_verdict.as_ref().expect("verdict attached");
    assert_eq!(attached.status, VerifyStatus::Confirmed);
    assert!(chain.reverify_reason.is_none(), "no reason on Confirmed");
}

#[test]
fn composite_inconclusive_downgrades_one_bucket_and_records_reason() {
    let mut chain = make_chain(0xBB, ChainSeverity::Critical, ImpactCategory::Rce, 100.0);
    let surface = SurfaceMap::new();
    let opts = VerifyOptions::default();
    let stub = StubReverifier(verdict(
        VerifyStatus::Inconclusive,
        Some(InconclusiveReason::BuildFailed),
    ));

    let result = reverify_chain_with(&mut chain, &[], &surface, &opts, &stub);
    assert!(result.was_downgraded(), "Inconclusive must downgrade");
    assert_eq!(result.severity_before, ChainSeverity::Critical);
    assert_eq!(result.severity_after, ChainSeverity::High);
    assert_eq!(chain.severity, ChainSeverity::High);
    let reason = chain
        .reverify_reason
        .as_deref()
        .expect("reverify_reason recorded");
    assert!(
        reason.contains("harness build failed"),
        "reason carries typed inconclusive reason; got {reason:?}"
    );
}

#[test]
fn top_n_limits_composite_reverification() {
    let mut chains = vec![
        make_chain(1, ChainSeverity::Critical, ImpactCategory::Rce, 200.0),
        make_chain(2, ChainSeverity::High, ImpactCategory::SessionHijack, 150.0),
        make_chain(
            3,
            ChainSeverity::Medium,
            ImpactCategory::InfoDisclosure,
            100.0,
        ),
        make_chain(4, ChainSeverity::Low, ImpactCategory::InfoDisclosure, 50.0),
    ];
    let surface = SurfaceMap::new();
    let opts = VerifyOptions::default();
    let stub = StubReverifier(verdict(VerifyStatus::Confirmed, None));

    let results = reverify_top_chains_with(&mut chains, &[], &surface, &opts, 2, &stub);
    assert_eq!(results.len(), 2);
    assert!(chains[0].dynamic_verdict.is_some());
    assert!(chains[1].dynamic_verdict.is_some());
    assert!(
        chains[2].dynamic_verdict.is_none(),
        "chain past top_n stays untouched"
    );
    assert!(
        chains[3].dynamic_verdict.is_none(),
        "chain past top_n stays untouched"
    );
}

#[test]
fn compose_chain_step_threads_prev_output_for_every_emitter() {
    // Phase 26 deliverable: each emitter exposes
    // `compose_chain_step(prev_output)`.  Walk the registered languages
    // and check the prev-output env var lands in `extra_env`.
    let prev = b"chain-step-witness".as_slice();
    for lang in [
        Lang::Python,
        Lang::Rust,
        Lang::JavaScript,
        Lang::TypeScript,
        Lang::Go,
        Lang::Java,
        Lang::Php,
        Lang::Ruby,
        Lang::C,
        Lang::Cpp,
    ] {
        let step = compose_chain_step(lang, Some(prev));
        assert!(
            step.extra_env
                .iter()
                .any(|(k, v)| k == ChainStepHarness::PREV_OUTPUT_ENV && v == "chain-step-witness"),
            "{lang:?} emitter must thread NYX_PREV_OUTPUT via extra_env; got {:?}",
            step.extra_env
        );
        assert!(!step.source.is_empty(), "{lang:?} step source must be non-empty");
        assert!(!step.command.is_empty(), "{lang:?} step command must be non-empty");
    }
}

#[test]
fn compose_chain_step_with_no_prev_output_has_empty_extra_env() {
    let step = compose_chain_step(Lang::Python, None);
    assert!(step.extra_env.is_empty());
}

#[test]
fn chain_step_specs_aligns_results_to_member_order_and_reports_missing_diags() {
    let chain = ChainFinding {
        stable_hash: 0x1234,
        members: vec![
            FindingRef {
                finding_id: "f-1".into(),
                stable_hash: 1,
                location: loc("a.py", 10),
                rule_id: "r1".into(),
                cap_bits: 0,
            },
            FindingRef {
                finding_id: "f-2".into(),
                stable_hash: 2,
                location: loc("a.py", 20),
                rule_id: "r2".into(),
                cap_bits: 0,
            },
            FindingRef {
                finding_id: "f-3".into(),
                stable_hash: 3,
                location: loc("a.py", 30),
                rule_id: "r3".into(),
                cap_bits: 0,
            },
        ],
        sink: ChainSink {
            file: "a.py".into(),
            line: 40,
            col: 1,
            function_name: "sink".into(),
            cap_bits: 0,
        },
        implied_impact: ImpactCategory::Rce,
        severity: ChainSeverity::Critical,
        score: 100.0,
        dynamic_verdict: None,
        reverify_reason: None,
    };
    // No diags threaded in — every member misses lookup and records
    // `NoFlowSteps`.  Result order must match member order.
    let opts = VerifyOptions::default();
    let specs = chain_step_specs(&chain, &[], &opts);
    assert_eq!(specs.len(), 3);
    assert_eq!(specs[0].member_hash, 1);
    assert_eq!(specs[1].member_hash, 2);
    assert_eq!(specs[2].member_hash, 3);
    for s in &specs {
        assert!(
            matches!(s.result, Err(UnsupportedReason::NoFlowSteps)),
            "missing-diag fallback got {:?}",
            s.result
        );
    }
}

#[test]
fn default_reverifier_detail_carries_zero_over_member_count() {
    use nyx_scanner::chain::reverify::reverify_chain;
    let mut chain = ChainFinding {
        stable_hash: 0xCAFE,
        members: vec![
            FindingRef {
                finding_id: "f-1".into(),
                stable_hash: 11,
                location: loc("a.py", 1),
                rule_id: "r".into(),
                cap_bits: 0,
            },
            FindingRef {
                finding_id: "f-2".into(),
                stable_hash: 22,
                location: loc("a.py", 2),
                rule_id: "r".into(),
                cap_bits: 0,
            },
        ],
        sink: ChainSink {
            file: "a.py".into(),
            line: 5,
            col: 1,
            function_name: "sink".into(),
            cap_bits: 0,
        },
        implied_impact: ImpactCategory::Rce,
        severity: ChainSeverity::Critical,
        score: 100.0,
        dynamic_verdict: None,
        reverify_reason: None,
    };
    let surface = SurfaceMap::new();
    let opts = VerifyOptions::default();
    let result = reverify_chain(&mut chain, &[], &surface, &opts);
    let detail = result
        .verdict
        .detail
        .as_deref()
        .expect("default reverifier populates detail");
    assert!(
        detail.contains("0/2"),
        "detail must report 0/2 specs derived for the two-member chain; got {detail:?}"
    );
}
