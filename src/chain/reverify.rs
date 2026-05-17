//! Phase 26 — Track G.3: end-to-end chain re-verification.
//!
//! Phase 25 emitted [`ChainFinding`]s scored by static + per-finding
//! feasibility but left `dynamic_verdict` permanently `None`.  Phase 26
//! drives the top-scoring Confirmed chains through a *single* composite
//! dynamic run: each member's step harness is composed via
//! [`crate::dynamic::lang::compose_chain_step`] and the output of one
//! step is threaded into the next via
//! [`crate::dynamic::lang::ChainStepHarness::PREV_OUTPUT_ENV`], with
//! the final step terminating at the chain's sink probe.
//!
//! # Outcome shape
//!
//! [`reverify_chain`] returns a [`ChainReverifyResult`] carrying the
//! composite [`VerifyResult`] alongside the severity before and after
//! the verdict was applied.  The severity-downgrade rule is documented
//! on [`crate::chain::finding::ChainFinding::apply_dynamic_verdict`]:
//! `Inconclusive` drops the chain one bucket and records a reason;
//! every other status leaves the severity intact.
//!
//! # Per-member harness specs
//!
//! Both the default reverifier and out-of-tree callers consume
//! [`chain_step_specs`] to materialise one [`HarnessSpec`] per
//! `chain.members` slot.  The helper looks each member up in the
//! caller-supplied `member_diags` slice by
//! [`crate::chain::edges::FindingRef::stable_hash`] and reuses
//! [`HarnessSpec::from_finding_full`] so the chain's per-step specs
//! match what the per-finding verifier would have derived.  This is
//! the API-shape sub-task of the Phase 26 live-execution split: it
//! lets callers (today: the default reverifier; tomorrow: a live
//! sandbox composer) inspect whether every step is drivable before
//! committing to a build / run pass.
//!
//! # Cost control
//!
//! Re-verification is opt-in via
//! [`crate::utils::config::ChainConfig::reverify_top_n`] — only the top
//! N chains by score reach the composite run.  Set to `0` to skip the
//! pass entirely.  The helper [`reverify_top_chains`] applies the
//! caller's reverifier to the top-N slice in place, leaving the rest
//! untouched.
//!
//! # Testability
//!
//! Production callers use [`reverify_chain`] (which dispatches to
//! [`DefaultCompositeReverifier`]).  Tests inject a stub
//! [`CompositeReverifier`] via [`reverify_chain_with`] /
//! [`reverify_top_chains_with`] so the severity-downgrade pipeline can
//! be exercised without a live sandbox backend.

use crate::chain::finding::{ChainFinding, ChainSeverity};
use crate::commands::scan::Diag;
use crate::dynamic::spec::HarnessSpec;
use crate::dynamic::verify::VerifyOptions;
use crate::evidence::{InconclusiveReason, UnsupportedReason, VerifyResult, VerifyStatus};
use crate::surface::SurfaceMap;
use std::collections::HashMap;

/// Outcome of composite re-verification for a single chain.
///
/// Carries the [`VerifyResult`] the composite run produced plus the
/// severity transition so callers (e.g. the scan command's output
/// pipeline) can decide whether to emit a Slack-style "downgraded by
/// dynamic verification" badge.
#[derive(Debug, Clone)]
pub struct ChainReverifyResult {
    /// Stable hash of the chain re-verified.
    pub chain_hash: u64,
    /// Composite dynamic verdict assembled by the reverifier.
    pub verdict: VerifyResult,
    /// Severity carried on the chain *before* the verdict was applied.
    pub severity_before: ChainSeverity,
    /// Severity carried on the chain *after* the verdict was applied.
    /// Equals `severity_before` unless the verdict was `Inconclusive`.
    pub severity_after: ChainSeverity,
    /// Human-readable downgrade reason, when one was recorded.
    /// Mirrors [`ChainFinding::reverify_reason`] for the post-apply
    /// state.
    pub downgrade_reason: Option<String>,
}

impl ChainReverifyResult {
    /// True when the verdict caused the chain's severity to drop a
    /// bucket.
    pub fn was_downgraded(&self) -> bool {
        self.severity_before != self.severity_after
    }
}

/// Per-member harness-spec derivation result.
///
/// One entry per `chain.members` slot, in chain order.  `member_hash`
/// is copied from the [`crate::chain::edges::FindingRef::stable_hash`];
/// `result` is the outcome of running [`HarnessSpec::from_finding_full`]
/// against the matching [`Diag`] from the caller's slice.
///
/// A member whose hash has no diag match records
/// [`UnsupportedReason::NoFlowSteps`] so the caller can distinguish
/// "spec derivation failed" from "diag missing from the scan input".
#[derive(Debug, Clone)]
pub struct ChainStepSpec {
    pub member_hash: u64,
    pub result: Result<HarnessSpec, UnsupportedReason>,
}

/// Derive one [`HarnessSpec`] per chain member, in chain order.
///
/// Looks each member up in `member_diags` by stable hash (zero-hash
/// diags are skipped — the pre-`compute_stable_hash` placeholder
/// produced by tests and synthetic harnesses).  Members whose hash has
/// no diag match record [`UnsupportedReason::NoFlowSteps`] so the
/// caller can tell the difference between "spec derivation failed" and
/// "diag missing from the scan input".
///
/// The function does **not** run anything: it returns derived specs so
/// the caller (today: [`DefaultCompositeReverifier`]; tomorrow: a live
/// sandbox composer) can decide whether to commit to a build / run
/// pass.  Used as the API-shape half of the Phase 26 live-execution
/// split — see the crate-level docs for the wider design.
pub fn chain_step_specs(
    chain: &ChainFinding,
    member_diags: &[Diag],
    opts: &VerifyOptions,
) -> Vec<ChainStepSpec> {
    let mut by_hash: HashMap<u64, &Diag> = HashMap::with_capacity(member_diags.len());
    for d in member_diags {
        if d.stable_hash != 0 {
            by_hash.insert(d.stable_hash, d);
        }
    }
    chain
        .members
        .iter()
        .map(|m| {
            let result = match by_hash.get(&m.stable_hash).copied() {
                Some(d) => HarnessSpec::from_finding_full(
                    d,
                    opts.verify_all_confidence,
                    opts.summaries.as_deref(),
                    opts.callgraph.as_deref(),
                ),
                None => Err(UnsupportedReason::NoFlowSteps),
            };
            ChainStepSpec {
                member_hash: m.stable_hash,
                result,
            }
        })
        .collect()
}

/// Pluggable composite-reverifier surface.
///
/// Production callers use [`DefaultCompositeReverifier`] (which drives
/// the per-step harness compose path).  Tests substitute a stub that
/// returns canned [`VerifyResult`]s so the downgrade-and-record
/// machinery can be exercised without a live sandbox backend.
///
/// `member_diags` carries the [`Diag`]s that produced `chain.members`,
/// in any order — implementations look them up by
/// [`crate::chain::edges::FindingRef::stable_hash`] via
/// [`chain_step_specs`].  Threading the slice (instead of a pre-built
/// `HashMap`) mirrors how
/// [`crate::dynamic::verify::VerifyOptions::summaries`] flows:
/// callers hold the full project diag list and the trait surface
/// stays free of cross-coupling.
pub trait CompositeReverifier {
    /// Run the composite dynamic re-verification for `chain` and return
    /// the resulting verdict.
    fn reverify(
        &self,
        chain: &ChainFinding,
        member_diags: &[Diag],
        surface: &SurfaceMap,
        opts: &VerifyOptions,
    ) -> VerifyResult;
}

/// Phase 26 default composite reverifier.
///
/// The composite-harness composer walks `chain.members`, derives one
/// [`HarnessSpec`] per member via [`chain_step_specs`], and (in a
/// future session) will call
/// [`crate::dynamic::lang::compose_chain_step`] per step to assemble a
/// per-step harness with `NYX_PREV_OUTPUT` threading.
///
/// Today the default reverifier surfaces
/// `Inconclusive(BackendInsufficient)` when invoked, but the `detail`
/// field reports how many of `chain.members` produced a derivable
/// [`HarnessSpec`] so operators (and the [`reverify_top_chains`]
/// caller) can see the spec-derivation coverage before the live
/// execution path lands.  Callers that need a deterministic outcome
/// (tests, CI) use [`reverify_chain_with`] with a stubbed reverifier.
pub struct DefaultCompositeReverifier;

impl CompositeReverifier for DefaultCompositeReverifier {
    fn reverify(
        &self,
        chain: &ChainFinding,
        member_diags: &[Diag],
        _surface: &SurfaceMap,
        opts: &VerifyOptions,
    ) -> VerifyResult {
        let finding_id = format!("chain-{:016x}", chain.stable_hash);
        let specs = chain_step_specs(chain, member_diags, opts);
        let total = specs.len();
        let derived = specs.iter().filter(|s| s.result.is_ok()).count();
        let detail = format!(
            "composite chain re-verification not yet wired for live runs; derived {derived}/{total} harness specs"
        );
        VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(InconclusiveReason::BackendInsufficient {
                backend: "composite-chain".to_owned(),
                oracle_kind: "chain-step-harness".to_owned(),
            }),
            detail: Some(detail),
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        }
    }
}

/// Phase 26 — Track G.3: drive composite dynamic re-verification for
/// one chain.
///
/// Wraps [`reverify_chain_with`] with the [`DefaultCompositeReverifier`].
pub fn reverify_chain(
    chain: &mut ChainFinding,
    member_diags: &[Diag],
    surface: &SurfaceMap,
    opts: &VerifyOptions,
) -> ChainReverifyResult {
    reverify_chain_with(chain, member_diags, surface, opts, &DefaultCompositeReverifier)
}

/// Inject-the-reverifier flavour of [`reverify_chain`].
///
/// Mutates `chain` in place: attaches the verdict via
/// [`ChainFinding::apply_dynamic_verdict`] (which applies the severity-
/// downgrade rule) and returns a [`ChainReverifyResult`] summarising
/// the transition.
pub fn reverify_chain_with(
    chain: &mut ChainFinding,
    member_diags: &[Diag],
    surface: &SurfaceMap,
    opts: &VerifyOptions,
    reverifier: &dyn CompositeReverifier,
) -> ChainReverifyResult {
    let chain_hash = chain.stable_hash;
    let severity_before = chain.severity;
    let verdict = reverifier.reverify(chain, member_diags, surface, opts);
    chain.apply_dynamic_verdict(verdict.clone());
    ChainReverifyResult {
        chain_hash,
        verdict,
        severity_before,
        severity_after: chain.severity,
        downgrade_reason: chain.reverify_reason.clone(),
    }
}

/// Phase 26 — Track G.3 cost-control entry point.
///
/// Re-verifies the top `top_n` chains by score order (chains are
/// canonicalised score-descending by [`crate::chain::search::find_chains`],
/// so the slice prefix is already the right set).  `top_n == 0`
/// short-circuits the entire pass.
///
/// `member_diags` is the full project diag list — each chain's
/// reverifier looks up its own constituent diags by stable hash via
/// [`chain_step_specs`].
///
/// Mutates `chains` in place; returns one [`ChainReverifyResult`] per
/// re-verified chain.  Chains past the `top_n` cut keep their
/// pre-existing `dynamic_verdict` / `reverify_reason` / `severity`.
pub fn reverify_top_chains(
    chains: &mut [ChainFinding],
    member_diags: &[Diag],
    surface: &SurfaceMap,
    opts: &VerifyOptions,
    top_n: usize,
) -> Vec<ChainReverifyResult> {
    reverify_top_chains_with(
        chains,
        member_diags,
        surface,
        opts,
        top_n,
        &DefaultCompositeReverifier,
    )
}

/// Inject-the-reverifier flavour of [`reverify_top_chains`].
pub fn reverify_top_chains_with(
    chains: &mut [ChainFinding],
    member_diags: &[Diag],
    surface: &SurfaceMap,
    opts: &VerifyOptions,
    top_n: usize,
    reverifier: &dyn CompositeReverifier,
) -> Vec<ChainReverifyResult> {
    if top_n == 0 || chains.is_empty() {
        return Vec::new();
    }
    let bound = top_n.min(chains.len());
    chains
        .iter_mut()
        .take(bound)
        .map(|c| reverify_chain_with(c, member_diags, surface, opts, reverifier))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::edges::FindingRef;
    use crate::chain::finding::{ChainFinding, ChainSink};
    use crate::chain::impact::ImpactCategory;
    use crate::surface::SourceLocation;

    fn mk_chain(hash: u64, severity: ChainSeverity, impact: ImpactCategory) -> ChainFinding {
        ChainFinding {
            stable_hash: hash,
            members: vec![FindingRef {
                finding_id: format!("f-{hash}"),
                stable_hash: hash,
                location: SourceLocation::new("a.py", 1, 1),
                rule_id: "r".into(),
                cap_bits: 0,
            }],
            sink: ChainSink {
                file: "a.py".into(),
                line: 5,
                col: 1,
                function_name: "sink".into(),
                cap_bits: 0,
            },
            implied_impact: impact,
            severity,
            score: 100.0,
            dynamic_verdict: None,
            reverify_reason: None,
        }
    }

    fn verdict(status: VerifyStatus) -> VerifyResult {
        VerifyResult {
            finding_id: "f".into(),
            status,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        }
    }

    struct StubReverifier(VerifyStatus);
    impl CompositeReverifier for StubReverifier {
        fn reverify(
            &self,
            _chain: &ChainFinding,
            _member_diags: &[Diag],
            _surface: &SurfaceMap,
            _opts: &VerifyOptions,
        ) -> VerifyResult {
            verdict(self.0)
        }
    }

    #[test]
    fn confirmed_verdict_leaves_severity_unchanged() {
        let mut chain = mk_chain(1, ChainSeverity::Critical, ImpactCategory::Rce);
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let result = reverify_chain_with(
            &mut chain,
            &[],
            &surface,
            &opts,
            &StubReverifier(VerifyStatus::Confirmed),
        );
        assert!(!result.was_downgraded());
        assert_eq!(result.severity_after, ChainSeverity::Critical);
        assert_eq!(chain.severity, ChainSeverity::Critical);
        assert_eq!(chain.dynamic_verdict.as_ref().unwrap().status, VerifyStatus::Confirmed);
        assert!(chain.reverify_reason.is_none());
    }

    #[test]
    fn inconclusive_verdict_downgrades_severity_and_records_reason() {
        let mut chain = mk_chain(2, ChainSeverity::Critical, ImpactCategory::Rce);
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let result = reverify_chain_with(
            &mut chain,
            &[],
            &surface,
            &opts,
            &StubReverifier(VerifyStatus::Inconclusive),
        );
        assert!(result.was_downgraded());
        assert_eq!(result.severity_before, ChainSeverity::Critical);
        assert_eq!(result.severity_after, ChainSeverity::High);
        assert_eq!(chain.severity, ChainSeverity::High);
        assert!(chain.reverify_reason.is_some());
    }

    #[test]
    fn inconclusive_at_low_floors_at_low() {
        let mut chain = mk_chain(3, ChainSeverity::Low, ImpactCategory::InfoDisclosure);
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let result = reverify_chain_with(
            &mut chain,
            &[],
            &surface,
            &opts,
            &StubReverifier(VerifyStatus::Inconclusive),
        );
        // Severity floors at Low; was_downgraded returns false because
        // the bucket did not change even though the verdict was
        // inconclusive.
        assert_eq!(result.severity_after, ChainSeverity::Low);
        assert!(chain.reverify_reason.is_some(), "reason still recorded");
    }

    #[test]
    fn top_n_zero_skips_pass_entirely() {
        let mut chains = vec![
            mk_chain(1, ChainSeverity::Critical, ImpactCategory::Rce),
            mk_chain(2, ChainSeverity::High, ImpactCategory::SessionHijack),
        ];
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let results = reverify_top_chains_with(
            &mut chains,
            &[],
            &surface,
            &opts,
            0,
            &StubReverifier(VerifyStatus::Confirmed),
        );
        assert!(results.is_empty());
        for c in &chains {
            assert!(c.dynamic_verdict.is_none(), "no verdict attached when top_n=0");
        }
    }

    #[test]
    fn top_n_limits_reverified_chain_count() {
        let mut chains = vec![
            mk_chain(1, ChainSeverity::Critical, ImpactCategory::Rce),
            mk_chain(2, ChainSeverity::High, ImpactCategory::SessionHijack),
            mk_chain(3, ChainSeverity::Medium, ImpactCategory::InfoDisclosure),
        ];
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let results = reverify_top_chains_with(
            &mut chains,
            &[],
            &surface,
            &opts,
            2,
            &StubReverifier(VerifyStatus::Confirmed),
        );
        assert_eq!(results.len(), 2);
        assert!(chains[0].dynamic_verdict.is_some());
        assert!(chains[1].dynamic_verdict.is_some());
        assert!(
            chains[2].dynamic_verdict.is_none(),
            "tail beyond top_n is untouched"
        );
    }

    #[test]
    fn default_reverifier_returns_inconclusive_backend_insufficient() {
        let mut chain = mk_chain(99, ChainSeverity::Critical, ImpactCategory::Rce);
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let result = reverify_chain(&mut chain, &[], &surface, &opts);
        assert_eq!(result.verdict.status, VerifyStatus::Inconclusive);
        assert!(matches!(
            result.verdict.inconclusive_reason,
            Some(InconclusiveReason::BackendInsufficient { .. })
        ));
        // Severity dropped one bucket because the default is inconclusive.
        assert_eq!(chain.severity, ChainSeverity::High);
    }

    #[test]
    fn default_reverifier_detail_reports_spec_derivation_coverage() {
        let mut chain = mk_chain(0xDE, ChainSeverity::High, ImpactCategory::SessionHijack);
        // No diags threaded in — every member should fall through to
        // `NoFlowSteps` and the detail string should report 0/N.
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let result = reverify_chain(&mut chain, &[], &surface, &opts);
        let detail = result.verdict.detail.as_deref().expect("detail populated");
        assert!(
            detail.contains("0/1"),
            "detail must report 0/1 specs derived for a single-member chain with no diags; got {detail:?}"
        );
    }

    #[test]
    fn chain_step_specs_reports_no_flow_steps_for_missing_diag() {
        let chain = mk_chain(7, ChainSeverity::Medium, ImpactCategory::InfoDisclosure);
        let opts = VerifyOptions::default();
        let specs = chain_step_specs(&chain, &[], &opts);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].member_hash, 7);
        assert!(matches!(
            specs[0].result,
            Err(UnsupportedReason::NoFlowSteps)
        ));
    }
}
