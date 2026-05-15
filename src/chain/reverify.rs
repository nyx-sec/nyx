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
use crate::dynamic::verify::VerifyOptions;
use crate::evidence::{InconclusiveReason, VerifyResult, VerifyStatus};
use crate::surface::SurfaceMap;

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

/// Pluggable composite-reverifier surface.
///
/// Production callers use [`DefaultCompositeReverifier`] (which drives
/// the per-step harness compose path).  Tests substitute a stub that
/// returns canned [`VerifyResult`]s so the downgrade-and-record
/// machinery can be exercised without a live sandbox backend.
pub trait CompositeReverifier {
    /// Run the composite dynamic re-verification for `chain` and return
    /// the resulting verdict.
    fn reverify(
        &self,
        chain: &ChainFinding,
        surface: &SurfaceMap,
        opts: &VerifyOptions,
    ) -> VerifyResult;
}

/// Phase 26 default composite reverifier.
///
/// The composite-harness composer walks `chain.members`, calls
/// [`crate::dynamic::lang::compose_chain_step`] for each member's
/// language to assemble a per-step harness, and threads the previous
/// step's stdout into the next via
/// [`crate::dynamic::lang::ChainStepHarness::PREV_OUTPUT_ENV`].
///
/// Today the default reverifier surfaces `Inconclusive(BackendInsufficient)`
/// when invoked: chain composer scaffolding lands in Phase 26 but the
/// live composite execution path depends on the per-emitter probe-shim
/// splicing that several language emitters still defer (see the
/// Phase 06 / 15 / 16 follow-ups in `.pitboss/play/deferred.md`).
/// Callers that need a deterministic outcome (tests, CI) use
/// [`reverify_chain_with`] with a stubbed reverifier.
pub struct DefaultCompositeReverifier;

impl CompositeReverifier for DefaultCompositeReverifier {
    fn reverify(
        &self,
        chain: &ChainFinding,
        _surface: &SurfaceMap,
        _opts: &VerifyOptions,
    ) -> VerifyResult {
        let finding_id = format!("chain-{:016x}", chain.stable_hash);
        VerifyResult {
            finding_id,
            status: VerifyStatus::Inconclusive,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(InconclusiveReason::BackendInsufficient {
                backend: "composite-chain".to_owned(),
                oracle_kind: "chain-step-harness".to_owned(),
            }),
            detail: Some(
                "composite chain re-verification not yet wired for live runs; per-emitter probe-shim splicing pending — see Phase 26 deferred follow-ups"
                    .to_owned(),
            ),
            attempts: vec![],
            toolchain_match: None,
            differential: None,
        }
    }
}

/// Phase 26 — Track G.3: drive composite dynamic re-verification for
/// one chain.
///
/// Wraps [`reverify_chain_with`] with the [`DefaultCompositeReverifier`].
pub fn reverify_chain(
    chain: &mut ChainFinding,
    surface: &SurfaceMap,
    opts: &VerifyOptions,
) -> ChainReverifyResult {
    reverify_chain_with(chain, surface, opts, &DefaultCompositeReverifier)
}

/// Inject-the-reverifier flavour of [`reverify_chain`].
///
/// Mutates `chain` in place: attaches the verdict via
/// [`ChainFinding::apply_dynamic_verdict`] (which applies the severity-
/// downgrade rule) and returns a [`ChainReverifyResult`] summarising
/// the transition.
pub fn reverify_chain_with(
    chain: &mut ChainFinding,
    surface: &SurfaceMap,
    opts: &VerifyOptions,
    reverifier: &dyn CompositeReverifier,
) -> ChainReverifyResult {
    let chain_hash = chain.stable_hash;
    let severity_before = chain.severity;
    let verdict = reverifier.reverify(chain, surface, opts);
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
/// Mutates `chains` in place; returns one [`ChainReverifyResult`] per
/// re-verified chain.  Chains past the `top_n` cut keep their
/// pre-existing `dynamic_verdict` / `reverify_reason` / `severity`.
pub fn reverify_top_chains(
    chains: &mut [ChainFinding],
    surface: &SurfaceMap,
    opts: &VerifyOptions,
    top_n: usize,
) -> Vec<ChainReverifyResult> {
    reverify_top_chains_with(chains, surface, opts, top_n, &DefaultCompositeReverifier)
}

/// Inject-the-reverifier flavour of [`reverify_top_chains`].
pub fn reverify_top_chains_with(
    chains: &mut [ChainFinding],
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
        .map(|c| reverify_chain_with(c, surface, opts, reverifier))
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
        }
    }

    struct StubReverifier(VerifyStatus);
    impl CompositeReverifier for StubReverifier {
        fn reverify(
            &self,
            _chain: &ChainFinding,
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
        let result = reverify_chain(&mut chain, &surface, &opts);
        assert_eq!(result.verdict.status, VerifyStatus::Inconclusive);
        assert!(matches!(
            result.verdict.inconclusive_reason,
            Some(InconclusiveReason::BackendInsufficient { .. })
        ));
        // Severity dropped one bucket because the default is inconclusive.
        assert_eq!(chain.severity, ChainSeverity::High);
    }
}
