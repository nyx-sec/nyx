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
use crate::dynamic::build_sandbox::dispatch_prepare;
use crate::dynamic::harness::{self, BuiltHarness};
use crate::dynamic::lang;
use crate::dynamic::sandbox;
use crate::dynamic::spec::HarnessSpec;
use crate::dynamic::verify::VerifyOptions;
use crate::evidence::{InconclusiveReason, UnsupportedReason, VerifyResult, VerifyStatus};
use crate::surface::SurfaceMap;
use std::collections::HashMap;
use std::path::PathBuf;

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
/// [`HarnessSpec`] per member via [`chain_step_specs`], drives each
/// derived spec through [`harness::build`] + [`dispatch_prepare`] so
/// the per-language build cost is amortised against the on-disk caches,
/// then runs each step sequentially through [`sandbox::run`] with the
/// previous step's stdout threaded into the next step via
/// [`crate::dynamic::lang::ChainStepHarness::PREV_OUTPUT_ENV`].
///
/// Today the default reverifier surfaces
/// `Inconclusive(BackendInsufficient)` when invoked.  The `detail`
/// field reports spec-derivation, per-step build coverage, AND per-
/// step run coverage so operators (and the [`reverify_top_chains`]
/// caller) can see how far down the live execution path the chain
/// got: `derived N/M`, `built B/N (cache_hit=H, build_ms=T,
/// build_errors=E)`, `ran S/B (sandbox_errors=SE, timeouts=TO,
/// nonzero_exits=NE, final_sink_hit=F)`.  Callers that need a
/// deterministic outcome (tests, CI) use [`reverify_chain_with`] with
/// a stubbed reverifier.
///
/// The verdict stays `Inconclusive` even on a fully-successful run
/// pass because today's per-language [`lang::compose_chain_step`]
/// shims echo `NYX_PREV_OUTPUT` to stdout but do not yet invoke the
/// chain's terminal sink — the sink-rewrite pass that wires the final
/// step's probe call lands separately.  Once that pass arrives, the
/// `final_sink_hit=true` branch will flip the verdict to `Confirmed`.
///
/// Languages whose [`dispatch_prepare`] returns `Unsupported`
/// (Ruby today) are counted under `build_errors` and skipped from the
/// run loop; their `compose_chain_step` source is never staged.
///
/// Workdir lifetime: every per-step build is content-addressed by
/// [`HarnessSpec::spec_hash`] under `/tmp/nyx-harness/{spec_hash}`,
/// and the per-language `prepare_*` caches under the host's
/// `ProjectDirs` cache root are keyed on `(lockfile_hash,
/// toolchain_id, language)`.  Repeated calls with the same specs are
/// idempotent — no per-call growth on disk.  The chain-step source
/// (`step.py`, `step.sh`, etc.) is written into the same workdir
/// alongside the harness source; filenames are distinct so they do
/// not collide with [`harness::build`] output for the same spec_hash.
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
        let derived_specs: Vec<&HarnessSpec> = specs
            .iter()
            .filter_map(|s| s.result.as_ref().ok())
            .collect();
        let derived = derived_specs.len();

        // Sub-task (b) main of the Phase 26 live-execution split:
        // drive each derived spec through the per-language build
        // pipeline so each step's interpreter / compile artefact is
        // staged in its content-addressed workdir before the run
        // pass.  Failures are counted, not propagated — the outer
        // verdict stays `Inconclusive(BackendInsufficient)` until
        // the sink-rewrite pass lands.
        let profile = opts.sandbox.process_hardening;
        let mut built = 0usize;
        let mut cache_hits = 0usize;
        let mut total_build_ms: u128 = 0;
        let mut build_errors = 0usize;
        let mut built_steps: Vec<(PathBuf, &HarnessSpec)> = Vec::with_capacity(derived);
        for spec in &derived_specs {
            match harness::build(spec) {
                Ok(built_harness) => {
                    match dispatch_prepare(spec, &built_harness.workdir, profile) {
                        Ok(result) => {
                            built += 1;
                            if result.cache_hit {
                                cache_hits += 1;
                            }
                            total_build_ms = total_build_ms
                                .saturating_add(result.duration.as_millis());
                            built_steps.push((built_harness.workdir, spec));
                        }
                        Err(_) => build_errors += 1,
                    }
                }
                Err(_) => build_errors += 1,
            }
        }

        // Sub-task (c) of the Phase 26 live-execution split:
        // sequentially run each built chain-step harness through
        // `sandbox::run`, threading the previous step's stdout into
        // the next step via `NYX_PREV_OUTPUT`.  The final step's
        // `sink_hit` is captured for the detail field; today it stays
        // false because `compose_chain_step` does not yet rewrite the
        // chain's terminal sink.
        let (steps_run, sandbox_errors, steps_timeout, nonzero_exits, final_sink_hit) =
            run_chain_steps(&built_steps, &opts.sandbox);

        let detail = format!(
            "composite chain re-verification: live runs collect step coverage; \
             derived {derived}/{total} harness specs; \
             built {built}/{derived} (cache_hit={cache_hits}, build_ms={total_build_ms}, build_errors={build_errors}); \
             ran {steps_run}/{built} (sandbox_errors={sandbox_errors}, timeouts={steps_timeout}, nonzero_exits={nonzero_exits}, final_sink_hit={final_sink_hit})"
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

/// Phase 26 sub-task (c): sequentially run each built chain step
/// through [`sandbox::run`] with `NYX_PREV_OUTPUT` threading.
///
/// Returns `(steps_run, sandbox_errors, timeouts, nonzero_exits,
/// final_sink_hit)`.  The final step's [`sandbox::SandboxOutcome::sink_hit`]
/// is captured for the verdict's `detail` field (sub-task (d)); today
/// the per-language [`lang::compose_chain_step`] sources echo
/// `NYX_PREV_OUTPUT` to stdout without invoking the chain's terminal
/// sink, so `final_sink_hit` stays `false` until the sink-rewrite
/// pass lands.
///
/// `sandbox_errors` aborts the rest of the chain — a step that can
/// neither spawn nor stage its source file has no useful `stdout` to
/// thread into the next step.  Non-zero exits and timeouts are
/// recorded but do not stop the chain: the previous step's stdout is
/// still threaded forward so partial-success chains keep collecting
/// coverage.
///
/// `base_opts` is cloned per step; the per-step clone overlays the
/// chain-step's `extra_env` (typically the single `NYX_PREV_OUTPUT`
/// binding) on top of any caller-provided extras and drops the
/// per-finding `stub_harness` because chain-step harnesses do not
/// drive boundary stubs.
fn run_chain_steps(
    built_steps: &[(PathBuf, &HarnessSpec)],
    base_opts: &sandbox::SandboxOptions,
) -> (usize, usize, usize, usize, bool) {
    let mut steps_run = 0usize;
    let mut sandbox_errors = 0usize;
    let mut steps_timeout = 0usize;
    let mut nonzero_exits = 0usize;
    let mut final_sink_hit = false;
    let mut prev_output: Option<Vec<u8>> = None;
    let last_idx = built_steps.len().saturating_sub(1);
    for (idx, (workdir, spec)) in built_steps.iter().enumerate() {
        let step = lang::compose_chain_step(spec.lang, prev_output.as_deref());

        let step_path = workdir.join(&step.filename);
        if let Some(parent) = step_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&step_path, step.source.as_bytes()).is_err() {
            sandbox_errors += 1;
            break;
        }
        let mut extra_files_failed = false;
        for (rel, content) in &step.extra_files {
            let dest = workdir.join(rel);
            if let Some(parent) = dest.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(&dest, content.as_bytes()).is_err() {
                extra_files_failed = true;
                break;
            }
        }
        if extra_files_failed {
            sandbox_errors += 1;
            break;
        }

        let mut step_opts = base_opts.clone();
        step_opts.extra_env.extend(step.extra_env.iter().cloned());
        step_opts.stub_harness = None;

        let step_built = BuiltHarness {
            workdir: workdir.clone(),
            command: step.command.clone(),
            env: vec![],
            source: step.source.clone(),
            entry_source: String::new(),
        };

        match sandbox::run(&step_built, b"", &step_opts) {
            Ok(outcome) => {
                steps_run += 1;
                if outcome.timed_out {
                    steps_timeout += 1;
                }
                if outcome.exit_code.unwrap_or(-1) != 0 {
                    nonzero_exits += 1;
                }
                if idx == last_idx {
                    final_sink_hit = outcome.sink_hit;
                }
                prev_output = Some(outcome.stdout);
            }
            Err(_) => {
                sandbox_errors += 1;
                break;
            }
        }
    }
    (steps_run, sandbox_errors, steps_timeout, nonzero_exits, final_sink_hit)
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
    fn default_reverifier_detail_reports_build_coverage_with_no_derived_specs() {
        // No diags → 0/N derived → 0/0 built.  Verifies the build
        // segment of the detail string is well-formed even when the
        // build pipeline is never invoked.
        let mut chain = mk_chain(0xBD, ChainSeverity::Medium, ImpactCategory::InfoDisclosure);
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let result = reverify_chain(&mut chain, &[], &surface, &opts);
        let detail = result.verdict.detail.as_deref().expect("detail populated");
        assert!(
            detail.contains("built 0/0"),
            "detail must report 0/0 built when no specs derived; got {detail:?}"
        );
        assert!(
            detail.contains("cache_hit=0"),
            "detail must zero cache_hit when no builds attempted; got {detail:?}"
        );
        assert!(
            detail.contains("build_ms=0"),
            "detail must zero build_ms when no builds attempted; got {detail:?}"
        );
        assert!(
            detail.contains("build_errors=0"),
            "detail must zero build_errors when no builds attempted; got {detail:?}"
        );
    }

    #[test]
    fn default_reverifier_detail_reports_run_coverage_with_no_built_steps() {
        // No diags → 0/N derived → 0/0 built → 0/0 ran.  Verifies the
        // run-coverage segment of the detail string is well-formed
        // even when the chain-step run loop is never entered.
        let mut chain = mk_chain(0xCD, ChainSeverity::Medium, ImpactCategory::InfoDisclosure);
        let surface = SurfaceMap::new();
        let opts = VerifyOptions::default();
        let result = reverify_chain(&mut chain, &[], &surface, &opts);
        let detail = result.verdict.detail.as_deref().expect("detail populated");
        assert!(
            detail.contains("ran 0/0"),
            "detail must report 0/0 ran when no specs built; got {detail:?}"
        );
        assert!(
            detail.contains("sandbox_errors=0"),
            "detail must zero sandbox_errors when no runs attempted; got {detail:?}"
        );
        assert!(
            detail.contains("timeouts=0"),
            "detail must zero timeouts when no runs attempted; got {detail:?}"
        );
        assert!(
            detail.contains("nonzero_exits=0"),
            "detail must zero nonzero_exits when no runs attempted; got {detail:?}"
        );
        assert!(
            detail.contains("final_sink_hit=false"),
            "detail must stamp final_sink_hit=false when no runs attempted; got {detail:?}"
        );
    }

    #[test]
    fn run_chain_steps_with_empty_input_is_a_no_op() {
        // Locks the contract that the run loop is a no-op when no
        // steps built — the run-coverage detail segment is wholly a
        // function of the (steps_run, sandbox_errors, timeouts,
        // nonzero_exits, final_sink_hit) tuple this helper returns.
        let opts = sandbox::SandboxOptions::default();
        let result = run_chain_steps(&[], &opts);
        assert_eq!(result, (0, 0, 0, 0, false));
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
