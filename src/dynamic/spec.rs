//! Harness specification: the bridge between a static finding and a runnable harness.
//!
//! A [`HarnessSpec`] is built from a [`crate::commands::scan::Diag`] without
//! any further analysis. It records what the dynamic side needs to know:
//! which entry point to drive, which parameter carries the payload, what
//! sink (cap) we expect to hit, and which language toolchain to use.
//!
//! Construction is total but may return `Err` when the finding lacks the
//! evidence required to drive it dynamically (confidence too low, no source
//! span, no callable entry, sink in dead code, etc.). Those findings stay
//! static-only.
//!
//! # Versioning
//!
//! [`SPEC_FORMAT_VERSION`] is baked into every [`HarnessSpec::spec_hash`].
//! Bump it — and update `compute_spec_hash` — whenever any field changes
//! meaning, the hash inputs change, or the corpus changes in a way that
//! would invalidate previously-computed hashes.

use crate::callgraph::{CallGraph, CallGraphAnalysis};
use crate::commands::scan::Diag;
use crate::dynamic::corpus::CORPUS_VERSION;
use crate::dynamic::framework::{FrameworkBinding, FrameworkDetectionContext, ProjectFileIndex};
use crate::dynamic::stubs::StubKind;
use crate::evidence::{Confidence, FlowStepKind, UnsupportedReason};
use crate::labels::Cap;
use crate::summary::{FuncSummary, GlobalSummaries};
use crate::symbol::{FuncKey, Lang};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// Re-export of the always-present [`crate::evidence::SpecDerivationStrategy`].
///
/// The canonical definition lives in `evidence.rs` so that
/// [`crate::evidence::InconclusiveReason::SpecDerivationFailed`] can carry a
/// `Vec` of attempted strategies without depending on the `dynamic` feature.
pub use crate::evidence::SpecDerivationStrategy;

/// Bump whenever [`HarnessSpec`] fields change meaning or the spec hash
/// inputs change. Downstream tools should reject specs with an unrecognised
/// version.
pub const SPEC_FORMAT_VERSION: u32 = 2;

/// Identifies the entry point extracted from a taint flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRef {
    /// Project-relative path of the file containing the entry function.
    pub file: String,
    /// Name of the entry function (unqualified).
    pub function: String,
}

/// Re-export of [`crate::evidence::EntryKind`].
///
/// The canonical definition lives in `evidence.rs` so that
/// [`crate::evidence::InconclusiveReason::EntryKindUnsupported`] can name the
/// attempted / supported variants without depending on the `dynamic` feature.
pub use crate::evidence::EntryKind;

/// Re-export of [`crate::evidence::EntryKindTag`].
///
/// The discriminant tag used by every site that needs a `Copy + Hash`
/// handle to an `EntryKind`: supported-set lookups, the
/// [`crate::evidence::InconclusiveReason::EntryKindUnsupported`] fields,
/// the lang-emitter trait surface.
pub use crate::evidence::EntryKindTag;

/// Where the payload goes when the harness fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadSlot {
    /// Nth positional parameter of the entry function.
    Param(usize),
    /// Named HTTP query parameter.
    QueryParam(String),
    /// HTTP request body (raw bytes).
    HttpBody,
    /// Environment variable.
    EnvVar(String),
    /// CLI argv slot (0-based, excluding argv[0]).
    Argv(usize),
    /// stdin.
    Stdin,
}

/// Self-contained recipe for building and running a single harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessSpec {
    /// Stable id of the source finding (`Diag::stable_hash` as hex).
    pub finding_id: String,
    /// Project-relative path to the file holding the entry point.
    pub entry_file: String,
    /// Function/route/subcommand name to drive.
    pub entry_name: String,
    /// How to invoke it.
    pub entry_kind: EntryKind,
    /// Source language (drives toolchain selection).
    pub lang: Lang,
    /// Toolchain identifier string (e.g. `"rust-stable"`, `"node-20"`).
    /// Informational; harness builder may override for local installs.
    pub toolchain_id: String,
    /// Where the payload is injected.
    pub payload_slot: PayloadSlot,
    /// Sink capability we expect to fire (drives oracle + corpus pick).
    pub expected_cap: Cap,
    /// Optional symex-derived constraint hints (prefix/suffix locks, etc.).
    /// Populated later from `Evidence::engine_notes` when available.
    #[serde(default)]
    pub constraint_hints: Vec<String>,
    /// Project-relative path of the file containing the sink call site.
    /// Used by the harness emitter to instrument the exact line.
    pub sink_file: String,
    /// 1-based line number of the sink call site in `sink_file`.
    pub sink_line: u32,
    /// Blake3 hash (16 hex chars) of the spec's key fields, version-pinned.
    /// Stable across identical specs; used for deduplication and caching.
    pub spec_hash: String,
    /// Which derivation strategy produced this spec. Populated by
    /// [`HarnessSpec::from_finding_opts`]; default for backward compatibility
    /// with deserialised specs that pre-date the typed strategy.
    #[serde(default = "default_derivation_strategy")]
    pub derivation: SpecDerivationStrategy,
    /// Stubs the verifier must spawn before the sandbox runs (Phase 10 —
    /// Track D.3).  Derived from [`Self::expected_cap`] via
    /// [`StubKind::for_cap`] at spec-construction time so the verifier
    /// only starts the boundaries a payload actually needs — a Cap that
    /// auto-derives no stub leaves this empty and
    /// [`crate::dynamic::stubs::StubHarness::start`] is a no-op (the
    /// "harness with `stubs_required: []` boots in under 500ms"
    /// performance invariant).
    ///
    /// `#[serde(default)]` so specs persisted by pre-Phase-10 versions of
    /// the cache deserialise as an empty list.
    #[serde(default)]
    pub stubs_required: Vec<StubKind>,
    /// Track L.0 — framework binding recovered for the entry function
    /// (route shape, request slots, response writer, middleware chain).
    ///
    /// Populated by [`crate::dynamic::framework::detect_binding`] when
    /// a registered [`crate::dynamic::framework::FrameworkAdapter`]
    /// matches the resolved entry; `None` when no adapter matches or
    /// when the spec-derivation path lacks the AST context required
    /// to dispatch.  Phase 01 ships with an empty adapter registry so
    /// this field is `None` for every spec; subsequent Track-L phases
    /// register adapters and back-fill the binding.
    ///
    /// Excluded from [`compute_spec_hash`]: the binding is descriptive
    /// metadata derived from the entry function and does not change
    /// the harness boundary topology that the spec hash protects.
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` so
    /// pre-Phase-01 serialised specs deserialise unchanged and an
    /// absent binding does not bloat repro-bundle JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<FrameworkBinding>,
    /// Phase 14 (Track L.12) — per-Java-shape toolchain knobs.  The
    /// Java emitter consults [`JavaToolchain::with_spring_test`] to
    /// decide whether to bootstrap a full Spring test context
    /// (`SpringApplication.run` + `MockMvc`) or the lighter
    /// reflective invocation path the legacy shapes use.  Populated
    /// by [`attach_framework_binding`] when the `java-spring`
    /// adapter binds.
    ///
    /// Excluded from [`compute_spec_hash`] for the same reason as
    /// `framework`: the toggle is descriptive metadata driven by the
    /// adapter binding, not a per-spec boundary topology axis.
    /// Pre-Phase-14 serialised specs deserialise to the default
    /// (`with_spring_test = false`).
    #[serde(default, skip_serializing_if = "JavaToolchain::is_default")]
    pub java_toolchain: JavaToolchain,
}

/// Phase 14 (Track L.12) — per-shape Java toolchain knobs.
///
/// Today the only knob is [`Self::with_spring_test`]; future Java
/// frameworks (Quarkus / Micronaut / Servlet) reuse this struct so
/// their per-shape build inputs (`@QuarkusTest`, `@MicronautTest`,
/// embedded `Server` jars) can be added without re-versioning the
/// spec format.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaToolchain {
    /// True when the harness should bootstrap a Spring test context
    /// (`SpringApplication.run` + `MockMvc`) before invoking the
    /// handler.  Other Java shapes (Quarkus / Micronaut / Servlet)
    /// keep this flag `false` and rely on the framework's own
    /// embedded server / reflective invocation path.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub with_spring_test: bool,
}

impl JavaToolchain {
    /// True when the struct equals [`JavaToolchain::default`].
    /// Used as the `skip_serializing_if` predicate so a default-only
    /// toolchain does not bloat repro-bundle JSON.
    pub fn is_default(&self) -> bool {
        !self.with_spring_test
    }
}

fn default_derivation_strategy() -> SpecDerivationStrategy {
    SpecDerivationStrategy::FromFlowSteps
}

/// Phase 25 (Track K.0) — the optional cross-file context consulted by the
/// multi-strategy scoring derivation.
///
/// Bundles the three inputs every scored strategy and the cross-file source
/// seeding read, so the public [`HarnessSpec::derive_best`] /
/// [`HarnessSpec::derive_all_strategies`] surface takes one borrowable
/// context rather than three positional `Option`s.  Cheap to copy (two
/// references + a bool).
#[derive(Clone, Copy)]
pub struct SpecDerivationCtx<'a> {
    /// When true, skip the `Confidence >= Medium` gate so low-confidence
    /// findings are still attempted.
    pub verify_all_confidence: bool,
    /// Cross-file function summaries (`FuncSummary` + `SsaFuncSummary`),
    /// shared by every finding in a scan.
    pub summaries: Option<&'a GlobalSummaries>,
    /// Whole-program call graph used for reverse-edge entry resolution and
    /// cross-file source seeding.
    pub callgraph: Option<&'a CallGraph>,
}

impl<'a> SpecDerivationCtx<'a> {
    /// Construct a context from the three positional inputs the legacy
    /// `from_finding_*` constructors take.
    pub fn new(
        verify_all_confidence: bool,
        summaries: Option<&'a GlobalSummaries>,
        callgraph: Option<&'a CallGraph>,
    ) -> Self {
        Self {
            verify_all_confidence,
            summaries,
            callgraph,
        }
    }
}

/// Phase 25 (Track K.0) — one scored derivation candidate.
///
/// Produced by [`HarnessSpec::derive_all_strategies`]; carries both the
/// built [`HarnessSpec`] and the [`SpecDerivationStrategy`] that produced
/// it.  The strategy tag is retained alongside `spec.derivation` (which
/// holds the same value) so the loser-ranking telemetry can report the tag
/// without unwrapping the spec.
#[derive(Debug, Clone)]
pub struct SpecCandidate {
    /// The derived harness recipe.
    pub spec: HarnessSpec,
    /// Which strategy produced [`Self::spec`].
    pub strategy: SpecDerivationStrategy,
}

/// Phase 25 (Track K.0) — lexicographic score for a candidate spec.
///
/// Field declaration order *is* the comparison priority: the derived
/// [`Ord`] compares `flow_depth` first, then `framework_bound`, then
/// `cross_file_resolved`, then `payloads_available`.  Higher is better, so
/// [`HarnessSpec::derive_best`] picks the candidate whose score is the
/// maximum.  `bool` orders `false < true`, so a framework-bound /
/// cross-file-resolved / payload-backed candidate outscores one that is
/// not, all else equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpecScore {
    /// Flow-step depth the spec covers: `evidence.flow_steps.len()` plus a
    /// hop when the entry was rewritten to an ancestor function (the
    /// callgraph-walk strategies cover more of the call chain than the
    /// helper that physically contains the sink).
    pub flow_depth: u32,
    /// A [`FrameworkBinding`] was attached to the spec.
    pub framework_bound: bool,
    /// The spec's entry resolves to a different file than the sink — the
    /// source was recovered across a file boundary.
    pub cross_file_resolved: bool,
    /// The `(expected_cap, lang)` pair has at least one curated payload, so
    /// the verifier has something to fire.
    pub payloads_available: bool,
}

impl HarnessSpec {
    /// Build a spec from a finding. Returns `Err` with a typed reason when
    /// the finding cannot be driven dynamically.
    ///
    /// Conditions for `Err` return:
    /// - Confidence below `Medium` (bypass with `from_finding_opts(diag, true)`)
    /// - No `flow_steps` in evidence
    /// - No callable entry (source step missing a `function` annotation)
    /// - Unknown language (file extension unrecognised)
    /// - Zero sink capability bits
    pub fn from_finding(diag: &Diag) -> Result<Self, UnsupportedReason> {
        Self::from_finding_opts(diag, false)
    }

    /// Like `from_finding`, but with `verify_all_confidence=true` the
    /// `Confidence >= Medium` gate is skipped so low-confidence findings
    /// are also attempted.
    ///
    /// Returns `Err(UnsupportedReason::ConfidenceTooLow)` immediately when
    /// the confidence gate fails. Otherwise tries each
    /// [`SpecDerivationStrategy`] in order:
    /// [`SpecDerivationStrategy::FromFlowSteps`],
    /// [`SpecDerivationStrategy::FromRuleNamespace`],
    /// [`SpecDerivationStrategy::FromFuncSummaryWalk`],
    /// [`SpecDerivationStrategy::FromCallgraphEntry`]. The first non-error
    /// strategy wins and its tag is stored on `spec.derivation`.
    ///
    /// Returns `Err(UnsupportedReason::NoFlowSteps)` only when no evidence is
    /// present at all. When evidence exists but every strategy fails, the
    /// caller is expected to surface the failure as
    /// [`crate::evidence::InconclusiveReason::SpecDerivationFailed`] —
    /// this method returns `Err(UnsupportedReason::SpecDerivationFailed)`
    /// in that case, and `verify_finding` decides whether to lift it to
    /// `Inconclusive` based on whether any strategy was actually tried.
    pub fn from_finding_opts(
        diag: &Diag,
        verify_all_confidence: bool,
    ) -> Result<Self, UnsupportedReason> {
        Self::from_finding_with_summaries(diag, verify_all_confidence, None)
    }

    /// Strategy-aware constructor that consults `summaries` when present.
    ///
    /// When `summaries` is `Some`, strategy 3 ([`SpecDerivationStrategy::FromFuncSummaryWalk`])
    /// looks up the enclosing function's [`FuncSummary`] by `(lang, name, file)`
    /// — derived from `evidence.flow_steps[*].function` — and pulls a real
    /// `tainted_sink_params` slot rather than no-op'ing as it does in the
    /// `None` path. Strategy 4 additionally upgrades the
    /// `.http.` / `.cli.` substring heuristic by consulting
    /// [`FuncSummary::entry_kind`] on the resolved summary; an HTTP-shaped
    /// entry-kind variant becomes `EntryKind::HttpRoute` regardless of the
    /// rule id, and the legacy substring fallback runs only when no summary
    /// is found.
    ///
    /// The `entry_name` populated by strategies 2 and 4 is also resolved
    /// from `evidence.flow_steps[*].function` (the authoritative enclosing
    /// function annotation set by the SSA taint engine) rather than from
    /// `evidence.sink.snippet` / `evidence.source.snippet`, which carry
    /// shortened callee text — never the enclosing-function name.
    pub fn from_finding_with_summaries(
        diag: &Diag,
        verify_all_confidence: bool,
        summaries: Option<&GlobalSummaries>,
    ) -> Result<Self, UnsupportedReason> {
        Self::from_finding_full(diag, verify_all_confidence, summaries, None)
    }

    /// Strategy-aware constructor that also consults a whole-program
    /// [`CallGraph`] when `callgraph` is `Some`.
    ///
    /// Strategy 4 ([`SpecDerivationStrategy::FromCallgraphEntry`]) walks
    /// reverse call-graph edges from the sink's enclosing function via
    /// [`crate::callgraph::callers_of`] to discover the *nearest* ancestor
    /// that qualifies as an entry point (see [`is_entry_point`]). When
    /// found, the spec's `entry_file` / `entry_name` are rewritten to the
    /// ancestor and `entry_kind` is classified from the ancestor's
    /// [`FuncSummary::entry_kind`] — capturing every framework-bound sink
    /// whose only real caller is a route decorator or CLI subcommand.
    ///
    /// When `callgraph` is `None` the behaviour matches
    /// [`HarnessSpec::from_finding_with_summaries`] verbatim: strategy 4
    /// falls back to the rule-id substring / summary-entry-kind path.
    /// When `summaries` is `None` the callgraph walk has no per-key
    /// summary to consult and degrades to a name-based entry recogniser
    /// (`main` / `__main__`).
    pub fn from_finding_full(
        diag: &Diag,
        verify_all_confidence: bool,
        summaries: Option<&GlobalSummaries>,
        callgraph: Option<&CallGraph>,
    ) -> Result<Self, UnsupportedReason> {
        // Phase 25 (Track K.0): the legacy sequential first-match ladder is
        // now a thin wrapper over the multi-strategy scoring path. Every
        // strategy this method used to try in priority order is still run by
        // `derive_all_strategies`; `derive_best` scores them and the
        // ascending-precedence ordering reproduces the old tie-break
        // (strict callgraph walk > flow_steps > rule_namespace >
        // func_summary > callgraph fallback) when scores are equal.
        let ctx = SpecDerivationCtx::new(verify_all_confidence, summaries, callgraph);
        Self::derive_best(diag, &ctx)
    }

    /// Convenience wrapper around [`HarnessSpec::from_finding_full`] that
    /// pins `verify_all_confidence = false` and accepts only callgraph
    /// context. Used by the verifier when the caller has built a fresh
    /// [`CallGraph`] but not yet plumbed the matching
    /// [`GlobalSummaries`]; in that mode the callgraph walk degrades to
    /// the name-based entry recogniser.
    ///
    /// The `analysis` argument is accepted to pin the API surface against
    /// future SCC-aware refinements (e.g. bounding the reverse-edge BFS
    /// against the analysis's pre-computed back edges); the current
    /// implementation does not consult it because the BFS already
    /// protects against recursive predecessor chains via its visited
    /// set.
    pub fn from_finding_with_callgraph(
        diag: &Diag,
        callgraph: &CallGraph,
        _analysis: &CallGraphAnalysis,
    ) -> Result<Self, UnsupportedReason> {
        Self::from_finding_full(diag, false, None, Some(callgraph))
    }

    /// True when [`HarnessSpec::entry_kind`] is in
    /// [`crate::dynamic::lang::entry_kinds_supported`] for [`HarnessSpec::lang`].
    ///
    /// Strategies 1–4 may stamp non-`Function` entry kinds (route handlers,
    /// CLI subcommands) onto the spec when the rule namespace or the
    /// resolved [`crate::summary::FuncSummary`] indicates the enclosing
    /// function is externally driven; not every lang emitter understands
    /// those shapes yet (Tracks B.12–B.16 add them per language).  The
    /// verifier consults this gate so unsupported shapes route to
    /// [`crate::evidence::InconclusiveReason::EntryKindUnsupported`] with a
    /// concrete supported list and hint, rather than degrading silently to
    /// `Unsupported`.
    pub fn entry_kind_is_supported(&self) -> bool {
        let supported = crate::dynamic::lang::entry_kinds_supported(self.lang);
        supported.contains(&self.entry_kind.tag())
    }

    /// True when the spec names a concrete enclosing entry function the
    /// harness can drive — i.e. `entry_name` resolved to a real symbol
    /// rather than the `"<unknown>"` placeholder a rule-namespace finding
    /// falls back to when no flow-step / summary / AST resolution can name
    /// the function the sink sits in.
    ///
    /// The per-language harness emitters consult this to decide whether to
    /// invoke the finding's enclosing function (so caller-side guards run
    /// before the sink) or fall back to a synthetic direct-sink harness;
    /// [`crate::dynamic::verify::verify_finding`] records the same decision
    /// on the [`crate::dynamic::trace::VerifyTrace`] via
    /// [`crate::dynamic::trace::TraceStage::EntryInvocation`].
    pub fn entry_is_derivable(&self) -> bool {
        !self.entry_name.is_empty() && self.entry_name != "<unknown>"
    }

    /// Returns the ordered list of derivation strategies that
    /// [`HarnessSpec::from_finding_opts`] attempts. Used by the verifier when
    /// it needs to report which candidates were tried before declaring an
    /// `Inconclusive(SpecDerivationFailed)` verdict.
    pub fn derivation_strategies() -> &'static [SpecDerivationStrategy] {
        &[
            SpecDerivationStrategy::FromFlowSteps,
            SpecDerivationStrategy::FromRuleNamespace,
            SpecDerivationStrategy::FromFuncSummaryWalk,
            SpecDerivationStrategy::FromCallgraphEntry,
        ]
    }

    /// Phase 25 (Track K.0) — run *every* derivation strategy and score each
    /// resulting candidate.
    ///
    /// Unlike the legacy sequential first-match ladder, this evaluates all
    /// strategies that fire for the finding and returns each as a
    /// `(SpecCandidate, SpecScore)` pair.  The caller
    /// ([`Self::derive_best_ranked`]) picks the maximum-scoring candidate.
    ///
    /// Candidates are returned in *ascending precedence* order (lowest-priority
    /// strategy first).  This is load-bearing: [`SpecScore`] is intentionally
    /// coarse and genuine ties are common (e.g. two strategies that both name
    /// the sink's own enclosing function as the entry).  When scores tie, the
    /// winner-selection in [`Self::derive_best_ranked`] keeps the *last*
    /// maximal element, so ascending precedence here reproduces the legacy
    /// ladder's tie-break (flow-steps beats rule-namespace beats
    /// func-summary, and the strict callgraph walk beats every other
    /// strategy) without baking strategy rank into the score itself.
    ///
    /// Returns an empty `Vec` when the finding carries no evidence or no
    /// strategy fires.
    pub fn derive_all_strategies(
        diag: &Diag,
        ctx: &SpecDerivationCtx,
    ) -> Vec<(SpecCandidate, SpecScore)> {
        let Some(evidence) = diag.evidence.as_ref() else {
            return Vec::new();
        };
        let summaries = ctx.summaries;
        let callgraph = ctx.callgraph;

        // Build raw candidates in ascending precedence (lowest first). The
        // two callgraph entries mirror the legacy two call sites: the
        // `*_full` variant carries the low-precedence summary-kind / rule-id
        // fallback, the `*_walk_only` and cross-file-seed variants are the
        // high-precedence reverse-edge walks.
        let mut raw: Vec<(HarnessSpec, SpecDerivationStrategy)> = Vec::new();
        if let Some(spec) = derive_from_callgraph_entry_full(diag, evidence, summaries, callgraph) {
            raw.push((spec, SpecDerivationStrategy::FromCallgraphEntry));
        }
        if let Some(spec) = derive_from_func_summary_auto(diag, evidence, summaries) {
            raw.push((spec, SpecDerivationStrategy::FromFuncSummaryWalk));
        }
        if let Some(spec) = derive_from_rule_namespace_with(diag, evidence, summaries) {
            raw.push((spec, SpecDerivationStrategy::FromRuleNamespace));
        }
        if let Some(spec) = derive_from_flow_steps(diag, evidence, summaries) {
            raw.push((spec, SpecDerivationStrategy::FromFlowSteps));
        }
        if let (Some(s), Some(cg)) = (summaries, callgraph) {
            if let Some(spec) = derive_from_callgraph_walk_only(diag, evidence, s, cg) {
                raw.push((spec, SpecDerivationStrategy::FromCallgraphEntry));
            }
            if let Some(spec) = derive_from_cross_file_seed(diag, evidence, s, cg) {
                raw.push((spec, SpecDerivationStrategy::FromCallgraphEntry));
            }
        }

        let sink_file = sink_file_of(diag, evidence);
        raw.into_iter()
            .map(|(spec, strategy)| {
                let score = score_candidate(&spec, evidence, &sink_file);
                (SpecCandidate { spec, strategy }, score)
            })
            .collect()
    }

    /// Phase 25 (Track K.0) — derive the single best spec for a finding.
    ///
    /// Runs [`Self::derive_all_strategies`] and returns the maximum-scoring
    /// candidate's spec.  The error contract matches the legacy
    /// [`Self::from_finding_full`]:
    /// - `Err(UnsupportedReason::ConfidenceTooLow)` when the confidence gate
    ///   fails (and `ctx.verify_all_confidence` is false),
    /// - `Err(UnsupportedReason::NoFlowSteps)` when the finding carries no
    ///   `Evidence` at all,
    /// - `Err(UnsupportedReason::SpecDerivationFailed)` when evidence is
    ///   present but no strategy fired.
    pub fn derive_best(diag: &Diag, ctx: &SpecDerivationCtx) -> Result<Self, UnsupportedReason> {
        Self::derive_best_ranked(diag, ctx).map(|(spec, _runners_up)| spec)
    }

    /// Phase 25 (Track K.0) — like [`Self::derive_best`] but also returns the
    /// loser ranking for telemetry.
    ///
    /// The second tuple element lists every non-winning candidate's
    /// `(strategy, score)` in descending score order, so the verifier can
    /// emit a [`crate::dynamic::trace::TraceStage::SpecScoringResult`] event
    /// that makes engine gaps visible (which strategies fired, how they
    /// scored, and which one lost the tie-break).
    pub fn derive_best_ranked(
        diag: &Diag,
        ctx: &SpecDerivationCtx,
    ) -> Result<(Self, Vec<(SpecDerivationStrategy, SpecScore)>), UnsupportedReason> {
        if !ctx.verify_all_confidence {
            match diag.confidence {
                Some(c) if c >= Confidence::Medium => {}
                _ => return Err(UnsupportedReason::ConfidenceTooLow),
            }
        }
        // Distinguish "no evidence at all" (NoFlowSteps) from "evidence
        // present but no strategy fired" (SpecDerivationFailed) — the
        // verifier lifts only the latter to `Inconclusive`.
        if diag.evidence.is_none() {
            return Err(UnsupportedReason::NoFlowSteps);
        }

        let mut scored = Self::derive_all_strategies(diag, ctx);
        if scored.is_empty() {
            return Err(UnsupportedReason::SpecDerivationFailed);
        }

        // Stable sort by score ascending. `derive_all_strategies` returns
        // candidates in ascending precedence, and a stable sort preserves
        // that order within equal scores — so the final element is the
        // highest-scoring candidate, and on a score tie it is the
        // highest-precedence one (legacy ladder tie-break).
        scored.sort_by(|a, b| a.1.cmp(&b.1));
        let (winner, _winner_score) = scored.pop().expect("non-empty checked above");
        let mut runners_up: Vec<(SpecDerivationStrategy, SpecScore)> = scored
            .into_iter()
            .map(|(cand, score)| (cand.strategy, score))
            .collect();
        // Report losers best-first.
        runners_up.reverse();
        Ok((winner.spec, runners_up))
    }
}

// ── Strategy 1: from flow_steps (original path) ──────────────────────────────

fn derive_from_flow_steps(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: Option<&GlobalSummaries>,
) -> Option<HarnessSpec> {
    if evidence.flow_steps.is_empty() {
        return None;
    }
    let expected_cap = Cap::from_bits_truncate(evidence.sink_caps);
    if expected_cap.is_empty() {
        return None;
    }

    let (sink_file, sink_line) = evidence
        .flow_steps
        .iter()
        .rev()
        .find(|s| matches!(s.kind, FlowStepKind::Sink))
        .map(|s| (s.file.clone(), s.line))
        .unwrap_or_else(|| (diag.path.clone(), diag.line as u32));

    // Entry resolution, in descending fidelity:
    //   1. the outermost `Source` step that carries a function annotation
    //      (the original behaviour — the outermost callable receiving input),
    //   2. the first flow step carrying *any* function annotation — covers the
    //      generic `taint-unsanitised-flow` shape whose flow begins at a `Call`
    //      / assignment step rather than a `Source` step, so it has no
    //      `Source`-kind step yet still names the enclosing function,
    //   3. the enclosing function resolved from the sink's AST span, and
    //   4. the `<unknown>` placeholder, which the per-language emitters route
    //      to a synthetic direct-sink harness.
    // The sink location plus a non-empty cap is enough to drive verification,
    // so a missing `Source` step no longer aborts derivation.
    let entry = outermost_entry(&evidence.flow_steps)
        .or_else(|| first_annotated_entry(&evidence.flow_steps));
    let (entry_file, entry_name) = match entry {
        Some(e) => (e.file, e.function),
        None => {
            let name = lang_from_path(&sink_file)
                .and_then(|l| resolve_enclosing_function_via_ast(&sink_file, sink_line as usize, l))
                .unwrap_or_else(|| "<unknown>".to_owned());
            (sink_file.clone(), name)
        }
    };

    let lang = lang_from_path(&entry_file).or_else(|| lang_from_path(&sink_file))?;

    Some(finalize_spec(
        diag,
        entry_file,
        entry_name,
        lang,
        expected_cap,
        sink_file,
        sink_line,
        SpecDerivationStrategy::FromFlowSteps,
        summaries,
    ))
}

/// Return an [`EntryRef`] for the first flow step that carries a non-empty
/// `function` annotation, regardless of its [`FlowStepKind`].
///
/// Unlike [`outermost_entry`] (which requires a `Source`-kind step), this
/// recovers an entry from flows that begin at a `Call` / assignment step —
/// the common shape for the generic `taint-unsanitised-flow` rule, whose
/// steps are annotated with the enclosing function but include no explicit
/// `Source` step.
fn first_annotated_entry(steps: &[crate::evidence::FlowStep]) -> Option<EntryRef> {
    steps.iter().find_map(|s| {
        s.function
            .as_ref()
            .filter(|f| !f.is_empty())
            .map(|f| EntryRef {
                file: s.file.clone(),
                function: f.clone(),
            })
    })
}

// ── Strategy 2: from rule namespace + sink evidence ──────────────────────────

/// Build a spec from a rule-namespace finding (e.g. `py.cmdi.os_system`,
/// `java.deser.readobject`, `rs.auth.missing_ownership_check.taint`) plus the
/// finding's sink evidence. The diag's path and line locate the sink call
/// site; the rule namespace's first segment selects the language, and the
/// second segment maps to a [`Cap`] via [`cap_for_rule_category`].
///
/// A synthetic single-step `Source` flow is constructed at the diag location
/// so downstream consumers that walk `evidence.flow_steps` keep working. The
/// entry function defaults to the sink-enclosing function from the diag's
/// evidence when available, otherwise to `"<unknown>"` (which keeps spec
/// hashing stable while signalling the lack of a concrete entry).
pub fn derive_from_rule_namespace(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
) -> Option<HarnessSpec> {
    derive_from_rule_namespace_with(diag, evidence, None)
}

/// Like [`derive_from_rule_namespace`], but consults `summaries` to recover the
/// enclosing function name when `evidence.flow_steps` does not carry one.
///
/// When neither flow_steps nor the summary index resolve a name, the entry
/// name falls back to `"<unknown>"` (kept stable across runs so spec hashes
/// remain reproducible).
pub fn derive_from_rule_namespace_with(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: Option<&GlobalSummaries>,
) -> Option<HarnessSpec> {
    // Path is required to locate the sink and to extension-check the lang.
    if diag.path.is_empty() {
        return None;
    }

    // Language-agnostic `taint-*` rule ids (e.g. `taint-ldap-injection`,
    // `taint-sql-injection`, `taint-data-exfiltration`) carry the cap in the
    // rule slug itself; the language comes from the file extension. Try this
    // shortcut first so taint findings with no flow_steps can still derive.
    if let Some(taint_cap) = cap_for_taint_rule_id(&diag.id) {
        let lang = lang_from_path(&diag.path)?;
        let expected_cap = {
            let from_ev = Cap::from_bits_truncate(evidence.sink_caps);
            if !from_ev.is_empty() {
                from_ev
            } else {
                taint_cap
            }
        };
        if expected_cap.is_empty() {
            return None;
        }
        let entry_function = resolve_enclosing_function(diag, evidence, summaries, lang)
            .unwrap_or_else(|| "<unknown>".to_owned());
        return Some(finalize_spec(
            diag,
            diag.path.clone(),
            entry_function,
            lang,
            expected_cap,
            diag.path.clone(),
            diag.line as u32,
            SpecDerivationStrategy::FromRuleNamespace,
            summaries,
        ));
    }

    let mut iter = diag.id.split('.');
    let lang_prefix = iter.next()?;
    let category = iter.next()?;

    let lang = lang_from_rule_prefix(lang_prefix)?;
    // The category token must map to a known [`Cap`]; if not, defer to the
    // callgraph-entry strategy or fall through to `SpecDerivationFailed`.
    let category_cap = cap_for_rule_category(category)?;

    // Sink caps: prefer explicit evidence; fall back to the category map.
    let expected_cap = {
        let from_ev = Cap::from_bits_truncate(evidence.sink_caps);
        if !from_ev.is_empty() {
            from_ev
        } else {
            category_cap
        }
    };
    if expected_cap.is_empty() {
        return None;
    }

    // Cross-check: the diag's file extension must agree with the rule's
    // language prefix when both are available. Disagreement is a stronger
    // signal of a mis-rooted finding than a missing extension.
    if let Some(path_lang) = lang_from_path(&diag.path)
        && path_lang != lang
    {
        return None;
    }

    let entry_function = resolve_enclosing_function(diag, evidence, summaries, lang)
        .unwrap_or_else(|| "<unknown>".to_owned());

    Some(finalize_spec(
        diag,
        diag.path.clone(),
        entry_function,
        lang,
        expected_cap,
        diag.path.clone(),
        diag.line as u32,
        SpecDerivationStrategy::FromRuleNamespace,
        summaries,
    ))
}

/// Map a language-agnostic `taint-*` rule id (as registered in
/// [`crate::labels::CAP_RULE_REGISTRY`]) to its [`Cap`].
///
/// Returns `None` for rule ids that are not registered as a class entry,
/// including the legacy generic `taint-unsanitised-flow` (which is not in
/// the registry — its findings carry their actual cap through evidence,
/// not the rule slug).
fn cap_for_taint_rule_id(rule_id: &str) -> Option<Cap> {
    if !rule_id.starts_with("taint-") {
        return None;
    }
    crate::labels::CAP_RULE_REGISTRY
        .iter()
        .find(|meta| meta.rule_id == rule_id)
        .map(|meta| meta.cap)
}

// ── Strategy 3: walk a FuncSummary for the sink's enclosing function ─────────

/// Build a spec by walking `summary` (the sink's enclosing function) for any
/// param-to-sink edge. When `summary` is `None` (the common case at verify
/// time, where global summaries are not threaded in), this returns `None`.
///
/// Picks the first `tainted_sink_params` entry as `PayloadSlot::Param(idx)`.
/// The synthetic flow has one source step pinned at the summary's parameter
/// and one sink step at the diag's line.
pub fn derive_from_func_summary(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summary: Option<&FuncSummary>,
) -> Option<HarnessSpec> {
    let summary = summary?;
    let param_idx = *summary.tainted_sink_params.first()?;
    let lang = Lang::from_slug(&summary.lang)?;
    let expected_cap = {
        let from_ev = Cap::from_bits_truncate(evidence.sink_caps);
        if !from_ev.is_empty() {
            from_ev
        } else {
            Cap::from_bits_truncate(summary.sink_caps)
        }
    };
    if expected_cap.is_empty() {
        return None;
    }

    let entry_file = if !summary.file_path.is_empty() {
        summary.file_path.clone()
    } else {
        diag.path.clone()
    };
    let entry_name = summary.name.clone();
    let mut spec = finalize_spec(
        diag,
        entry_file,
        entry_name,
        lang,
        expected_cap,
        diag.path.clone(),
        diag.line as u32,
        SpecDerivationStrategy::FromFuncSummaryWalk,
        None,
    );
    spec.payload_slot = PayloadSlot::Param(param_idx);
    spec.spec_hash = compute_spec_hash(&spec);
    Some(spec)
}

// ── Strategy 3 (auto): locate the enclosing FuncSummary in `summaries` ───────

/// Resolve the enclosing function's [`FuncSummary`] from `summaries` and
/// delegate to [`derive_from_func_summary`].
///
/// Returns `None` when `summaries` is `None`, when the enclosing function
/// name cannot be recovered from `evidence.flow_steps`, or when no summary
/// matches `(lang, name, file)`.
fn derive_from_func_summary_auto(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: Option<&GlobalSummaries>,
) -> Option<HarnessSpec> {
    let summaries = summaries?;
    let lang = lang_from_path(&diag.path)?;
    let name = enclosing_function_from_flow_steps(evidence)?;
    let summary = find_summary_by_path(summaries, lang, &name, &diag.path)?;
    let mut spec = derive_from_func_summary(diag, evidence, Some(summary))?;
    // Re-run the framework attach with `summaries` so adapters can see
    // the real callees on the enclosing function; framework binding is
    // excluded from `compute_spec_hash`, so no rehash needed.
    attach_framework_binding(&mut spec, Some(summaries));
    Some(spec)
}

// ── Strategy 4: callgraph entry-kind ─────────────────────────────────────────

/// Build a spec by treating the sink's enclosing function as an entry point
/// when its rule namespace marks it as an externally-driven entry (HTTP route,
/// CLI subcommand). Currently fires when the rule id contains `.http.` or
/// `.cli.`; otherwise returns `None`.
///
/// Without a threaded [`crate::callgraph::CallGraph`] this strategy is a
/// minimal heuristic; it remains as the last-chance resort so the verifier
/// has something to drive against rather than declaring unsupported.
pub fn derive_from_callgraph_entry(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
) -> Option<HarnessSpec> {
    derive_from_callgraph_entry_with(diag, evidence, None)
}

/// Like [`derive_from_callgraph_entry`], but prefers
/// [`FuncSummary::entry_kind`] over the `.http.` / `.cli.` rule-id substring
/// heuristic when a matching summary is available in `summaries`.
///
/// An HTTP-shaped [`crate::entry_points::EntryKind`] variant on the enclosing
/// function's summary becomes [`EntryKind::HttpRoute`] regardless of the rule
/// id. The substring fallback runs only when no summary entry-kind is found
/// — e.g. for AST-only findings with no taint-engine flow_steps.
pub fn derive_from_callgraph_entry_with(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: Option<&GlobalSummaries>,
) -> Option<HarnessSpec> {
    derive_from_callgraph_entry_full(diag, evidence, summaries, None)
}

/// Strict reverse-edge-BFS-only variant of
/// [`derive_from_callgraph_entry_full`].
///
/// Returns `Some(spec)` only when [`find_entry_via_callgraph`] resolves
/// the sink's enclosing function to a framework-bound ancestor via the
/// whole-program callgraph. Unlike
/// [`derive_from_callgraph_entry_full`], the summary-entry-kind fallback
/// on the enclosing function and the rule-id `.http.` / `.cli.`
/// substring heuristic are *not* consulted here — those remain
/// strategy-4 last-chance behaviour invoked from
/// [`HarnessSpec::from_finding_full`]'s strategy ladder.
///
/// Used by the Phase 04 pre-step in [`HarnessSpec::from_finding_full`]
/// so a successful callgraph walk takes precedence over strategies 1–3,
/// while the substring / summary fallbacks do not short-circuit
/// [`SpecDerivationStrategy::FromFlowSteps`] /
/// [`SpecDerivationStrategy::FromRuleNamespace`] /
/// [`SpecDerivationStrategy::FromFuncSummaryWalk`].
pub fn derive_from_callgraph_walk_only(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: &GlobalSummaries,
    callgraph: &CallGraph,
) -> Option<HarnessSpec> {
    let lang = lang_from_path(&diag.path)?;
    let expected_cap = Cap::from_bits_truncate(evidence.sink_caps);
    if expected_cap.is_empty() {
        return None;
    }
    let found = find_entry_via_callgraph(diag, evidence, summaries, callgraph, lang)?;
    let entry_kind = found
        .summary
        .entry_kind
        .as_ref()
        .map(entry_kind_from_summary)
        .unwrap_or_else(|| name_to_entry_kind(&found.summary.name));
    let entry_file = if !found.summary.file_path.is_empty() {
        found.summary.file_path.clone()
    } else {
        diag.path.clone()
    };
    let mut spec = finalize_spec(
        diag,
        entry_file,
        found.summary.name.clone(),
        lang,
        expected_cap,
        diag.path.clone(),
        diag.line as u32,
        SpecDerivationStrategy::FromCallgraphEntry,
        Some(summaries),
    );
    spec.entry_kind = entry_kind;
    spec.spec_hash = compute_spec_hash(&spec);
    Some(spec)
}

/// Like [`derive_from_callgraph_entry_with`], but also consults the
/// whole-program [`CallGraph`] when `callgraph` is `Some`.
///
/// When both `summaries` and `callgraph` are present, the sink's
/// enclosing function is resolved to a [`FuncKey`] and a reverse-edge
/// BFS walks predecessors until an ancestor satisfies
/// [`is_entry_point`]. The spec's `entry_file` / `entry_name` are
/// rewritten to that ancestor and `entry_kind` is classified from the
/// ancestor's [`FuncSummary::entry_kind`] (HTTP variants → HttpRoute).
/// The legacy rule-id `.http.` / `.cli.` substring fallback is still
/// consulted when the callgraph walk finds nothing.
pub fn derive_from_callgraph_entry_full(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: Option<&GlobalSummaries>,
    callgraph: Option<&CallGraph>,
) -> Option<HarnessSpec> {
    let lang = lang_from_path(&diag.path)?;
    let expected_cap = Cap::from_bits_truncate(evidence.sink_caps);
    if expected_cap.is_empty() {
        return None;
    }

    // Step 0: callgraph-aware reverse-edge walk to the nearest entry-point
    // ancestor. Only fires when both summaries *and* callgraph are present.
    if let (Some(s), Some(cg)) = (summaries, callgraph)
        && let Some(found) = find_entry_via_callgraph(diag, evidence, s, cg, lang)
    {
        let entry_kind = found
            .summary
            .entry_kind
            .as_ref()
            .map(entry_kind_from_summary)
            .unwrap_or_else(|| name_to_entry_kind(&found.summary.name));
        let entry_file = if !found.summary.file_path.is_empty() {
            found.summary.file_path.clone()
        } else {
            diag.path.clone()
        };
        let mut spec = finalize_spec(
            diag,
            entry_file,
            found.summary.name.clone(),
            lang,
            expected_cap,
            diag.path.clone(),
            diag.line as u32,
            SpecDerivationStrategy::FromCallgraphEntry,
            Some(s),
        );
        spec.entry_kind = entry_kind;
        spec.spec_hash = compute_spec_hash(&spec);
        return Some(spec);
    }

    // Step 1: try summary-based classification of the enclosing function.
    let summary_kind = enclosing_function_from_flow_steps(evidence)
        .and_then(|name| find_summary_by_path(summaries?, lang, &name, &diag.path))
        .and_then(|s| s.entry_kind.as_ref().map(entry_kind_from_summary));

    // Step 2: fall back to rule-id substring heuristic (legacy).
    let id = &diag.id;
    let id_kind = if id.contains(".http.") {
        Some(EntryKind::HttpRoute)
    } else if id.contains(".cli.") {
        Some(EntryKind::CliSubcommand)
    } else {
        None
    };

    let entry_kind = summary_kind.or(id_kind)?;

    let entry_function = resolve_enclosing_function(diag, evidence, summaries, lang)
        .unwrap_or_else(|| "<unknown>".to_owned());

    let mut spec = finalize_spec(
        diag,
        diag.path.clone(),
        entry_function,
        lang,
        expected_cap,
        diag.path.clone(),
        diag.line as u32,
        SpecDerivationStrategy::FromCallgraphEntry,
        summaries,
    );
    spec.entry_kind = entry_kind;
    spec.spec_hash = compute_spec_hash(&spec);
    Some(spec)
}

/// Recognise function-name-only entry points when no static
/// [`crate::entry_points::EntryKind`] tag is available.
///
/// `main` / `fn main` / `__main__` (Python's `if __name__ == "__main__":`
/// block-as-function convention) become [`EntryKind::CliSubcommand`];
/// every other name defaults to [`EntryKind::Function`]. Used to give
/// the verifier a non-`Function` entry kind for callgraph-discovered
/// ancestors whose summaries pre-date the static entry-kind detector.
fn name_to_entry_kind(name: &str) -> EntryKind {
    match name {
        "main" | "__main__" => EntryKind::CliSubcommand,
        _ => EntryKind::Function,
    }
}

/// True when `func` qualifies as a static entry point: framework-bound
/// route handler (`func.entry_kind.is_some()`), Rust / C-style program
/// `main`, or Python `__main__` block-as-function.
///
/// `callgraph` is accepted as future-extension surface (e.g. checking
/// in-degree == 0 to claim externally-driven CLI helpers) but the
/// current implementation only uses it for the in-degree heuristic when
/// the function name itself does not match a recognised pattern.
pub fn is_entry_point(func: &FuncSummary, callgraph: &CallGraph) -> bool {
    if func.entry_kind.is_some() {
        return true;
    }
    if matches!(func.name.as_str(), "main" | "__main__") {
        return true;
    }
    // Last-resort: if the call graph has zero static callers for this
    // function and it is *not* a closure / lambda (which legitimately
    // have zero callers but are inlined at their use site), treat it as
    // externally driven. We only claim this when the function lives at
    // file top level (empty container) so we do not promote leaf helper
    // methods on classes to entry points.
    if !func.container.is_empty() {
        return false;
    }
    let lang = match Lang::from_slug(&func.lang) {
        Some(l) => l,
        None => return false,
    };
    let key = FuncKey {
        lang,
        namespace: func.file_path.clone(),
        container: func.container.clone(),
        name: func.name.clone(),
        arity: Some(func.param_count),
        disambig: func.disambig,
        kind: func.kind,
    };
    if let Some(&node) = callgraph.index.get(&key) {
        callgraph
            .graph
            .neighbors_directed(node, petgraph::Direction::Incoming)
            .next()
            .is_none()
    } else {
        false
    }
}

/// Result of a successful callgraph-driven entry-point lookup.
struct EntryHit<'a> {
    #[allow(dead_code)]
    key: FuncKey,
    summary: &'a FuncSummary,
}

/// Walk reverse edges from the sink's enclosing function until an entry
/// point is found.
///
/// Returns `None` when:
/// * the sink's enclosing function cannot be resolved from
///   `evidence.flow_steps`, or
/// * the resolved function has no node in the callgraph (e.g. defined
///   in a file pass 1 did not summarise), or
/// * no ancestor satisfies [`is_entry_point`] within the BFS frontier.
fn find_entry_via_callgraph<'a>(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: &'a GlobalSummaries,
    callgraph: &CallGraph,
    lang: Lang,
) -> Option<EntryHit<'a>> {
    let enclosing = enclosing_function_from_flow_steps(evidence)
        .or_else(|| resolve_enclosing_function(diag, evidence, Some(summaries), lang))?;
    // Locate the FuncKey by matching name + file_path against the summaries.
    let (sink_key, sink_summary) = summaries
        .iter()
        .find(|(k, s)| {
            k.lang == lang && s.name == enclosing && paths_match(&s.file_path, &diag.path)
        })
        .map(|(k, s)| (k.clone(), s))?;
    // Sink's own enclosing function may itself be an entry (route
    // handler that contains the sink directly). When that is the case
    // the existing summary-classification path already returns the
    // right answer, but seeding the BFS with it keeps the two paths
    // consistent.
    let start = *callgraph.index.get(&sink_key)?;
    if is_entry_point(sink_summary, callgraph) {
        return Some(EntryHit {
            key: sink_key,
            summary: sink_summary,
        });
    }
    let mut visited: HashSet<petgraph::graph::NodeIndex> = HashSet::new();
    visited.insert(start);
    let mut queue: VecDeque<petgraph::graph::NodeIndex> = VecDeque::new();
    queue.push_back(start);
    while let Some(node) = queue.pop_front() {
        for caller_node in callgraph
            .graph
            .neighbors_directed(node, petgraph::Direction::Incoming)
        {
            if !visited.insert(caller_node) {
                continue;
            }
            let caller_key = &callgraph.graph[caller_node];
            if let Some(caller_summary) = summaries.get(caller_key)
                && is_entry_point(caller_summary, callgraph)
            {
                return Some(EntryHit {
                    key: caller_key.clone(),
                    summary: caller_summary,
                });
            }
            queue.push_back(caller_node);
        }
    }
    None
}

/// Map a static-analysis [`crate::entry_points::EntryKind`] (route shape) onto
/// the dynamic-side [`EntryKind`] taxonomy. Every current variant of the
/// static enum describes an HTTP route handler — no CLI / library-API
/// variants exist statically — so they all collapse to
/// [`EntryKind::HttpRoute`]. When the static taxonomy grows non-HTTP variants
/// (e.g. clap subcommand detection), extend this match to preserve them.
fn entry_kind_from_summary(_kind: &crate::entry_points::EntryKind) -> EntryKind {
    EntryKind::HttpRoute
}

// ── Phase 25 (Track K.0): multi-strategy scoring + cross-file seeding ────────

/// Maximum reverse-edge hops the cross-file source seeding walks before
/// giving up.  Bounds the BFS so a deep call chain cannot stall derivation;
/// the [`crate::dynamic::spec`] Phase 25 spec fixes this at 5.
const CROSS_FILE_SEED_MAX_DEPTH: usize = 5;

/// The sink call-site's file: the last `Sink` flow step, falling back to the
/// diag's own path.  Used by [`score_candidate`] to decide whether a
/// candidate's entry was resolved across a file boundary.
fn sink_file_of(diag: &Diag, evidence: &crate::evidence::Evidence) -> String {
    evidence
        .flow_steps
        .iter()
        .rev()
        .find(|s| matches!(s.kind, FlowStepKind::Sink))
        .map(|s| s.file.clone())
        .unwrap_or_else(|| diag.path.clone())
}

/// Flow-step depth a candidate covers.
///
/// Base is `evidence.flow_steps.len()`.  A candidate whose entry was
/// rewritten to a *different* function than the sink's enclosing function
/// (i.e. one of the callgraph-walk strategies climbed the call chain to a
/// route handler / source ancestor) earns a `+1` hop bonus, so it scores
/// strictly above the strategies that merely name the sink's own enclosing
/// helper as the entry.  This is what lets a successful reverse-edge walk
/// win the [`SpecScore`] comparison without baking strategy rank into the
/// score.
fn candidate_flow_depth(spec: &HarnessSpec, evidence: &crate::evidence::Evidence) -> u32 {
    let base = evidence.flow_steps.len() as u32;
    let hop = match enclosing_function_from_flow_steps(evidence) {
        Some(ref f) if !f.is_empty() && *f != spec.entry_name => 1,
        _ => 0,
    };
    base + hop
}

/// True when the `(cap, lang)` pair has at least one curated payload to fire.
///
/// `expected_cap` may carry several bits; a direct multi-bit lookup misses
/// (the corpus is keyed by single caps), so on a miss we test each set bit
/// individually.
fn candidate_has_payloads(cap: Cap, lang: Lang) -> bool {
    use crate::dynamic::corpus::registry::payloads_for_lang;
    if !payloads_for_lang(cap, lang).is_empty() {
        return true;
    }
    cap.iter()
        .any(|bit| !payloads_for_lang(bit, lang).is_empty())
}

/// Score a single candidate spec on the four Phase 25 axes.
fn score_candidate(
    spec: &HarnessSpec,
    evidence: &crate::evidence::Evidence,
    sink_file: &str,
) -> SpecScore {
    SpecScore {
        flow_depth: candidate_flow_depth(spec, evidence),
        framework_bound: spec.framework.is_some(),
        cross_file_resolved: !sink_file.is_empty()
            && !spec.entry_file.is_empty()
            && spec.entry_file != sink_file,
        payloads_available: candidate_has_payloads(spec.expected_cap, spec.lang),
    }
}

/// Phase 25 (Track K.0) deliverable 4 — cross-file source seeding.
///
/// Walks reverse call-graph edges from the sink's enclosing function,
/// consulting [`GlobalSummaries::get_ssa`] (the `ssa_by_key` index) at each
/// ancestor, until it finds either:
/// * a **Source** — an ancestor whose [`crate::summary::ssa_summary::SsaFuncSummary::source_caps`]
///   is non-empty, i.e. it introduces externally-controlled input, or
/// * a **framework binding** — an ancestor that satisfies [`is_entry_point`].
///
/// Bounded at [`CROSS_FILE_SEED_MAX_DEPTH`] reverse hops.  Unlike
/// [`find_entry_via_callgraph`], which stops only at framework entry points,
/// this also stops at SSA-confirmed sources — so it recovers a drivable
/// entry for findings whose taint originates in a cross-file helper that
/// reads input but is not itself a route handler.  That additional reach is
/// the lever Phase 25 pulls to cut the `Inconclusive(SpecDerivationFailed)`
/// rate.
fn seed_cross_file_source<'a>(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: &'a GlobalSummaries,
    callgraph: &CallGraph,
    lang: Lang,
) -> Option<EntryHit<'a>> {
    let enclosing = enclosing_function_from_flow_steps(evidence)
        .or_else(|| resolve_enclosing_function(diag, evidence, Some(summaries), lang))?;
    let sink_key = summaries
        .iter()
        .find(|(k, s)| {
            k.lang == lang && s.name == enclosing && paths_match(&s.file_path, &diag.path)
        })
        .map(|(k, _)| k.clone())?;
    let start = *callgraph.index.get(&sink_key)?;

    let mut visited: HashSet<petgraph::graph::NodeIndex> = HashSet::new();
    visited.insert(start);
    let mut frontier: Vec<petgraph::graph::NodeIndex> = vec![start];
    for _ in 0..CROSS_FILE_SEED_MAX_DEPTH {
        let mut next: Vec<petgraph::graph::NodeIndex> = Vec::new();
        for node in frontier.drain(..) {
            for caller in callgraph
                .graph
                .neighbors_directed(node, petgraph::Direction::Incoming)
            {
                if !visited.insert(caller) {
                    continue;
                }
                let caller_key = &callgraph.graph[caller];
                let summary = summaries.get(caller_key);
                let is_source = summaries
                    .get_ssa(caller_key)
                    .is_some_and(|ssa| !ssa.source_caps.is_empty());
                let is_framework = summary.is_some_and(|s| is_entry_point(s, callgraph));
                if (is_source || is_framework)
                    && let Some(s) = summary
                {
                    return Some(EntryHit {
                        key: caller_key.clone(),
                        summary: s,
                    });
                }
                next.push(caller);
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    None
}

/// Strategy candidate built from [`seed_cross_file_source`].
///
/// Rewrites the spec's entry to the cross-file Source / framework ancestor
/// the seed walk resolved, classifying its [`EntryKind`] from the ancestor's
/// summary (HTTP-shaped static entry kinds → [`EntryKind::HttpRoute`], else
/// name-based).  Tagged [`SpecDerivationStrategy::FromCallgraphEntry`] — it
/// is a reverse-edge call-graph walk, like the other two callgraph
/// candidates — and emitted at the highest precedence in
/// [`HarnessSpec::derive_all_strategies`].
fn derive_from_cross_file_seed(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: &GlobalSummaries,
    callgraph: &CallGraph,
) -> Option<HarnessSpec> {
    let lang = lang_from_path(&diag.path)?;
    let expected_cap = Cap::from_bits_truncate(evidence.sink_caps);
    if expected_cap.is_empty() {
        return None;
    }
    let found = seed_cross_file_source(diag, evidence, summaries, callgraph, lang)?;
    let entry_kind = found
        .summary
        .entry_kind
        .as_ref()
        .map(entry_kind_from_summary)
        .unwrap_or_else(|| name_to_entry_kind(&found.summary.name));
    let entry_file = if !found.summary.file_path.is_empty() {
        found.summary.file_path.clone()
    } else {
        diag.path.clone()
    };
    let (sink_file, sink_line) = evidence
        .flow_steps
        .iter()
        .rev()
        .find(|s| matches!(s.kind, FlowStepKind::Sink))
        .map(|s| (s.file.clone(), s.line))
        .unwrap_or_else(|| (diag.path.clone(), diag.line as u32));
    let mut spec = finalize_spec(
        diag,
        entry_file,
        found.summary.name.clone(),
        lang,
        expected_cap,
        sink_file,
        sink_line,
        SpecDerivationStrategy::FromCallgraphEntry,
        Some(summaries),
    );
    spec.entry_kind = entry_kind;
    spec.spec_hash = compute_spec_hash(&spec);
    Some(spec)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve the language for a finding path using extension first, then a
/// shebang / content sniff against the first 200 bytes of the file.
///
/// Phase 02 widens this resolver beyond `Lang::from_extension` so that
/// extensionless CLI entry points and idiomatic non-canonical extensions
/// (`.cjs`, `.mts`, `.pyi`, …) no longer cause `SpecDerivationFailed`. File
/// I/O is best-effort: an unreadable / absent file falls through to the
/// extension-only path so callers in tests that pass synthetic paths still
/// resolve when the extension is well-known.
fn lang_from_path(path: &str) -> Option<Lang> {
    let p = Path::new(path);
    if let Some(ext) = p.extension().and_then(|e| e.to_str())
        && let Some(lang) = Lang::from_extension(ext)
    {
        return Some(lang);
    }
    // Fall back to a shebang / content sniff over the file head.
    let head = read_file_head(p, 200);
    if head.is_empty() {
        return None;
    }
    Lang::from_path_or_content(p, &head)
}

/// Read up to `cap` bytes from `path`, returning an empty buffer on any I/O
/// error. The verifier never wants a missing file to abort spec derivation —
/// callers downstream already gate on `Lang` being `Some`.
fn read_file_head(path: &Path, cap: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(cap);
    let Ok(f) = std::fs::File::open(path) else {
        return buf;
    };
    let _ = f.take(cap as u64).read_to_end(&mut buf);
    buf
}

/// Return the first non-empty `function` annotation found on any flow step.
///
/// Strategy 1 ([`derive_from_flow_steps`]) consumes the `Source`-step
/// annotation directly; strategies 2 and 4 fall back to *any* step with a
/// `function` set because the SSA engine annotates sink and assignment steps
/// as well. The annotation is authoritative — it carries the enclosing
/// function as resolved against the CFG — so it is preferred over the call
/// snippet, which carries shortened callee text.
fn enclosing_function_from_flow_steps(evidence: &crate::evidence::Evidence) -> Option<String> {
    evidence
        .flow_steps
        .iter()
        .find_map(|s| s.function.clone().filter(|f| !f.is_empty()))
}

/// Resolve the enclosing function name for the diag using, in order:
/// 1. any `flow_steps[*].function` annotation (always authoritative),
/// 2. a [`GlobalSummaries`] lookup when `summaries` is `Some` and exactly one
///    function in the diag's file shares the rule-language tag (last-resort
///    disambiguation when flow_steps is empty),
/// 3. `None` (callers default to `"<unknown>"`).
fn resolve_enclosing_function(
    diag: &Diag,
    evidence: &crate::evidence::Evidence,
    summaries: Option<&GlobalSummaries>,
    lang: Lang,
) -> Option<String> {
    if let Some(name) = enclosing_function_from_flow_steps(evidence) {
        return Some(name);
    }
    if let Some(summaries) = summaries {
        let mut hits = summaries
            .iter()
            .filter(|(k, _)| k.lang == lang)
            .filter(|(_, s)| paths_match(&s.file_path, &diag.path));
        if let Some(first) = hits.next()
            && hits.next().is_none()
        {
            // Unambiguous: exactly one function in this file.
            return Some(first.1.name.clone());
        }
        // Ambiguous (or none): fall through to AST resolution below rather
        // than refusing to guess — the sink line disambiguates.
    }
    // Last resort: parse the file and name the innermost function whose
    // line span contains the sink. Recovers a drivable entry for
    // rule-namespace findings that carry no flow_steps and have no (or an
    // ambiguous) summary — e.g. the deserialize fixtures verified with
    // `--index off`.
    resolve_enclosing_function_via_ast(&diag.path, diag.line, lang)
}

/// Parse `path` and return the name of the innermost function/method
/// definition whose 1-based line span contains `line`.
///
/// Used as the final fallback in [`resolve_enclosing_function`] so the
/// spec names the function a sink sits in even when the taint engine
/// produced no flow_steps and no [`GlobalSummaries`] were threaded
/// (the common `--index off` rule-namespace path). Best-effort: returns
/// `None` when the file cannot be read/parsed, the grammar is missing, or
/// the sink is at file top level with no enclosing function.
fn resolve_enclosing_function_via_ast(path: &str, line: usize, lang: Lang) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let ts_lang = tree_sitter_lang_for(lang)?;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).ok()?;
    let tree = parser.parse(&bytes, None)?;
    let slug = lang_slug(lang);
    let target_row = line.saturating_sub(1);

    // Walk every node spanning the target row, keeping the smallest-span
    // `Kind::Function` node (the innermost enclosing function).
    let mut best: Option<(usize, String)> = None;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let start_row = node.start_position().row;
        let end_row = node.end_position().row;
        if start_row > target_row || end_row < target_row {
            continue;
        }
        if crate::labels::lookup(slug, node.kind()) == crate::labels::Kind::Function
            && let Some(name) = function_node_name(node, &bytes)
        {
            let span = end_row - start_row;
            if best.as_ref().is_none_or(|(best_span, _)| span < *best_span) {
                best = Some((span, name));
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    best.map(|(_, name)| name)
}

/// Extract the declared name of a `Kind::Function` AST node.
///
/// Prefers the grammar's `name` field (present on Java `method_declaration`,
/// Ruby `method`, JS `function_declaration`, Python `function_definition`,
/// …); falls back to the first identifier-shaped child for grammars that do
/// not expose a `name` field. Returns `None` for anonymous functions.
fn function_node_name(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(text) = name_node.utf8_text(bytes)
        && !text.is_empty()
    {
        return Some(text.to_owned());
    }
    // C / C++ expose the function name inside the `declarator` subtree
    // (`function_definition` -> `function_declarator` -> `identifier`), not a
    // `name` field, so the direct-child scan below misses it.  Descend the
    // declarator chain first.
    if let Some(decl) = node.child_by_field_name("declarator")
        && let Some(name) = declarator_name(decl, bytes)
    {
        return Some(name);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if (kind == "identifier"
            || kind == "name"
            || kind == "field_identifier"
            || kind.ends_with("_identifier"))
            && let Ok(text) = child.utf8_text(bytes)
            && !text.is_empty()
        {
            return Some(text.to_owned());
        }
    }
    None
}

/// Follow a C / C++ declarator chain (`pointer_declarator`,
/// `function_declarator`, `parenthesized_declarator`, `array_declarator`, …)
/// down to the leaf identifier — the declared function name.
fn declarator_name(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut cur = node;
    loop {
        let kind = cur.kind();
        if kind == "identifier" || kind == "field_identifier" || kind == "type_identifier" {
            return cur
                .utf8_text(bytes)
                .ok()
                .filter(|t| !t.is_empty())
                .map(|t| t.to_owned());
        }
        match cur.child_by_field_name("declarator") {
            Some(next) => cur = next,
            None => break,
        }
    }
    // Leaf was not reached via the `declarator` field (e.g. an inner
    // `parenthesized_declarator`); scan immediate children for the identifier.
    let mut cursor = cur.walk();
    for child in cur.children(&mut cursor) {
        let kind = child.kind();
        if (kind == "identifier" || kind == "field_identifier")
            && let Ok(text) = child.utf8_text(bytes)
            && !text.is_empty()
        {
            return Some(text.to_owned());
        }
    }
    None
}

/// Lookup a `FuncSummary` by `(lang, name)` and filter to one whose
/// `file_path` matches `diag_path`. Returns `None` on no match.
fn find_summary_by_path<'a>(
    summaries: &'a GlobalSummaries,
    lang: Lang,
    name: &str,
    diag_path: &str,
) -> Option<&'a FuncSummary> {
    summaries
        .lookup_same_lang(lang, name)
        .into_iter()
        .find(|(_, s)| paths_match(&s.file_path, diag_path))
        .map(|(_, s)| s)
}

/// Companion to [`find_summary_by_path`] that returns the SSA
/// summary registered at the same `FuncKey`.  Used by
/// [`attach_framework_binding`] to feed
/// [`crate::dynamic::framework::detect_binding_with_context`] so
/// adapters can consult `typed_call_receivers` for FP narrowing.
fn find_ssa_summary_by_path<'a>(
    summaries: &'a GlobalSummaries,
    lang: Lang,
    name: &str,
    diag_path: &str,
) -> Option<&'a crate::summary::ssa_summary::SsaFuncSummary> {
    summaries
        .lookup_same_lang(lang, name)
        .into_iter()
        .find(|(_, s)| paths_match(&s.file_path, diag_path))
        .and_then(|(k, _)| summaries.get_ssa(k))
}

/// Loose path comparison that tolerates absolute / project-relative drift.
///
/// `FuncSummary::file_path` may be stored relative to the project root while
/// `Diag::path` may be canonicalised. A suffix match is permissive enough to
/// link them without dragging the canonicaliser into the verify hot path.
fn paths_match(summary_path: &str, diag_path: &str) -> bool {
    if summary_path == diag_path {
        return true;
    }
    summary_path.ends_with(diag_path) || diag_path.ends_with(summary_path)
}

/// Map the first segment of a Nyx rule id (`py`, `js`, `ts`, `java`, …) to a
/// [`Lang`]. Returns `None` for non-language prefixes (`taint-`, `cfg-`,
/// `state-`).
fn lang_from_rule_prefix(prefix: &str) -> Option<Lang> {
    match prefix {
        "rs" | "rust" => Some(Lang::Rust),
        "py" | "python" => Some(Lang::Python),
        "js" | "javascript" => Some(Lang::JavaScript),
        "ts" | "typescript" => Some(Lang::TypeScript),
        "java" => Some(Lang::Java),
        "go" => Some(Lang::Go),
        "php" => Some(Lang::Php),
        "rb" | "ruby" => Some(Lang::Ruby),
        "c" => Some(Lang::C),
        "cpp" => Some(Lang::Cpp),
        _ => None,
    }
}

/// Map the second segment of a Nyx rule id (e.g. `cmdi`, `xss`, `sqli`,
/// `deser`, `ssrf`, `path`, `auth`) to a [`Cap`].
fn cap_for_rule_category(category: &str) -> Option<Cap> {
    match category {
        "cmdi" | "command" => Some(Cap::SHELL_ESCAPE),
        "xss" => Some(Cap::HTML_ESCAPE),
        "sqli" | "sql" => Some(Cap::SQL_QUERY),
        "code_exec" | "eval" => Some(Cap::CODE_EXEC),
        "ssrf" => Some(Cap::SSRF),
        "path" | "traversal" => Some(Cap::FILE_IO),
        "deser" | "deserialize" => Some(Cap::DESERIALIZE),
        "auth" => Some(Cap::UNAUTHORIZED_ID),
        "format" | "fmtstr" => Some(Cap::FMT_STRING),
        "ldap" => Some(Cap::LDAP_INJECTION),
        "xpath" => Some(Cap::XPATH_INJECTION),
        "header" => Some(Cap::HEADER_INJECTION),
        "redirect" => Some(Cap::OPEN_REDIRECT),
        "ssti" | "template" => Some(Cap::SSTI),
        "xxe" => Some(Cap::XXE),
        "proto" | "prototype" => Some(Cap::PROTOTYPE_POLLUTION),
        _ => None,
    }
}

/// Remap a static *sink* capability onto the capability the dynamic corpus
/// keys its payload set + sound oracle under.
///
/// The static taint engine tags a shell command-injection sink with
/// [`Cap::SHELL_ESCAPE`] — the "data reaches a shell context" property — but
/// the dynamic corpus keys the command-injection oracle and every cmdi payload
/// under [`Cap::CODE_EXEC`] (see [`crate::dynamic::corpus::registry`]).  Left
/// unmapped, every command-injection finding derives a spec whose cap has no
/// oracle and routes to `Unsupported(SoundOracleUnavailable)` instead of being
/// executed — historically the single largest "unsupported" class.
///
/// `SHELL_ESCAPE` on a *sink* is always command injection, so swapping it for
/// `CODE_EXEC` is sound now that the cmdi oracle is collision-resistant
/// (corpus v16: the marker is produced only by executing the injected command,
/// not by a sink that safely echoes the quoted payload — so a benign
/// `os.system("echo " + shlex.quote(x))` control no longer false-confirms).
/// Other set bits are preserved so a multi-cap sink keeps its other
/// (already-driveable) capabilities.
pub(crate) fn drivable_expected_cap(cap: Cap) -> Cap {
    if cap.contains(Cap::SHELL_ESCAPE) {
        (cap - Cap::SHELL_ESCAPE) | Cap::CODE_EXEC
    } else {
        cap
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize_spec(
    diag: &Diag,
    entry_file: String,
    entry_name: String,
    lang: Lang,
    expected_cap: Cap,
    sink_file: String,
    sink_line: u32,
    derivation: SpecDerivationStrategy,
    summaries: Option<&GlobalSummaries>,
) -> HarnessSpec {
    // Drive the finding against the cap the corpus actually keys an oracle
    // under (command injection: SHELL_ESCAPE -> CODE_EXEC) instead of routing
    // to `Unsupported(SoundOracleUnavailable)`.
    let expected_cap = drivable_expected_cap(expected_cap);
    let toolchain_id = default_toolchain_id(lang).to_owned();
    let stubs_required = StubKind::for_cap(expected_cap);
    let mut spec = HarnessSpec {
        finding_id: format!("{:016x}", diag.stable_hash),
        entry_file,
        entry_name,
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id,
        payload_slot: PayloadSlot::Param(0),
        expected_cap,
        constraint_hints: vec![],
        sink_file,
        sink_line,
        spec_hash: String::new(),
        derivation,
        stubs_required,
        // Phase 01 (Track L.0): the framework adapter registry is
        // empty, so leave the binding unpopulated.  Subsequent phases
        // back-fill via `attach_framework_binding` once the spec's
        // entry has been resolved and an AST is available.
        framework: None,
        java_toolchain: JavaToolchain::default(),
    };
    attach_framework_binding(&mut spec, summaries);
    spec.spec_hash = compute_spec_hash(&spec);
    spec
}

/// Dispatch the resolved entry function through
/// [`crate::dynamic::framework::detect_binding`] and stash the result
/// on [`HarnessSpec::framework`].
///
/// Invoked unconditionally at the tail of [`finalize_spec`] so every
/// strategy ([`SpecDerivationStrategy::FromFlowSteps`] …
/// [`SpecDerivationStrategy::FromCallgraphEntry`]) benefits without
/// per-strategy plumbing.
///
/// # Phase 01 contract
///
/// The framework adapter registry is empty in Phase 01, so this
/// function fast-paths to a no-op when
/// [`crate::dynamic::framework::registry::adapters_for`] returns an
/// empty slice.  That avoids parsing the entry file from disk in the
/// common (empty) case and keeps the spec-derivation path side-effect
/// free.  Subsequent Track-L phases that register concrete adapters
/// also extend this function to parse `spec.entry_file` and call
/// [`crate::dynamic::framework::detect_binding`] with the resulting
/// tree-sitter root.
///
/// # GlobalSummaries lookup (Phase 01 follow-up)
///
/// When `summaries` is `Some`, the function resolves the real
/// [`FuncSummary`] for the spec's entry via
/// [`find_summary_by_path`] so the dispatched adapter sees the
/// function's actual `callees` (the field every
/// `any_callee_matches` check reads).  When `summaries` is `None`
/// or the lookup misses, the function falls back to a synthetic
/// [`FuncSummary`] carrying only `name` / `file_path` / `lang` — at
/// which point detection rides on the per-adapter `matches_source`
/// byte-grep fallback.
fn attach_framework_binding(spec: &mut HarnessSpec, summaries: Option<&GlobalSummaries>) {
    if crate::dynamic::framework::registry::adapters_for(spec.lang).is_empty() {
        return;
    }
    // Phase 03 (Track J.1 / deferred-fix from Phase 01): read the
    // entry file from disk, parse it with the language's tree-sitter
    // grammar, look up the matching `FuncSummary` from `summaries` so
    // adapters see the real `callees`, then dispatch through the
    // framework registry.  Failures along the way leave
    // `spec.framework = None` rather than aborting the run; the
    // framework binding is descriptive metadata, not a load-bearing
    // field on the verifier path.
    let Some(bytes) = std::fs::read(&spec.entry_file).ok() else {
        return;
    };
    let Some(ts_lang) = tree_sitter_lang_for(spec.lang) else {
        return;
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&ts_lang).is_err() {
        return;
    }
    let Some(tree) = parser.parse(&bytes, None) else {
        return;
    };
    let synthetic = FuncSummary {
        name: spec.entry_name.clone(),
        file_path: spec.entry_file.clone(),
        lang: lang_slug(spec.lang).to_owned(),
        ..Default::default()
    };
    let resolved = summaries
        .and_then(|gs| find_summary_by_path(gs, spec.lang, &spec.entry_name, &spec.entry_file));
    let summary_ref = resolved.unwrap_or(&synthetic);
    let ssa_ref = summaries
        .and_then(|gs| find_ssa_summary_by_path(gs, spec.lang, &spec.entry_name, &spec.entry_file));
    let project_files = framework_project_files_for_entry(&spec.entry_file, spec.lang);
    let context = FrameworkDetectionContext {
        ssa_summary: ssa_ref,
        project_files: &project_files,
    };
    if let Some(binding) = crate::dynamic::framework::detect_binding_with_project_context(
        summary_ref,
        context,
        tree.root_node(),
        &bytes,
        spec.lang,
    ) {
        stamp_framework_binding(spec, binding);
    }
}

fn framework_project_files_for_entry(entry_file: &str, lang: Lang) -> ProjectFileIndex {
    let Some(root) = infer_framework_project_root(Path::new(entry_file), lang) else {
        return ProjectFileIndex::new();
    };
    let rel_paths: &[&str] = match lang {
        Lang::Ruby => &["config/routes.rb"],
        Lang::Php => &[
            "config/routes.yaml",
            "config/routes.yml",
            "routes/web.php",
            "routes/api.php",
            "app/Config/Routes.php",
        ],
        Lang::Java => &[
            "changelog.xml",
            "changelog.yaml",
            "changelog.yml",
            "changelog.json",
            "db/changelog/db.changelog-master.xml",
            "db/changelog/db.changelog-master.yaml",
            "db/changelog/db.changelog-master.yml",
            "db/changelog/db.changelog-master.json",
            "src/main/resources/db/changelog/db.changelog-master.xml",
            "src/main/resources/db/changelog/db.changelog-master.yaml",
            "src/main/resources/db/changelog/db.changelog-master.yml",
            "src/main/resources/db/changelog/db.changelog-master.json",
        ],
        _ => &[],
    };
    let index = ProjectFileIndex::from_root(&root, rel_paths);
    match lang {
        Lang::Go => index.include_dirs(&root, &["migrations", "db/migrations"], &["sql"]),
        _ => index,
    }
}

fn infer_framework_project_root(entry_path: &Path, lang: Lang) -> Option<PathBuf> {
    let dirs: &[&str] = match lang {
        Lang::Ruby => &["app"],
        Lang::Php => &["src", "app"],
        _ => &[],
    };
    for ancestor in entry_path.ancestors() {
        let Some(name) = ancestor.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if dirs.contains(&name)
            && let Some(parent) = ancestor.parent()
        {
            return Some(parent.to_path_buf());
        }
    }
    entry_path.parent().map(|p| p.to_path_buf())
}

/// Phase 18 (Track M.0) — apply a resolved [`FrameworkBinding`] onto
/// the spec.  Carved out of [`attach_framework_binding`] so the
/// stamping branch (Phase 18 data-bearing-variant propagation +
/// Phase 14 Spring-test toolchain knob) is unit-testable without
/// needing a registered framework adapter — the deferred-fix Phase
/// 18 test for `spec_attach_framework_binding_stamps_new_entry_kind_variant`
/// drives a synthetic binding through this helper directly.
fn stamp_framework_binding(spec: &mut HarnessSpec, binding: FrameworkBinding) {
    let mut hash_material_changed = false;
    // Phase 14 (Track L.12): flip the Spring-test toolchain knob
    // when the java-spring adapter binds, so the Java emitter
    // bootstraps `SpringApplication.run` / `MockMvc` for Spring
    // routes and skips that heavier path for the other Java
    // shapes (Quarkus / Micronaut / Servlet).
    if spec.lang == Lang::Java && binding.adapter == "java-spring" {
        spec.java_toolchain.with_spring_test = true;
    }
    // Phase 18 (Track M.0): the binding carries the adapter's view
    // of the entry shape — when the adapter stamps one of the new
    // data-bearing variants (`ClassMethod`, `MessageHandler`,
    // `ScheduledJob`, …), propagate that onto the spec so the
    // verifier's `entry_kind_is_supported` gate sees the structural
    // shape and short-circuits to a typed
    // `Inconclusive(EntryKindUnsupported)`.  We deliberately do not
    // overwrite the legacy unit variants here: every adapter
    // shipped through Phase 17 stamps `Function` / `HttpRoute` and
    // the derivation pipeline already routes those correctly.
    if matches!(
        binding.kind.tag(),
        crate::evidence::EntryKindTag::ClassMethod
            | crate::evidence::EntryKindTag::MessageHandler
            | crate::evidence::EntryKindTag::ScheduledJob
            | crate::evidence::EntryKindTag::GraphQLResolver
            | crate::evidence::EntryKindTag::WebSocket
            | crate::evidence::EntryKindTag::Middleware
            | crate::evidence::EntryKindTag::Migration
    ) {
        spec.entry_kind = binding.kind.clone();
        hash_material_changed = true;
    }
    if let Some(kind) = broker_stub_kind_for_adapter(&binding.adapter)
        && !spec.stubs_required.contains(&kind)
    {
        spec.stubs_required.push(kind);
        hash_material_changed = true;
    }
    if matches!(binding.kind.tag(), crate::evidence::EntryKindTag::Migration)
        && !spec.stubs_required.contains(&StubKind::Sql)
    {
        spec.stubs_required.push(StubKind::Sql);
        hash_material_changed = true;
    }
    spec.framework = Some(binding);
    if hash_material_changed {
        spec.spec_hash = compute_spec_hash(spec);
    }
}

fn broker_stub_kind_for_adapter(adapter: &str) -> Option<StubKind> {
    match adapter.split_once('-').map(|(broker, _)| broker) {
        Some("kafka") => Some(StubKind::Kafka),
        Some("sqs") => Some(StubKind::Sqs),
        Some("pubsub") => Some(StubKind::Pubsub),
        Some("rabbit") => Some(StubKind::Rabbit),
        Some("nats") => Some(StubKind::Nats),
        _ => None,
    }
}

/// Pick the tree-sitter `Language` for a given [`Lang`].  Returns
/// `None` for languages whose grammar is not linked into the dynamic
/// path (rare — every supported `Lang` carries a grammar).
fn tree_sitter_lang_for(lang: Lang) -> Option<tree_sitter::Language> {
    Some(match lang {
        Lang::Rust => tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
        Lang::C => tree_sitter::Language::from(tree_sitter_c::LANGUAGE),
        Lang::Cpp => tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE),
        Lang::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Lang::Go => tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
        Lang::Php => tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
        Lang::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Lang::Ruby => tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE),
        Lang::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        Lang::TypeScript => {
            tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT)
        }
    })
}

fn lang_slug(lang: Lang) -> &'static str {
    match lang {
        Lang::Rust => "rust",
        Lang::C => "c",
        Lang::Cpp => "cpp",
        Lang::Java => "java",
        Lang::Go => "go",
        Lang::Php => "php",
        Lang::Python => "python",
        Lang::Ruby => "ruby",
        Lang::JavaScript => "javascript",
        Lang::TypeScript => "typescript",
    }
}

/// Walk `flow_steps` and return the entry point: the enclosing function of
/// the first `Source` step that has a function annotation. This is the
/// outermost callable that receives the tainted input.
pub fn outermost_entry(steps: &[crate::evidence::FlowStep]) -> Option<EntryRef> {
    for step in steps {
        if matches!(step.kind, FlowStepKind::Source)
            && let Some(ref func) = step.function
            && !func.is_empty()
        {
            return Some(EntryRef {
                file: step.file.clone(),
                function: func.clone(),
            });
        }
    }
    None
}

/// Default toolchain label for a language (informational; harness builder
/// may override for locally-installed compilers/runtimes).
pub fn default_toolchain_id(lang: Lang) -> &'static str {
    match lang {
        Lang::Rust => "rust-stable",
        Lang::C => "gcc-stable",
        Lang::Cpp => "g++-stable",
        Lang::Java => "java-21",
        Lang::Go => "go-stable",
        Lang::Php => "php-8",
        Lang::Python => "python-3",
        Lang::Ruby => "ruby-3",
        Lang::TypeScript | Lang::JavaScript => "node-20",
    }
}

/// Blake3 hash of the spec's key fields, truncated to 8 bytes and hex-encoded.
///
/// Inputs (in order): [`SPEC_FORMAT_VERSION`] (u32 LE), entry_file,
/// entry_name, payload_slot tag + value, expected_cap bits (u32 LE),
/// sorted constraint_hints, toolchain_id, [`CORPUS_VERSION`] (u32 LE).
///
/// Bump [`SPEC_FORMAT_VERSION`] when the inputs or semantics change.
fn compute_spec_hash(spec: &HarnessSpec) -> String {
    let mut h = blake3::Hasher::new();

    h.update(&SPEC_FORMAT_VERSION.to_le_bytes());
    h.update(spec.entry_file.as_bytes());
    h.update(b"\0");
    h.update(spec.entry_name.as_bytes());
    h.update(b"\0");

    // Payload slot: tag byte + optional value
    match &spec.payload_slot {
        PayloadSlot::Param(n) => {
            h.update(&[0u8]);
            h.update(&(*n as u64).to_le_bytes());
        }
        PayloadSlot::QueryParam(s) => {
            h.update(&[1u8]);
            h.update(s.as_bytes());
        }
        PayloadSlot::HttpBody => {
            h.update(&[2u8]);
        }
        PayloadSlot::EnvVar(s) => {
            h.update(&[3u8]);
            h.update(s.as_bytes());
        }
        PayloadSlot::Argv(n) => {
            h.update(&[4u8]);
            h.update(&(*n as u64).to_le_bytes());
        }
        PayloadSlot::Stdin => {
            h.update(&[5u8]);
        }
    }

    h.update(&spec.expected_cap.bits().to_le_bytes());

    let mut hints = spec.constraint_hints.clone();
    hints.sort_unstable();
    for hint in &hints {
        h.update(hint.as_bytes());
        h.update(b"\0");
    }

    h.update(spec.toolchain_id.as_bytes());
    h.update(b"\0");
    h.update(spec.sink_file.as_bytes());
    h.update(b"\0");
    h.update(&spec.sink_line.to_le_bytes());
    h.update(&CORPUS_VERSION.to_le_bytes());

    // Phase 10: spec hash must flip when stubs_required changes so the
    // dynamic verdict cache evicts entries computed under a different
    // boundary topology. Sort first so order-independence holds.
    let mut stubs: Vec<&StubKind> = spec.stubs_required.iter().collect();
    stubs.sort_unstable_by_key(|k| k.tag());
    for s in stubs {
        h.update(s.tag().as_bytes());
        h.update(b"\0");
    }

    let out = h.finalize();
    let bytes = out.as_bytes();
    format!(
        "{:016x}",
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, FlowStep, FlowStepKind};

    #[test]
    fn ast_resolver_names_run_for_deser_fixtures() {
        // The deserialize fixtures carry no flow_steps and resolve no
        // summaries under `--index off`; AST resolution must still name the
        // enclosing `run` function the sink sits in so the harness can drive
        // it and the author's guard participates in the verdict.
        let cases = [
            (
                "tests/dynamic_fixtures/deserialize/java/Benign.java",
                36,
                Lang::Java,
            ),
            (
                "tests/dynamic_fixtures/deserialize/java/Vuln.java",
                14,
                Lang::Java,
            ),
            (
                "tests/dynamic_fixtures/deserialize/ruby/benign.rb",
                14,
                Lang::Ruby,
            ),
            (
                "tests/dynamic_fixtures/deserialize/ruby/vuln.rb",
                7,
                Lang::Ruby,
            ),
        ];
        for (path, line, lang) in cases {
            assert_eq!(
                resolve_enclosing_function_via_ast(path, line, lang).as_deref(),
                Some("run"),
                "AST resolution should name `run` for {path}:{line}"
            );
        }
    }

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

    #[test]
    fn outermost_entry_picks_source_step() {
        let steps = vec![
            source_step("src/main.rs", "handle_request"),
            sink_step("src/main.rs"),
        ];
        let entry = outermost_entry(&steps).unwrap();
        assert_eq!(entry.file, "src/main.rs");
        assert_eq!(entry.function, "handle_request");
    }

    #[test]
    fn outermost_entry_none_when_no_source() {
        let steps = vec![sink_step("src/main.rs")];
        assert!(outermost_entry(&steps).is_none());
    }

    #[test]
    fn outermost_entry_none_when_source_has_no_function() {
        let mut step = source_step("src/main.rs", "");
        step.function = None;
        let steps = vec![step, sink_step("src/main.rs")];
        assert!(outermost_entry(&steps).is_none());
    }

    #[test]
    fn from_finding_err_low_confidence() {
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::Low),
            ..Default::default()
        };
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::ConfidenceTooLow
        );
    }

    #[test]
    fn from_finding_err_no_flow_steps_falls_through_to_spec_derivation_failed() {
        // Pre–Phase 01, this returned `NoFlowSteps` directly. After the
        // typed-strategy rewrite, the verifier still tries the rule-namespace
        // and func-summary strategies; only when *every* strategy fails does
        // it surface `SpecDerivationFailed`. Empty evidence + empty rule
        // id leaves nothing for any strategy to chew on.
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::Medium),
            evidence: Some(Evidence::default()),
            ..Default::default()
        };
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::SpecDerivationFailed
        );
    }

    #[test]
    fn from_finding_err_no_evidence_returns_no_flow_steps() {
        // When the finding carries no Evidence struct at all, there is no
        // signal for any strategy. Reported as `NoFlowSteps`.
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::Medium),
            evidence: None,
            ..Default::default()
        };
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::NoFlowSteps
        );
    }

    #[test]
    fn from_finding_ok_rust_medium_confidence() {
        use crate::labels::Cap;
        let evidence = Evidence {
            flow_steps: vec![
                source_step("src/handler.rs", "process"),
                sink_step("src/handler.rs"),
            ],
            sink_caps: Cap::SQL_QUERY.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::Medium),
            evidence: Some(evidence),
            ..Default::default()
        };
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.lang, Lang::Rust);
        assert_eq!(spec.entry_name, "process");
        assert_eq!(spec.toolchain_id, "rust-stable");
        assert!(!spec.spec_hash.is_empty());
        // A flow-step-named entry is drivable — the harness invokes it.
        assert!(spec.entry_is_derivable());
    }

    #[test]
    fn entry_is_derivable_distinguishes_real_name_from_placeholder() {
        let mut spec = HarnessSpec {
            finding_id: "0".into(),
            entry_file: "src/app.rs".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Rust,
            toolchain_id: "rust-stable".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: crate::labels::Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/app.rs".into(),
            sink_line: 1,
            spec_hash: "0".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: JavaToolchain::default(),
        };
        assert!(spec.entry_is_derivable());
        spec.entry_name = "<unknown>".into();
        assert!(!spec.entry_is_derivable());
        spec.entry_name = String::new();
        assert!(!spec.entry_is_derivable());
    }

    #[test]
    fn spec_hash_is_deterministic() {
        use crate::labels::Cap;
        let evidence = Evidence {
            flow_steps: vec![
                source_step("src/handler.rs", "process"),
                sink_step("src/handler.rs"),
            ],
            sink_caps: Cap::SQL_QUERY.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::High),
            evidence: Some(evidence),
            ..Default::default()
        };
        let s1 = HarnessSpec::from_finding(&diag).unwrap();
        let s2 = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(s1.spec_hash, s2.spec_hash);
    }

    fn base_spec() -> HarnessSpec {
        use crate::labels::Cap;
        let mut spec = HarnessSpec {
            finding_id: "0000000000000000".into(),
            entry_file: "src/handler.rs".into(),
            entry_name: "process".into(),
            entry_kind: EntryKind::Function,
            lang: crate::symbol::Lang::Rust,
            toolchain_id: "rust-stable".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/handler.rs".into(),
            sink_line: 10,
            spec_hash: String::new(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: JavaToolchain::default(),
        };
        spec.spec_hash = compute_spec_hash(&spec);
        spec
    }

    #[test]
    fn spec_hash_flips_on_entry_file() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.entry_file = "src/other.rs".into();
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(
            s1.spec_hash, s2.spec_hash,
            "entry_file mutation must change spec_hash"
        );
    }

    #[test]
    fn spec_hash_flips_on_entry_name() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.entry_name = "other_handler".into();
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(
            s1.spec_hash, s2.spec_hash,
            "entry_name mutation must change spec_hash"
        );
    }

    #[test]
    fn spec_hash_flips_on_payload_slot() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.payload_slot = PayloadSlot::Param(1);
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(
            s1.spec_hash, s2.spec_hash,
            "payload_slot mutation must change spec_hash"
        );

        let mut s3 = s1.clone();
        s3.payload_slot = PayloadSlot::HttpBody;
        s3.spec_hash = compute_spec_hash(&s3);
        assert_ne!(
            s1.spec_hash, s3.spec_hash,
            "payload_slot tag change must change spec_hash"
        );

        let mut s4 = s1.clone();
        s4.payload_slot = PayloadSlot::EnvVar("NYX_INPUT".into());
        s4.spec_hash = compute_spec_hash(&s4);
        assert_ne!(
            s1.spec_hash, s4.spec_hash,
            "EnvVar payload_slot must change spec_hash"
        );
    }

    #[test]
    fn spec_hash_flips_on_expected_cap() {
        use crate::labels::Cap;
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.expected_cap = Cap::CODE_EXEC;
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(
            s1.spec_hash, s2.spec_hash,
            "expected_cap mutation must change spec_hash"
        );
    }

    #[test]
    fn spec_hash_flips_on_constraint_hints() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.constraint_hints = vec!["prefix:admin/".into()];
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(
            s1.spec_hash, s2.spec_hash,
            "constraint_hints mutation must change spec_hash"
        );
    }

    #[test]
    fn spec_hash_flips_on_toolchain_id() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.toolchain_id = "rust-nightly".into();
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(
            s1.spec_hash, s2.spec_hash,
            "toolchain_id mutation must change spec_hash"
        );
    }

    // ── Phase 01: derivation strategies ──────────────────────────────────────

    fn diag_with_rule_id(id: &str, path: &str, sink_caps: u32) -> crate::commands::scan::Diag {
        crate::commands::scan::Diag {
            id: id.into(),
            path: path.into(),
            line: 12,
            col: 4,
            confidence: Some(Confidence::Medium),
            evidence: Some(Evidence {
                sink_caps,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn derivation_strategies_returns_ordered_list() {
        let strategies = HarnessSpec::derivation_strategies();
        assert_eq!(strategies.len(), 4);
        assert_eq!(strategies[0], SpecDerivationStrategy::FromFlowSteps);
        assert_eq!(strategies[1], SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(strategies[2], SpecDerivationStrategy::FromFuncSummaryWalk);
        assert_eq!(strategies[3], SpecDerivationStrategy::FromCallgraphEntry);
    }

    #[test]
    fn flow_steps_strategy_records_derivation_tag() {
        use crate::labels::Cap;
        let evidence = Evidence {
            flow_steps: vec![
                source_step("src/handler.py", "handle_request"),
                sink_step("src/handler.py"),
            ],
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::High),
            evidence: Some(evidence),
            path: "src/handler.py".into(),
            ..Default::default()
        };
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromFlowSteps);
        assert_eq!(spec.entry_name, "handle_request");
    }

    #[test]
    fn rule_namespace_strategy_fires_without_flow_steps() {
        use crate::labels::Cap;
        let diag = diag_with_rule_id(
            "py.cmdi.os_system",
            "app/handler.py",
            Cap::SHELL_ESCAPE.bits(),
        );
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, Lang::Python);
        // cmdi sink cap `SHELL_ESCAPE` remaps to the driveable `CODE_EXEC`.
        assert_eq!(spec.expected_cap, Cap::CODE_EXEC);
        assert_eq!(spec.entry_file, "app/handler.py");
        assert_eq!(spec.sink_line, 12);
    }

    #[test]
    fn rule_namespace_strategy_picks_cap_from_category_when_sink_caps_zero() {
        let diag = diag_with_rule_id("java.deser.readobject", "src/Main.java", 0);
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, Lang::Java);
        assert_eq!(spec.expected_cap, Cap::DESERIALIZE);
    }

    #[test]
    fn drivable_expected_cap_remaps_shell_escape_to_code_exec() {
        // Command injection: the oracle + payloads live under `CODE_EXEC`,
        // while the static engine tags cmdi sinks `SHELL_ESCAPE` (which has no
        // sound oracle of its own).  The remap routes cmdi findings to the real
        // (collision-resistant, corpus v16) oracle instead of
        // `SoundOracleUnavailable`.
        assert_eq!(drivable_expected_cap(Cap::SHELL_ESCAPE), Cap::CODE_EXEC);
        // Multi-cap sinks keep their other (already-driveable) bits.
        assert_eq!(
            drivable_expected_cap(Cap::SHELL_ESCAPE | Cap::FILE_IO),
            Cap::CODE_EXEC | Cap::FILE_IO
        );
        // Caps without SHELL_ESCAPE pass through untouched.
        assert_eq!(drivable_expected_cap(Cap::SQL_QUERY), Cap::SQL_QUERY);
        assert_eq!(drivable_expected_cap(Cap::CODE_EXEC), Cap::CODE_EXEC);
    }

    #[test]
    fn rule_namespace_strategy_pins_rs_auth_mapping() {
        // Regression: `rs.auth.*` must map to `Lang::Rust` + `Cap::UNAUTHORIZED_ID`.
        // The plan calls out this exemplar but had no test coverage.
        let diag = diag_with_rule_id("rs.auth.missing_ownership_check.taint", "src/handler.rs", 0);
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, Lang::Rust);
        assert_eq!(spec.expected_cap, Cap::UNAUTHORIZED_ID);
        assert_eq!(spec.toolchain_id, "rust-stable");
    }

    #[test]
    fn rule_namespace_strategy_rejects_path_lang_mismatch() {
        use crate::labels::Cap;
        // `py.*` rule id, but a `.java` file — the cross-check refuses.
        let diag = diag_with_rule_id(
            "py.cmdi.os_system",
            "src/Main.java",
            Cap::SHELL_ESCAPE.bits(),
        );
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::SpecDerivationFailed
        );
    }

    #[test]
    fn rule_namespace_strategy_rejects_unknown_category() {
        // Cap evidence zero AND category unknown → no fallback cap available.
        let diag = diag_with_rule_id("py.weirdcategory.unknown", "app/handler.py", 0);
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::SpecDerivationFailed
        );
    }

    #[test]
    fn rule_namespace_strategy_skips_unknown_taint_ids() {
        use crate::labels::Cap;
        // Unregistered `taint-*` rule slugs (e.g. the legacy generic
        // `taint-unsanitised-flow`) are not in `CAP_RULE_REGISTRY`; the
        // shortcut must skip them so downstream strategies can try.
        let diag = diag_with_rule_id(
            "taint-unsanitised-flow",
            "app/handler.py",
            Cap::SHELL_ESCAPE.bits(),
        );
        // No flow_steps, no http/cli marker → ends in SpecDerivationFailed.
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::SpecDerivationFailed
        );
    }

    #[test]
    fn rule_namespace_strategy_resolves_registered_taint_ldap_injection() {
        use crate::labels::Cap;
        // Java OWASP fixtures emit `taint-ldap-injection` with no flow_steps;
        // the rule slug carries the cap, the file extension carries the lang.
        let diag = diag_with_rule_id(
            "taint-ldap-injection",
            "src/main/java/org/owasp/benchmark/Vuln.java",
            Cap::LDAP_INJECTION.bits(),
        );
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, Lang::Java);
        assert_eq!(spec.expected_cap, Cap::LDAP_INJECTION);
        assert_eq!(spec.sink_line, 12);
    }

    #[test]
    fn rule_namespace_strategy_taint_id_falls_back_to_registry_cap_when_evidence_zero() {
        use crate::labels::Cap;
        // sink_caps=0 → use the cap from `CAP_RULE_REGISTRY`.
        let diag = diag_with_rule_id("taint-sql-injection", "app/handler.py", 0);
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, Lang::Python);
        assert_eq!(spec.expected_cap, Cap::SQL_QUERY);
    }

    #[test]
    fn rule_namespace_strategy_taint_id_lang_follows_path_extension() {
        use crate::labels::Cap;
        // Same rule slug, different file extension → derives a Go spec.
        let diag = diag_with_rule_id(
            "taint-data-exfiltration",
            "cmd/leak.go",
            Cap::DATA_EXFIL.bits(),
        );
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, Lang::Go);
        assert_eq!(spec.expected_cap, Cap::DATA_EXFIL);
    }

    #[test]
    fn rule_namespace_strategy_taint_id_requires_path() {
        use crate::labels::Cap;
        // Path empty → cannot infer lang; strategy bails so callgraph-entry
        // can try.
        let diag = crate::commands::scan::Diag {
            id: "taint-ldap-injection".into(),
            path: String::new(),
            line: 12,
            col: 4,
            confidence: Some(Confidence::Medium),
            evidence: Some(Evidence {
                sink_caps: Cap::LDAP_INJECTION.bits(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            HarnessSpec::from_finding(&diag).unwrap_err(),
            UnsupportedReason::SpecDerivationFailed
        );
    }

    #[test]
    fn func_summary_strategy_picks_first_tainted_param() {
        use crate::labels::Cap;
        let evidence = Evidence::default();
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::Medium),
            evidence: Some(evidence.clone()),
            path: "src/lib.rs".into(),
            line: 7,
            ..Default::default()
        };
        let summary = FuncSummary {
            name: "open_path".into(),
            file_path: "src/lib.rs".into(),
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
        let spec = derive_from_func_summary(&diag, &evidence, Some(&summary))
            .expect("summary strategy must fire");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromFuncSummaryWalk);
        assert!(matches!(spec.payload_slot, PayloadSlot::Param(1)));
        assert_eq!(spec.entry_name, "open_path");
        assert_eq!(spec.expected_cap, Cap::FILE_IO);
    }

    #[test]
    fn callgraph_entry_strategy_fires_on_http_rule_id() {
        use crate::labels::Cap;
        // `http` is not in `cap_for_rule_category`, so rule-namespace bails.
        // The id contains `.http.`, so callgraph-entry catches it.
        let diag = diag_with_rule_id("py.http.flask_route", "app/views.py", Cap::SSRF.bits());
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromCallgraphEntry);
        assert!(matches!(spec.entry_kind, EntryKind::HttpRoute));
        assert_eq!(spec.lang, Lang::Python);
    }

    #[test]
    fn callgraph_entry_strategy_fires_on_cli_rule_id() {
        use crate::labels::Cap;
        let diag = diag_with_rule_id(
            "rs.cli.parse_subcommand",
            "src/main.rs",
            Cap::SHELL_ESCAPE.bits(),
        );
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromCallgraphEntry);
        assert!(matches!(spec.entry_kind, EntryKind::CliSubcommand));
    }

    #[test]
    fn strategy_priority_flow_steps_beats_rule_namespace() {
        use crate::labels::Cap;
        // Both signals present: flow_steps wins because it appears first
        // in the strategy order.
        let evidence = Evidence {
            flow_steps: vec![
                source_step("src/handler.py", "handle_request"),
                sink_step("src/handler.py"),
            ],
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            id: "py.cmdi.os_system".into(),
            confidence: Some(Confidence::High),
            evidence: Some(evidence),
            path: "src/handler.py".into(),
            ..Default::default()
        };
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromFlowSteps);
    }

    // ── Phase 01 follow-ups: GlobalSummaries threading ───────────────────────

    fn sink_only_step_with_function(file: &str, function: &str) -> crate::evidence::FlowStep {
        crate::evidence::FlowStep {
            step: 1,
            kind: FlowStepKind::Sink,
            file: file.into(),
            line: 6,
            col: 0,
            snippet: Some("os.system".into()),
            variable: None,
            callee: Some("os.system".into()),
            function: Some(function.into()),
            is_cross_file: false,
        }
    }

    fn build_summary(
        name: &str,
        file: &str,
        lang: &str,
        sink_caps: u32,
        tainted_params: Vec<usize>,
        entry_kind: Option<crate::entry_points::EntryKind>,
    ) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            file_path: file.into(),
            lang: lang.into(),
            param_count: 1,
            param_names: vec!["req".into()],
            source_caps: 0,
            sanitizer_caps: 0,
            sink_caps,
            propagating_params: vec![],
            propagates_taint: false,
            tainted_sink_params: tainted_params,
            param_to_sink: vec![],
            callees: vec![],
            container: String::new(),
            disambig: None,
            kind: Default::default(),
            module_path: None,
            rust_use_map: None,
            rust_wildcards: None,
            hierarchy_edges: vec![],
            entry_kind,
        }
    }

    #[test]
    fn entry_name_uses_flow_steps_function_not_snippet() {
        // Strategy 2 was previously populating `entry_name` from the sink's
        // *snippet* (callee text like `"os.system"`). The fix prefers the
        // `function` annotation on any flow step, which carries the
        // enclosing function name.
        use crate::labels::Cap;
        let ev = Evidence {
            flow_steps: vec![sink_only_step_with_function("app/handler.py", "do_request")],
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            id: "py.cmdi.os_system".into(),
            path: "app/handler.py".into(),
            line: 6,
            confidence: Some(Confidence::High),
            evidence: Some(ev.clone()),
            ..Default::default()
        };
        let spec = derive_from_rule_namespace(&diag, &ev).expect("must derive");
        assert_eq!(spec.entry_name, "do_request");
        // The callee text never leaks into the entry name.
        assert!(!spec.entry_name.contains("os.system"));
    }

    #[test]
    fn func_summary_auto_resolves_via_global_summaries() {
        // Strategy 3 with `summaries = Some(_)`: the enclosing function
        // name comes from the flow_steps annotation, the summary is found
        // by `(lang, name)` lookup filtered by file_path, and the spec
        // picks `tainted_sink_params[0]` as the payload slot.
        //
        // The evidence intentionally carries `sink_caps = 0`: this is the
        // scenario `func_summary_auto` exists for — recovering the cap (and
        // the tainted-param slot) from the summary when the finding's own
        // flow evidence lacks them.  With a zero evidence cap, `FromFlowSteps`
        // bails (it requires a non-empty cap), so `FromFuncSummaryWalk` is the
        // strategy that supplies the cap and wins.  (When the evidence *does*
        // carry a cap, `FromFlowSteps` derives the same enclosing-function
        // entry directly and outranks the summary walk per the precedence
        // ladder — that path is covered by the flow-steps tests.)
        use crate::labels::Cap;
        use crate::symbol::FuncKey;
        let mut gs = GlobalSummaries::new();
        let summary = build_summary(
            "do_request",
            "app/handler.py",
            "python",
            Cap::SHELL_ESCAPE.bits(),
            vec![0],
            None,
        );
        let key = FuncKey::new_function(Lang::Python, "app/handler.py", "do_request", Some(1));
        gs.insert(key, summary);

        let ev = Evidence {
            flow_steps: vec![sink_only_step_with_function("app/handler.py", "do_request")],
            sink_caps: 0,
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            id: "taint-unsanitised-flow".into(),
            path: "app/handler.py".into(),
            line: 6,
            confidence: Some(Confidence::High),
            evidence: Some(ev),
            ..Default::default()
        };
        let spec = HarnessSpec::from_finding_with_summaries(&diag, false, Some(&gs))
            .expect("summary-driven derivation must succeed");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromFuncSummaryWalk);
        assert!(matches!(spec.payload_slot, PayloadSlot::Param(0)));
        assert_eq!(spec.entry_name, "do_request");
    }

    #[test]
    fn callgraph_entry_uses_summary_entry_kind_over_rule_id() {
        // Strategy 4 with summaries: a non-http/non-cli rule id still wins
        // HttpRoute classification when the enclosing function's
        // `entry_kind` is set on its summary.
        use crate::entry_points::{EntryKind as StaticEntryKind, HttpMethod};
        use crate::labels::Cap;
        use crate::symbol::FuncKey;
        let mut gs = GlobalSummaries::new();
        let summary = build_summary(
            "index",
            "app/views.py",
            "python",
            Cap::SSRF.bits(),
            vec![],
            Some(StaticEntryKind::FlaskRoute {
                method: HttpMethod::GET,
            }),
        );
        let key = FuncKey::new_function(Lang::Python, "app/views.py", "index", Some(1));
        gs.insert(key, summary);

        let ev = Evidence {
            flow_steps: vec![sink_only_step_with_function("app/views.py", "index")],
            sink_caps: Cap::SSRF.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            // Note: the rule id has no `.http.` or `.cli.` segment — the
            // legacy substring heuristic would bail. Only the summary
            // entry_kind unlocks HttpRoute classification.
            id: "taint-unsanitised-flow".into(),
            path: "app/views.py".into(),
            line: 6,
            confidence: Some(Confidence::High),
            evidence: Some(ev.clone()),
            ..Default::default()
        };
        let spec = derive_from_callgraph_entry_with(&diag, &ev, Some(&gs))
            .expect("entry-kind-driven derivation must succeed");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromCallgraphEntry);
        assert!(matches!(spec.entry_kind, EntryKind::HttpRoute));
        assert_eq!(spec.entry_name, "index");
    }

    #[test]
    fn attach_framework_binding_uses_real_callees_from_global_summaries() {
        // Phase 03 deferred-fix: `attach_framework_binding` resolves the
        // entry's real `FuncSummary` from `GlobalSummaries` so the
        // adapter's `any_callee_matches` predicate sees populated
        // `callees`.  The fixture's source text deliberately omits any
        // `Marshal.load` / `YAML.load` keyword so the
        // `matches_source` byte-grep fallback in
        // `RubyMarshalAdapter::detect` cannot fire — only the
        // callee-driven path can produce a binding.
        use crate::labels::Cap;
        use crate::summary::CalleeSite;
        use crate::symbol::FuncKey;
        use std::io::Write;

        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = dir.path().join("handler.rb");
        // No `Marshal.load` or `YAML.load` substring; the adapter must
        // rely on `summary.callees` to bind.
        let src = b"def run(blob)\n  helper(blob)\nend\n";
        std::fs::File::create(&fixture)
            .expect("fixture create")
            .write_all(src)
            .expect("fixture write");
        let entry_file = fixture.to_string_lossy().into_owned();

        let ev = Evidence {
            flow_steps: vec![sink_only_step_with_function(&entry_file, "run")],
            sink_caps: Cap::DESERIALIZE.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            id: "rb.deser.marshal_load".into(),
            path: entry_file.clone(),
            line: 2,
            confidence: Some(Confidence::High),
            evidence: Some(ev.clone()),
            ..Default::default()
        };

        // 1. Without summaries: synthetic FuncSummary, callees empty,
        //    source byte-grep misses → spec.framework = None.
        let spec_no_summaries = derive_from_rule_namespace_with(&diag, &ev, None)
            .expect("rule-namespace derivation must succeed");
        assert!(
            spec_no_summaries.framework.is_none(),
            "synthetic FuncSummary path must not produce a binding when source bytes lack the sink keyword",
        );

        // 2. With summaries: real FuncSummary lookup picks up the
        //    populated `callees` and the adapter binds.
        let mut gs = GlobalSummaries::new();
        let mut summary = build_summary(
            "run",
            &entry_file,
            "ruby",
            Cap::DESERIALIZE.bits(),
            vec![0],
            None,
        );
        summary.callees = vec![CalleeSite::bare("Marshal.load")];
        let key = FuncKey::new_function(Lang::Ruby, &entry_file, "run", Some(1));
        gs.insert(key, summary);

        let spec_with_summaries = derive_from_rule_namespace_with(&diag, &ev, Some(&gs))
            .expect("rule-namespace derivation must succeed");
        let binding = spec_with_summaries
            .framework
            .as_ref()
            .expect("real FuncSummary lookup must populate the framework binding");
        assert_eq!(binding.adapter, "ruby-marshal");
        assert_eq!(binding.kind, EntryKind::Function);

        // 3. `compute_spec_hash` excludes the binding, so the two specs
        //    hash identically.  Phase 01 contract: framework is purely
        //    descriptive metadata.
        assert_eq!(spec_no_summaries.spec_hash, spec_with_summaries.spec_hash);
    }

    #[test]
    fn attach_framework_binding_reads_project_route_config() {
        use crate::dynamic::framework::HttpMethod;
        use std::fs;
        use std::io::Write;

        let dir = tempfile::tempdir().expect("tempdir");
        let action_dir = dir.path().join("app/actions/books");
        fs::create_dir_all(&action_dir).expect("action dir");
        let config_dir = dir.path().join("config");
        fs::create_dir_all(&config_dir).expect("config dir");
        let action = action_dir.join("show.rb");
        fs::File::create(&action)
            .expect("action create")
            .write_all(
                b"require 'hanami/action'\nmodule Books\n  class Show\n    include Hanami::Action\n    def call(req)\n      system(req.params[:cmd])\n    end\n  end\nend\n",
            )
            .expect("action write");
        fs::File::create(config_dir.join("routes.rb"))
            .expect("routes create")
            .write_all(b"Hanami.app.routes do\n  post '/books/:id', to: 'books.show'\nend\n")
            .expect("routes write");
        let entry_file = action.to_string_lossy().into_owned();

        let ev = Evidence {
            flow_steps: vec![source_step(&entry_file, "call"), sink_step(&entry_file)],
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            id: "rb.cmdi.system".into(),
            path: entry_file.clone(),
            line: 5,
            confidence: Some(Confidence::High),
            evidence: Some(ev),
            ..Default::default()
        };

        let spec = HarnessSpec::from_finding_full(&diag, false, None, None)
            .expect("spec derives and attaches framework config");
        let binding = spec.framework.expect("hanami binding");
        assert_eq!(binding.adapter, "ruby-hanami");
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/books/:id");
    }

    /// Phase 18 (Track M.0) deferred-fix: when a [`FrameworkBinding`]
    /// carries one of the seven data-bearing variants
    /// (`ClassMethod`, `MessageHandler`, …), the spec stamping path
    /// propagates the variant onto `spec.entry_kind` and recomputes
    /// `spec.spec_hash`.  Validated against the synthetic
    /// [`stamp_framework_binding`] entry point so the test does not
    /// need to register an adapter that emits the variant.
    #[test]
    fn spec_attach_framework_binding_stamps_new_entry_kind_variant() {
        let mut spec = HarnessSpec {
            finding_id: "phase18stamp0001".into(),
            entry_file: "src/handler.py".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "phase18".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: crate::labels::Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/handler.py".into(),
            sink_line: 1,
            spec_hash: "phase18stamp0001".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: JavaToolchain::default(),
        };
        let pre_hash = spec.spec_hash.clone();
        let pre_tag = spec.entry_kind.tag();

        let binding = FrameworkBinding {
            adapter: "phase19-synthetic".to_owned(),
            kind: EntryKind::ClassMethod {
                class: "UserRepository".to_owned(),
                method: "find_by_name".to_owned(),
            },
            route: None,
            request_params: vec![],
            response_writer: None,
            middleware: vec![],
        };

        stamp_framework_binding(&mut spec, binding);

        assert_eq!(
            spec.entry_kind.tag(),
            crate::evidence::EntryKindTag::ClassMethod,
            "stamping must replace Function with ClassMethod when the binding carries one of the Phase 18 variants",
        );
        assert_ne!(pre_tag, spec.entry_kind.tag());
        assert_ne!(
            pre_hash, spec.spec_hash,
            "spec_hash must change when entry_kind tag flips",
        );
        assert_eq!(
            spec.framework.as_ref().map(|b| b.adapter.as_str()),
            Some("phase19-synthetic"),
        );
    }

    /// Phase 20 (Track M.2) deferred-fix companion: when a real
    /// `MessageHandler` adapter binds, the spec carries both the
    /// `MessageHandler` variant on `entry_kind` and the broker
    /// adapter id on `framework.adapter`.  The Python emitter's
    /// `python_broker_for_adapter` reads `framework.adapter` to
    /// route the broker pick, and the `MessageHandler` short-circuit
    /// reads `entry_kind` to dispatch — both fields must be
    /// populated by `stamp_framework_binding` so real spec-derivation
    /// matches the manual fixture path in `tests/message_handler_corpus.rs`.
    #[test]
    fn spec_attach_framework_binding_stamps_message_handler_and_sets_broker_adapter() {
        let mut spec = HarnessSpec {
            finding_id: "phase20stamp0001".into(),
            entry_file: "src/consumer.py".into(),
            entry_name: "on_message".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "phase20".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: crate::labels::Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: "src/consumer.py".into(),
            sink_line: 1,
            spec_hash: "phase20stamp0001".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: JavaToolchain::default(),
        };
        let pre_hash = spec.spec_hash.clone();

        let binding = FrameworkBinding {
            adapter: "kafka-python".to_owned(),
            kind: EntryKind::MessageHandler {
                queue: "orders".to_owned(),
                message_schema: None,
            },
            route: None,
            request_params: vec![],
            response_writer: None,
            middleware: vec![],
        };
        stamp_framework_binding(&mut spec, binding);

        assert_eq!(
            spec.entry_kind.tag(),
            crate::evidence::EntryKindTag::MessageHandler,
            "MessageHandler variant must propagate from binding onto spec.entry_kind",
        );
        if let EntryKind::MessageHandler { queue, .. } = &spec.entry_kind {
            assert_eq!(queue, "orders");
        } else {
            panic!("expected MessageHandler variant");
        }
        let fw = spec.framework.as_ref().expect("framework must be set");
        assert_eq!(fw.adapter, "kafka-python");
        assert_eq!(
            spec.stubs_required,
            vec![crate::dynamic::stubs::StubKind::Kafka],
            "MessageHandler specs must request the matching broker runtime provider",
        );
        assert_ne!(pre_hash, spec.spec_hash);
    }

    #[test]
    fn spec_attach_framework_binding_stamps_migration_and_sets_sql_stub() {
        let mut spec = HarnessSpec {
            finding_id: "phase21migration0001".into(),
            entry_file: "db/migrate/001.py".into(),
            entry_name: "upgrade".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "phase21".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: crate::labels::Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: "db/migrate/001.py".into(),
            sink_line: 1,
            spec_hash: "phase21migration0001".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: JavaToolchain::default(),
        };
        let pre_hash = spec.spec_hash.clone();

        let binding = FrameworkBinding {
            adapter: "migration-django".to_owned(),
            kind: EntryKind::Migration {
                version: Some("001".to_owned()),
            },
            route: None,
            request_params: vec![],
            response_writer: None,
            middleware: vec![],
        };
        stamp_framework_binding(&mut spec, binding);

        assert_eq!(
            spec.entry_kind.tag(),
            crate::evidence::EntryKindTag::Migration
        );
        assert_eq!(
            spec.stubs_required,
            vec![crate::dynamic::stubs::StubKind::Sql],
            "Migration specs must request the SQL runtime provider"
        );
        assert_ne!(pre_hash, spec.spec_hash);
    }

    /// Companion guard: when the binding carries a legacy unit
    /// variant (`Function` / `HttpRoute`), the stamping branch keeps
    /// `spec.entry_kind` and `spec.spec_hash` unchanged.
    #[test]
    fn spec_attach_framework_binding_keeps_legacy_unit_variant_unchanged() {
        let mut spec = HarnessSpec {
            finding_id: "phase18stamp0002".into(),
            entry_file: "src/handler.py".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "phase18".into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: crate::labels::Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/handler.py".into(),
            sink_line: 1,
            spec_hash: "phase18stamp0002".into(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: JavaToolchain::default(),
        };
        let pre_hash = spec.spec_hash.clone();

        let binding = FrameworkBinding {
            adapter: "phase17-synthetic".to_owned(),
            kind: EntryKind::Function,
            route: None,
            request_params: vec![],
            response_writer: None,
            middleware: vec![],
        };
        stamp_framework_binding(&mut spec, binding);

        assert_eq!(
            spec.entry_kind.tag(),
            crate::evidence::EntryKindTag::Function
        );
        assert_eq!(spec.spec_hash, pre_hash);
        assert!(spec.framework.is_some());
    }

    // ── Phase 25 (Track K.0): multi-strategy scoring + cross-file seeding ────

    #[test]
    fn spec_score_orders_lexicographically() {
        // `flow_depth` dominates every lower-priority axis.
        let deep = SpecScore {
            flow_depth: 3,
            framework_bound: false,
            cross_file_resolved: false,
            payloads_available: false,
        };
        let shallow_but_rich = SpecScore {
            flow_depth: 2,
            framework_bound: true,
            cross_file_resolved: true,
            payloads_available: true,
        };
        assert!(deep > shallow_but_rich);

        // Equal `flow_depth`: `framework_bound` breaks the tie.
        let fw = SpecScore {
            flow_depth: 2,
            framework_bound: true,
            cross_file_resolved: false,
            payloads_available: false,
        };
        let no_fw = SpecScore {
            flow_depth: 2,
            framework_bound: false,
            cross_file_resolved: true,
            payloads_available: true,
        };
        assert!(fw > no_fw);

        // Equal `flow_depth` + `framework_bound`: `cross_file_resolved` wins.
        let xfile = SpecScore {
            flow_depth: 1,
            framework_bound: false,
            cross_file_resolved: true,
            payloads_available: false,
        };
        let no_xfile = SpecScore {
            flow_depth: 1,
            framework_bound: false,
            cross_file_resolved: false,
            payloads_available: true,
        };
        assert!(xfile > no_xfile);

        // Only `payloads_available` differs: it is the final tie-breaker.
        let with_payloads = SpecScore {
            flow_depth: 1,
            framework_bound: false,
            cross_file_resolved: false,
            payloads_available: true,
        };
        let without = SpecScore {
            flow_depth: 1,
            framework_bound: false,
            cross_file_resolved: false,
            payloads_available: false,
        };
        assert!(with_payloads > without);
    }

    #[test]
    fn derive_all_strategies_empty_without_evidence() {
        // No `Evidence` struct at all → no strategy has anything to derive
        // from, so the candidate set is empty (and `derive_best_ranked`
        // lifts this to `NoFlowSteps`, exercised separately).
        let diag = crate::commands::scan::Diag {
            confidence: Some(Confidence::High),
            evidence: None,
            ..Default::default()
        };
        let ctx = SpecDerivationCtx::new(false, None, None);
        assert!(HarnessSpec::derive_all_strategies(&diag, &ctx).is_empty());
    }

    #[test]
    fn derive_best_ranked_reports_runner_up_strategies() {
        use crate::labels::Cap;
        // A finding both the flow-steps and rule-namespace strategies can
        // drive: identical entry → identical score → flow_steps wins the
        // precedence tie-break, and rule_namespace is reported as a loser.
        let evidence = Evidence {
            flow_steps: vec![
                source_step("src/handler.py", "handle_request"),
                sink_step("src/handler.py"),
            ],
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            id: "py.cmdi.os_system".into(),
            confidence: Some(Confidence::High),
            evidence: Some(evidence),
            path: "src/handler.py".into(),
            ..Default::default()
        };
        let ctx = SpecDerivationCtx::new(false, None, None);
        let (spec, runners_up) = HarnessSpec::derive_best_ranked(&diag, &ctx).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromFlowSteps);
        assert!(
            runners_up
                .iter()
                .any(|(s, _)| *s == SpecDerivationStrategy::FromRuleNamespace),
            "rule-namespace strategy must appear in the runner-up ranking, got {runners_up:?}",
        );
    }

    #[test]
    fn seed_cross_file_source_stops_at_cross_file_source() {
        use crate::labels::Cap;
        use crate::summary::CalleeSite;
        use crate::summary::ssa_summary::SsaFuncSummary;
        use crate::symbol::FuncKey;

        let mut gs = GlobalSummaries::new();

        // Sink helper in db.rs — contains the dangerous call, no callees.
        let run_query = build_summary(
            "run_query",
            "src/db.rs",
            "rust",
            Cap::SHELL_ESCAPE.bits(),
            vec![0],
            None,
        );
        let run_query_key = FuncKey::new_function(Lang::Rust, "src/db.rs", "run_query", Some(1));
        gs.insert(run_query_key, run_query);

        // Source ancestor in input.rs — reads external input, calls run_query.
        let mut read_input = build_summary("read_input", "src/input.rs", "rust", 0, vec![], None);
        read_input.callees = vec![CalleeSite::bare("run_query")];
        let read_input_key =
            FuncKey::new_function(Lang::Rust, "src/input.rs", "read_input", Some(1));
        gs.insert(read_input_key.clone(), read_input);
        // SSA summary marks read_input a Source (non-empty source_caps) —
        // the signal `seed_cross_file_source` stops on.
        gs.insert_ssa(
            read_input_key,
            SsaFuncSummary {
                source_caps: Cap::SHELL_ESCAPE,
                ..Default::default()
            },
        );

        // A caller of read_input gives it in-degree 1, so the
        // `is_entry_point` zero-caller heuristic does NOT fire — proving the
        // walk stops because read_input is a SOURCE, not a framework entry.
        let mut dispatch = build_summary("dispatch", "src/main.rs", "rust", 0, vec![], None);
        dispatch.callees = vec![CalleeSite::bare("read_input")];
        let dispatch_key = FuncKey::new_function(Lang::Rust, "src/main.rs", "dispatch", Some(1));
        gs.insert(dispatch_key, dispatch);

        let cg = crate::callgraph::build_call_graph(&gs, &[]);

        let ev = Evidence {
            flow_steps: vec![sink_only_step_with_function("src/db.rs", "run_query")],
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            id: "rust.cmdi.command".into(),
            path: "src/db.rs".into(),
            line: 6,
            confidence: Some(Confidence::High),
            evidence: Some(ev.clone()),
            ..Default::default()
        };

        let hit = seed_cross_file_source(&diag, &ev, &gs, &cg, Lang::Rust)
            .expect("reverse walk must reach the cross-file source ancestor");
        assert_eq!(hit.summary.name, "read_input");
        assert_eq!(hit.summary.file_path, "src/input.rs");
        // read_input must not itself be a framework entry point — confirming
        // the stop was on the source condition.
        assert!(!is_entry_point(hit.summary, &cg));
    }

    #[test]
    fn derive_from_cross_file_seed_rewrites_entry_across_file_boundary() {
        use crate::labels::Cap;
        use crate::summary::CalleeSite;
        use crate::summary::ssa_summary::SsaFuncSummary;
        use crate::symbol::FuncKey;

        let mut gs = GlobalSummaries::new();
        let run_query = build_summary(
            "run_query",
            "src/db.rs",
            "rust",
            Cap::SHELL_ESCAPE.bits(),
            vec![0],
            None,
        );
        gs.insert(
            FuncKey::new_function(Lang::Rust, "src/db.rs", "run_query", Some(1)),
            run_query,
        );

        let mut read_input = build_summary("read_input", "src/input.rs", "rust", 0, vec![], None);
        read_input.callees = vec![CalleeSite::bare("run_query")];
        let read_input_key =
            FuncKey::new_function(Lang::Rust, "src/input.rs", "read_input", Some(1));
        gs.insert(read_input_key.clone(), read_input);
        gs.insert_ssa(
            read_input_key,
            SsaFuncSummary {
                source_caps: Cap::SHELL_ESCAPE,
                ..Default::default()
            },
        );

        let cg = crate::callgraph::build_call_graph(&gs, &[]);

        let ev = Evidence {
            flow_steps: vec![sink_only_step_with_function("src/db.rs", "run_query")],
            sink_caps: Cap::SHELL_ESCAPE.bits(),
            ..Default::default()
        };
        let diag = crate::commands::scan::Diag {
            id: "rust.cmdi.command".into(),
            path: "src/db.rs".into(),
            line: 6,
            confidence: Some(Confidence::High),
            evidence: Some(ev.clone()),
            ..Default::default()
        };

        let spec = derive_from_cross_file_seed(&diag, &ev, &gs, &cg)
            .expect("cross-file seed must derive a spec");
        assert_eq!(spec.entry_name, "read_input");
        assert_eq!(spec.entry_file, "src/input.rs");
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromCallgraphEntry);

        // End-to-end: the scorer prefers the cross-file entry — deeper flow
        // (one reverse hop) plus cross-file resolution beats the sink-local
        // strategies that name `run_query` itself as the entry.
        let ctx = SpecDerivationCtx::new(false, Some(&gs), Some(&cg));
        let best = HarnessSpec::derive_best(&diag, &ctx).expect("derive_best must succeed");
        assert_eq!(best.entry_name, "read_input");
        assert_eq!(best.derivation, SpecDerivationStrategy::FromCallgraphEntry);
    }
}
