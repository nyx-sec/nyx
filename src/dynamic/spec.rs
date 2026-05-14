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
use crate::evidence::{Confidence, FlowStepKind, UnsupportedReason};
use crate::labels::Cap;
use crate::summary::{FuncSummary, GlobalSummaries};
use crate::symbol::{FuncKey, Lang};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::path::Path;

/// Re-export of the always-present [`crate::evidence::SpecDerivationStrategy`].
///
/// The canonical definition lives in `evidence.rs` so that
/// [`crate::evidence::InconclusiveReason::SpecDerivationFailed`] can carry a
/// `Vec` of attempted strategies without depending on the `dynamic` feature.
pub use crate::evidence::SpecDerivationStrategy;

/// Bump whenever [`HarnessSpec`] fields change meaning or the spec hash
/// inputs change. Downstream tools should reject specs with an unrecognised
/// version.
pub const SPEC_FORMAT_VERSION: u32 = 1;

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
}

fn default_derivation_strategy() -> SpecDerivationStrategy {
    SpecDerivationStrategy::FromFlowSteps
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
        if !verify_all_confidence {
            match diag.confidence {
                Some(c) if c >= Confidence::Medium => {}
                _ => return Err(UnsupportedReason::ConfidenceTooLow),
            }
        }

        let evidence = diag.evidence.as_ref().ok_or(UnsupportedReason::NoFlowSteps)?;

        // Phase 04 pre-step: when both callgraph *and* summaries are
        // present, walk reverse edges to a framework-bound ancestor.
        // Takes precedence over the four-strategy ladder because a route
        // handler / CLI entry is always a stronger driving anchor than
        // the helper function that physically contains the sink.
        //
        // Strict variant: only the reverse-edge BFS (`find_entry_via_callgraph`)
        // counts here. The summary-entry-kind + rule-id substring fallbacks
        // that live in `derive_from_callgraph_entry_full` stay at strategy-4
        // priority — calling them here would short-circuit the more precise
        // strategies (FromFlowSteps / FromRuleNamespace / FromFuncSummaryAuto)
        // whenever the rule id happens to contain `.http.` / `.cli.`.
        if let (Some(s), Some(cg)) = (summaries, callgraph) {
            if let Some(spec) = derive_from_callgraph_walk_only(diag, evidence, s, cg) {
                return Ok(spec);
            }
        }

        // Try each strategy in priority order; first non-None wins.
        if let Some(spec) = derive_from_flow_steps(diag, evidence) {
            return Ok(spec);
        }
        if let Some(spec) = derive_from_rule_namespace_with(diag, evidence, summaries) {
            return Ok(spec);
        }
        if let Some(spec) = derive_from_func_summary_auto(diag, evidence, summaries) {
            return Ok(spec);
        }
        if let Some(spec) = derive_from_callgraph_entry_full(diag, evidence, summaries, callgraph)
        {
            return Ok(spec);
        }

        Err(UnsupportedReason::SpecDerivationFailed)
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
        supported.contains(&self.entry_kind)
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
}

// ── Strategy 1: from flow_steps (original path) ──────────────────────────────

fn derive_from_flow_steps(diag: &Diag, evidence: &crate::evidence::Evidence) -> Option<HarnessSpec> {
    if evidence.flow_steps.is_empty() {
        return None;
    }
    let entry = outermost_entry(&evidence.flow_steps)?;

    let lang = lang_from_path(&entry.file)?;
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

    Some(finalize_spec(
        diag,
        entry.file,
        entry.function,
        lang,
        expected_cap,
        sink_file,
        sink_line,
        SpecDerivationStrategy::FromFlowSteps,
    ))
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

    // Path is required to locate the sink and to extension-check the lang.
    if diag.path.is_empty() {
        return None;
    }
    // Cross-check: the diag's file extension must agree with the rule's
    // language prefix when both are available. Disagreement is a stronger
    // signal of a mis-rooted finding than a missing extension.
    if let Some(path_lang) = lang_from_path(&diag.path) {
        if path_lang != lang {
            return None;
        }
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
    ))
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
    derive_from_func_summary(diag, evidence, Some(summary))
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
    if let (Some(s), Some(cg)) = (summaries, callgraph) {
        if let Some(found) = find_entry_via_callgraph(diag, evidence, s, cg, lang) {
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
            );
            spec.entry_kind = entry_kind;
            spec.spec_hash = compute_spec_hash(&spec);
            return Some(spec);
        }
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
            if let Some(caller_summary) = summaries.get(caller_key) {
                if is_entry_point(caller_summary, callgraph) {
                    return Some(EntryHit {
                        key: caller_key.clone(),
                        summary: caller_summary,
                    });
                }
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
    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
        if let Some(lang) = Lang::from_extension(ext) {
            return Some(lang);
        }
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
    let summaries = summaries?;
    let mut hits = summaries
        .iter()
        .filter(|(k, _)| k.lang == lang)
        .filter(|(_, s)| paths_match(&s.file_path, &diag.path));
    let first = hits.next()?;
    if hits.next().is_some() {
        // Ambiguous: multiple functions in this file; refuse to guess.
        return None;
    }
    Some(first.1.name.clone())
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
) -> HarnessSpec {
    let toolchain_id = toolchain_id_for_lang(lang).to_owned();
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
    };
    spec.spec_hash = compute_spec_hash(&spec);
    spec
}

/// Walk `flow_steps` and return the entry point: the enclosing function of
/// the first `Source` step that has a function annotation. This is the
/// outermost callable that receives the tainted input.
pub fn outermost_entry(steps: &[crate::evidence::FlowStep]) -> Option<EntryRef> {
    for step in steps {
        if matches!(step.kind, FlowStepKind::Source) {
            if let Some(ref func) = step.function {
                if !func.is_empty() {
                    return Some(EntryRef {
                        file: step.file.clone(),
                        function: func.clone(),
                    });
                }
            }
        }
    }
    None
}

/// Default toolchain label for a language (informational; harness builder
/// may override for locally-installed compilers/runtimes).
fn toolchain_id_for_lang(lang: Lang) -> &'static str {
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
/// Inputs (in order):
///   `SPEC_FORMAT_VERSION` (u32 LE), entry_file, entry_name, payload_slot tag
///   + value, expected_cap bits (u32 LE), sorted constraint_hints,
///   toolchain_id, `CORPUS_VERSION` (u32 LE).
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

    let out = h.finalize();
    let bytes = out.as_bytes();
    format!("{:016x}", u64::from_le_bytes(bytes[..8].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, FlowStep, FlowStepKind};

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
        let steps = vec![source_step("src/main.rs", "handle_request"), sink_step("src/main.rs")];
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
        assert_ne!(s1.spec_hash, s2.spec_hash, "entry_file mutation must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_entry_name() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.entry_name = "other_handler".into();
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "entry_name mutation must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_payload_slot() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.payload_slot = PayloadSlot::Param(1);
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "payload_slot mutation must change spec_hash");

        let mut s3 = s1.clone();
        s3.payload_slot = PayloadSlot::HttpBody;
        s3.spec_hash = compute_spec_hash(&s3);
        assert_ne!(s1.spec_hash, s3.spec_hash, "payload_slot tag change must change spec_hash");

        let mut s4 = s1.clone();
        s4.payload_slot = PayloadSlot::EnvVar("NYX_INPUT".into());
        s4.spec_hash = compute_spec_hash(&s4);
        assert_ne!(s1.spec_hash, s4.spec_hash, "EnvVar payload_slot must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_expected_cap() {
        use crate::labels::Cap;
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.expected_cap = Cap::CODE_EXEC;
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "expected_cap mutation must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_constraint_hints() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.constraint_hints = vec!["prefix:admin/".into()];
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "constraint_hints mutation must change spec_hash");
    }

    #[test]
    fn spec_hash_flips_on_toolchain_id() {
        let s1 = base_spec();
        let mut s2 = s1.clone();
        s2.toolchain_id = "rust-nightly".into();
        s2.spec_hash = compute_spec_hash(&s2);
        assert_ne!(s1.spec_hash, s2.spec_hash, "toolchain_id mutation must change spec_hash");
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
        let diag = diag_with_rule_id("py.cmdi.os_system", "app/handler.py", Cap::SHELL_ESCAPE.bits());
        let spec = HarnessSpec::from_finding(&diag).unwrap();
        assert_eq!(spec.derivation, SpecDerivationStrategy::FromRuleNamespace);
        assert_eq!(spec.lang, Lang::Python);
        assert_eq!(spec.expected_cap, Cap::SHELL_ESCAPE);
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
    fn rule_namespace_strategy_pins_rs_auth_mapping() {
        // Regression: `rs.auth.*` must map to `Lang::Rust` + `Cap::UNAUTHORIZED_ID`.
        // The plan calls out this exemplar but had no test coverage.
        let diag = diag_with_rule_id(
            "rs.auth.missing_ownership_check.taint",
            "src/handler.rs",
            0,
        );
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
        let diag = diag_with_rule_id("py.cmdi.os_system", "src/Main.java", Cap::SHELL_ESCAPE.bits());
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
    fn rule_namespace_strategy_skips_legacy_taint_ids() {
        use crate::labels::Cap;
        // `taint-...` is *not* a language-namespace prefix; rule-namespace
        // strategy must skip it so the next strategy can try.
        let diag = diag_with_rule_id("taint-unsanitised-flow", "app/handler.py", Cap::SHELL_ESCAPE.bits());
        // No flow_steps, no http/cli marker → ends in SpecDerivationFailed.
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
        let diag = diag_with_rule_id("rs.cli.parse_subcommand", "src/main.rs", Cap::SHELL_ESCAPE.bits());
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

    fn build_summary(name: &str, file: &str, lang: &str, sink_caps: u32, tainted_params: Vec<usize>, entry_kind: Option<crate::entry_points::EntryKind>) -> FuncSummary {
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
            flow_steps: vec![sink_only_step_with_function(
                "app/handler.py",
                "do_request",
            )],
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
            flow_steps: vec![sink_only_step_with_function(
                "app/handler.py",
                "do_request",
            )],
            sink_caps: Cap::SHELL_ESCAPE.bits(),
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
            Some(StaticEntryKind::FlaskRoute { method: HttpMethod::GET }),
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
}
