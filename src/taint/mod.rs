//! Forward SSA taint analysis: the primary vulnerability detection engine.
//!
//! Tracks untrusted data from **sources** (where it enters the program) through
//! assignments and calls to **sinks** (where it is used dangerously). A finding
//! fires when the flow reaches a sink without passing a matching **sanitizer**.
//!
//! The engine is a monotone forward dataflow over a finite lattice with
//! guaranteed termination. It is flow-sensitive within a function and
//! interprocedural across files via persisted [`crate::summary::FuncSummary`]
//! and [`crate::summary::ssa_summary::SsaFuncSummary`] values.
//!
//! # Rule ID
//!
//! ```text
//! taint-unsanitised-flow (source <line>:<col>)
//! taint-data-exfiltration (source <line>:<col>)
//! ```
//!
//! The source location is part of the ID so sibling paths to the same sink
//! get distinct IDs. Suppressions can target either the base ID or the full
//! string.
//!
//! # Capabilities
//!
//! Sources, sanitizers, and sinks are linked by [`crate::labels::Cap`] bits.
//! A sanitizer only clears the cap it declares; a sink only fires when the
//! remaining taint still carries its required cap.
//!
//! | Cap | Typical source | Typical sanitizer | Typical sink |
//! |-----|----------------|-------------------|--------------|
//! | `env_var` | `env::var`, `getenv`, `process.env` | | |
//! | `html_escape` | | `html.escape`, `DOMPurify.sanitize` | `innerHTML`, `document.write` |
//! | `shell_escape` | | `shlex.quote`, `shell_escape::escape` | `system`, `Command::new` |
//! | `url_encode` | | `encodeURIComponent` | HTTP client URL arg |
//! | `file_io` | | `realpath`, `filepath.Clean` | `open`, `fs::read_to_string` |
//! | `sql_query` | | parameterized query binders | `cursor.execute`, `db.query` |
//! | `deserialize` | | | `pickle.loads`, `Marshal.load` |
//! | `ssrf` | | URL-prefix locks | `fetch` URL arg, outbound HTTP |
//! | `code_exec` | | | `eval`, `exec`, `system` |
//! | `crypto` | | | weak-algorithm constructors |
//! | `data_exfil` | cookies, headers, env, db rows (Sensitive tier) | | `fetch` body/json/headers |
//!
//! Sources typically carry `Cap::all()` so they match any sink.
//!
//! # Source sensitivity
//!
//! Each source carries a [`crate::labels::SourceKind`] and a derived tier:
//!
//! - `Plain` — direct attacker input (`UserInput`): request bodies, query
//!   strings, argv, stdin.
//! - `Sensitive` — operator-bound state: cookies, headers, env, files, DB rows,
//!   caught exceptions.
//!
//! `Cap::DATA_EXFIL` only fires on `Sensitive`-tier sources. Plain user input
//! flowing into an outbound request body is suppressed — the canonical false
//! positive for API gateways that proxy `req.body`.
//!
//! # Confidence signals
//!
//! Higher confidence: source and sink both present in evidence, `source_kind:
//! user_input`, `path_validated: false`, symbolic witness produced.
//!
//! Lower confidence: path-validated taint, source is a database read or
//! internal file, engine note `ForwardBailed` / `PathWidened`.
//!
//! # Submodules
//!
//! - [`domain`]: taint lattice types (`VarTaint`, `TaintOrigin`, `SmallBitSet`,
//!   `PredicateSummary`)
//! - [`ssa_transfer`]: SSA taint transfer functions and the forward worklist
//!   (`SsaTaintState`, `SsaTaintTransfer`, `run_ssa_taint`)
//! - [`path_state`]: predicate classification for branch-sensitive propagation
//! - [`backwards`]: demand-driven backwards walk from sinks (off by default)

#![allow(clippy::collapsible_if, clippy::too_many_arguments)]

pub mod backwards;
pub mod domain;
pub mod path_state;
pub mod ssa_transfer;

use crate::cfg::{BodyCfg, BodyId, Cfg, FileCfg, FuncSummaries};
use crate::engine_notes::EngineNote;
use crate::interop::InteropEdge;
use crate::labels::SourceKind;
use crate::state::engine::MAX_TRACKED_VARS;
use crate::state::symbol::SymbolInterner;
use crate::summary::GlobalSummaries;
use crate::symbol::{FuncKey, FuncKind, Lang};
use path_state::PredicateKind;
use petgraph::graph::NodeIndex;
use petgraph::visit::IntoNodeReferences;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Safety cap on JS/TS in-file pass-2 convergence iterations.
///
/// Pass 2 runs a Jacobi-style round over every non-toplevel body in a
/// JS/TS file, combining each body's exit state (filtered to top-level
/// keys) into the shared seed and re-running non-toplevel bodies until
/// the seed stabilises.  A chain of `k` top-level bindings threaded
/// through `k` helper functions needs up to `k` iterations for taint to
/// walk the chain; the old hardcoded `3` silently truncated any
/// 4-stage chain with no warning.
///
/// This mirrors `scan::SCC_FIXPOINT_SAFETY_CAP` in intent: the lattice
/// is monotone and finite-height, so the real fixed-point is always
/// reachable in a small multiple of the chain depth.  64 is generous
/// enough to cover every realistic JS/TS file we have seen while still
/// bounding worst-case cost.
const JS_TS_PASS2_SAFETY_CAP: usize = 64;

/// Test-only override for [`JS_TS_PASS2_SAFETY_CAP`].  When non-zero,
/// the pass-2 loop uses this value instead of the const cap.  Default
/// `0` leaves production behaviour unchanged.
static JS_TS_PASS2_CAP_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// Observability hook: records the number of pass-2 iterations used by
/// the most recent [`analyse_file`] invocation.  Reset at the start of
/// each call so convergence regression tests can read a fresh value.
/// `1` means the initial lexical-containment pass completed; higher
/// values indicate the iterative convergence loop ran that many times
/// without detecting convergence (so the `iters`th iteration was the
/// last round actually executed).  `1` is the common case for
/// non-JS/TS languages and for JS/TS files with no cross-body globals.
static LAST_JS_TS_PASS2_ITERATIONS: AtomicUsize = AtomicUsize::new(0);

/// Set (or clear) the test-only JS/TS pass-2 cap override.  `cap = 0`
/// restores the default.  Intended exclusively for integration tests
/// that need to force cap-hit behaviour on small fixtures.
#[doc(hidden)]
pub fn set_js_ts_pass2_cap_override(cap: usize) {
    JS_TS_PASS2_CAP_OVERRIDE.store(cap, Ordering::Relaxed);
}

/// Returns the pass-2 iteration count observed during the most recent
/// [`analyse_file`] invocation.  Intended for tests and diagnostics.
pub fn last_js_ts_pass2_iterations() -> usize {
    LAST_JS_TS_PASS2_ITERATIONS.load(Ordering::Relaxed)
}

fn js_ts_pass2_cap() -> usize {
    let o = JS_TS_PASS2_CAP_OVERRIDE.load(Ordering::Relaxed);
    if o == 0 { JS_TS_PASS2_SAFETY_CAP } else { o }
}

// ── Perf-audit sub-stage timers (lower_all_functions_from_bodies) ───────
//
// Slot layout (µs):
//   [0] lower_to_ssa_with_params (per-body sum)
//   [1] extract_ssa_func_summary (per-body sum, includes per-param probes)
//   [2] optimize_ssa_with_param_types (per-body sum)
//   [3] typed_call_receivers + pointer fact extraction (per-body sum)
//   [4] augment_summaries_with_child_sinks
//   [5] rerun_extraction_with_augmented_summaries
//   [6] per-body misc (FuncKey resolve, HashMap insert, interner ctor)
//
// Active only when the slot is `Some`.  Production code path leaves it
// `None`, making instrumentation cost a single thread-local borrow + a
// `match Option::None` per measured chunk, sub-nanosecond.
thread_local! {
    static PERF_LOWER_TIMINGS: std::cell::Cell<Option<[u128; 7]>> =
        const { std::cell::Cell::new(None) };
}

#[doc(hidden)]
pub fn perf_lower_timings_start() {
    PERF_LOWER_TIMINGS.with(|c| c.set(Some([0; 7])));
}

#[doc(hidden)]
pub fn perf_lower_timings_take() -> Option<[u128; 7]> {
    PERF_LOWER_TIMINGS.with(|c| c.replace(None))
}

#[inline]
fn perf_lower_record(slot: usize, micros: u128) {
    PERF_LOWER_TIMINGS.with(|c| {
        if let Some(mut t) = c.get() {
            t[slot] = t[slot].saturating_add(micros);
            c.set(Some(t));
        }
    });
}

/// Test-only override for the Gauss-Seidel toggle.  Values:
///
/// * `0`, respect `NYX_JS_GAUSS_SEIDEL` env var (default production
///   behaviour).
/// * `1`, force Jacobi (env ignored).
/// * `2`, force Gauss-Seidel (env ignored).
///
/// Used exclusively by integration tests that need to assert both
/// variants produce equal findings without per-test process isolation.
static JS_TS_GAUSS_SEIDEL_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// Force Jacobi or Gauss-Seidel from test code.  `0` clears the
/// override and restores env-var-driven behaviour.
#[doc(hidden)]
pub fn set_js_ts_gauss_seidel_override(mode: usize) {
    JS_TS_GAUSS_SEIDEL_OVERRIDE.store(mode, Ordering::Relaxed);
}

/// Returns true when the Gauss-Seidel variant of JS/TS pass-2 is
/// enabled.
///
/// Default: **Jacobi** (order-independent, reproducible, one round
/// per chain hop).  Set `NYX_JS_GAUSS_SEIDEL=1` to enable
/// **Gauss-Seidel** (in-place updates: a body's exit becomes visible
/// to later bodies in the same round, typically halving iteration
/// count on chain-shaped code).
///
/// Opt-in deliberately: Gauss-Seidel is order-dependent (the result
/// depends on the traversal order of bodies), which can affect
/// reproducibility for scanners whose output feeds CI gates.  Before
/// flipping this on by default we need the Phase-A corpus run to
/// prove chain-depth ≥4 is common enough to justify the complexity.
///
/// Test-override via [`set_js_ts_gauss_seidel_override`] takes
/// precedence over the env var.
///
/// See `tests/gauss_seidel_tests.rs` for the determinism test that
/// guards the invariant "same fixture → same findings under both
/// variants".
pub fn js_ts_gauss_seidel_enabled() -> bool {
    match JS_TS_GAUSS_SEIDEL_OVERRIDE.load(Ordering::Relaxed) {
        1 => return false, // force Jacobi
        2 => return true,  // force Gauss-Seidel
        _ => {}
    }
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| match std::env::var("NYX_JS_GAUSS_SEIDEL") {
        Ok(v) => !matches!(v.as_str(), "" | "0" | "false"),
        Err(_) => false,
    })
}

/// A raw flow step at CFG level (before line/col resolution).
#[derive(Debug, Clone)]
pub struct FlowStepRaw {
    pub cfg_node: NodeIndex,
    pub var_name: Option<String>,
    pub op_kind: crate::evidence::FlowStepKind,
}

/// Resolved source-location of the primary (callee-internal) sink instruction.
///
/// Populated on [`Finding`] when the sink was resolved via a callee summary
/// that recorded a [`crate::summary::SinkSite`].  Data-only primary
/// sink-location attribution: downstream formatters (SARIF, JSON, diag)
/// still report the caller's call-site until they opt in.
#[derive(Debug, Clone, PartialEq)]
pub struct SinkLocation {
    /// Callee file path relative to the workspace root.  Matches the
    /// `FuncKey::namespace` convention used in [`crate::summary::SinkSite`].
    pub file_rel: String,
    /// 1-based line of the sink instruction inside the callee body.
    pub line: u32,
    /// 1-based column of the sink instruction inside the callee body.
    pub col: u32,
    /// Trimmed source line at the sink, copied from the upstream
    /// [`crate::summary::SinkSite`].  Empty when the extractor had no
    /// tree/bytes context.  Used by formatters so the primary-location
    /// display does not need to re-read the callee file.
    pub snippet: String,
}

/// A detected taint finding with both source and sink locations.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Identifies which body's graph the NodeIndex values reference.
    pub body_id: BodyId,
    /// The CFG node where tainted data reaches a dangerous operation.
    pub sink: NodeIndex,
    /// The CFG node where taint originated (may be Entry if source is
    /// cross-file and couldn't be pinpointed to a specific node).
    pub source: NodeIndex,
    /// The full path from source to sink through the CFG.
    #[allow(dead_code)] // used for future detailed diagnostics / path display
    pub path: Vec<NodeIndex>,
    /// The kind of source that originated the taint.
    pub source_kind: SourceKind,
    /// Whether all tainted sink variables are guarded by a validation
    /// predicate on this path (metadata only, does not change severity).
    pub path_validated: bool,
    /// The kind of validation guard protecting this path, if any.
    pub guard_kind: Option<PredicateKind>,
    /// Number of SSA blocks between source and sink (0 = same block).
    pub hop_count: u16,
    /// Capability specificity: number of matching cap bits between source and sink.
    /// Higher = more specific match (e.g. SQL_QUERY→SQL_QUERY vs broad Cap::all()).
    pub cap_specificity: u8,
    /// Whether this finding was resolved via a function summary (cross-function)
    /// rather than direct intra-function flow.
    pub uses_summary: bool,
    /// Reconstructed flow path from source to sink (CFG-level, pre-resolution).
    pub flow_steps: Vec<FlowStepRaw>,
    /// Symbolic constraint analysis verdict, if attempted.
    pub symbolic: Option<crate::evidence::SymbolicVerdict>,
    /// Original source byte span, preserved when origin was remapped across
    /// body boundaries.  `None` for intra-body findings
    /// (use `cfg[source].classification_span()`).
    pub source_span: Option<usize>,
    /// Source-location of the callee-internal dangerous instruction when the
    /// sink was resolved via a function summary carrying a
    /// [`crate::summary::SinkSite`] with concrete coordinates for primary
    /// sink-location attribution.  `None` for:
    /// * intra-procedural / label-based sinks, the caller's `cfg[sink]`
    ///   span already names the dangerous instruction;
    /// * summary-resolved sinks whose `SinkSite` was cap-only (no tree or
    ///   bytes context at extraction time).
    ///
    /// # Invariant
    ///
    /// `primary_location.is_some()` ⇒ the inner [`SinkLocation`] has
    /// `line != 0`.  `file_rel` may be empty for single-file scans where
    /// the scan root is the file itself (every namespace normalizes to
    /// `""`); consumers resolve empty `file_rel` against the file under
    /// analysis.  Enforced at `ssa_events_to_findings` by a
    /// `debug_assert!`, upstream filters drop cap-only sites before
    /// they reach this field.
    ///
    /// Deliberately independent of `uses_summary`: that flag tracks whether
    /// the **taint chain** used a callee summary, not whether the **sink**
    /// was summary-resolved.  A local source can reach a cross-file sink,
    /// yielding `uses_summary == false` alongside a populated
    /// `primary_location`.
    pub primary_location: Option<SinkLocation>,
    /// Engine provenance notes recorded during the analysis that produced
    /// this finding.  Populated when an internal budget/cap was hit, see
    /// [`crate::engine_notes::EngineNote`].  Empty for the typical
    /// under-budget finding.
    pub engine_notes: SmallVec<[EngineNote; 2]>,
    /// Stable hash of the intermediate-variable sequence between `source`
    /// and `sink`.  Used to keep distinct paths through different
    /// variables as separate findings during deduplication, two
    /// `(body_id, sink, source)` siblings with different `path_hash`
    /// values represent flows along different data paths and are
    /// preserved as alternatives rather than collapsed.
    ///
    /// Derived from the `cfg_node` indices in `flow_steps` at the time
    /// the finding is emitted; stable for a given scan but not
    /// necessarily stable across AST/CFG changes.
    pub path_hash: u64,
    /// Stable identifier for this finding, derived from
    /// `(body_id, source.index, sink.index, path_hash, path_validated)`.
    /// Populated after `body_id` is set so the ID is consistent across
    /// the lifetime of the finding and can be used to cross-reference
    /// alternative paths via [`Self::alternative_finding_ids`].  Empty
    /// string before the post-analysis linking pass runs.
    pub finding_id: String,
    /// Stable identifiers of sibling findings that share
    /// `(body_id, sink, source)` but differ in `path_validated` or
    /// `path_hash`.  Populated by the dedup pass in
    /// [`analyse_file`] after all findings are collected.
    ///
    /// The canonical case is a guarded/unguarded pair: if an `exec(x)`
    /// call is reachable from the same source `x` through both a
    /// whitelisted branch and an unguarded branch, both findings
    /// survive dedup and each lists the other here so downstream
    /// formatters can present them as "this flow … and N alternative
    /// path(s)" rather than silently dropping one.
    pub alternative_finding_ids: SmallVec<[String; 2]>,
    /// Sink-cap mask that this specific finding fired against.  Carries the
    /// per-event `sink_caps` from the multi-gate dispatch (e.g.
    /// `Cap::SSRF` for a URL-flow finding on `fetch`, `Cap::DATA_EXFIL`
    /// for a body-flow finding on the same call).  Used by `ast.rs` to
    /// route the finding to a cap-specific rule id rather than the
    /// generic `taint-unsanitised-flow` bucket.
    pub effective_sink_caps: crate::labels::Cap,
}

impl Finding {
    /// Append an engine provenance note, deduplicating against notes
    /// already present.  Intended as a builder-style helper for construction
    /// sites that want to tag a new finding inline.
    pub fn with_note(mut self, note: EngineNote) -> Self {
        crate::engine_notes::push_unique(&mut self.engine_notes, note);
        self
    }

    /// Merge a note into `engine_notes`, skipping duplicates.
    pub fn merge_note(&mut self, note: EngineNote) {
        crate::engine_notes::push_unique(&mut self.engine_notes, note);
    }
}

/// Pre-compute module aliases from an unoptimized SSA body for JS/TS.
///
/// Runs const propagation (read-only) to get constant values, then detects
/// `require()` calls to known modules and propagates through phis/copies.
/// Used to make module aliases available during summary extraction.
fn compute_module_aliases_for_summary(
    ssa: &crate::ssa::SsaBody,
    lang: Lang,
) -> std::collections::HashMap<crate::ssa::SsaValue, smallvec::SmallVec<[String; 2]>> {
    if !matches!(lang, Lang::JavaScript | Lang::TypeScript) {
        return std::collections::HashMap::new();
    }
    let cp = crate::ssa::const_prop::const_propagate(ssa);
    crate::ssa::const_prop::collect_module_aliases(ssa, &cp.values)
}

/// Run taint analysis on all bodies in a file.
///
/// Uses a unified multi-body analysis for all languages:
/// 1. Lexical containment propagation: parent body exit state seeds child bodies.
/// 2. JS/TS iterative convergence: functions that modify globals can feed taint
///    back to other functions (up to `MAX_JS_ITERATIONS` rounds).
pub fn analyse_file(
    file_cfg: &FileCfg,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    caller_lang: Lang,
    caller_namespace: &str,
    interop_edges: &[InteropEdge],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Vec<Finding> {
    // Reset BEFORE lowering: per-parameter probes inside
    // `lower_all_functions_from_bodies` may record path-safe sink spans
    // (via `record_path_safe_suppressed_span`).  Resetting here keeps the
    // historical contract that "the span set starts empty for each file"
    // while letting both the probe phase and the taint flow phase
    // accumulate into the same set, which is what
    // `take_path_safe_suppressed_spans` then drains for state analysis.
    // The all-validated span set (cap-agnostic, drained by AST-pattern
    // suppression in `TaintSuppressionCtx::build`) follows the same
    // lifecycle.
    ssa_transfer::reset_path_safe_suppressed_spans();
    ssa_transfer::reset_all_validated_spans();
    // No locator: pass-2 intra-file summaries are transient (not persisted)
    // and behavior depends on SinkSite.cap only, which is always populated.
    let (ssa_summaries, callee_bodies) = lower_all_functions_from_bodies(
        file_cfg,
        caller_lang,
        caller_namespace,
        local_summaries,
        global_summaries,
        None,
    );
    analyse_file_with_lowered(
        file_cfg,
        local_summaries,
        global_summaries,
        caller_lang,
        caller_namespace,
        interop_edges,
        extra_labels,
        &ssa_summaries,
        &callee_bodies,
    )
}

/// Same as [`analyse_file`] but takes pre-lowered SSA summaries + callee
/// bodies.  Used by [`crate::ast::analyse_file_fused`] to share a single
/// `lower_all_functions_from_bodies` invocation across the taint engine and
/// the SSA-artifact extractor; the bare [`analyse_file`] entry-point keeps
/// its prior signature for any caller that does not have a pre-lowered
/// result handy.
#[allow(clippy::too_many_arguments)]
pub(crate) fn analyse_file_with_lowered(
    file_cfg: &FileCfg,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    caller_lang: Lang,
    caller_namespace: &str,
    interop_edges: &[InteropEdge],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa_summaries: &std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    callee_bodies: &std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>,
) -> Vec<Finding> {
    let _span = tracing::debug_span!("taint_analyse_file").entered();

    // NOTE: the path-safe-suppressed span set is reset by the caller, not
    // here.  Per-parameter probes inside the lowering phase
    // (`lower_all_functions_from_bodies`) can already publish spans via
    // `record_path_safe_suppressed_span`; resetting here would wipe them
    // before `take_path_safe_suppressed_spans` drains the set for state
    // analysis.  Both `analyse_file` (which lowers internally) and
    // `analyse_file_fused` (which lowers up-front) reset the set before
    // their lowering call.

    let ssa_sums_ref = if ssa_summaries.is_empty() {
        None
    } else {
        Some(ssa_summaries)
    };

    // 2. Context-sensitive inline analysis setup.  Toggle lives at
    //    `analysis.engine.context_sensitive` in `nyx.conf` (or the
    //    `--context-sensitive / --no-context-sensitive` CLI flag).
    let context_sensitive = crate::utils::analysis_options::current().context_sensitive;
    let inline_cache = std::cell::RefCell::new(std::collections::HashMap::new());
    let callee_bodies_ref = if context_sensitive && !callee_bodies.is_empty() {
        Some(callee_bodies)
    } else {
        None
    };
    let inline_cache_ref = if context_sensitive {
        Some(&inline_cache)
    } else {
        None
    };

    // 3. Unified multi-body analysis with lexical containment propagation.
    //
    // `max_iterations` is the safety cap, not an expected depth, the
    // pass-2 loop breaks on seed equality (monotone lattice, finite
    // height) and only rides the cap when convergence legitimately
    // needs more rounds than the cap allows.  See
    // [`JS_TS_PASS2_SAFETY_CAP`] for the rationale.
    let max_iterations = if matches!(caller_lang, Lang::JavaScript | Lang::TypeScript) {
        js_ts_pass2_cap()
    } else {
        1
    };
    // Reset the observability counter before this scan so tests always
    // read a fresh value.  Non-JS/TS languages leave it at `1` (the
    // lexical-containment pass counts as a single round).
    LAST_JS_TS_PASS2_ITERATIONS.store(0, Ordering::Relaxed);
    let import_bindings_ref = if file_cfg.import_bindings.is_empty() {
        None
    } else {
        Some(&file_cfg.import_bindings)
    };
    // Cross-file bodies come from GlobalSummaries. Threaded through the
    // transfer for context-sensitive resolution; plumbing only when no
    // reader is configured, preserving prior behaviour byte-for-byte.
    let cross_file_bodies_ref = global_summaries.and_then(|gs| gs.bodies_by_key());
    if let Some(map) = cross_file_bodies_ref {
        tracing::debug!(
            cross_file_bodies = map.len(),
            file = %caller_namespace,
            "taint: cross-file bodies available for pass 2"
        );
    }

    let mut all_findings = analyse_multi_body(
        file_cfg,
        caller_lang,
        caller_namespace,
        local_summaries,
        global_summaries,
        interop_edges,
        extra_labels,
        ssa_sums_ref,
        callee_bodies_ref,
        inline_cache_ref,
        max_iterations,
        import_bindings_ref,
        cross_file_bodies_ref,
    );

    // 4. Deduplicate findings using a richer key that preserves distinct
    //    flows.
    //
    //    The historical dedup at this point was:
    //
    //        sort_by_key(|f| (body_id, sink.index(), source.index(), !path_validated));
    //        dedup_by_key(|f| (body_id, sink, source));
    //
    //    which silently collapsed an *unguarded* flow reaching the same
    //    `(sink, source)` as a guarded flow, the `!path_validated` sort
    //    ordered `path_validated == true` first, so the exploitable
    //    branch was the one that got dropped.
    //
    //    New behaviour: the dedup key is
    //        (body_id, sink, source, path_validated, path_hash).
    //    Findings that differ on `path_validated` *or* on `path_hash`
    //    (i.e. traverse different intermediate variables) are kept as
    //    distinct findings.  `link_alternative_paths` then populates
    //    `alternative_finding_ids` on each finding so downstream
    //    formatters can render "… and N alternative path(s)".
    all_findings.sort_by_key(|f| {
        (
            f.body_id.0,
            f.sink.index(),
            f.source.index(),
            !f.path_validated,
            f.path_hash,
            f.effective_sink_caps.bits(),
        )
    });
    all_findings.dedup_by_key(|f| {
        (
            f.body_id,
            f.sink,
            f.source,
            f.path_validated,
            f.path_hash,
            f.effective_sink_caps.bits(),
        )
    });

    // 5. Assign stable finding IDs now that `body_id` has been set and
    //    the dedup has picked the final set of distinct flows.  The ID
    //    is used to cross-reference siblings via
    //    `Finding.alternative_finding_ids`.
    for f in &mut all_findings {
        f.finding_id = make_finding_id(f);
    }

    // 6. Link alternative paths: for every group of findings that share
    //    `(body_id, sink, source)`, publish each finding's ID into the
    //    other findings' `alternative_finding_ids` list.
    link_alternative_paths(&mut all_findings);

    all_findings
}

/// Build the stable identifier for a [`Finding`].
///
/// Format: `taint-<body_id>-<source_idx>-<sink_idx>-<path_hash_hex>-<v|u>`.
/// The `v`/`u` suffix disambiguates validated (`v`) from unvalidated
/// (`u`) flows that share `(body, sink, source, path_hash)`.  The hex
/// hash disambiguates distinct intermediate paths.  Both components are
/// independent of caller-side formatters so the ID survives
/// serialization to JSON/SARIF unchanged.
fn make_finding_id(f: &Finding) -> String {
    format!(
        "taint-{}-{}-{}-{:016x}-{}",
        f.body_id.0,
        f.source.index(),
        f.sink.index(),
        f.path_hash,
        if f.path_validated { 'v' } else { 'u' },
    )
}

/// Cross-link findings that share `(body_id, sink, source)` but differ
/// on `path_validated` or `path_hash`.  After this call each such
/// finding's `alternative_finding_ids` lists every sibling's
/// [`Finding::finding_id`], so a guarded flow links to the unguarded
/// sibling and vice versa.  Isolated findings (no sibling) get an
/// empty list.
fn link_alternative_paths(findings: &mut [Finding]) {
    // Group indices by (body_id, sink, source).  A simple O(n log n)
    // sort would clobber the caller-visible order; use a hashmap instead.
    let mut groups: HashMap<(BodyId, NodeIndex, NodeIndex), Vec<usize>> = HashMap::new();
    for (idx, f) in findings.iter().enumerate() {
        groups
            .entry((f.body_id, f.sink, f.source))
            .or_default()
            .push(idx);
    }
    for (_, members) in groups {
        if members.len() < 2 {
            continue;
        }
        // Collect IDs once, then distribute to every member *except self*.
        let ids: Vec<String> = members
            .iter()
            .map(|&i| findings[i].finding_id.clone())
            .collect();
        for &member_idx in &members {
            let own_id = findings[member_idx].finding_id.clone();
            findings[member_idx].alternative_finding_ids.clear();
            findings[member_idx]
                .alternative_finding_ids
                .extend(ids.iter().filter(|id| **id != own_id).cloned());
        }
    }
}

/// Compute containment-topological order: parent bodies before children.
///
/// Uses BFS from roots (bodies with no parent), ensuring a body is always
/// processed after its parent, required for lexical seed propagation.
/// Returns indices into `file_cfg.bodies` in processing order.
fn containment_order(bodies: &[BodyCfg]) -> Vec<usize> {
    let mut children: HashMap<BodyId, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        match body.meta.parent_body_id {
            Some(parent) => children.entry(parent).or_default().push(i),
            None => roots.push(i),
        }
    }
    let mut order = Vec::with_capacity(bodies.len());
    let mut queue: VecDeque<usize> = roots.into();
    while let Some(idx) = queue.pop_front() {
        order.push(idx);
        if let Some(kids) = children.get(&bodies[idx].meta.id) {
            queue.extend(kids);
        }
    }
    order
}

/// Build a `var_name → TypeKind` map from a body's optimised SSA + type-fact
/// result.  Used by [`analyse_multi_body`] to forward closure-captured types
/// from a parent body into its children, so that bound-variable receiver
/// idioms (`const c = ldap.createClient(...); function f() { c.search(...) }`)
/// pick up `TypeKind::LdapClient` on the inner reference via the
/// [`ssa_transfer::resolve_type_qualified_labels`] receiver scan.
///
/// Conflict policy: if the same `var_name` reaches multiple SSA values with
/// distinct `TypeKind`s the entry is dropped — propagating an ambiguous type
/// into a child body would fabricate facts, while dropping it just falls back
/// to the existing structural resolution paths.
fn extract_named_type_facts(
    ssa: &crate::ssa::SsaBody,
    type_facts: &crate::ssa::type_facts::TypeFactResult,
) -> HashMap<String, crate::ssa::type_facts::TypeKind> {
    use crate::ssa::type_facts::TypeKind;
    let mut acc: HashMap<String, TypeKind> = HashMap::new();
    let mut conflicts: HashSet<String> = HashSet::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            let Some(name) = inst.var_name.as_deref() else {
                continue;
            };
            if conflicts.contains(name) {
                continue;
            }
            let Some(kind) = type_facts.get_type(inst.value) else {
                continue;
            };
            if matches!(kind, TypeKind::Unknown) {
                continue;
            }
            match acc.get(name) {
                Some(existing) if existing != kind => {
                    acc.remove(name);
                    conflicts.insert(name.to_string());
                }
                Some(_) => {}
                None => {
                    acc.insert(name.to_string(), kind.clone());
                }
            }
        }
    }
    acc
}

/// Inject parent-known closure-capture types into a per-body
/// [`crate::ssa::type_facts::TypeFactResult`].
///
/// Scoped lowering ([`crate::ssa::lower_to_ssa_with_params`]) injects a
/// `SsaOp::Param` (or `SsaOp::SelfParam`) at the entry block for every
/// free / closure-captured variable read by the body.  The per-body type
/// analysis can only seed declared formal-parameter types (via
/// `BodyMeta.param_types`); free variables are left as `TypeKind::Unknown`
/// because their definition lives in an enclosing body whose SSA is not
/// in scope.
///
/// This pass walks the entry block's synthetic prologue and, for each
/// external Param whose name resolves in `parent_var_types`, inserts the
/// matching [`crate::ssa::type_facts::TypeFact`] into `type_facts.facts`.
/// Strictly additive: existing facts (e.g. a fact already produced by
/// `BodyMeta.param_types` seeding for a real formal that happens to share
/// a name) are never overwritten.
fn inject_external_type_facts(
    ssa: &crate::ssa::SsaBody,
    type_facts: &mut crate::ssa::type_facts::TypeFactResult,
    parent_var_types: &HashMap<String, crate::ssa::type_facts::TypeKind>,
) {
    use crate::ssa::ir::SsaOp;
    use crate::ssa::type_facts::TypeFact;
    if parent_var_types.is_empty() || ssa.blocks.is_empty() {
        return;
    }
    for inst in ssa.blocks[0].body.iter() {
        if !matches!(inst.op, SsaOp::Param { .. } | SsaOp::SelfParam) {
            continue;
        }
        if type_facts.facts.contains_key(&inst.value) {
            // `analyze_types_with_param_types` may have already typed this
            // value via a non-Unknown entry from BodyMeta.param_types; in
            // that case the formal-parameter declaration wins.  Note: the
            // analysis seeds an Unknown placeholder for unparameterised
            // Param ops, so we still need to override Unknown entries.
            if !matches!(
                type_facts.facts.get(&inst.value).map(|f| &f.kind),
                Some(crate::ssa::type_facts::TypeKind::Unknown)
            ) {
                continue;
            }
        }
        let Some(name) = inst.var_name.as_deref() else {
            continue;
        };
        let Some(kind) = parent_var_types.get(name) else {
            continue;
        };
        let nullable = matches!(kind, crate::ssa::type_facts::TypeKind::Null);
        type_facts.facts.insert(
            inst.value,
            TypeFact {
                kind: kind.clone(),
                nullable,
            },
        );
    }
}

/// Analyse a single body with an optional parent seed.
///
/// Shared logic extracted from `analyse_multi_body` to avoid deep nesting.
fn analyse_body_with_seed(
    body: &BodyCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    interop_edges: &[InteropEdge],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa_summaries: Option<
        &std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    callee_bodies: Option<&std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>>,
    inline_cache: Option<&std::cell::RefCell<ssa_transfer::InlineCache>>,
    seed: Option<&HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>>,
    import_bindings: Option<&crate::cfg::ImportBindings>,
    cross_file_bodies: Option<&std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>>,
    parent_var_types: Option<&HashMap<String, crate::ssa::type_facts::TypeKind>>,
) -> (
    Vec<Finding>,
    Option<HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>>,
    Option<HashMap<String, crate::ssa::type_facts::TypeKind>>,
) {
    let cfg = &body.graph;
    let entry = body.entry;
    let body_id = body.meta.id;

    let interner = SymbolInterner::from_cfg(cfg);
    if interner.len() > MAX_TRACKED_VARS {
        tracing::warn!(
            symbols = interner.len(),
            max = MAX_TRACKED_VARS,
            "taint analysis: too many variables, some will be ignored"
        );
    }

    // Per-body graphs contain only the body's own nodes.
    // For non-toplevel bodies, use lower_to_ssa_with_params with scope to
    // create SsaOp::Param ops for external/captured variables and formal
    // parameters, required for global_seed to inject taint from the parent.
    // Top-level bodies use lower_to_ssa with scope_all=true (no Param ops).
    let is_toplevel = body.meta.parent_body_id.is_none();
    // JS/TS function bodies always use scoped lowering to create Param ops
    // for captured variables (globals that flow via seed between bodies).
    // Other languages: scoped lowering only when the parent seed is non-empty,
    // i.e. the parent body actually has taint to propagate.  Without a seed,
    // Param ops would just introduce unused SSA values.
    let has_nonempty_seed = seed.is_some_and(|s| !s.is_empty());
    // Scoped lowering creates SsaOp::Param ops for formal parameters, required
    // for handler-param auto-seeding to fire. Java lambda bodies need this too
    // so that `cmd -> Runtime.exec(cmd)` picks up `cmd` as a handler param.
    let is_java_lambda =
        lang == Lang::Java && body.meta.kind == crate::cfg::BodyKind::AnonymousFunction;
    let use_scoped_lowering = !is_toplevel
        && (matches!(lang, Lang::JavaScript | Lang::TypeScript)
            || has_nonempty_seed
            || is_java_lambda);
    let ssa_result = if use_scoped_lowering {
        let func_name = body.meta.name.clone().unwrap_or_else(|| {
            body.meta
                .func_key
                .as_ref()
                .and_then(|k| k.disambig.map(|d| format!("<anon#{d}>")))
                .unwrap_or_else(|| format!("<anon@{}>", body.meta.span.0))
        });
        crate::ssa::lower_to_ssa_with_params(cfg, entry, Some(&func_name), false, &body.meta.params)
    } else {
        crate::ssa::lower_to_ssa(cfg, entry, None, true)
    };

    // Clear per-body engine-note collector before the body's analysis;
    // any WorklistCapped / OriginsTruncated notes recorded during
    // transfer land in this bucket and are attached to every finding
    // emitted from the body once analysis is done.
    ssa_transfer::reset_body_engine_notes();

    match ssa_result {
        Ok(mut ssa_body) => {
            let mut opt = crate::ssa::optimize_ssa_with_param_types(
                &mut ssa_body,
                cfg,
                Some(lang),
                &body.meta.param_types,
            );
            // Forward parent-body type facts onto closure-captured Param ops
            // before any consumer reads `opt.type_facts`.  This is the lever
            // that makes bound-variable receiver idioms work in scoped bodies
            // (`let c = ldap.createClient(...); function f() { c.search(...) }`)
            // — without it the inner `c` SSA value stays Unknown because the
            // per-body type-fact pass cannot see the enclosing definition.
            if let Some(pvt) = parent_var_types {
                inject_external_type_facts(&ssa_body, &mut opt.type_facts, pvt);
            }
            if tracing::enabled!(tracing::Level::TRACE) {
                tracing::trace!(
                    func = body.meta.name.as_deref().unwrap_or("<anon>"),
                    ssa = %ssa_body,
                    "SSA body lowered",
                );
                for block in &ssa_body.blocks {
                    for inst in block.phis.iter().chain(block.body.iter()) {
                        if let Some(t) = opt.type_facts.get_type(inst.value) {
                            tracing::trace!(value = inst.value.0, ty = ?t, "type fact");
                        }
                    }
                }
            }
            let dynamic_pts = std::cell::RefCell::new(std::collections::HashMap::new());
            // Static-map abstract analysis: recognises provably-bounded
            // lookup idioms (e.g. `map.get(x).unwrap_or("safe")`) so the SSA
            // taint engine can clear command-injection findings whose payload
            // is a finite set of literal strings.
            let static_map =
                crate::ssa::static_map::analyze(&ssa_body, cfg, Some(lang), &opt.const_values);
            let static_map_opt = if static_map.is_empty() {
                None
            } else {
                Some(static_map)
            };
            // Per-body field-sensitive points-to facts. Cost is
            // amortised across field-write read-back, container ELEM
            // cells, and the cross-call resolver.
            let pointer_facts = if crate::pointer::is_enabled() {
                Some(crate::pointer::analyse_body(&ssa_body, body.meta.id))
            } else {
                None
            };
            let transfer = ssa_transfer::SsaTaintTransfer {
                lang,
                namespace,
                interner: &interner,
                local_summaries,
                global_summaries,
                interop_edges,
                owner_body_id: body.meta.id,
                parent_body_id: body.meta.parent_body_id,
                global_seed: seed,
                param_seed: None,
                receiver_seed: None,
                const_values: Some(&opt.const_values),
                type_facts: Some(&opt.type_facts),
                xml_parser_config: Some(&opt.xml_parser_config),
                xpath_config: Some(&opt.xpath_config),
                ssa_summaries,
                extra_labels,
                base_aliases: Some(&opt.alias_result),
                callee_bodies,
                inline_cache,
                context_depth: 0,
                callback_bindings: None,
                points_to: Some(&opt.points_to),
                dynamic_pts: Some(&dynamic_pts),
                import_bindings,
                promisify_aliases: None,
                module_aliases: if opt.module_aliases.is_empty() {
                    None
                } else {
                    Some(&opt.module_aliases)
                },
                static_map: static_map_opt.as_ref(),
                auto_seed_handler_params: matches!(lang, Lang::JavaScript | Lang::TypeScript)
                    || (lang == Lang::Java
                        && body.meta.kind == crate::cfg::BodyKind::AnonymousFunction),
                cross_file_bodies,
                pointer_facts: pointer_facts.as_ref(),
            };
            let (events, block_states) =
                ssa_transfer::run_ssa_taint_full(&ssa_body, cfg, &transfer);
            let mut findings = ssa_transfer::ssa_events_to_findings(&events, &ssa_body, cfg);
            let body_notes = ssa_transfer::take_body_engine_notes();
            for f in &mut findings {
                f.body_id = body_id;
                for note in &body_notes {
                    f.merge_note(note.clone());
                }
            }
            if crate::symex::is_enabled() {
                let symex_ctx = crate::symex::SymexContext {
                    ssa: &ssa_body,
                    cfg,
                    const_values: &opt.const_values,
                    type_facts: &opt.type_facts,
                    global_summaries,
                    lang,
                    namespace,
                    points_to: Some(&opt.points_to),
                    callee_bodies,
                    scc_membership: None,
                    cross_file_bodies: global_summaries,
                };
                crate::symex::annotate_findings(&mut findings, &symex_ctx);
            }
            // After forward taint + symex have produced a final
            // `Finding.symbolic` shape, run the demand-driven backwards pass
            // and layer its verdict on top.  Placing this *after* symex
            // (which overwrites `symbolic`) preserves any symex witness
            // while still annotating `backwards-confirmed` / `-infeasible`
            // onto the `cutoff_notes` vector.  Gated by
            // `analysis.engine.backwards_analysis` (default off).
            if crate::utils::analysis_options::current().backwards_analysis {
                let bctx = backwards::BackwardsCtx {
                    ssa: &ssa_body,
                    cfg,
                    lang,
                    global_summaries,
                    intra_file_bodies: callee_bodies,
                    depth_budget: backwards::DEFAULT_BACKWARDS_DEPTH,
                };
                for finding in &mut findings {
                    let Some(sink_val) = ssa_body.cfg_node_map.get(&finding.sink).copied() else {
                        continue;
                    };
                    let sink_caps = cfg[finding.sink].taint.labels.iter().fold(
                        crate::labels::Cap::empty(),
                        |acc, l| match l {
                            crate::labels::DataLabel::Sink(c) => acc | *c,
                            _ => acc,
                        },
                    );
                    let caps = if sink_caps.is_empty() {
                        crate::labels::Cap::all()
                    } else {
                        sink_caps
                    };
                    let flows =
                        backwards::analyse_sink_backwards(&bctx, sink_val, finding.sink, caps);
                    let verdict = backwards::aggregate_verdict(&flows);
                    backwards::annotate_finding(finding, verdict);
                }
            }
            // Extract exit state for seeding child bodies.  Tag every
            // entry with the owner body's id so a later join (e.g. the
            // JS/TS two-level `combined_exit`) cannot silently alias
            // same-named bindings from different bodies.
            let exit_state = ssa_transfer::extract_ssa_exit_state(
                &block_states,
                &ssa_body,
                cfg,
                &transfer,
                body_id,
            );
            // Snapshot named TypeKinds so child bodies can pick up
            // closure-captured types (e.g. an outer `LdapClient` flowing
            // into an inner function via free-variable read).
            let named_types = extract_named_type_facts(&ssa_body, &opt.type_facts);
            let named_types = if named_types.is_empty() {
                None
            } else {
                Some(named_types)
            };
            (findings, Some(exit_state), named_types)
        }
        Err(e) => {
            // SSA lowering produced no analyzable body.  We still surface
            // the event so downstream tooling can tell "we tried and gave
            // up" from "we ran clean", a TRACE-level log records the
            // reason (no synthetic Finding is manufactured because a
            // diag pointing at no source location would be misleading).
            tracing::trace!(
                body_id = body_id.0,
                body_name = ?body.meta.name,
                error = %e,
                "SSA lowering bailed; emitting engine note",
            );
            ssa_transfer::record_engine_note(crate::engine_notes::EngineNote::SsaLoweringBailed {
                reason: format!("{e}"),
            });
            // Drain the collector so the note does not bleed into the
            // next body (which will call reset on entry, but be explicit).
            let _ = ssa_transfer::take_body_engine_notes();
            (Vec::new(), None, None)
        }
    }
}

/// Unified multi-body taint analysis with lexical containment propagation.
///
/// Pass 1: process all bodies in containment-topological order (parent before
/// child), seeding each child body with its parent's exit state.
///
/// Pass 2 (JS/TS only, `max_iterations > 1`): iterative convergence for
/// functions that modify global state, feeding taint back to other functions.
fn analyse_multi_body(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    interop_edges: &[InteropEdge],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa_summaries: Option<
        &std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    >,
    callee_bodies: Option<&std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>>,
    inline_cache: Option<&std::cell::RefCell<ssa_transfer::InlineCache>>,
    max_iterations: usize,
    import_bindings: Option<&crate::cfg::ImportBindings>,
    cross_file_bodies: Option<&std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>>,
) -> Vec<Finding> {
    let order = containment_order(&file_cfg.bodies);
    let mut all_findings: Vec<Finding> = Vec::new();

    // Exit states per body, used to seed children.
    let mut body_exit_states: HashMap<
        BodyId,
        HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>,
    > = HashMap::new();

    // Per-body `var_name → TypeKind` snapshots, used to forward closure-
    // captured types from parent bodies into their children's type-fact
    // results.  Only populated when a body produces a non-empty set of
    // typed named values, i.e. it has at least one named SSA value with
    // a concrete `TypeKind` after optimisation.
    let mut body_var_types: HashMap<
        BodyId,
        HashMap<String, crate::ssa::type_facts::TypeKind>,
    > = HashMap::new();

    // ── Pass 1: lexical containment propagation ──────────────────────
    for &idx in &order {
        let body = &file_cfg.bodies[idx];
        // Determine seed from parent body's exit state.
        let parent_seed = body
            .meta
            .parent_body_id
            .and_then(|pid| body_exit_states.get(&pid));
        let parent_var_types = body
            .meta
            .parent_body_id
            .and_then(|pid| body_var_types.get(&pid));

        let (findings, exit_state, var_types) = analyse_body_with_seed(
            body,
            lang,
            namespace,
            local_summaries,
            global_summaries,
            interop_edges,
            extra_labels,
            ssa_summaries,
            callee_bodies,
            inline_cache,
            parent_seed,
            import_bindings,
            cross_file_bodies,
            parent_var_types,
        );
        tracing::debug!(
            body_id = body.meta.id.0,
            body_name = ?body.meta.name,
            findings = findings.len(),
            graph_nodes = body.graph.node_count(),
            has_seed = parent_seed.is_some(),
            "analyse_multi_body: body analysed"
        );
        all_findings.extend(findings);
        if let Some(es) = exit_state {
            body_exit_states.insert(body.meta.id, es);
        }
        if let Some(vt) = var_types {
            body_var_types.insert(body.meta.id, vt);
        }
    }

    // ── Pass 2: JS/TS iterative convergence ──────────────────────────
    // Only for JS/TS: functions that modify global variables can feed taint
    // back to other functions.  Iterate until the top-level seed stabilises.
    //
    // `iters_used` counts how many rounds of the convergence loop
    // actually ran (not including the initial lexical-containment pass
    // above).  It is used to detect cap-hit after the loop exits: a
    // cap-hit is the case where we exhausted the budget without the
    // `combined_exit == current_seed` break firing.
    let mut converged_early = true;
    let mut iters_used: usize = 0;
    // Trajectory of per-round seed-delta sizes; populated inside the
    // max_iterations > 1 branch and read on cap-hit.  Default empty
    // → classifier returns `Unknown`, which is the correct outcome
    // for non-JS/TS languages (no iterative loop ran).
    let mut convergence_trajectory: smallvec::SmallVec<[u32; 4]> = smallvec::SmallVec::new();
    if max_iterations > 1 {
        let top = file_cfg.toplevel();
        let top_cfg = &top.graph;

        // Collect top-level binding keys for seed filtering.  Always
        // keyed under `BodyId(0)`, `filter_seed_to_toplevel` matches
        // by name and re-keys every surviving entry to `BodyId(0)`
        // anyway, so the body_id on the probe keys is informational.
        let toplevel_keys: HashSet<ssa_transfer::BindingKey> = {
            let mut keys = HashSet::new();
            for (_idx, info) in top_cfg.node_references() {
                if let Some(ref d) = info.taint.defines {
                    keys.insert(ssa_transfer::BindingKey::new(d.as_str(), BodyId(0)));
                }
                for u in &info.taint.uses {
                    keys.insert(ssa_transfer::BindingKey::new(u.as_str(), BodyId(0)));
                }
            }
            keys
        };

        // Phase-B (body granularity): precompute per-body read-set of
        // top-level binding names.  A non-toplevel body only needs
        // re-analysis when a name it reads via Param or via the
        // global_seed ancestor-lookup path has actually changed in
        // the combined seed.  `reads` is a superset of the body's
        // top-level dependencies, we err on the side of over-running
        // (false dirty) rather than missing a dependency.
        let body_reads: HashMap<BodyId, HashSet<String>> = {
            let mut m: HashMap<BodyId, HashSet<String>> = HashMap::new();
            for body in &file_cfg.bodies {
                if body.meta.parent_body_id.is_none() {
                    continue; // top-level has no global_seed lookups
                }
                let mut names: HashSet<String> = HashSet::new();
                for (_idx, info) in body.graph.node_references() {
                    for u in &info.taint.uses {
                        names.insert(u.to_string());
                    }
                }
                m.insert(body.meta.id, names);
            }
            m
        };

        // Initial seed is the top-level exit state.
        let mut current_seed = body_exit_states
            .get(&BodyId(0))
            .cloned()
            .unwrap_or_default();

        // Phase-B per-body findings cache: retains the most-recent
        // round's findings for each body.  Round N re-runs only dirty
        // bodies; clean bodies keep their round N-1 findings.  This
        // replaces the previous "drop all non-toplevel findings, run
        // everything, repeat" pattern.
        let mut findings_by_body: HashMap<BodyId, Vec<Finding>> = HashMap::new();

        // Seed the cache with the pass-1 findings so round 0 of the
        // worklist has a consistent starting state.  We partition
        // `all_findings` into "toplevel" (kept verbatim) and
        // "non-toplevel" (moved into the cache, keyed by body).
        let mut toplevel_findings: Vec<Finding> = Vec::new();
        for f in std::mem::take(&mut all_findings) {
            let body = file_cfg.bodies.get(f.body_id.0 as usize);
            if body.is_some_and(|b| b.meta.parent_body_id.is_none()) {
                toplevel_findings.push(f);
            } else {
                findings_by_body
                    .entry(BodyId(f.body_id.0))
                    .or_default()
                    .push(f);
            }
        }

        let rounds = max_iterations.saturating_sub(1);
        converged_early = rounds == 0;
        let use_gauss_seidel = js_ts_gauss_seidel_enabled();
        for round in 0..rounds {
            iters_used = round + 1;
            // Combine function body exits filtered to top-level scope.
            let mut combined_exit = current_seed.clone();
            for &idx in &order {
                let body = &file_cfg.bodies[idx];
                if body.meta.parent_body_id.is_none() {
                    continue; // skip top-level itself
                }
                if let Some(es) = body_exit_states.get(&body.meta.id) {
                    let filtered = ssa_transfer::filter_seed_to_toplevel(es, &toplevel_keys);
                    combined_exit = ssa_transfer::join_seed_maps(&combined_exit, &filtered);
                }
            }

            // Record seed-delta for cap-hit classification.  Count the
            // number of keys whose value differs between current_seed
            // and combined_exit.  This mirrors scan.rs's diff helpers
            // but at BindingKey granularity.
            let iter_delta = seed_delta_size(&current_seed, &combined_exit);
            if convergence_trajectory.len() == 4 {
                convergence_trajectory.remove(0);
            }
            convergence_trajectory.push(iter_delta as u32);

            // Converged: seed didn't change.
            if combined_exit == current_seed {
                converged_early = true;
                break;
            }

            // Phase-B: compute which binding names changed so we can
            // skip bodies whose read-set is disjoint from the change
            // set.
            let changed_names = changed_binding_names(&current_seed, &combined_exit);
            current_seed = combined_exit;

            // Re-run non-toplevel bodies with updated seed.
            body_exit_states.insert(BodyId(0), current_seed.clone());
            // Phase-C: Gauss-Seidel variant, as each body is
            // re-analysed, merge its new exit into `current_seed`
            // immediately so subsequent bodies in the same round see
            // the fresh value.  Order matters here; we pin to
            // `order` (containment-topological) for reproducibility.
            // The Jacobi path leaves `current_seed` untouched for
            // the rest of the round.
            for &idx in &order {
                let body = &file_cfg.bodies[idx];
                if body.meta.parent_body_id.is_none() {
                    continue; // don't re-run top-level
                }
                // Skip clean bodies: nothing this body reads has
                // changed, so re-analysis would produce byte-identical
                // output.  The cached findings from the previous
                // round (or pass-1) remain correct.
                if let Some(reads) = body_reads.get(&body.meta.id) {
                    if reads.is_disjoint(&changed_names) {
                        continue;
                    }
                }
                let parent_seed = body
                    .meta
                    .parent_body_id
                    .and_then(|pid| body_exit_states.get(&pid));
                let parent_var_types = body
                    .meta
                    .parent_body_id
                    .and_then(|pid| body_var_types.get(&pid));

                let (findings, exit_state, var_types) = analyse_body_with_seed(
                    body,
                    lang,
                    namespace,
                    local_summaries,
                    global_summaries,
                    interop_edges,
                    extra_labels,
                    ssa_summaries,
                    callee_bodies,
                    inline_cache,
                    parent_seed,
                    import_bindings,
                    cross_file_bodies,
                    parent_var_types,
                );
                // Phase-B: replace (not append) this body's findings
                // in the cache.  Previous rounds' findings for this
                // body are superseded by the new round's output.
                findings_by_body.insert(body.meta.id, findings);
                if let Some(vt) = var_types {
                    body_var_types.insert(body.meta.id, vt);
                }
                if let Some(es) = exit_state {
                    // Phase-C Gauss-Seidel: immediately publish this
                    // body's filtered exit into `current_seed` and
                    // `body_exit_states[BodyId(0)]` so the next body
                    // in this same round sees the updated seed via
                    // its `global_seed` ancestor lookup.
                    if use_gauss_seidel {
                        let filtered = ssa_transfer::filter_seed_to_toplevel(&es, &toplevel_keys);
                        current_seed = ssa_transfer::join_seed_maps(&current_seed, &filtered);
                        body_exit_states.insert(BodyId(0), current_seed.clone());
                    }
                    body_exit_states.insert(body.meta.id, es);
                }
            }
        }

        // After the loop, flatten per-body caches back into
        // `all_findings`, preserving the toplevel findings we set
        // aside earlier.
        all_findings = toplevel_findings;
        for body in &file_cfg.bodies {
            if body.meta.parent_body_id.is_none() {
                continue;
            }
            if let Some(fs) = findings_by_body.remove(&body.meta.id) {
                all_findings.extend(fs);
            }
        }
    }

    // Record observability counter.  `iters_used == 0` covers the
    // non-JS/TS path (`max_iterations == 1`) and the JS/TS case where
    // the convergence loop did not enter, report `1` so the counter
    // always reflects "at least the lexical-containment pass ran".
    let reported_iters = if iters_used == 0 { 1 } else { iters_used };
    LAST_JS_TS_PASS2_ITERATIONS.store(reported_iters, Ordering::Relaxed);

    // Convergence telemetry: record this file's pass-2 outcome.
    // No-op unless `NYX_CONVERGENCE_TELEMETRY=1`.  Only emitted for
    // JS/TS (`max_iterations > 1`) where a pass-2 loop actually ran;
    // single-iteration languages do not produce a convergence event.
    if max_iterations > 1 {
        let non_toplevel_bodies = file_cfg
            .bodies
            .iter()
            .filter(|b| b.meta.parent_body_id.is_some())
            .count();
        crate::convergence_telemetry::record(
            crate::convergence_telemetry::ConvergenceEvent::InFilePass2(
                crate::convergence_telemetry::InFilePass2Record {
                    schema: crate::convergence_telemetry::SCHEMA_VERSION,
                    namespace: namespace.to_string(),
                    body_count: non_toplevel_bodies,
                    iterations: iters_used,
                    cap: max_iterations,
                    converged: converged_early,
                    trajectory: convergence_trajectory.clone(),
                },
            ),
        );
    }

    // Cap-hit: the loop exhausted `max_iterations` without the
    // `combined_exit == current_seed` break firing.  Tag every finding
    // produced by this file so downstream consumers know the results
    // may be under-reported.  Only meaningful for JS/TS
    // (`max_iterations > 1`); single-iteration languages always
    // converge trivially by definition.
    if max_iterations > 1 && !converged_early {
        // Trajectory is captured in the convergence loop above; empty
        // when the loop never entered the delta-push path (rounds ==
        // 0, non-JS/TS, etc.).  Classifier defaults to `Unknown` for
        // <2 samples.
        let reason = crate::engine_notes::CapHitReason::classify(&convergence_trajectory);
        tracing::warn!(
            file = %namespace,
            iterations = iters_used,
            cap = max_iterations,
            reason = reason.tag(),
            "JS/TS pass-2 in-file fixpoint did not converge within safety cap — \
             results may be imprecise. This usually indicates a very deep chain \
             of top-level bindings threaded through helper functions; please \
             file a bug with a reproducer."
        );
        let note = EngineNote::InFileFixpointCapped {
            iterations: iters_used as u32,
            reason,
        };
        for f in &mut all_findings {
            f.merge_note(note.clone());
        }
    }

    all_findings
}

/// Return the set of binding **names** whose value differs between two
/// seed maps.  Used by the Phase-B body-level worklist to decide
/// which non-toplevel bodies must re-run.
///
/// Names (not full `BindingKey`s) because `filter_seed_to_toplevel`
/// re-keys every surviving entry to `BodyId(0)` anyway, and
/// per-body reads are plain identifier strings from the SSA IR.
/// Collapsing to names avoids a spurious mismatch when the same
/// binding appears under different body-scoped keys.
fn changed_binding_names(
    before: &HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>,
    after: &HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>,
) -> HashSet<String> {
    let mut changed = HashSet::new();
    for (k, v_after) in after {
        match before.get(k) {
            Some(v_before) if v_before == v_after => {}
            _ => {
                changed.insert(k.name.to_string());
            }
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            changed.insert(k.name.to_string());
        }
    }
    changed
}

/// Count [`ssa_transfer::BindingKey`]s whose [`VarTaint`] differs
/// between two seed maps.  Keys present in one map but missing from the
/// other count as differences.
fn seed_delta_size(
    before: &HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>,
    after: &HashMap<ssa_transfer::BindingKey, crate::taint::domain::VarTaint>,
) -> usize {
    let mut changed = 0usize;
    for (k, v_after) in after {
        match before.get(k) {
            Some(v_before) if v_before == v_after => {}
            _ => changed += 1,
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            changed += 1;
        }
    }
    changed
}

/// Find function entry nodes: (func_name, entry_node) pairs.
///
/// A function entry is the first node with a given `enclosing_func` value.
fn find_function_entries(cfg: &Cfg) -> Vec<(String, NodeIndex)> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for (idx, info) in cfg.node_references() {
        if let Some(ref func_name) = info.ast.enclosing_func
            && seen.insert(func_name.clone())
        {
            entries.push((func_name.clone(), idx));
        }
    }

    entries
}

/// Look up formal parameter names (in declaration order) for a function from
/// the CFG-level local summaries. Returns empty vec if not found.
fn lookup_formal_params(local_summaries: &FuncSummaries, func_name: &str) -> Vec<String> {
    local_summaries
        .iter()
        .find(|(k, _)| k.name == func_name)
        .map(|(_, s)| s.param_names.clone())
        .unwrap_or_default()
}

/// Resolve a bare function name + param count to a canonical [`FuncKey`] by
/// consulting the already FuncKey-keyed `local_summaries`.
///
/// When exactly one `(name, arity)`-matching entry exists we use its full
/// identity (container / disambig / kind preserved).  When zero or multiple
/// match we fall back to a free-function key so the caller still has a
/// well-formed key, this can only happen in legacy discovery paths that
/// cannot see through same-name siblings, and those paths were already
/// collision-prone before this refactor.  New intra-file analysis code
/// should prefer [`BodyMeta::func_key`].
fn lookup_canonical_func_key(
    local_summaries: &FuncSummaries,
    lang: Lang,
    namespace: &str,
    func_name: &str,
    param_count: usize,
) -> FuncKey {
    // `local_summaries` is file-local, so every entry's namespace agrees with
    // whatever `build_cfg` wrote (raw file path). We match by lang + name +
    // arity and fall back to name-only, the caller's `namespace` argument is
    // only used when we have to synthesise a key as a last resort.
    let mut matches = local_summaries
        .keys()
        .filter(|k| k.lang == lang && k.name == func_name && k.arity == Some(param_count));
    let first = matches.next().cloned();
    if let Some(first) = first
        && matches.next().is_none()
    {
        return first;
    }
    if let Some(name_only) = local_summaries
        .keys()
        .find(|k| k.lang == lang && k.name == func_name)
    {
        return name_only.clone();
    }
    FuncKey {
        lang,
        namespace: namespace.to_string(),
        container: String::new(),
        name: func_name.to_string(),
        arity: Some(param_count),
        disambig: None,
        kind: FuncKind::Function,
    }
}

/// Extract precise SSA function summaries for all functions in a file.
///
/// Lowers each function to SSA individually and runs per-parameter probing
/// to produce an `SsaFuncSummary`. The resulting map is keyed by canonical
/// [`FuncKey`] so that same-name functions on different containers in the
/// same file produce distinct summary entries.
#[allow(dead_code)] // Used by tests; production code uses extract_ssa_artifacts
pub(crate) fn extract_intra_file_ssa_summaries(
    cfg: &Cfg,
    interner: &SymbolInterner,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
) -> std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary> {
    let func_entries = find_function_entries(cfg);
    let mut summaries = std::collections::HashMap::new();

    for (func_name, func_entry) in &func_entries {
        let formal_params = lookup_formal_params(local_summaries, func_name);
        let func_ssa = match crate::ssa::lower_to_ssa_with_params(
            cfg,
            *func_entry,
            Some(func_name),
            false,
            &formal_params,
        ) {
            Ok(ssa) => ssa,
            Err(_) => continue,
        };

        // Param count = number of formal params (from CFG), falling back to
        // counting all SsaOp::Param ops when no local summary is available.
        let param_count = if !formal_params.is_empty() {
            formal_params.len()
        } else {
            func_ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count()
        };

        // Zero-param helpers are normally elided, a fixture with no
        // parameters cannot carry per-parameter taint transforms.  But
        // zero-arg factories (`function makeBag() { return []; }`) do
        // have one observable cross-file effect: the return is a fresh
        // container allocation.  Run the summary extractor for those and
        // keep the result only when `returns_fresh_alloc` is set;
        // everything else falls through the observable-effects filter
        // below.
        //
        // Pre-compute module aliases for JS/TS (read-only const prop pass)
        let mod_aliases = compute_module_aliases_for_summary(&func_ssa, lang);
        let mod_aliases_ref = if mod_aliases.is_empty() {
            None
        } else {
            Some(&mod_aliases)
        };

        let summary = ssa_transfer::extract_ssa_func_summary(
            &func_ssa,
            cfg,
            local_summaries,
            global_summaries,
            lang,
            namespace,
            interner,
            param_count,
            mod_aliases_ref,
            None,
            Some(&formal_params),
            None,
            None,
        );

        // Only store if the summary has observable effects.  With
        // `points_to` support, a void helper whose only observable behaviour
        // is a parameter-to-parameter alias (e.g. `fn set(t, v) { t.x = v; }`)
        // must survive this filter so summary application at cross-file
        // call sites can replay the alias edges.  Zero-param factories
        // are kept via the `returns_fresh_alloc` leg of
        // `points_to.is_empty()`, `is_empty()` returns false when the
        // fresh-alloc flag is set.
        if !summary.param_to_return.is_empty()
            || !summary.param_to_sink.is_empty()
            || !summary.source_caps.is_empty()
            || !summary.param_container_to_return.is_empty()
            || !summary.param_to_container_store.is_empty()
            || summary.return_abstract.is_some()
            || !summary.points_to.is_empty()
        {
            let key =
                lookup_canonical_func_key(local_summaries, lang, namespace, func_name, param_count);
            summaries.insert(key, summary);
        }
    }

    if !summaries.is_empty() {
        tracing::debug!(
            count = summaries.len(),
            "SSA summary extraction: produced intra-file summaries"
        );
    }

    summaries
}

/// Lower all function bodies from `FileCfg` to produce SSA summaries + cached
/// bodies.  Each body's own graph is used directly, no scope filtering needed.
///
/// Both returned maps are keyed by each body's canonical [`FuncKey`] (carried
/// on [`crate::cfg::BodyMeta::func_key`]).  This is the most collision-
/// resistant identity we have: same-name methods on different classes, same-
/// name overloads with different arity, and anonymous bodies at distinct
/// source spans all get distinct keys.
pub(crate) fn lower_all_functions_from_bodies(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    locator: Option<&crate::summary::SinkSiteLocator<'_>>,
) -> (
    std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>,
) {
    let mut summaries = std::collections::HashMap::new();
    let mut bodies = std::collections::HashMap::new();

    for body in file_cfg.function_bodies() {
        let _t_misc = std::time::Instant::now();
        let func_name = body.meta.name.clone().unwrap_or_else(|| {
            body.meta
                .func_key
                .as_ref()
                .and_then(|k| k.disambig.map(|d| format!("<anon#{d}>")))
                .unwrap_or_else(|| format!("<anon@{}>", body.meta.span.0))
        });

        let interner = SymbolInterner::from_cfg(&body.graph);
        let formal_params = &body.meta.params;
        perf_lower_record(6, _t_misc.elapsed().as_micros());

        let _t_lower = std::time::Instant::now();
        let mut func_ssa = match crate::ssa::lower_to_ssa_with_params(
            &body.graph,
            body.entry,
            Some(&func_name),
            false,
            formal_params,
        ) {
            Ok(ssa) => ssa,
            Err(_) => continue,
        };
        perf_lower_record(0, _t_lower.elapsed().as_micros());

        let param_count = if !formal_params.is_empty() {
            formal_params.len()
        } else {
            func_ssa
                .blocks
                .iter()
                .flat_map(|b| b.phis.iter().chain(b.body.iter()))
                .filter(|i| matches!(i.op, crate::ssa::ir::SsaOp::Param { .. }))
                .count()
        };

        // Canonical FuncKey: prefer the identity attached to the body at
        // CFG-construction time; otherwise fall back to matching in
        // `local_summaries`.
        //
        // `body.meta.func_key` carries the raw file-path namespace that
        // `build_cfg` wrote. The caller passes `namespace` already normalized
        // against `scan_root`, which is what FuncSummary keys use on the
        // cross-file side (`FuncSummary::func_key`). Overriding the namespace
        // here keeps both sides of `GlobalSummaries` agreement, otherwise
        // `resolve_callee` resolves to the normalized FuncSummary key and
        // misses the raw-path SSA entry.
        let mut key = body.meta.func_key.clone().unwrap_or_else(|| {
            lookup_canonical_func_key(local_summaries, lang, namespace, &func_name, param_count)
        });
        key.namespace = namespace.to_string();

        // Run the extractor even for zero-param functions so factories
        // (`returns_fresh_alloc = true`) emit a summary the caller can
        // replay.  A completely empty summary is still inserted for
        // non-zero-param functions (see the existing rationale below) but
        // zero-param cases without the factory flag stay out of the map
        // to avoid cluttering `GlobalSummaries` with trivially-empty
        // entries.
        {
            let _t_extract = std::time::Instant::now();
            let mod_aliases = compute_module_aliases_for_summary(&func_ssa, lang);
            let mod_aliases_ref = if mod_aliases.is_empty() {
                None
            } else {
                Some(&mod_aliases)
            };
            let formal_destructured = if !body.meta.param_destructured_fields.is_empty() {
                Some(body.meta.param_destructured_fields.as_slice())
            } else {
                None
            };
            let param_types_ref = if !body.meta.param_types.is_empty() {
                Some(body.meta.param_types.as_slice())
            } else {
                None
            };
            let summary = ssa_transfer::extract_ssa_func_summary(
                &func_ssa,
                &body.graph,
                local_summaries,
                global_summaries,
                lang,
                namespace,
                &interner,
                param_count,
                mod_aliases_ref,
                locator,
                Some(formal_params),
                formal_destructured,
                param_types_ref,
            );

            // Always insert the summary, even when all fields are empty/default.
            // An empty summary tells resolve_callee "this function exists and has
            // no taint effects", preventing fallthrough to the less precise old
            // FuncSummary which may report false source_caps from internal sources.
            // For zero-param functions we only insert when the summary carries
            // the fresh-container signal (the only observable effect worth
            // persisting for a parameter-less body).
            if param_count > 0 || summary.points_to.returns_fresh_alloc {
                summaries.insert(key.clone(), summary);
            }
            perf_lower_record(1, _t_extract.elapsed().as_micros());
        }

        let _t_opt = std::time::Instant::now();
        let opt = crate::ssa::optimize_ssa_with_param_types(
            &mut func_ssa,
            &body.graph,
            Some(lang),
            &body.meta.param_types,
        );
        perf_lower_record(2, _t_opt.elapsed().as_micros());

        let _t_typed = std::time::Instant::now();
        // For every SSA method call, look up the receiver's TypeKind
        // and record `(call_ordinal, container_name)` so devirtualisation
        // in `build_call_graph` can narrow the edge to the receiver-typed
        // container. Free-function calls and unknown types fall back to
        // bare-name resolution.
        let typed_receivers = collect_typed_call_receivers(&func_ssa, &body.graph, &opt.type_facts);
        if !typed_receivers.is_empty() {
            // Zero-param/no-fresh-alloc bodies are skipped above;
            // force-insert so receiver-type info still reaches
            // build_call_graph.
            let entry = summaries.entry(key.clone()).or_default();
            entry.typed_call_receivers = typed_receivers;
        }

        // Populate `field_points_to` from the body's pointer facts.
        // `extract_field_points_to` covers both reads (FieldProj walks)
        // and writes (`field_writes` side-table) in one pass.
        if crate::pointer::is_enabled() {
            let facts = crate::pointer::analyse_body(&func_ssa, body.meta.id);
            let fpt = crate::pointer::extract_field_points_to(&func_ssa, &facts);
            if !fpt.is_empty() {
                let entry = summaries.entry(key.clone()).or_default();
                entry.field_points_to = fpt;
            }
        }

        perf_lower_record(3, _t_typed.elapsed().as_micros());

        let _t_misc2 = std::time::Instant::now();
        bodies.insert(
            key,
            ssa_transfer::CalleeSsaBody {
                ssa: func_ssa,
                opt,
                param_count,
                node_meta: std::collections::HashMap::new(),
                body_graph: Some(body.graph.clone()),
            },
        );
        perf_lower_record(6, _t_misc2.elapsed().as_micros());
    }

    // ── Closure-capture summary augmentation ─────────────────────────
    //
    // Lift child-body sinks into the parent's `param_to_sink` for
    // every parent body with lexically contained children. This
    // handles the direct-wrapper case
    // `f(x) { return new Promise((res, rej) => sink(x)) }`, the
    // executor's gated http.get sink becomes visible to callers of
    // `f` via `f.summary.param_to_sink`.
    //
    // Without this pass, `f.summary.param_to_sink` stays empty
    // because the sink lives in a separately-extracted child body
    // that the parent's pass-1 probe never sees. The
    // lexical-containment propagation in `analyse_multi_body`
    // carries seeded taint into child bodies for the production
    // analysis path, but the single-body summary extractor in
    // `extract_ssa_func_summary` does not. This pass reproduces that
    // propagation at summary-extraction time so cross-call
    // resolution sees the sink at every caller of `f`.
    //
    // Strict-additive: only ADDs `param_to_sink` entries, never
    // removes or modifies existing data, so it cannot regress
    // detection. Bounded: each parent-param probe runs each child
    // body's analysis exactly once.
    let _t_aug = std::time::Instant::now();
    augment_summaries_with_child_sinks(
        file_cfg,
        lang,
        namespace,
        local_summaries,
        global_summaries,
        &bodies,
        &mut summaries,
    );
    perf_lower_record(4, _t_aug.elapsed().as_micros());

    // ── Second extraction pass: transitive cross-function summary lift ───
    //
    // The augment pass populates direct sink-wrapper summaries
    // (`f(x) { Promise(() => sink(x)) }`). This second pass then
    // re-runs every body's per-parameter probe with the augmented
    // `summaries` map plumbed through to the probe transfer's
    // `ssa_summaries` field, so callers of those wrappers (e.g. an
    // `addFileDataIfNeeded` whose body calls a `downloadFileFromURI`
    // sink wrapper) see the augmented `param_to_sink` at step 0 of
    // `resolve_callee_full` and propagate it onto their own summary.
    //
    // OR-merge: only adds `param_to_sink` / `param_to_sink_param`
    // entries to existing summaries. Existing entries (return
    // transforms, source caps, augment-populated sinks, etc.) are
    // preserved. Strict-additive, cannot regress detection.
    let _t_rerun = std::time::Instant::now();
    rerun_extraction_with_augmented_summaries(
        file_cfg,
        lang,
        namespace,
        local_summaries,
        global_summaries,
        locator,
        &bodies,
        &mut summaries,
    );
    perf_lower_record(5, _t_rerun.elapsed().as_micros());

    if !summaries.is_empty() {
        tracing::debug!(
            count = summaries.len(),
            bodies = bodies.len(),
            "lower_all_functions_from_bodies: produced summaries + cached bodies"
        );
    }

    (summaries, bodies)
}

/// Second extraction pass: re-runs `extract_ssa_func_summary_full` for
/// every body with the augmented `summaries` map plumbed through.
///
/// Only sink-related fields (`param_to_sink`, `param_to_sink_param`)
/// are merged into existing summaries; other fields stay as-produced
/// by the first pass.  Bounded: one re-extraction per body.
#[allow(clippy::too_many_arguments)]
fn rerun_extraction_with_augmented_summaries(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    locator: Option<&crate::summary::SinkSiteLocator<'_>>,
    bodies: &std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>,
    summaries: &mut std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
) {
    use crate::ssa::ir::SsaOp;
    use crate::state::symbol::SymbolInterner;

    // Fast-out: rerun matters only when at least one body in the file has
    // an SSA summary entry that *another* body in the same file might
    // resolve a Call to.  If no SSA summaries were produced, nothing to
    // re-extract.  This is the dominant case for files of unrelated
    // functions or with all-cross-file callees.
    if summaries.is_empty() {
        return;
    }

    // Snapshot the augmented summaries map so the probes resolve
    // callees against a stable view (the merge below mutates
    // `summaries` as we iterate).
    let augmented_snapshot: std::collections::HashMap<
        FuncKey,
        crate::summary::ssa_summary::SsaFuncSummary,
    > = summaries.clone();

    // Set of bare callee names known to have an in-file SsaFuncSummary.
    // `extract_ssa_func_summary_full` only consults `ssa_summaries` at
    // Call resolution time, so a body with no Call to any of these names
    // produces a summary identical to its first-pass output.
    //
    // SSA `Call::callee` carries the bare method name after lowering
    // decomposes chained-receiver calls, which matches `FuncKey::name`.
    // Borrows `augmented_snapshot` (immutable view) so the loop below can
    // freely mutate `summaries`.
    let in_file_names: std::collections::HashSet<&str> =
        augmented_snapshot.keys().map(|k| k.name.as_str()).collect();

    for body in file_cfg.function_bodies() {
        let Some(parent_key) = body.meta.func_key.clone() else {
            continue;
        };
        let mut key = parent_key;
        key.namespace = namespace.to_string();

        let Some(callee) = bodies.get(&key) else {
            continue;
        };
        if callee.param_count == 0 {
            continue;
        }
        let Some(parent_cfg) = callee.body_graph.as_ref() else {
            continue;
        };

        // Narrow: rerun only bodies whose SSA references at least one
        // in-file summary by name.  Bodies with no in-file Call cannot
        // benefit from the augmented `ssa_summaries` view, so their
        // re-extraction is a strict no-op.
        let has_in_file_call = callee.ssa.blocks.iter().any(|b| {
            b.body.iter().any(|inst| {
                if let SsaOp::Call { callee: name, .. } = &inst.op {
                    in_file_names.contains(name.as_str())
                } else {
                    false
                }
            })
        });
        if !has_in_file_call {
            continue;
        }

        let interner = SymbolInterner::from_cfg(parent_cfg);
        let mod_aliases = compute_module_aliases_for_summary(&callee.ssa, lang);
        let mod_aliases_ref = if mod_aliases.is_empty() {
            None
        } else {
            Some(&mod_aliases)
        };

        let formal_destructured = if !body.meta.param_destructured_fields.is_empty() {
            Some(body.meta.param_destructured_fields.as_slice())
        } else {
            None
        };
        let param_types_ref = if !body.meta.param_types.is_empty() {
            Some(body.meta.param_types.as_slice())
        } else {
            None
        };
        let new_summary = ssa_transfer::extract_ssa_func_summary_full(
            &callee.ssa,
            parent_cfg,
            local_summaries,
            global_summaries,
            lang,
            namespace,
            &interner,
            callee.param_count,
            mod_aliases_ref,
            locator,
            Some(&body.meta.params),
            Some(&augmented_snapshot),
            formal_destructured,
            param_types_ref,
        );

        // OR-merge sink-only fields into the existing summary.
        let entry = summaries.entry(key).or_default();
        merge_sink_fields(entry, &new_summary);
    }
}

/// OR-merge `param_to_sink`, `param_to_sink_param`, and
/// `validated_params_to_return` from `src` into `dst`.  Existing entries
/// are preserved; only NEW entries are added.
///
/// The validated-param list grows monotonically across extraction
/// rounds: a parameter that proves validated under any extraction
/// pass (the augmented second pass typically resolves more
/// cross-function summaries than the first) stays validated.  Drops
/// here would silently lose CVE-2026-25544-class precision the
/// re-extraction pass was specifically designed to recover.
fn merge_sink_fields(
    dst: &mut crate::summary::ssa_summary::SsaFuncSummary,
    src: &crate::summary::ssa_summary::SsaFuncSummary,
) {
    for (idx, sites) in &src.param_to_sink {
        if let Some((_, dst_sites)) = dst.param_to_sink.iter_mut().find(|(i, _)| i == idx) {
            for site in sites {
                let key = site.dedup_key();
                if !dst_sites.iter().any(|s| s.dedup_key() == key) {
                    dst_sites.push(site.clone());
                }
            }
        } else {
            dst.param_to_sink.push((*idx, sites.clone()));
        }
    }
    for &(idx, pos, caps) in &src.param_to_sink_param {
        if !dst
            .param_to_sink_param
            .iter()
            .any(|(i, p, c)| *i == idx && *p == pos && *c == caps)
        {
            dst.param_to_sink_param.push((idx, pos, caps));
        }
    }
    for &idx in &src.validated_params_to_return {
        if !dst.validated_params_to_return.contains(&idx) {
            dst.validated_params_to_return.push(idx);
        }
    }
}

/// Walk lexical-containment children of every parent body and lift
/// their sinks into the parent's [`SsaFuncSummary::param_to_sink`].
///
/// For each parent body P with at least one lexically contained
/// child:
///   - For each formal parameter `p_i` of P:
///     - Seed a probe with `{ p_i → Cap::all() }`, run P's SSA
///       analysis, extract P's exit state.
///     - For every descendant child body C of P, run C's SSA
///       analysis with the parent's exit state seeded as
///       `global_seed`. Collect sink events.
///     - For each event whose `sink_caps` is non-empty, append a
///       cap-only [`SinkSite`] under `p_i` on P's summary
///       (deduplicated by cap-mask so repeat probes don't inflate
///       the entry).
///
/// Strict-additive: only inserts new `param_to_sink` entries; never
/// modifies `param_return_paths`, `points_to`, `source_caps`, etc.
fn augment_summaries_with_child_sinks(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    bodies: &std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>,
    summaries: &mut std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
) {
    use crate::cfg::BodyId;
    use crate::labels::{Cap, SourceKind};
    use crate::summary::SinkSite;
    use crate::taint::domain::{TaintOrigin, VarTaint};
    use ssa_transfer::BindingKey;

    // ── Build lexical-containment relationships ──────────────────────
    // Map parent BodyId → list of descendant body indices.  Reverse-walk
    // each body's `parent_body_id` chain so a grand-child's sinks are
    // attributed to every ancestor in its containment chain.
    let body_id_to_idx: std::collections::HashMap<BodyId, usize> = file_cfg
        .bodies
        .iter()
        .enumerate()
        .map(|(i, b)| (b.meta.id, i))
        .collect();
    let mut descendants: std::collections::HashMap<BodyId, Vec<usize>> =
        std::collections::HashMap::new();
    for (idx, body) in file_cfg.bodies.iter().enumerate() {
        // Walk up the parent chain, registering this body as a descendant
        // of every ancestor.
        let mut cur = body.meta.parent_body_id;
        while let Some(pid) = cur {
            descendants.entry(pid).or_default().push(idx);
            cur = body_id_to_idx
                .get(&pid)
                .and_then(|i| file_cfg.bodies[*i].meta.parent_body_id);
        }
    }

    // ── Map each parent body to its FuncKey and the SSA body cache ──
    // Skip bodies with no formal params (nothing to probe) and bodies
    // whose SSA was never lowered (lowering errors logged earlier).
    for parent_body in &file_cfg.bodies {
        let Some(parent_key) = parent_body.meta.func_key.clone() else {
            continue;
        };
        let mut parent_key = parent_key;
        parent_key.namespace = namespace.to_string();

        let Some(parent_callee) = bodies.get(&parent_key) else {
            continue;
        };
        if parent_callee.param_count == 0 {
            continue;
        }
        let Some(child_indices) = descendants.get(&parent_body.meta.id) else {
            continue;
        };
        if child_indices.is_empty() {
            continue;
        }

        let parent_ssa = &parent_callee.ssa;
        let parent_cfg = match parent_callee.body_graph.as_ref() {
            Some(g) => g,
            None => continue,
        };
        let parent_interner = crate::state::symbol::SymbolInterner::from_cfg(parent_cfg);

        // Collect (formal_param_idx, var_name, ssa_value) for the parent's
        // formal params, mirrors `extract_ssa_func_summary`'s param scan.
        let mut parent_param_info: Vec<(usize, String)> = Vec::new();
        for block in &parent_ssa.blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                if let crate::ssa::ir::SsaOp::Param { index } = &inst.op {
                    if *index < parent_callee.param_count {
                        if let Some(name) = inst.var_name.as_ref() {
                            parent_param_info.push((*index, name.clone()));
                        }
                    }
                }
            }
        }

        for (param_idx, param_name) in &parent_param_info {
            // Seed parent's probe with this single param tainted to all caps.
            let mut seed: std::collections::HashMap<BindingKey, VarTaint> =
                std::collections::HashMap::new();
            seed.insert(
                BindingKey::new(param_name.as_str(), BodyId(0)),
                VarTaint {
                    caps: Cap::all(),
                    origins: smallvec::SmallVec::from_elem(
                        TaintOrigin {
                            node: petgraph::graph::NodeIndex::new(0),
                            source_kind: SourceKind::UserInput,
                            source_span: None,
                        },
                        1,
                    ),
                    uses_summary: false,
                },
            );

            let parent_transfer = ssa_transfer::SsaTaintTransfer {
                lang,
                namespace,
                interner: &parent_interner,
                local_summaries,
                global_summaries,
                interop_edges: &[],
                owner_body_id: BodyId(0),
                parent_body_id: None,
                global_seed: Some(&seed),
                param_seed: None,
                receiver_seed: None,
                const_values: None,
                type_facts: None,
                xml_parser_config: None,
                xpath_config: None,
                ssa_summaries: Some(summaries),
                extra_labels: None,
                base_aliases: None,
                callee_bodies: None,
                inline_cache: None,
                context_depth: 0,
                callback_bindings: None,
                points_to: None,
                dynamic_pts: None,
                import_bindings: None,
                promisify_aliases: None,
                module_aliases: None,
                static_map: None,
                auto_seed_handler_params: false,
                cross_file_bodies: None,
                pointer_facts: None,
            };

            let (_parent_events, parent_block_states) =
                ssa_transfer::run_ssa_taint_full(parent_ssa, parent_cfg, &parent_transfer);
            let parent_exit = ssa_transfer::extract_ssa_exit_state(
                &parent_block_states,
                parent_ssa,
                parent_cfg,
                &parent_transfer,
                BodyId(0),
            );
            if parent_exit.is_empty() {
                continue;
            }

            for &child_idx in child_indices {
                let child_body = &file_cfg.bodies[child_idx];
                let Some(child_key) = child_body.meta.func_key.clone() else {
                    continue;
                };
                let mut child_key = child_key;
                child_key.namespace = namespace.to_string();
                let Some(child_callee) = bodies.get(&child_key) else {
                    continue;
                };
                let child_ssa = &child_callee.ssa;
                let Some(child_cfg) = child_callee.body_graph.as_ref() else {
                    continue;
                };

                let child_interner = crate::state::symbol::SymbolInterner::from_cfg(child_cfg);

                let child_transfer = ssa_transfer::SsaTaintTransfer {
                    lang,
                    namespace,
                    interner: &child_interner,
                    local_summaries,
                    global_summaries,
                    interop_edges: &[],
                    owner_body_id: BodyId(0),
                    parent_body_id: None,
                    global_seed: Some(&parent_exit),
                    param_seed: None,
                    receiver_seed: None,
                    const_values: None,
                    type_facts: None,
                    xml_parser_config: None,
                    xpath_config: None,
                    ssa_summaries: Some(summaries),
                    extra_labels: None,
                    base_aliases: None,
                    callee_bodies: None,
                    inline_cache: None,
                    context_depth: 0,
                    callback_bindings: None,
                    points_to: None,
                    dynamic_pts: None,
                    import_bindings: None,
                    promisify_aliases: None,
                    module_aliases: None,
                    static_map: None,
                    auto_seed_handler_params: false,
                    cross_file_bodies: None,
                    pointer_facts: None,
                };

                let (child_events, _child_block_states) =
                    ssa_transfer::run_ssa_taint_full(child_ssa, child_cfg, &child_transfer);

                if child_events.is_empty() {
                    continue;
                }

                // Aggregate sink caps across all child events into one
                // entry per parent param (cap-only SinkSite, the
                // exact location lives in the child body's CFG and is
                // not directly addressable from the parent's summary).
                let mut union_caps = Cap::empty();
                for ev in &child_events {
                    union_caps |= ev.sink_caps;
                }
                if union_caps.is_empty() {
                    continue;
                }

                let entry = summaries.entry(parent_key.clone()).or_default();
                let new_site = SinkSite::cap_only(union_caps);
                let new_key = new_site.dedup_key();
                if let Some((_, sites)) = entry
                    .param_to_sink
                    .iter_mut()
                    .find(|(i, _)| *i == *param_idx)
                {
                    if !sites.iter().any(|s| s.dedup_key() == new_key) {
                        sites.push(new_site);
                    }
                } else {
                    entry
                        .param_to_sink
                        .push((*param_idx, smallvec::smallvec![new_site]));
                }

                // Mirror cap-only attribution into `param_to_sink_param`
                // so the call-site emission path that consults it (the
                // engine's primary sink-site picker uses
                // `param_to_sink_param` for arg-position filtering)
                // sees this captured-flow sink. Position 0 is a
                // best-effort placeholder, the actual filtering at
                // the caller is by SSRF cap, not arg position, when
                // the wrapper is itself non-gated.
                if !entry
                    .param_to_sink_param
                    .iter()
                    .any(|(i, _, c)| *i == *param_idx && *c == union_caps)
                {
                    entry.param_to_sink_param.push((*param_idx, 0, union_caps));
                }
            }
        }
    }
}

/// Walk every SSA `Call` instruction in `ssa` and produce
/// `(call_ordinal, container_name)` entries for those whose receiver
/// SSA value has a [`crate::ssa::type_facts::TypeKind`] with a
/// non-empty [`crate::ssa::type_facts::TypeKind::container_name`].
///
/// Free-function calls (`receiver: None`) and unknown receiver types
/// are skipped, the cross-file call-graph builder will fall back to
/// today's name-only resolution for those, preserving the
/// "subset of today's targets, never a superset" invariant from
/// `docs/typed-call-graph-prompt.md`.
///
/// Ordinals are pulled from the underlying CFG node's
/// [`crate::cfg::CallMeta::call_ordinal`] so they line up with
/// [`crate::summary::CalleeSite::ordinal`] at consumer time.  Calls
/// whose CFG node has no recoverable ordinal (synthetic / removed
/// nodes) are silently dropped.
fn collect_typed_call_receivers(
    ssa: &crate::ssa::ir::SsaBody,
    cfg: &crate::cfg::Cfg,
    type_facts: &crate::ssa::type_facts::TypeFactResult,
) -> Vec<(u32, String)> {
    use crate::ssa::ir::SsaOp;

    let mut out: Vec<(u32, String)> = Vec::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for block in &ssa.blocks {
        for inst in block.body.iter() {
            let SsaOp::Call { receiver, .. } = &inst.op else {
                continue;
            };
            let Some(receiver_val) = receiver else {
                continue; // free-function call, no devirtualisation possible
            };
            let Some(kind) = type_facts.get_type(*receiver_val) else {
                continue; // type unknown, fall back to name-only resolution
            };
            let Some(container) = kind.container_name() else {
                continue; // scalar/unknown type, no useful container
            };
            let Some(node_info) = cfg.node_weight(inst.cfg_node) else {
                continue;
            };
            let ordinal = node_info.call.call_ordinal;
            // A single SSA call instruction maps 1:1 with a CFG call
            // node, so each ordinal should appear at most once.  The
            // dedup guard exists in case lowering ever introduces a
            // second SSA Call sharing a cfg_node, first wins.
            if !seen.insert(ordinal) {
                continue;
            }
            out.push((ordinal, container));
        }
    }

    out.sort_by_key(|(ord, _)| *ord);
    out
}

/// Maximum blocks for a callee body to be eligible for cross-file persistence.
const MAX_CROSS_FILE_BODY_BLOCKS: usize = 100;

type SsaArtifactSummaries =
    std::collections::HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>;
type EligibleCalleeBodies = Vec<(FuncKey, ssa_transfer::CalleeSsaBody)>;

/// FileCfg-based artifact extraction: iterates per-body (not per function
/// entry) and lowers each body's graph with its recorded entry/params. This
/// path is equivalent to what `analyse_file` uses at taint time, so the SSA
/// summaries produced here line up exactly with what pass 2 will consult.
pub(crate) fn extract_ssa_artifacts_from_file_cfg(
    file_cfg: &FileCfg,
    lang: Lang,
    namespace: &str,
    local_summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    locator: Option<&crate::summary::SinkSiteLocator<'_>>,
) -> (SsaArtifactSummaries, EligibleCalleeBodies) {
    let (summaries, bodies) = lower_all_functions_from_bodies(
        file_cfg,
        lang,
        namespace,
        local_summaries,
        global_summaries,
        locator,
    );
    let eligible_bodies = build_eligible_bodies(file_cfg, bodies);
    (summaries, eligible_bodies)
}

/// Filter pre-lowered SSA bodies down to the cross-file-eligible subset and
/// populate per-node metadata against the original CFG.
///
/// Split out from [`extract_ssa_artifacts_from_file_cfg`] so callers that
/// already hold a freshly-lowered `bodies` map (specifically
/// `analyse_file_fused`, which now lowers once and feeds both the taint
/// engine and this filter) don't pay for a second lowering pass.
pub(crate) fn build_eligible_bodies(
    file_cfg: &FileCfg,
    bodies: std::collections::HashMap<FuncKey, ssa_transfer::CalleeSsaBody>,
) -> EligibleCalleeBodies {
    let mut eligible_bodies = Vec::new();
    if crate::symex::cross_file_symex_enabled() {
        for (key, mut body) in bodies {
            if body.ssa.blocks.len() > MAX_CROSS_FILE_BODY_BLOCKS {
                continue;
            }
            // Populate node metadata against the per-body graph whose NodeIndex
            // space the SSA was produced on, otherwise cross-file replay can't
            // find the original CFG nodes.
            //
            // `key.namespace` was already normalised against `scan_root` in
            // `lower_all_functions_from_bodies`; `body.meta.func_key.namespace`
            // still carries the raw `build_cfg` file path.  Compare on
            // structural identity (everything *but* namespace) so the two
            // agree even when the namespace representations differ.
            let Some(body_cfg) = file_cfg.bodies.iter().find(|b| {
                b.meta.func_key.as_ref().is_some_and(|k| {
                    k.lang == key.lang
                        && k.container == key.container
                        && k.name == key.name
                        && k.arity == key.arity
                        && k.disambig == key.disambig
                        && k.kind == key.kind
                })
            }) else {
                continue;
            };
            if !ssa_transfer::populate_node_meta(&mut body, &body_cfg.graph) {
                continue;
            }
            eligible_bodies.push((key, body));
        }
    }
    eligible_bodies
}

#[cfg(test)]
mod tests;
