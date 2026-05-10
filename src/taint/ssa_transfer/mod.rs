#![allow(
    clippy::collapsible_if,
    clippy::if_same_then_else,
    clippy::manual_flatten,
    clippy::needless_range_loop,
    clippy::only_used_in_recursion,
    clippy::single_match,
    clippy::too_many_arguments,
    clippy::unnecessary_map_or
)]

mod events;
mod inline;
mod state;
mod summary_extract;

#[cfg(test)]
mod tests;

pub use events::{SsaTaintEvent, ssa_events_to_findings};
pub(crate) use inline::{ArgTaintSig, InlineCache};
use inline::{CachedInlineShape, InlineResult, MAX_INLINE_BLOCKS, ReturnShape};
pub use inline::{CalleeSsaBody, CrossFileNodeMeta, populate_node_meta, rebuild_body_graph};
#[allow(unused_imports)] // retained for future shared-cache refactor / tests
pub(crate) use inline::{inline_cache_clear_epoch, inline_cache_fingerprint};
pub use state::{
    BindingKey, SsaTaintState, max_worklist_iterations, origins_truncation_count,
    reset_all_validated_spans, reset_origins_observability, reset_path_safe_suppressed_spans,
    reset_worklist_observability, seed_lookup, set_max_origins_override, set_worklist_cap_override,
    take_all_validated_spans, take_path_safe_suppressed_spans, worklist_cap_hit_count,
};
use state::{
    MAX_WORKLIST_ITERATIONS, ORIGINS_TRUNCATION_COUNT, WORKLIST_CAP_HITS, effective_max_origins,
    effective_worklist_cap,
};
pub(crate) use state::{
    push_origin_bounded, record_engine_note, reset_body_engine_notes, take_body_engine_notes,
};
pub use summary_extract::{extract_ssa_func_summary, extract_ssa_func_summary_full};

use crate::abstract_interp::AbstractState;
use crate::callgraph::{callee_container_hint, callee_leaf_name};
use crate::cfg::{BodyId, Cfg, FuncSummaries, NodeInfo};
use crate::constraint;
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule, SourceKind};
use crate::ssa::heap::{HeapObjectId, HeapSlot, PointsToResult, PointsToSet};
use crate::ssa::ir::*;
use crate::ssa::type_facts::InputValidatorPolarity;
use crate::state::lattice::Lattice;
use crate::state::symbol::SymbolInterner;
use crate::summary::{CalleeQuery, CalleeResolution, GlobalSummaries, SinkSite};
use crate::symbol::{FuncKey, Lang};
use crate::taint::domain::{PredicateSummary, TaintOrigin, VarTaint, predicate_kind_bit};
use crate::taint::path_state::{PredicateKind, classify_condition_with_target};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

// ── SSA Taint Transfer ──────────────────────────────────────────────────

/// Configuration for SSA taint analysis.
pub struct SsaTaintTransfer<'a> {
    pub lang: Lang,
    pub namespace: &'a str,
    pub interner: &'a SymbolInterner,
    pub local_summaries: &'a FuncSummaries,
    pub global_summaries: Option<&'a GlobalSummaries>,
    pub interop_edges: &'a [InteropEdge],
    /// The [`BodyId`] of the body currently being analysed.  Used as the
    /// owning scope when writing seed entries that leave this body
    /// (e.g. [`extract_ssa_exit_state`]) and as the identity recorded on
    /// engine notes.  Defaults to `BodyId(0)` (top-level) for inline
    /// probes and unit tests that analyse a single synthetic body.
    pub owner_body_id: BodyId,
    /// The [`BodyId`] of this body's lexical parent, if any.  Drives the
    /// `Param`-op reader's lookup into [`Self::global_seed`]: we read
    /// from the parent's scope first (the seed entries produced by
    /// [`extract_ssa_exit_state`] on the parent body), then fall back to
    /// `BodyId(0)` to pick up JS/TS two-level re-keyed entries (see
    /// [`filter_seed_to_toplevel`]).  `None` for the top-level body and
    /// for probes with no surrounding scope.
    pub parent_body_id: Option<BodyId>,
    /// Taint from enclosing/parent body scope, keyed by [`BindingKey`].
    /// Read-only fallback for `Param` ops representing captured or
    /// module-scope variables.  Used in multi-body analysis for lexical
    /// containment propagation (top-level → function → closure).
    pub global_seed: Option<&'a HashMap<BindingKey, VarTaint>>,
    /// Per-call-site parameter seed for context-sensitive inline
    /// analysis.  Indexed by callee's formal [`SsaOp::Param`] index: a
    /// `Some(taint)` at index `i` seeds the callee's formal param `i`
    /// with the caller's argument taint.  Out-of-range indices (e.g.
    /// synthetic capture params emitted by scoped lowering) fall back
    /// to [`Self::global_seed`].
    pub param_seed: Option<&'a [Option<VarTaint>]>,
    /// Per-call-site receiver seed for context-sensitive inline
    /// analysis.  Mirrors [`Self::param_seed`] for [`SsaOp::SelfParam`]
    /// reads, seeds the callee's implicit `this` / `self` slot with
    /// the caller's method-receiver taint.
    pub receiver_seed: Option<&'a VarTaint>,
    /// Per-SSA-value constant lattice from constant propagation.
    /// Used for SSA-level literal suppression at sinks.
    pub const_values: Option<&'a HashMap<SsaValue, crate::ssa::const_prop::ConstLattice>>,
    /// Type facts from type analysis.
    /// Used for type-aware sink filtering (e.g., suppress SQL injection for int-typed values).
    pub type_facts: Option<&'a crate::ssa::type_facts::TypeFactResult>,
    /// XML-parser config facts. Used to suppress XXE bits at parse-class
    /// sinks whose receiver was provably hardened
    /// (`setFeature(FEATURE_SECURE_PROCESSING, true)`, etc.).  Strictly
    /// additive: `None` falls back to the existing flat / gated XXE
    /// classification.
    pub xml_parser_config: Option<&'a crate::ssa::xml_config::XmlParserConfigResult>,
    /// XPath-receiver config facts.  Used to suppress XPATH_INJECTION at
    /// `evaluate` / `compile` sinks whose receiver was provably bound to
    /// an `XPathVariableResolver` (parameterised-XPath shape).  Strictly
    /// additive: `None` falls back to the existing flat / gated XPATH
    /// classification.
    pub xpath_config: Option<&'a crate::ssa::xpath_config::XPathConfigResult>,
    /// Precise per-function SSA summaries for intra-file callee resolution.
    /// Checked before legacy FuncSummary resolution.
    ///
    /// Keyed by canonical [`FuncKey`], never bare function name, so
    /// same-name functions in the same file cannot silently overwrite one
    /// another.
    pub ssa_summaries: Option<&'a HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>>,
    /// Extra label rules from user config (custom sources/sanitizers/sinks).
    /// Used as fallback when `resolve_callee` finds no summary for an inner
    /// arg callee, so label-only sanitizers still reduce sink caps.
    pub extra_labels: Option<&'a [RuntimeLabelRule]>,
    /// Pre-lowered + optimized SSA bodies for intra-file functions.
    /// When present, enables context-sensitive inline analysis at call sites.
    ///
    /// Keyed by canonical [`FuncKey`] (same identity model as `ssa_summaries`).
    pub callee_bodies: Option<&'a HashMap<FuncKey, CalleeSsaBody>>,
    /// Cache for context-sensitive inline results. Uses `RefCell` for interior
    /// mutability (safe: k=1 depth limit prevents re-entrancy during borrow).
    pub(crate) inline_cache: Option<&'a RefCell<InlineCache>>,
    /// Base-variable alias groups for alias-aware sanitization propagation.
    /// When present, sanitization of `alias.field` also sanitizes `base.field`
    /// for all must-aliased base names.
    pub base_aliases: Option<&'a crate::ssa::alias::BaseAliasResult>,
    /// Current inline analysis depth (0 = top-level caller). When >= 1,
    /// inline analysis falls back to summary resolution (k=1 bound).
    pub context_depth: u8,
    /// Callback bindings: maps callee parameter name → resolved callee
    /// [`FuncKey`].
    ///
    /// Populated during inline analysis when the caller passes a function
    /// reference as an argument.  The value is a full `FuncKey` so that when
    /// the callee invokes the parameter the call resolves back to the exact
    /// same definition without re-entering bare-name lookup.
    pub callback_bindings: Option<&'a HashMap<String, FuncKey>>,
    /// Points-to analysis result: per-SSA-value abstract heap object sets.
    /// When present, container taint flows through heap objects instead of
    /// being merged directly into SSA values.
    pub points_to: Option<&'a PointsToResult>,
    /// Dynamic points-to set: populated at call sites by inter-procedural
    /// container identity propagation from `param_container_to_return` summaries.
    /// Uses `RefCell` for interior mutability (same pattern as `inline_cache`).
    pub dynamic_pts: Option<&'a RefCell<HashMap<SsaValue, PointsToSet>>>,
    /// Import alias bindings: local alias → (original name, module path).
    /// Used in `resolve_callee` to map aliased import names back to their
    /// original exported symbol before summary lookup.
    pub import_bindings: Option<&'a crate::cfg::ImportBindings>,
    /// Promisify alias bindings: `const alias = util.promisify(wrapped)` for
    /// JS/TS.  Used in `resolve_callee` so summary lookup for `alias(...)` falls
    /// back to `wrapped`'s summary.  Label-based sink/source detection is
    /// handled by a CFG post-pass that unions the wrapped callee's labels into
    /// every matching call-site's `info.taint.labels`.
    pub promisify_aliases: Option<&'a crate::cfg::PromisifyAliases>,
    /// Module aliases from `require()` calls: SSA value → possible module names.
    /// Used to resolve dynamic dispatch (e.g., `lib.request()` where
    /// `lib = require("http")`) for sink label matching.
    pub module_aliases: Option<&'a HashMap<SsaValue, smallvec::SmallVec<[String; 2]>>>,
    /// Static-map analysis result: SSA values whose concrete string value is
    /// provably bounded to a finite set of literals (e.g. the result of
    /// `map.get(x).unwrap_or("fallback")` over an all-literal-insert map).
    /// When present, seeded into [`AbstractState`] at entry so downstream sink
    /// suppression can clear command-injection findings whose payload is
    /// provably metacharacter-free.
    pub static_map: Option<&'a crate::ssa::static_map::StaticMapResult>,
    /// When `true`, JS/TS formal parameters whose names strongly imply user
    /// input (see [`crate::labels::is_js_ts_handler_param_name`]) are
    /// auto-seeded with a `UserInput` source on entry.  Defaults to `false`
    /// so summary probes and non-JS/TS pipelines keep their existing
    /// baseline-subtraction semantics; the findings pipeline flips this on
    /// to detect handler-style flows that have no registered caller.
    pub auto_seed_handler_params: bool,
    /// Cross-file callee bodies sourced from
    /// [`GlobalSummaries`].  Populated in pass 2 to enable
    /// context-sensitive inline re-analysis across file boundaries the
    /// same way `callee_bodies` enables it intra-file.  `None` preserves
    /// non-cross-file behaviour for unit tests and non-cross-file
    /// construction sites.
    pub cross_file_bodies: Option<&'a HashMap<FuncKey, CalleeSsaBody>>,
    /// per-body field-sensitive points-to facts.
    /// Populated only when [`crate::pointer::is_enabled()`].  When
    /// present, [`SsaOp::FieldProj`] reads consult
    /// [`SsaTaintState::field_taint`] for each `loc ∈ pt(receiver)`,
    /// unioning the field-cell taint into the projected value.  Field
    /// writes (synthetic base-update [`SsaOp::Assign`] instructions
    /// emitted by SSA lowering) likewise record argument taint into
    /// the matching cells.  Strict-additive: `None` reproduces today's
    /// pointer-unaware behaviour.
    pub pointer_facts: Option<&'a crate::pointer::PointsToFacts>,
    /// Phase-09 cross-package import lookup: maps the caller-file's local
    /// binding name (e.g. `escapeHtml`) to the canonical [`FuncKey`] of
    /// the imported function in its own package's namespace.
    ///
    /// Populated by [`crate::taint::build_cross_package_func_keys`] from
    /// each file's [`crate::cfg::FileCfg::resolved_imports`] before pass-2
    /// taint analysis. Consumed by `resolve_callee_full` at step 0.7 to
    /// look up the cross-package callee's SSA summary directly via
    /// [`crate::summary::GlobalSummaries::get_ssa`].
    ///
    /// `None` (or empty map) when the file has no resolver-resolved
    /// imports (non-JS/TS, no `ModuleGraph`, no resolved package boundary).
    /// In that case step 0.7 is a no-op and resolution falls through to
    /// the existing flat-name paths.
    pub cross_package_imports: Option<&'a HashMap<String, FuncKey>>,
    /// Phase-10 Next.js entry-point classification for the body
    /// currently under analysis.  When `Some(_)`, every formal
    /// [`SsaOp::Param`] in the entry block is seeded with
    /// `Cap::all()` taint and a `TaintOrigin` whose
    /// [`SourceKind`] is derived from the entry kind, mirroring an
    /// HTTP request handler's adversary-controlled inputs.  `None`
    /// preserves today's per-callsite seeding (`global_seed`,
    /// `param_seed`, `auto_seed_handler_params`).
    pub entry_kind: Option<crate::entry_points::EntryKind>,
}

/// Per-predecessor state tracking for path-sensitive phi evaluation.
/// Maps (successor_block_idx, predecessor_block_idx) → predecessor's exit state.
type PredStates = HashMap<(usize, usize), SsaTaintState>;

struct SsaTaintRunResult {
    events: Vec<SsaTaintEvent>,
    block_states: Vec<Option<SsaTaintState>>,
    block_exit_states: Vec<Option<SsaTaintState>>,
}

/// Run SSA-based taint analysis, returning events AND converged block states.
pub fn run_ssa_taint_full(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> (Vec<SsaTaintEvent>, Vec<Option<SsaTaintState>>) {
    let result = run_ssa_taint_internal(ssa, cfg, transfer);
    (result.events, result.block_states)
}

/// Run SSA-based taint analysis, returning events plus converged entry and
/// exit states for each block. Intended for debug/introspection views.
pub fn run_ssa_taint_full_with_exits(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> (
    Vec<SsaTaintEvent>,
    Vec<Option<SsaTaintState>>,
    Vec<Option<SsaTaintState>>,
) {
    let result = run_ssa_taint_internal(ssa, cfg, transfer);
    (result.events, result.block_states, result.block_exit_states)
}

fn run_ssa_taint_internal(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> SsaTaintRunResult {
    let num_blocks = ssa.blocks.len();

    // Detect induction variables before analysis
    let back_edges = detect_back_edges(ssa);
    let induction_vars = detect_induction_phis(ssa, &back_edges);

    // Per-block entry states
    let mut block_states: Vec<Option<SsaTaintState>> = vec![None; num_blocks];
    let mut block_exit_states: Vec<Option<SsaTaintState>> = vec![None; num_blocks];
    block_states[ssa.entry.0 as usize] = Some(SsaTaintState::initial());

    // Phase 10 + Phase 16 — entry-point parameter seeding.  When the
    // body under analysis is a recognised framework entry (Next.js,
    // Express, Django, FastAPI, Flask, Spring, JAX-RS, Rails, Sinatra,
    // axum, actix-web, rocket, net/http, gin, ...), seed the relevant
    // formal `Param` operations in the entry block with `Cap::all()` and
    // a `TaintOrigin::UserInput` so the engine treats request-bound
    // inputs as adversary-controlled without waiting for a caller-side
    // flow.  Per-variant policy below selects which formals to seed:
    // most variants seed every named formal; Express seeds only the
    // first (`req`); `net/http` seeds only the second (`r` after `w`);
    // class-method shapes (Django CBV) skip implicit `self`.
    if let (Some(entry_kind), Some(state)) = (
        transfer.entry_kind.as_ref(),
        block_states[ssa.entry.0 as usize].as_mut(),
    ) {
        use crate::entry_points::EntryKind;
        let source_kind = SourceKind::UserInput;
        // (skip_self_param, only_param_index, seed_at_all) —
        // `only_param_index = Some(i)` restricts seeding to the `i`-th
        // non-self formal Param op (counted in SSA insertion order).
        // `None` seeds every Param.  `seed_at_all = false` skips seeding
        // entirely; the engine relies on existing label rules instead.
        let (skip_self, only_index, seed_at_all): (bool, Option<usize>, bool) = match entry_kind {
            // Pure Param-only handlers, all named formals are request-bound.
            EntryKind::AppRouteHandler { .. }
            | EntryKind::UseServerDirective
            | EntryKind::FormAction
            | EntryKind::FastApiRoute { .. }
            | EntryKind::FlaskRoute { .. }
            | EntryKind::SpringMapping { .. }
            | EntryKind::JaxRsResource
            | EntryKind::SinatraRoute { .. }
            | EntryKind::AxumHandler
            | EntryKind::ActixHandler
            | EntryKind::RocketRoute
            | EntryKind::GinRoute => (true, None, true),
            // Class-method shapes — `self` is the controller instance,
            // not adversary input.
            EntryKind::DjangoView { .. } | EntryKind::RailsAction => (true, None, true),
            // Express handler `(req, res, next)` — `req.body` /
            // `req.query` / `req.params` / `req.headers` already classify
            // as Source via the JS label rules shipped before phase 16,
            // so the SSA engine sees user input via member-access paths
            // without needing a flat `req` seed.  Seeding `req` itself
            // as `Source(Cap::all())` adds nothing for those flows but
            // re-fires every excluded `req.session.*` / `req.app.*`
            // lifecycle method as a structural sink (FP regression in
            // `session_destroy_safe.js` /
            // `session_destroy_with_query.js`).  Skip seeding for
            // Express; the existing label rules carry the request.
            EntryKind::ExpressRoute { .. } => (true, Some(0), false),
            // net/http `(w http.ResponseWriter, r *http.Request)` —
            // only `r` carries adversary bytes.
            EntryKind::GoNetHttp => (true, Some(1), true),
        };
        let entry_block = &ssa.blocks[ssa.entry.0 as usize];
        for inst in entry_block.phis.iter().chain(entry_block.body.iter()) {
            if !seed_at_all {
                continue;
            }
            let (is_self, param_index) = match &inst.op {
                SsaOp::SelfParam => (true, None),
                SsaOp::Param { index } => (false, Some(*index)),
                _ => continue,
            };
            if skip_self && is_self {
                continue;
            }
            if ssa.synthetic_externals.contains(&inst.value) {
                continue;
            }
            let seed_this = match (only_index, param_index) {
                (Some(want), Some(idx)) => idx == want,
                (Some(_), None) => false,
                (None, _) => true,
            };
            if !seed_this {
                continue;
            }
            let origin = TaintOrigin {
                node: inst.cfg_node,
                source_kind,
                source_span: None,
            };
            state.set(
                inst.value,
                VarTaint {
                    caps: Cap::all(),
                    origins: SmallVec::from_elem(origin, 1),
                    uses_summary: false,
                },
            );
        }
    }

    // Seed entry block's PathEnv from optimization results
    if let Some(ref mut entry_state) = block_states[ssa.entry.0 as usize] {
        if let Some(ref mut env) = entry_state.path_env {
            if let (Some(cv), Some(tf)) = (transfer.const_values, transfer.type_facts) {
                env.seed_from_optimization(cv, tf);
            }
        }
    }

    // Seed entry block's AbstractState from optimization results
    if let Some(ref mut entry_state) = block_states[ssa.entry.0 as usize] {
        if let Some(ref mut abs) = entry_state.abstract_state {
            if let Some(cv) = transfer.const_values {
                use crate::abstract_interp::{
                    AbstractValue, BitFact, IntervalFact, PathFact, StringFact,
                };
                use crate::ssa::const_prop::ConstLattice;
                for (v, cl) in cv {
                    match cl {
                        ConstLattice::Int(n) => {
                            abs.set(
                                *v,
                                AbstractValue {
                                    interval: IntervalFact::exact(*n),
                                    string: StringFact::top(),
                                    bits: BitFact::from_const(*n),
                                    path: PathFact::top(),
                                },
                            );
                        }
                        ConstLattice::Str(s) => {
                            abs.set(
                                *v,
                                AbstractValue {
                                    interval: IntervalFact::top(),
                                    string: StringFact::exact(s),
                                    bits: BitFact::top(),
                                    path: PathFact::top(),
                                },
                            );
                        }
                        _ => {}
                    }
                }
            }
            // Static-map seeding is intentionally NOT fused into the
            // AbstractState here.  A blanket `StringFact::finite_set` would
            // compose with `StringFact::exact` facts emitted by
            // `transfer_abstract` for every string literal, and downstream
            // suppression logic can't distinguish "single-literal exact"
            // from "multi-literal bounded lookup".  Instead the sink check
            // consults `transfer.static_map` directly via the dedicated
            // `is_static_map_shell_safe` predicate, which only fires when
            // the value was proved bounded by the HashMap idiom detector.
        }
    }

    // Compute loop heads for widening
    let loop_heads: HashSet<usize> = back_edges
        .iter()
        .map(|(_, target)| target.0 as usize)
        .collect();

    // Per-predecessor exit states for path-sensitive phi evaluation
    let mut pred_states: PredStates = HashMap::new();

    // Fixed-point iteration
    let mut worklist: VecDeque<usize> = VecDeque::new();
    let mut in_worklist: HashSet<usize> = HashSet::new();
    worklist.push_back(ssa.entry.0 as usize);
    in_worklist.insert(ssa.entry.0 as usize);

    // Initialize orphan blocks (no predecessors, not entry) with initial state.
    // This handles catch blocks that are disconnected after exception edge stripping.
    for (bid, block) in ssa.blocks.iter().enumerate() {
        if bid != ssa.entry.0 as usize && block.preds.is_empty() {
            block_states[bid] = Some(SsaTaintState::initial());
            worklist.push_back(bid);
            in_worklist.insert(bid);
        }
    }
    if !ssa.exception_edges.is_empty() {
        tracing::debug!(
            count = ssa.exception_edges.len(),
            "SSA taint: exception edges for catch-block seeding"
        );
    }
    let mut iterations: usize = 0;
    let budget = effective_worklist_cap();
    let mut worklist_capped = false;

    while let Some(bid) = worklist.pop_front() {
        in_worklist.remove(&bid);
        iterations += 1;
        if iterations >= budget {
            tracing::warn!("SSA taint: worklist budget exceeded");
            worklist_capped = true;
            break;
        }

        let entry_state = match &block_states[bid] {
            Some(s) => s.clone(),
            None => continue,
        };

        let block = &ssa.blocks[bid];
        let exit_state = transfer_block(
            block,
            cfg,
            ssa,
            transfer,
            entry_state,
            &induction_vars,
            Some(&pred_states),
        );
        block_exit_states[bid] = Some(exit_state.clone());

        // Build per-successor states (branch-aware for Branch terminators)
        let succ_states = compute_succ_states(block, cfg, ssa, transfer, &exit_state);

        // Store predecessor-specific states before joining
        for &(succ_id, ref succ_state) in &succ_states {
            let succ_idx = succ_id.0 as usize;
            pred_states.insert((succ_idx, bid), succ_state.clone());
        }

        // Propagate to successors
        for (succ_id, succ_state) in succ_states {
            let succ_idx = succ_id.0 as usize;

            let new_succ_state = match &block_states[succ_idx] {
                Some(existing) => {
                    let mut joined = existing.join(&succ_state);
                    // Widen abstract values at loop heads
                    if loop_heads.contains(&succ_idx) {
                        if let (Some(new_abs), Some(old_abs)) =
                            (&joined.abstract_state, &existing.abstract_state)
                        {
                            let widened = old_abs.widen(new_abs);
                            joined.abstract_state = Some(widened);
                        }
                    }
                    joined
                }
                None => succ_state,
            };

            let changed = block_states[succ_idx]
                .as_ref()
                .is_none_or(|existing| *existing != new_succ_state);

            if changed {
                block_states[succ_idx] = Some(new_succ_state);
                if in_worklist.insert(succ_idx) {
                    worklist.push_back(succ_idx);
                }
            }
        }

        // Propagate taint to catch blocks via exception edges.
        // Mirrors legacy semantics: variable taint carries across exception
        // edges but predicates are cleared (exception bypasses try conditions).
        let bid_id = BlockId(bid as u32);
        for &(src_blk, catch_blk) in &ssa.exception_edges {
            if src_blk != bid_id {
                continue;
            }
            let catch_idx = catch_blk.0 as usize;
            let mut exc_state = exit_state.clone();
            exc_state.predicates.clear();
            exc_state.path_env = None; // constraints don't survive exceptions

            let new_catch_state = match &block_states[catch_idx] {
                Some(existing) => existing.join(&exc_state),
                None => exc_state,
            };

            let changed = block_states[catch_idx]
                .as_ref()
                .is_none_or(|existing| *existing != new_catch_state);

            if changed {
                block_states[catch_idx] = Some(new_catch_state);
                if in_worklist.insert(catch_idx) {
                    worklist.push_back(catch_idx);
                }
            }
        }
    }

    MAX_WORKLIST_ITERATIONS.fetch_max(iterations, std::sync::atomic::Ordering::Relaxed);
    if worklist_capped {
        WORKLIST_CAP_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        record_engine_note(crate::engine_notes::EngineNote::WorklistCapped {
            iterations: iterations as u32,
        });
    }

    // Post-hoc origin-truncation detection.  If any converged block state
    // has a `VarTaint` whose origin list reached the cap, assume at least
    // one origin was dropped during the fixed-point iteration.  Coarse
    // but useful signal, `merge_origins` already emits the precise-count
    // note on the merge path; this complements push sites inside transfer.
    let cap = effective_max_origins();
    let mut saturated = 0u32;
    for state in block_states.iter().flatten() {
        for (_v, taint) in &state.values {
            if taint.origins.len() >= cap {
                saturated = saturated.saturating_add(1);
            }
        }
    }
    if saturated > 0 {
        ORIGINS_TRUNCATION_COUNT
            .fetch_add(saturated as usize, std::sync::atomic::Ordering::Relaxed);
        record_engine_note(crate::engine_notes::EngineNote::OriginsTruncated {
            dropped: saturated,
        });
    }

    // Single pass over converged states to collect events
    let mut events: Vec<SsaTaintEvent> = Vec::new();

    for bid in 0..num_blocks {
        let entry_state = match &block_states[bid] {
            Some(s) => s.clone(),
            None => continue,
        };

        let block = &ssa.blocks[bid];
        collect_block_events(
            block,
            cfg,
            ssa,
            transfer,
            entry_state,
            &mut events,
            &induction_vars,
            Some(&pred_states),
        );
    }

    SsaTaintRunResult {
        events,
        block_states,
        block_exit_states,
    }
}

/// Convenience wrapper: returns only events (existing signature).
pub fn run_ssa_taint(ssa: &SsaBody, cfg: &Cfg, transfer: &SsaTaintTransfer) -> Vec<SsaTaintEvent> {
    run_ssa_taint_full(ssa, cfg, transfer).0
}

/// Project SsaValue-keyed taint back to [`BindingKey`]-keyed taint via var_name.
///
/// Recomputes exit states from converged entry states, then maps
/// SsaValue → var_name → `BindingKey`.  The returned map is suitable
/// for seeding child bodies via `global_seed`.
///
/// `owner_body_id` is the id of the body being summarised; it tags
/// every key via [`BindingKey::new`] so that same-named bindings from
/// different bodies do not silently alias when the seed is later
/// merged (e.g. in the JS/TS two-level solve).
pub fn extract_ssa_exit_state(
    block_states: &[Option<SsaTaintState>],
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
    owner_body_id: BodyId,
) -> HashMap<BindingKey, VarTaint> {
    // Compute exit states by replaying transfer on converged entry states
    let empty_induction = HashSet::new();
    let mut joined = SsaTaintState::initial();
    for (bid, entry_state) in block_states.iter().enumerate() {
        if let Some(state) = entry_state {
            let exit_state = transfer_block(
                &ssa.blocks[bid],
                cfg,
                ssa,
                transfer,
                state.clone(),
                &empty_induction,
                None,
            );
            joined = joined.join(&exit_state);
        }
    }

    // Map SsaValue → var_name → BindingKey, scoped to the owning body.
    let mut result: HashMap<BindingKey, VarTaint> = HashMap::new();
    for (val, taint) in &joined.values {
        let var_name = ssa
            .value_defs
            .get(val.0 as usize)
            .and_then(|vd| vd.var_name.as_deref());
        if let Some(name) = var_name {
            let key = BindingKey::new(name, owner_body_id);
            result
                .entry(key)
                .and_modify(|existing| {
                    existing.caps |= taint.caps;
                    for orig in &taint.origins {
                        push_origin_bounded(&mut existing.origins, *orig);
                    }
                })
                .or_insert_with(|| taint.clone());
        }
    }

    // Capture source spans on all origins before the seed crosses a body
    // boundary.  At consumption time the parent's graph is not in scope,
    // so we snapshot each origin's span now.  Use the classification span
    // so the recorded origin points at the labeled sub-expression (e.g.
    // the inner `req.query.x` call) rather than the enclosing statement.
    for taint in result.values_mut() {
        for origin in taint.origins.iter_mut() {
            if origin.source_span.is_none() {
                if let Some(info) = cfg.node_weight(origin.node) {
                    origin.source_span = Some(info.classification_span());
                }
            }
        }
    }

    result
}

/// Join two [`BindingKey`]-keyed seed maps (OR caps, merge origins).
pub fn join_seed_maps(
    a: &HashMap<BindingKey, VarTaint>,
    b: &HashMap<BindingKey, VarTaint>,
) -> HashMap<BindingKey, VarTaint> {
    let mut result = a.clone();
    for (key, taint) in b {
        result
            .entry(key.clone())
            .and_modify(|existing| {
                existing.caps |= taint.caps;
                for orig in &taint.origins {
                    push_origin_bounded(&mut existing.origins, *orig);
                }
            })
            .or_insert_with(|| taint.clone());
    }
    result
}

/// Filter a per-body exit seed map down to the top-level scope.
///
/// `toplevel` is the set of binding names that appear syntactically at
/// the top level (always keyed with `BodyId(0)`).  Every matching entry
/// in `seed` is kept but **re-keyed** to `BodyId(0)` so the resulting
/// map is single-scope: same-name entries from different bodies merge
/// via the normal OR-and-push-origins path in
/// [`join_seed_maps`] instead of coexisting as distinct keys.
///
/// This is the one legitimate place where a binding's owning scope
/// changes: the JS/TS two-level solve joins exit states from many
/// sibling function bodies into a single `combined_exit`, and each
/// sibling's surviving bindings conceptually belong to the top-level
/// scope they all write into.  Every other writer in the pipeline
/// preserves the owner's id.
pub fn filter_seed_to_toplevel(
    seed: &HashMap<BindingKey, VarTaint>,
    toplevel: &HashSet<BindingKey>,
) -> HashMap<BindingKey, VarTaint> {
    let toplevel_names: HashSet<&str> = toplevel.iter().map(|k| k.name.as_str()).collect();
    let mut out: HashMap<BindingKey, VarTaint> = HashMap::new();
    for (key, taint) in seed.iter() {
        if !toplevel_names.contains(key.name.as_str()) {
            continue;
        }
        let rekeyed = BindingKey::new(key.name.clone(), BodyId(0));
        out.entry(rekeyed)
            .and_modify(|existing| {
                existing.caps |= taint.caps;
                for orig in &taint.origins {
                    push_origin_bounded(&mut existing.origins, *orig);
                }
                existing.uses_summary |= taint.uses_summary;
            })
            .or_insert_with(|| taint.clone());
    }
    out
}

// ── Loop Induction Variable Detection ────────────────────────────────────

/// Detect back edges using block numbering heuristic.
/// A back edge is (pred, block) where pred.0 >= block.0, valid because
/// `form_blocks()` builds blocks in BFS order.
fn detect_back_edges(ssa: &SsaBody) -> HashSet<(BlockId, BlockId)> {
    let mut back_edges = HashSet::new();
    for block in &ssa.blocks {
        for &pred in &block.preds {
            if pred.0 >= block.id.0 {
                back_edges.insert((pred, block.id));
            }
        }
    }
    back_edges
}

/// Check if `inc_val` is defined as a simple increment of `phi_val`:
/// `inc_val = phi_val + const` or `inc_val = phi_val - const`.
fn is_simple_increment(ssa: &SsaBody, inc_val: SsaValue, phi_val: SsaValue) -> bool {
    let def = ssa.def_of(inc_val);
    let block = ssa.block(def.block);
    // Look in the block body for the defining instruction
    for inst in &block.body {
        if inst.value == inc_val {
            if let SsaOp::Assign(ref uses) = inst.op {
                // Pattern: assign([phi_val, const_val]), simple binary op
                if uses.len() == 2 && uses.contains(&phi_val) {
                    let other = if uses[0] == phi_val { uses[1] } else { uses[0] };
                    // Check if the other operand is a constant
                    let other_def = ssa.def_of(other);
                    let other_block = ssa.block(other_def.block);
                    for other_inst in other_block.phis.iter().chain(other_block.body.iter()) {
                        if other_inst.value == other && matches!(other_inst.op, SsaOp::Const(_)) {
                            return true;
                        }
                    }
                }
            }
            break;
        }
    }
    false
}

/// Detect phi nodes that represent loop induction variables.
/// Returns the set of SsaValues (phi results) that are simple induction variables.
fn detect_induction_phis(
    ssa: &SsaBody,
    back_edges: &HashSet<(BlockId, BlockId)>,
) -> HashSet<SsaValue> {
    let mut induction_vars = HashSet::new();

    for block in &ssa.blocks {
        for phi in &block.phis {
            if let SsaOp::Phi(ref operands) = phi.op {
                if operands.len() != 2 {
                    continue;
                }

                // Identify which operand comes via back edge
                let mut back_edge_op = None;
                let mut init_op = None;
                for &(pred_blk, operand_val) in operands {
                    if back_edges.contains(&(pred_blk, block.id)) {
                        back_edge_op = Some(operand_val);
                    } else {
                        init_op = Some(operand_val);
                    }
                }

                if let (Some(back_val), Some(_init_val)) = (back_edge_op, init_op) {
                    if is_simple_increment(ssa, back_val, phi.value) {
                        induction_vars.insert(phi.value);
                    }
                }
            }
        }
    }

    induction_vars
}

/// Transfer a single block: process phis then body, return exit state.
pub(super) fn transfer_block(
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    mut state: SsaTaintState,
    induction_vars: &HashSet<SsaValue>,
    pred_states: Option<&PredStates>,
) -> SsaTaintState {
    // Process phis
    let block_idx = block.id.0 as usize;
    for phi in &block.phis {
        if let SsaOp::Phi(ref operands) = phi.op {
            // Induction variable optimization: skip back-edge operands
            let is_induction = induction_vars.contains(&phi.value);

            let mut combined_caps = Cap::empty();
            let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            let mut all_tainted_validated = true;
            let mut any_tainted = false;

            for &(pred_blk, operand_val) in operands {
                // Skip back-edge operands for induction vars
                if is_induction && pred_blk.0 >= block.id.0 {
                    continue;
                }

                // Skip predecessor operands from infeasible paths
                if let Some(ps) = pred_states {
                    if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                        if pred_st.path_env.as_ref().is_some_and(|e| e.is_unsat()) {
                            continue;
                        }
                    }
                }

                // Use predecessor-specific state when available (path sensitivity)
                let operand_taint = if let Some(ps) = pred_states {
                    ps.get(&(block_idx, pred_blk.0 as usize))
                        .and_then(|pred_st| pred_st.get(operand_val))
                } else {
                    None
                };
                // Fall back to joined entry state
                let operand_taint = operand_taint.or_else(|| state.get(operand_val));

                if let Some(taint) = operand_taint {
                    any_tainted = true;
                    combined_caps |= taint.caps;
                    for orig in &taint.origins {
                        push_origin_bounded(&mut combined_origins, *orig);
                    }

                    // Path sensitivity: check if this operand is validated in its predecessor
                    if let Some(ps) = pred_states {
                        if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                            let var_name = ssa
                                .value_defs
                                .get(operand_val.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref());
                            if let Some(name) = var_name {
                                if let Some(sym) = transfer.interner.get(name) {
                                    if !pred_st.validated_must.contains(sym) {
                                        all_tainted_validated = false;
                                    }
                                } else {
                                    all_tainted_validated = false;
                                }
                            } else {
                                all_tainted_validated = false;
                            }
                        } else {
                            all_tainted_validated = false;
                        }
                    } else {
                        all_tainted_validated = false;
                    }
                }
            }

            if combined_caps.is_empty() {
                state.remove(phi.value);
            } else {
                state.set(
                    phi.value,
                    VarTaint {
                        caps: combined_caps,
                        origins: combined_origins,
                        uses_summary: false,
                    },
                );

                // Path sensitivity: if all tainted predecessors validated, propagate to phi result
                if any_tainted && all_tainted_validated {
                    if let Some(name) = ssa
                        .value_defs
                        .get(phi.value.0 as usize)
                        .and_then(|vd| vd.var_name.as_deref())
                    {
                        if let Some(sym) = transfer.interner.get(name) {
                            state.validated_may.insert(sym);
                            state.validated_must.insert(sym);
                        }
                    }
                }
            }
        }
    }

    // Abstract value phi join (from predecessor exit states)
    if state.abstract_state.is_some() {
        for phi in &block.phis {
            if let SsaOp::Phi(ref operands) = phi.op {
                use crate::abstract_interp::AbstractValue;
                let is_induction = induction_vars.contains(&phi.value);
                let mut joined = AbstractValue::bottom();
                let mut any_operand = false;

                for &(pred_blk, operand_val) in operands {
                    if is_induction && pred_blk.0 >= block.id.0 {
                        continue;
                    }
                    // Skip infeasible predecessors
                    if let Some(ps) = pred_states {
                        if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                            if pred_st.path_env.as_ref().is_some_and(|e| e.is_unsat()) {
                                continue;
                            }
                        }
                    }
                    // Look up operand abstract value from predecessor exit state
                    let pred_abs = pred_states
                        .and_then(|ps| ps.get(&(block_idx, pred_blk.0 as usize)))
                        .and_then(|s| s.abstract_state.as_ref())
                        .map(|a| a.get(operand_val))
                        .unwrap_or_else(AbstractValue::top);
                    joined = joined.join(&pred_abs);
                    any_operand = true;
                }

                if any_operand {
                    if let Some(ref mut abs) = state.abstract_state {
                        abs.set(phi.value, joined);
                    }
                }
            }
        }
    }

    // Process body
    for inst in &block.body {
        transfer_inst(inst, cfg, ssa, transfer, &mut state);
    }

    state
}

/// Compute per-successor states with branch-aware predicate handling.
///
/// For `Branch` terminators, inspects the condition node for validation/predicate
/// info and produces specialized true/false states. For other terminators,
/// propagates the exit state uniformly.
fn compute_succ_states(
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    exit_state: &SsaTaintState,
) -> SmallVec<[(BlockId, SsaTaintState); 2]> {
    match &block.terminator {
        Terminator::Branch {
            cond,
            true_blk,
            false_blk,
            condition,
        } => {
            // Defensive: `cond` should always be present in `cfg`, but cross-file
            // proxy CFGs synthesized in `rebuild_body_graph` previously missed
            // Branch.cond entries (now fixed above).  Falling through to uniform
            // propagation on a missing cond preserves liveness rather than
            // crashing the worker thread if a future regression re-introduces it.
            let Some(cond_info) = cfg.node_weight(*cond) else {
                return smallvec::smallvec![
                    (*true_blk, exit_state.clone()),
                    (*false_blk, exit_state.clone()),
                ];
            };
            if cond_info.kind == crate::cfg::StmtKind::If && !cond_info.condition_vars.is_empty() {
                let cond_text = cond_info.condition_text.as_deref().unwrap_or("");
                let (kind, target_var) = classify_condition_with_target(cond_text);

                // Determine which vars to apply validation to:
                // If we extracted a specific target, narrow to just that var
                // (if it's in condition_vars). Otherwise use all condition_vars.
                let effective_vars: Vec<String> = if let Some(ref target) = target_var {
                    if cond_info.condition_vars.iter().any(|v| v == target) {
                        vec![target.clone()]
                    } else {
                        cond_info.condition_vars.clone()
                    }
                } else {
                    cond_info.condition_vars.clone()
                };

                let mut true_state = exit_state.clone();
                let mut false_state = exit_state.clone();

                // Detect semantic negation that isn't captured by AST-level
                // `condition_negated` (which only detects unary `!`/`not`).
                //
                // - Python `not in`: comparison operator, not unary negation
                // - TypeCheck with `!==`/`!=`: "typeof x !== 'number'" means
                //   the true branch is the REJECT path (type mismatch)
                let cond_lower = cond_text.to_ascii_lowercase();
                let has_semantic_negation = (kind == PredicateKind::AllowlistCheck
                    && cond_lower.contains(" not in "))
                    || (kind == PredicateKind::TypeCheck
                        && (cond_lower.contains("!==") || cond_lower.contains("!=")));
                let effective_negated = if has_semantic_negation {
                    !cond_info.condition_negated
                } else {
                    cond_info.condition_negated
                };

                // True edge polarity: effective_negated XOR true
                let true_polarity = !effective_negated;
                let false_polarity = effective_negated;

                // Apply validation/predicate to true branch
                apply_branch_predicates(
                    &mut true_state,
                    &effective_vars,
                    kind,
                    true_polarity,
                    transfer.interner,
                    ssa,
                );
                // Apply validation/predicate to false branch
                apply_branch_predicates(
                    &mut false_state,
                    &effective_vars,
                    kind,
                    false_polarity,
                    transfer.interner,
                    ssa,
                );

                // PathFact branch narrowing, language-agnostic.  The
                // text-level rejection patterns recognised by
                // `classify_path_rejection_atom` cover the common idioms
                // across all 10 supported languages:
                //   * `.contains("..")` (Rust, Java, JS String) /
                //     `.includes("..")` (JS/TS) / `.include?("..")` (Ruby) /
                //     `strings.Contains(s, "..")` (Go) /
                //     `".." in s` (Python).
                //   * `.starts_with('/')` (Rust) /
                //     `.startsWith("/")` (JS/TS/Java) /
                //     `.startswith("/")` (Python) /
                //     `.start_with?("/")` (Ruby) /
                //     `strings.HasPrefix(s, "/")` (Go).
                //   * `.is_absolute()` / `.isAbsolute()` /
                //     `os.path.isabs(s)` / `filepath.IsAbs(s)`.
                //
                // Rust positive-assertion `prefix_lock` recognition still
                // fires regardless of language; for non-Rust languages the
                // assertion classifier returns `None` for unfamiliar shapes.
                apply_path_fact_branch_narrowing_with_interner(
                    &mut true_state,
                    &mut false_state,
                    cond_text,
                    &effective_vars,
                    ssa,
                    Some(transfer.interner),
                    effective_negated,
                );

                // Validation-call err-check narrowing.  When the condition
                // is an `err`-check (e.g. `if err != nil`) and `err` is the
                // result of a known value-producing validator
                // (`strconv.Atoi`, `parseInt`, etc.), mark the validator's
                // input argument(s) as validated on the success branch
                // (where `err` is null / `Ok` / no exception).  Mirrors the
                // ValidationCall pathway but for the two-statement
                // validation idiom common in Go:
                //   `_, err := strconv.Atoi(input); if err != nil { return }`
                // post-condition: input is provably a numeric string on the
                // surviving (`err == nil`) branch, so downstream sinks like
                // `db.Query("... " + input)` should suppress.
                if matches!(kind, PredicateKind::ErrorCheck) {
                    apply_validation_err_check_narrowing(
                        &mut true_state,
                        &mut false_state,
                        cond_text,
                        &cond_info.condition_vars,
                        ssa,
                        block.id,
                        transfer.interner,
                    );
                }

                // Generic input-validator branch narrowing.  Recognises the
                // two-statement idiom
                //   `const err = validate(x); if (err) throw …;`
                // (also `if (!isValid(x)) throw`), kinds the predicate
                // classifier returns Unknown / NullCheck / ErrorCheck for
                // because the if-condition is a bare result variable, not a
                // direct call expression.  The narrowing only fires when
                // the condition has exactly one variable and that
                // variable's reaching SSA def is a Call to a callee
                // recognised by `classify_input_validator_callee`.
                //
                // Motivated by Novu CVE GHSA-4x48-cgf9-q33f
                // (`const ssrfError = await validateUrlSsrf(child.webhookUrl);
                //   if (ssrfError) throw …;`).
                if matches!(
                    kind,
                    PredicateKind::Unknown | PredicateKind::NullCheck | PredicateKind::ErrorCheck
                ) {
                    apply_input_validator_branch_narrowing(
                        &mut true_state,
                        &mut false_state,
                        cond_text,
                        &cond_info.condition_vars,
                        ssa,
                        block.id,
                        transfer.interner,
                    );
                }

                // Constraint refinement
                //
                // `lower_condition` returns a ConditionExpr that represents the
                // full semantic condition (it already applies `condition_negated`
                // internally). The true branch is where the condition holds
                // (polarity=true), the false branch is where it doesn't
                // (polarity=false). We do NOT reuse `effective_negated` here ,
                // that variable incorporates `has_semantic_negation` which is a
                // predicate-system concern, not a constraint-system concern.
                if true_state.path_env.is_some() || false_state.path_env.is_some() {
                    // Prefer pre-lowered structured condition from terminator;
                    // fall back to text-based lowering for backward compat.
                    let cond_expr = if let Some(pre_lowered) = condition {
                        (**pre_lowered).clone()
                    } else {
                        constraint::lower_condition(cond_info, ssa, block.id, transfer.const_values)
                    };
                    if !matches!(cond_expr, constraint::ConditionExpr::Unknown) {
                        if let Some(ref mut env) = true_state.path_env {
                            *env = constraint::refine_env(env, &cond_expr, true);
                            if env.is_unsat() {
                                tracing::debug!(
                                    block = ?block.id,
                                    cond = cond_text,
                                    "constraint: pruned true branch (unsat)"
                                );
                            }
                        }
                        if let Some(ref mut env) = false_state.path_env {
                            *env = constraint::refine_env(env, &cond_expr, false);
                            if env.is_unsat() {
                                tracing::debug!(
                                    block = ?block.id,
                                    cond = cond_text,
                                    "constraint: pruned false branch (unsat)"
                                );
                            }
                        }
                    }
                }

                // Contradiction pruning.
                //
                // Two sources of contradiction:
                //   (a) `predicates`, a known_true and known_false bit
                //       set for the same predicate kind on the same
                //       symbol.  This is genuine: prior branches asserted
                //       conflicting truth values about the same predicate,
                //       so the joined branch is unreachable.  Reset the
                //       branch state to bot.
                //   (b) `path_env.is_unsat()`, the constraint solver's
                //       interval / nullability domain proved the branch
                //       infeasible.  Empirically the constraint refinement
                //       can over-prune branches whose feasibility hinges
                //       on data introduced by writeback / container ops
                //       (`err` from `dec.Decode(body)` becoming
                //       constraint-bounded only after the writeback's
                //       caps land on the destination).  In those cases
                //       resetting the data state to bot drops legitimate
                //       taint flow that travels through the surviving
                //       branch, see CVE-2024-31450's
                //       `if err := …Decode(emoji); err != nil { return }`
                //       shape.
                //
                // To preserve soundness without losing real flow, only
                // reset to bot when the contradiction is in `predicates`.
                // For path_env-only unsat, drop path_env (treat as Top
                // for downstream path-sensitive reasoning) and keep the
                // rest of the state, values, field_taint, heap,
                // predicates, validated_*, abstract_state.
                let true_pred_contra = true_state
                    .predicates
                    .iter()
                    .any(|(_, s)| s.has_contradiction());
                let false_pred_contra = false_state
                    .predicates
                    .iter()
                    .any(|(_, s)| s.has_contradiction());
                if true_pred_contra {
                    true_state = SsaTaintState::bot();
                } else if true_state.path_env.as_ref().is_some_and(|e| e.is_unsat()) {
                    true_state.path_env = None;
                }
                if false_pred_contra {
                    false_state = SsaTaintState::bot();
                } else if false_state.path_env.as_ref().is_some_and(|e| e.is_unsat()) {
                    false_state.path_env = None;
                }

                smallvec::smallvec![(*true_blk, true_state), (*false_blk, false_state),]
            } else {
                // Non-If condition or no condition vars, uniform propagation
                smallvec::smallvec![
                    (*true_blk, exit_state.clone()),
                    (*false_blk, exit_state.clone()),
                ]
            }
        }
        Terminator::Goto(_) => {
            // `block.succs` is authoritative. The terminator target records
            // the single logical successor (or the first of a collapsed
            // ≥3-way fanout, see src/ssa/lower.rs `three_successor_collapse`).
            // Propagating only the terminator target would drop flow to the
            // other successors; iterate `succs` instead so every downstream
            // block receives the exit state.
            block
                .succs
                .iter()
                .map(|s| (*s, exit_state.clone()))
                .collect()
        }
        Terminator::Switch { .. } => {
            // Switch: all targets and default receive the same input state.
            // Per-target branch narrowing would require per-case literal
            // metadata on the terminator (a follow-up); for now, uniform
            // propagation across `block.succs` preserves soundness.
            block
                .succs
                .iter()
                .map(|s| (*s, exit_state.clone()))
                .collect()
        }
        Terminator::Return(_) | Terminator::Unreachable => {
            // `block.succs` is authoritative for analysis flow; the terminator
            // is advisory.  Lowering records finally/cleanup continuation
            // edges on the try-body's succs even when the structured
            // terminator is `Return`/`Unreachable`.  Propagate the exit state
            // across those edges (determinism: iterate in stored order) so
            // downstream analysis sees the flow.  Empty `succs` preserves the
            // true-terminal fast path.
            block
                .succs
                .iter()
                .map(|s| (*s, exit_state.clone()))
                .collect()
        }
    }
}

/// Apply validation and predicate bits for a branch edge.
fn apply_branch_predicates(
    state: &mut SsaTaintState,
    condition_vars: &[String],
    kind: PredicateKind,
    polarity: bool,
    interner: &SymbolInterner,
    ssa: &SsaBody,
) {
    // Validation-like predicates: mark condition vars as validated when polarity is true
    if matches!(
        kind,
        PredicateKind::ValidationCall | PredicateKind::AllowlistCheck | PredicateKind::TypeCheck
    ) && polarity
    {
        for var in condition_vars {
            if let Some(sym) = interner.get(var) {
                state.validated_may.insert(sym);
                state.validated_must.insert(sym);
            }
        }
    }

    // RelativeUrlValidated: TRUE branch is the validated path
    // (`x.startsWith("/")` succeeded → `x` cannot redirect off-host).
    // Cap-aware: clear `Cap::OPEN_REDIRECT` only; non-redirect sinks
    // (XSS / SQLi / FILE_IO) downstream still fire on residual taint.
    if kind == PredicateKind::RelativeUrlValidated && polarity {
        for var in condition_vars {
            let mut to_clear: SmallVec<[SsaValue; 4]> = SmallVec::new();
            for (val, _) in state.values.iter() {
                if let Some(name) = ssa
                    .value_defs
                    .get(val.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    if name == var {
                        to_clear.push(*val);
                    }
                }
            }
            for val in to_clear {
                if let Some(taint) = state.get(val).cloned() {
                    let new_caps = taint.caps & !Cap::OPEN_REDIRECT;
                    if new_caps.is_empty() {
                        state.remove(val);
                    } else {
                        state.set(
                            val,
                            VarTaint {
                                caps: new_caps,
                                origins: taint.origins,
                                uses_summary: taint.uses_summary,
                            },
                        );
                    }
                }
            }
        }
    }

    // HostAllowlistValidated: TRUE branch is the validated path
    // (`new URL(x).host === ALLOWED` succeeded → `x` cannot redirect off-host).
    // Cap-aware: clear `Cap::OPEN_REDIRECT` only; non-redirect sinks downstream
    // still fire on the residual taint caps.  Mirrors the
    // `RelativeUrlValidated` handler exactly, the only difference is the
    // recogniser shape (multi-statement parse + host comparison instead of
    // inline leading-slash check).
    if kind == PredicateKind::HostAllowlistValidated && polarity {
        for var in condition_vars {
            let mut to_clear: SmallVec<[SsaValue; 4]> = SmallVec::new();
            for (val, _) in state.values.iter() {
                if let Some(name) = ssa
                    .value_defs
                    .get(val.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    if name == var {
                        to_clear.push(*val);
                    }
                }
            }
            for val in to_clear {
                if let Some(taint) = state.get(val).cloned() {
                    let new_caps = taint.caps & !Cap::OPEN_REDIRECT;
                    if new_caps.is_empty() {
                        state.remove(val);
                    } else {
                        state.set(
                            val,
                            VarTaint {
                                caps: new_caps,
                                origins: taint.origins,
                                uses_summary: taint.uses_summary,
                            },
                        );
                    }
                }
            }
        }
    }

    // ShellMetaValidated: inverted polarity, the FALSE branch (no metachar
    // found) is the validated path; the TRUE branch is the rejection path.
    //
    // Cap-aware: shell-metachar rejection only proves the value is safe for
    // shell-family sinks (it strips `;|&` etc.), not for SQL, path, code-exec,
    // SSRF, or other sink classes.  Clear `Cap::SHELL_ESCAPE` from the var's
    // taint on the validated branch instead of marking it generically
    // validated, so non-shell sinks downstream still fire on the residual
    // taint caps.
    if kind == PredicateKind::ShellMetaValidated && !polarity {
        for var in condition_vars {
            let mut to_clear: SmallVec<[SsaValue; 4]> = SmallVec::new();
            for (val, _) in state.values.iter() {
                if let Some(name) = ssa
                    .value_defs
                    .get(val.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    if name == var {
                        to_clear.push(*val);
                    }
                }
            }
            for val in to_clear {
                if let Some(taint) = state.get(val).cloned() {
                    let new_caps = taint.caps & !Cap::SHELL_ESCAPE;
                    if new_caps.is_empty() {
                        state.remove(val);
                    } else {
                        state.set(
                            val,
                            VarTaint {
                                caps: new_caps,
                                origins: taint.origins,
                                uses_summary: taint.uses_summary,
                            },
                        );
                    }
                }
            }
        }
    }

    // Whitelisted predicate kinds: update PredicateSummary bits
    if let Some(bit_idx) = predicate_kind_bit(kind) {
        for var in condition_vars {
            if let Some(sym) = interner.get(var) {
                let mut summary = state
                    .predicates
                    .binary_search_by_key(&sym, |(id, _)| *id)
                    .ok()
                    .map(|idx| state.predicates[idx].1)
                    .unwrap_or_else(PredicateSummary::empty);
                if polarity {
                    summary.known_true |= 1 << bit_idx;
                } else {
                    summary.known_false |= 1 << bit_idx;
                }
                match state.predicates.binary_search_by_key(&sym, |(id, _)| *id) {
                    Ok(idx) => state.predicates[idx].1 = summary,
                    Err(idx) => state.predicates.insert(idx, (sym, summary)),
                }
            }
        }
    }
}

/// Mark the input arguments of a value-producing validator as validated
/// on the success branch of a downstream `err`-check.
///
/// Recognised idiom (most idiomatic in Go):
///
/// ```text
/// _, err := strconv.Atoi(input)
/// if err != nil { return }
/// // → input is provably a valid integer string on the surviving branch
/// ```
///
/// Walks `cond_info.condition_vars` to locate the SSA value bound to the
/// condition's `err`/result variable, finds the SsaInst that defined that
/// value, and, if the defining op is a [`SsaOp::Call`] to a
/// [`crate::ssa::type_facts::is_int_producing_callee`], copies the call's
/// argument variable names into `validated_must` / `validated_may` on the
/// `err == null` branch.
///
/// The "success" branch direction is determined from `cond_text`:
///
/// * `err == nil` / `err == None` / `error == nil` / `is_ok()` → TRUE branch
/// * `err != nil` / `error != nil` / `is_err()`               → FALSE branch
///
/// Strict-additive: when the condition does not match the err-check shape,
/// the defining op is not a Call, the callee is not recognised as a
/// validator, or the arg has no SSA-level var_name to mark, the function
/// is a no-op.
fn apply_validation_err_check_narrowing(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    cond_text: &str,
    condition_vars: &[String],
    ssa: &SsaBody,
    block: BlockId,
    interner: &SymbolInterner,
) {
    if condition_vars.is_empty() {
        return;
    }
    // Determine which branch corresponds to "err is null / Ok / no error".
    // Defaults to FALSE for `err != nil`-style; flips to TRUE for
    // `err == nil`-style and `is_ok()`.
    let lower = cond_text.to_ascii_lowercase();
    let success_branch_is_true = lower.contains("== nil")
        || lower.contains("== none")
        || lower.contains("is none")
        || lower.contains("is_ok")
        || lower.contains("=== null")
        || lower.contains("== null");

    // Resolve `err`'s reaching SSA value (last def in this or earlier block).
    // We restrict to single-var conditions to avoid mis-attributing
    // validation when the condition mixes err and another variable
    // (e.g. `err != nil || other`).
    if condition_vars.len() != 1 {
        return;
    }
    let err_name = condition_vars[0].as_str();
    let err_val = match resolve_var_to_ssa_value(err_name, ssa, block) {
        Some(v) => v,
        None => return,
    };

    // Find the defining SsaInst.  Search across blocks because the
    // assignment might have happened in a predecessor.
    let def_inst = ssa
        .blocks
        .iter()
        .flat_map(|b| b.body.iter())
        .find(|i| i.value == err_val);
    let Some(def_inst) = def_inst else { return };

    let SsaOp::Call {
        ref callee,
        ref args,
        ..
    } = def_inst.op
    else {
        return;
    };
    if !crate::ssa::type_facts::is_int_producing_callee(callee) {
        return;
    }
    // Collect candidate input arg variable names: every SSA value across
    // every positional arg group, looked up by var_name.  Conservative ,
    // we mark *all* of them validated rather than guessing which arg the
    // validator narrows.  The validators we recognise here
    // (`strconv.Atoi`, `parseInt`, `ParseFloat`, …) all take exactly one
    // primary string argument, so in practice this collects one name.
    let mut arg_names: SmallVec<[String; 2]> = SmallVec::new();
    for arg_group in args {
        for &v in arg_group {
            if let Some(name) = ssa
                .value_defs
                .get(v.0 as usize)
                .and_then(|vd| vd.var_name.as_deref())
            {
                if !arg_names.iter().any(|s: &String| s == name) {
                    arg_names.push(name.to_string());
                }
            }
        }
    }
    if arg_names.is_empty() {
        return;
    }
    let success_state = if success_branch_is_true {
        true_state
    } else {
        false_state
    };
    for name in &arg_names {
        if let Some(sym) = interner.get(name) {
            success_state.validated_may.insert(sym);
            success_state.validated_must.insert(sym);
        }
    }
}

/// Mark the input arguments of a generic input-validator helper as
/// validated on the success branch of a downstream truthiness check.
///
/// Recognised idioms:
///
/// ```text
/// // ErrorReturning (Novu CVE GHSA-4x48-cgf9-q33f)
/// const err = validateUrlSsrf(child.webhookUrl);
/// if (err) throw …;
/// // → child.webhookUrl is validated on the falsy (false) branch
///
/// // BooleanTrueIsValid
/// const ok = isValidPath(p);
/// if (!ok) throw …;
/// // → p is validated on the !ok==false (true value of ok) branch
/// ```
///
/// Resolves `condition_vars[0]` to its reaching SSA def, checks that
/// the def is a [`SsaOp::Call`] to a callee classified by
/// [`classify_input_validator_callee`], and copies the call's input
/// argument variable names into `validated_must`/`validated_may` on
/// the branch the validator's polarity says succeeded.
///
/// The branch direction starts from `cond_text` (uses the same
/// `success_branch_is_true` heuristics as
/// [`apply_validation_err_check_narrowing`]) and is then flipped for
/// `BooleanTrueIsValid` validators (a truthy result means "valid", so
/// the *true* branch carries the validation).
///
/// Strict-additive: when no condition var matches, the def isn't a
/// Call, the callee isn't a recognised validator, or no arg has an
/// SSA-level var_name, the function is a no-op.
fn apply_input_validator_branch_narrowing(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    cond_text: &str,
    condition_vars: &[String],
    ssa: &SsaBody,
    block: BlockId,
    interner: &SymbolInterner,
) {
    if condition_vars.len() != 1 {
        return;
    }

    let result_name = condition_vars[0].as_str();
    let result_val = match resolve_var_to_ssa_value(result_name, ssa, block) {
        Some(v) => v,
        None => return,
    };

    let def_inst = ssa
        .blocks
        .iter()
        .flat_map(|b| b.body.iter())
        .find(|i| i.value == result_val);
    let Some(def_inst) = def_inst else { return };

    let SsaOp::Call {
        ref callee,
        ref args,
        ..
    } = def_inst.op
    else {
        return;
    };

    let polarity = match crate::ssa::type_facts::classify_input_validator_callee(callee.as_str()) {
        Some(p) => p,
        None => return,
    };

    // Determine the success branch.
    //
    // Default: bare `if (X)` truthy-test → success is the FALSE branch
    // for ErrorReturning (X truthy means "error"), and the TRUE branch
    // for BooleanTrueIsValid (X truthy means "valid").
    //
    // Equality checks (`X === null`, `X == null`, etc.) flip the
    // truthiness sense, match the same set of patterns
    // `apply_validation_err_check_narrowing` uses for the `err == nil`
    // family.
    let lower = cond_text.to_ascii_lowercase();
    let cond_text_says_null_branch_is_true = lower.contains("== nil")
        || lower.contains("== none")
        || lower.contains("is none")
        || lower.contains("is_ok")
        || lower.contains("=== null")
        || lower.contains("== null");

    let success_branch_is_true = match polarity {
        InputValidatorPolarity::ErrorReturning => cond_text_says_null_branch_is_true,
        InputValidatorPolarity::BooleanTrueIsValid => !cond_text_says_null_branch_is_true,
    };

    // Collect candidate input-arg variable names.  Conservative, every
    // SSA value across every positional arg group, looked up by
    // var_name, OR'd into validated_*.  Validators usually take one
    // primary arg so this collects ≤ 1 name in practice.
    let mut arg_names: SmallVec<[String; 2]> = SmallVec::new();
    for arg_group in args {
        for &v in arg_group {
            if let Some(name) = ssa
                .value_defs
                .get(v.0 as usize)
                .and_then(|vd| vd.var_name.as_deref())
            {
                if !arg_names.iter().any(|s: &String| s == name) {
                    arg_names.push(name.to_string());
                }
            }
        }
    }
    if arg_names.is_empty() {
        return;
    }

    let success_state = if success_branch_is_true {
        true_state
    } else {
        false_state
    };
    for name in &arg_names {
        if let Some(sym) = interner.get(name) {
            success_state.validated_may.insert(sym);
            success_state.validated_must.insert(sym);
        }
    }
}

/// JS/TS Array-method validator-callback narrowing.
///
/// `arr.filter(isSafeIdentifier)`, `arr.find(isValidId)`, and the
/// `findLast` variant are gating array methods whose return value is
/// composed of elements that passed the callback.  When the callback
/// argument resolves to a name `classify_input_validator_callee` tags
/// as `BooleanTrueIsValid` (`isValid…`, `isSafe…`, `hasValid…` and
/// snake-case variants), every element of the result satisfies the
/// validator, so the call's downstream sinks see the same flow as
/// validated taint.
///
/// The companion `if (isValidX(x)) use(x)` narrowing already exists in
/// [`apply_input_validator_branch_narrowing`]; this is the same idea
/// lifted to the call site for filter/find chains so taint stops at
/// the gate rather than leaking through subsequent
/// `Array[index]`/template/sink reads.
///
/// Strict-additive: if the callback's name does not match the
/// validator pattern (anonymous arrow, opaque identifier, etc.), the
/// helper is a no-op and the existing default propagation runs
/// unchanged.
///
/// Motivated by CVE-2026-42353 (i18next-http-middleware path
/// traversal): the patched fix is `languages.filter(utils.isSafeIdentifier)`
/// before forwarding `languages` into the backend connector, and the
/// dual deferred TS-side gap CVE-2026-25544 (Payload sqli).
fn try_array_method_validator_callback_narrowing(
    inst: &SsaInst,
    info: &NodeInfo,
    callee: &str,
    args: &[SmallVec<[SsaValue; 2]>],
    return_bits: &mut Cap,
    return_origins: &mut SmallVec<[TaintOrigin; 2]>,
    state: &mut SsaTaintState,
    transfer: &SsaTaintTransfer,
    ssa: &SsaBody,
) -> bool {
    if !matches!(transfer.lang, Lang::JavaScript | Lang::TypeScript) {
        return false;
    }
    // Method-call shape: callee text contains a `.` and the trailing
    // segment is one of the gating array methods.  `findIndex` /
    // `every` / `some` return scalar shapes (index, boolean) rather
    // than a filtered collection so they are excluded — element-level
    // validation does not apply to a numeric/boolean result.
    let dot = match callee.rfind('.') {
        Some(p) => p,
        None => return false,
    };
    let method = &callee[dot + 1..];
    if !matches!(method, "filter" | "find" | "findLast") {
        return false;
    }
    // The first positional argument's callable name.  Two channels:
    //   1. `info.arg_callees` — populated by `extract_arg_callees`
    //      (`call_ident_of` walks call shapes inside the arg).  Catches
    //      `arr.filter(cb())` and dotted-callback shapes where the
    //      tree-sitter node kind reaches `Kind::CallFn` or
    //      `Kind::CallMethod`.
    //   2. SSA `value_defs[v].var_name` for the arg's first SSA value
    //      — covers the bare-identifier shape (`arr.filter(cb)`)
    //      where the AST node is a plain identifier and
    //      `extract_arg_callees` pushes `None` because there is no
    //      call to recurse into.  This is the shape every patched
    //      CVE fix uses, so it is the dominant source of validator
    //      callbacks in real code.
    let arg0 = match args.first() {
        Some(a) => a,
        None => return false,
    };
    let cb_from_arg_callees = info.arg_callees.first().and_then(|s| s.as_deref());
    let cb_from_ssa = arg0.iter().find_map(|&v| {
        ssa.value_defs
            .get(v.0 as usize)
            .and_then(|vd| vd.var_name.as_deref())
    });
    let cb_name = match cb_from_arg_callees.or(cb_from_ssa) {
        Some(n) => n,
        None => return false,
    };
    if crate::ssa::type_facts::classify_input_validator_callee(cb_name)
        != Some(InputValidatorPolarity::BooleanTrueIsValid)
    {
        return false;
    }

    // Strip every cap from the return value: the returned array (or
    // single found element) is composed exclusively of elements the
    // recognised validator approved.  `Cap::all()` is the conservative
    // ceiling because the validator's body is opaque to this layer; a
    // future extension could narrow caps by inspecting the body's
    // rejection patterns.
    *return_bits = Cap::empty();
    return_origins.clear();

    // Mark the result's var_name as validated, mirroring the
    // [`apply_input_validator_branch_narrowing`] insertion.  Useful
    // for direct same-name reads of the rebound array (`arr =
    // arr.filter(p)` then `arr.length`) but does not propagate
    // through Assigns to differently-named bindings (`const lng =
    // arr[0]`); the `return_bits` strip above is what gates those
    // downstream flows.
    if let Some(name) = ssa
        .value_defs
        .get(inst.value.0 as usize)
        .and_then(|vd| vd.var_name.as_deref())
    {
        if let Some(sym) = transfer.interner.get(name) {
            state.validated_must.insert(sym);
            state.validated_may.insert(sym);
        }
    }
    true
}

/// Find the latest reaching SSA definition for `var_name` at the end of
/// `block`.  Mirrors `crate::constraint::lower::resolve_single_var` but
/// avoids the cross-module privacy leak: callers in this module need it
/// for branch narrowing on err-check shapes.
fn resolve_var_to_ssa_value(var_name: &str, ssa: &SsaBody, block: BlockId) -> Option<SsaValue> {
    let mut best_in_block: Option<SsaValue> = None;
    let mut best_outside: Option<SsaValue> = None;
    for (idx, vd) in ssa.value_defs.iter().enumerate() {
        if vd.var_name.as_deref() != Some(var_name) {
            continue;
        }
        let v = SsaValue(idx as u32);
        if vd.block == block {
            best_in_block = Some(match best_in_block {
                Some(existing) if existing.0 > v.0 => existing,
                _ => v,
            });
        } else {
            best_outside = Some(match best_outside {
                Some(existing) if existing.0 > v.0 => existing,
                _ => v,
            });
        }
    }
    best_in_block.or(best_outside)
}

/// Apply Rust path-rejection / path-assertion branch narrowing to the
/// true/false branch states produced by `compute_succ_states`.
///
/// Looks up each SSA value in the per-branch `abstract_state` whose
/// `var_name` matches one of the `effective_vars` (the condition's target
/// variables) and updates its [`PathFact`] according to the classified
/// rejection / assertion idiom.
///
/// `negated` reflects the effective negation of `cond_text`: when true,
/// the condition's surface form is `!<cond_text>` (or `not <cond_text>`)
/// and the True/False successor states correspond to the *rejection* /
/// *surviving* arms inverted relative to the unwrapped condition.  The
/// narrowing functions are written against the unwrapped condition; this
/// flag lets the caller route prefix-lock / rejection-axis narrowing to
/// the arm where the unwrapped condition holds.
#[cfg(test)]
fn apply_path_fact_branch_narrowing(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    cond_text: &str,
    effective_vars: &[String],
    ssa: &SsaBody,
) {
    apply_path_fact_branch_narrowing_with_interner(
        true_state,
        false_state,
        cond_text,
        effective_vars,
        ssa,
        None,
        false,
    );
}

fn apply_path_fact_branch_narrowing_with_interner(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    cond_text: &str,
    effective_vars: &[String],
    ssa: &SsaBody,
    interner: Option<&SymbolInterner>,
    negated: bool,
) {
    use crate::abstract_interp::PathFact;
    use crate::abstract_interp::path_domain::{
        PathAssertion, PathRejection, classify_path_assertion, classify_path_rejection_axes,
        cond_has_pre_negated_islocal_clause,
    };

    let rejection_axes = classify_path_rejection_axes(cond_text);
    let assertion = classify_path_assertion(cond_text);

    if rejection_axes.is_empty() && matches!(assertion, PathAssertion::None) {
        return;
    }

    // Resolve the "safe arm" for the rejection axes.
    //
    // `classify_path_rejection_axes` reports axes that hold on the FALSE
    // branch of `cond_text` AS WRITTEN, with one exception: the
    // `!filepath.IsLocal(...)` Go idiom is matched at the clause level
    // and the classifier consumes the leading `!` itself (the safe arm
    // remains the FALSE branch of the whole condition).
    //
    // For polarity-blind atoms like `!path.contains("..")`, the
    // classifier ignores the leading `!` and still extracts `..`.  In
    // that shape, AST detects the unary `!` and sets
    // `condition_negated = true`, but the rejection axis's *true* safe
    // arm is the TRUE branch of the whole condition.  So when
    // `negated == true` AND no clause is the pre-negated IsLocal idiom,
    // flip the narrow target.
    let rejection_pre_negated = cond_has_pre_negated_islocal_clause(cond_text);
    let rejection_safe_is_true = negated && !rejection_pre_negated;

    // Mark validated_may on the safe arm when a path-rejection
    // pattern fires.  Mirrors the AllowlistCheck quirk that already
    // marks validated on the rejection-arm via `apply_branch_predicates`
    // for languages whose `.contains(...)` / membership idiom hits the
    // AllowlistCheck classifier, but normalises behaviour for shapes
    // like C `strstr(path, "..") != NULL` that hit the NullCheck arm
    // first and never get a chance to mark validation through the
    // allowlist path.
    if !rejection_axes.is_empty()
        && let Some(intern) = interner
    {
        let safe_state: &mut SsaTaintState = if rejection_safe_is_true {
            &mut *true_state
        } else {
            &mut *false_state
        };
        for var in effective_vars {
            if let Some(sym) = intern.get(var) {
                safe_state.validated_may.insert(sym);
                safe_state.validated_must.insert(sym);
            }
        }
    }

    // Collect SSA values whose `var_name` appears in `effective_vars`.  We
    // pick the *highest-index* matching value (latest definition by SSA
    // ordering, closest to the current program point).  Absent an
    // explicit name table, iterating `ssa.value_defs` is the only way to
    // recover the mapping from name → SsaValue.
    let mut targets: smallvec::SmallVec<[SsaValue; 2]> = smallvec::SmallVec::new();
    for var_name in effective_vars {
        let mut latest: Option<SsaValue> = None;
        for (idx, vd) in ssa.value_defs.iter().enumerate() {
            if vd.var_name.as_deref() == Some(var_name.as_str()) {
                latest = Some(SsaValue(idx as u32));
            }
        }
        if let Some(v) = latest {
            targets.push(v);
        }
    }
    if targets.is_empty() {
        return;
    }

    // Apply rejection: true branch = reject (widen to Top / leave alone),
    // false branch = narrow the axis.  The plan's polarity rule about
    // whether the enclosing block inherits the narrowing when the true
    // branch terminates is enforced by the existing CFG successor graph ,
    // when the true branch returns/panics, only the false state reaches
    // subsequent blocks and the narrowed fact propagates naturally.
    let narrow_false = |fact: &mut PathFact| {
        for axis in rejection_axes.iter() {
            match axis {
                PathRejection::DotDot => {
                    fact.dotdot = crate::abstract_interp::Tri::No;
                }
                PathRejection::AbsoluteSlash | PathRejection::IsAbsolute => {
                    fact.absolute = crate::abstract_interp::Tri::No;
                }
                PathRejection::None => {}
            }
        }
    };

    // Apply assertion (positive): true branch narrows prefix_lock.
    let narrow_true = |fact: &mut PathFact| {
        if let PathAssertion::PrefixLock(ref root) = assertion {
            let updated = fact.clone().with_prefix_lock(root);
            *fact = updated;
        }
    };

    // Apply rejection axes to the safe arm.  The rejection classifier
    // (`has_negated_filepath_is_local` + `classify_path_rejection_atom`)
    // reports axes that hold on the FALSE branch of `cond_text` AS
    // WRITTEN, with one exception: the `!filepath.IsLocal(...)` Go idiom
    // is matched at the clause level and the classifier consumes the
    // leading `!` itself (safe arm remains the FALSE branch).
    //
    // For polarity-blind atoms like `!path.contains("..")` the classifier
    // ignores the leading `!` but AST-level negation flips the safe arm
    // to TRUE.  Use the same `rejection_safe_is_true` resolution as the
    // validated-marker block above so soundness is consistent.
    let rejection_state: &mut SsaTaintState = if rejection_safe_is_true {
        &mut *true_state
    } else {
        &mut *false_state
    };
    for v in &targets {
        if let Some(ref mut abs) = rejection_state.abstract_state {
            let mut av = abs.get(*v);
            narrow_false(&mut av.path);
            if !av.is_top() {
                abs.set(*v, av);
            }
        }
    }

    // Apply prefix-lock assertion to the cond-holds branch.  Unlike the
    // rejection classifier, `classify_path_assertion` is naive about
    // leading negation — it just searches cond_text for a
    // `starts_with`-like substring.  When `condition_negated` is true
    // (e.g. `if !target.startsWith(ROOT) { return; }`) the assertion
    // actually holds on the *false* CFG edge, where the sink is reached.
    // Flip the destination state in that case so the lock attaches to
    // the surviving block.
    let assertion_state = if negated {
        &mut *false_state
    } else {
        &mut *true_state
    };
    for v in &targets {
        if let Some(ref mut abs) = assertion_state.abstract_state {
            let mut av = abs.get(*v);
            narrow_true(&mut av.path);
            if !av.is_top() {
                abs.set(*v, av);
            }
        }
    }
}

// ── Context-Sensitive Inline Analysis Functions ───────────────────────

/// Build a compact taint signature from the actual argument taint at a call site.
/// Cache-key builder.  Folds optional Phase 03 promise-callback seeds in.
///
/// Cap bits from `promise_callback_seeds[i] = (idx, taint)` are unioned
/// onto position `idx` of the signature so two cache lookups for the
/// same callback function but different receiver-promise taints map to
/// distinct entries.  Without this, an unseeded `cb()` call earlier in
/// the same file would poison the cache for a later seeded
/// `p.then(cb)`.
fn build_arg_taint_sig_with_seeds(
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    promise_callback_seeds: PromiseCallbackSeeds<'_>,
) -> ArgTaintSig {
    let mut sig: SmallVec<[(usize, u32); 4]> = SmallVec::new();

    // Receiver taint at position usize::MAX (sentinel)
    if let Some(rv) = receiver {
        if let Some(taint) = state.get(*rv) {
            sig.push((usize::MAX, taint.caps.bits()));
        }
    }

    // Per-argument-position taint
    for (i, arg_vals) in args.iter().enumerate() {
        let mut caps = Cap::empty();
        for v in arg_vals {
            if let Some(taint) = state.get(*v) {
                caps |= taint.caps;
            }
        }
        if !caps.is_empty() {
            sig.push((i, caps.bits()));
        }
    }

    // Phase 03: fold extra param seeds into the signature so two
    // callers seeding the same callback with different caps cache
    // separately.
    for (idx, seed) in promise_callback_seeds {
        if seed.caps.is_empty() {
            continue;
        }
        if let Some(slot) = sig.iter_mut().find(|(j, _)| *j == *idx) {
            slot.1 |= seed.caps.bits();
        } else {
            sig.push((*idx, seed.caps.bits()));
        }
    }

    sig.sort_by_key(|(idx, _)| *idx);
    ArgTaintSig(sig)
}

/// Attempt context-sensitive inline analysis of a callee at a specific call site.
///
/// Returns `Some(InlineResult)` if inline analysis succeeded, `None` if the
/// callee is unavailable, the body is too large, or we're already at depth limit.
///
/// Resolution ordering for the callee body:
///
/// 1. **Intra-file** (`transfer.callee_bodies`): resolve the callee via
///    [`resolve_local_func_key`] against this file's local summaries and
///    look up the body by canonical [`FuncKey`].  This is the intra-file
///    context-sensitive path.
/// 2. **Cross-file**: if (1) misses but
///    [`GlobalSummaries::resolve_callee`] resolves the call site to a
///    cross-file [`FuncKey`], look up the body in
///    `transfer.cross_file_bodies`.  Both in-memory and indexed-scan
///    bodies are usable here: the former arrives with `body_graph`
///    already set (pass 1), the latter has it rehydrated from
///    `node_meta` via [`rebuild_body_graph`] at load time.
///
/// The cache ([`InlineCache`]) is keyed by `(FuncKey, ArgTaintSig)`.
/// `FuncKey` carries the callee's namespace, so cross-file and intra-file
/// entries never collide even when two files define same-leaf helpers.
fn inline_analyse_callee(
    callee: &str,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    transfer: &SsaTaintTransfer,
    cfg: &Cfg,
    caller_ssa: &SsaBody,
    call_inst: &SsaInst,
) -> Option<InlineResult> {
    inline_analyse_callee_with_seeds(
        callee, args, receiver, state, transfer, cfg, caller_ssa, call_inst, &[],
    )
}

/// Promise-callback seed entries plumbed into [`inline_analyse_callee_with_seeds`].
///
/// Each entry is `(param_idx, seed)`: when the inline-analyzed callee binds
/// `Param { index: param_idx }`, the corresponding parameter's entry-state
/// taint is unioned with `seed` *before* `run_ssa_taint_full` executes.
///
/// Phase 03 uses this to seed the first parameter of a `.then(cb)` /
/// `.catch(cb)` callback with the receiver Promise's resolved-value taint
/// when the callback itself is the inlined callee (the outer `.then` call's
/// receiver does not appear in `args`, so the existing `arg → param` seed
/// mechanism would otherwise lose the flow).
pub(crate) type PromiseCallbackSeeds<'a> = &'a [(usize, VarTaint)];

fn inline_analyse_callee_with_seeds(
    callee: &str,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    transfer: &SsaTaintTransfer,
    cfg: &Cfg,
    caller_ssa: &SsaBody,
    call_inst: &SsaInst,
    promise_callback_seeds: PromiseCallbackSeeds<'_>,
) -> Option<InlineResult> {
    // Enforce k=1 depth limit
    if transfer.context_depth >= 1 {
        return None;
    }

    let cache_ref = transfer.inline_cache?;

    // Resolve the call site to a canonical FuncKey and the body to inline.
    // Step 1: intra-file.  Step 2: cross-file.
    //
    // Without a resolved key we cannot inline safely, bare-name lookup could
    // pick the wrong same-name sibling (e.g. `A::process/1` vs `B::process/1`).
    let normalized = callee_leaf_name(callee);
    let container_raw = callee_container_hint(callee);
    let container_hint = if container_raw.is_empty() {
        None
    } else {
        Some(container_raw)
    };

    let intra_key = transfer.callee_bodies.and_then(|_| {
        resolve_local_func_key(
            transfer.local_summaries,
            transfer.lang,
            transfer.namespace,
            normalized,
            container_hint,
        )
    });
    let intra_body = intra_key
        .as_ref()
        .and_then(|k| transfer.callee_bodies.and_then(|cb| cb.get(k)));

    let (callee_key, callee_body) = if let (Some(k), Some(b)) = (intra_key, intra_body) {
        (k, b)
    } else if let Some(gs) = transfer.global_summaries {
        // Cross-file fallback.  Build a structured query mirroring
        // resolve_callee_full (qualifier/receiver_var/caller_container) so that
        // qualified-first policy is preserved.
        let (namespace_qualifier, receiver_var) = split_qualifier(callee);
        let caller_func = caller_ssa
            .blocks
            .iter()
            .flat_map(|b| b.phis.iter().chain(b.body.iter()))
            .filter_map(|inst| {
                cfg.node_weight(inst.cfg_node)
                    .and_then(|info| info.ast.enclosing_func.as_deref())
            })
            .next()
            .unwrap_or("");
        let caller_container_opt = caller_container_for(transfer, caller_func);
        let caller_container: Option<&str> = caller_container_opt.as_deref();
        let receiver_type = receiver_type_prefix(transfer, *receiver);
        let arity_hint = Some(args.len());
        let query = CalleeQuery {
            name: normalized,
            caller_lang: transfer.lang,
            caller_namespace: transfer.namespace,
            caller_container,
            receiver_type,
            namespace_qualifier,
            receiver_var,
            arity: arity_hint,
        };
        match gs.resolve_callee(&query) {
            CalleeResolution::Resolved(key) => {
                let xfile_bodies = transfer.cross_file_bodies?;
                let body = xfile_bodies.get(&key)?;
                // Indexed-scan bodies deserialized from SQLite
                // arrive with `body_graph: None`, but the load path
                // ([`rebuild_body_graph`] in `load_all_ssa_bodies`)
                // synthesizes a proxy `Cfg` from `node_meta` so the taint
                // engine can index `cfg[inst.cfg_node]` uniformly.  A
                // body that still has neither a real graph nor any
                // rehydrated metadata is structurally unusable, skip it.
                if body.body_graph.is_none() {
                    tracing::debug!(
                        callee = %normalized,
                        "cross-file inline miss: body has no body_graph and no node_meta"
                    );
                    return None;
                }
                tracing::debug!(
                    callee = %normalized,
                    namespace = %key.namespace,
                    "cross-file inline hit: using GlobalSummaries.bodies_by_key"
                );
                (key, body)
            }
            _ => return None,
        }
    } else {
        return None;
    };

    // Skip very large function bodies
    if callee_body.ssa.blocks.len() > MAX_INLINE_BLOCKS {
        tracing::debug!(
            callee = %callee_key.name,
            namespace = %callee_key.namespace,
            blocks = callee_body.ssa.blocks.len(),
            max = MAX_INLINE_BLOCKS,
            "inline miss: body too large (budget-exceeded)"
        );
        return None;
    }

    // Build cache key from actual argument taint, folding any extra
    // promise-callback seeds into the signature.
    let sig = build_arg_taint_sig_with_seeds(args, receiver, state, promise_callback_seeds);

    // Check cache (keyed by FuncKey + arg signature).  The cached value
    // is a structural shape, re-attribute origins to the current call
    // site before returning so two callers with matching caps but
    // different origins see their own source chains.
    {
        let cache = cache_ref.borrow();
        if let Some(cached) = cache.get(&(callee_key.clone(), sig.clone())) {
            record_engine_note(crate::engine_notes::EngineNote::InlineCacheReused);
            return Some(apply_cached_shape(
                cached,
                args,
                receiver,
                state,
                call_inst.cfg_node,
            ));
        }
    }

    // Build per-call-site seed from actual argument taint, indexed by the
    // callee's formal parameter position (not by name).  A caller with N
    // arguments produces an N-entry `Vec<Option<VarTaint>>`; the callee's
    // `Param { index }` read picks up slot `index` directly via
    // `SsaTaintTransfer::param_seed`.  Receiver taint is carried on a
    // separate channel (`SsaTaintTransfer::receiver_seed`) consumed by
    // `SelfParam`.  Name-based keying is not needed here, the callee
    // analysis is scoped to this one call site and cannot merge with
    // another callee's param seed.

    // Cross-file note: `populate_span` lazily fills `source_span` from
    // the *caller's* CFG before the origin crosses into the callee.  The
    // Param-op branch of `transfer_inst` remaps `node` to the callee's
    // own `cfg_node` and preserves only `source_span`, so without this
    // pre-fill cross-file inline would lose the caller's source line
    // entirely (finding emission in `ast.rs` uses `source_span` first,
    // falls back to indexing the caller's CFG at `node`, which is now
    // the callee's NodeIndex and resolves to a wrong or missing span).
    let populate_span = |mut o: TaintOrigin| -> TaintOrigin {
        if o.source_span.is_none() {
            if let Some(info) = cfg.node_weight(o.node) {
                o.source_span = Some(info.classification_span());
            }
        }
        o
    };
    let combine_taint = |arg_vals: &SmallVec<[SsaValue; 2]>| -> Option<VarTaint> {
        let mut combined_caps = Cap::empty();
        let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        for v in arg_vals {
            if let Some(taint) = state.get(*v) {
                combined_caps |= taint.caps;
                for orig in &taint.origins {
                    push_origin_bounded(&mut combined_origins, populate_span(*orig));
                }
            }
        }
        if combined_caps.is_empty() {
            None
        } else {
            Some(VarTaint {
                caps: combined_caps,
                origins: combined_origins,
                uses_summary: false,
            })
        }
    };

    let mut param_seed: Vec<Option<VarTaint>> = args.iter().map(combine_taint).collect();
    // Phase 03 promise-callback hook: union extra per-param seeds (from
    // `.then(cb)` / `.catch(cb)` resolved-value flows) into `param_seed`.
    // Cap union + origin merge keeps the cache key (`ArgTaintSig`) the
    // same shape as a normal call: the seeded caps end up reflected in
    // the `(idx, caps_bits)` signature, so two callbacks with different
    // receiver caps cache under different keys.
    if !promise_callback_seeds.is_empty() {
        for (idx, seed) in promise_callback_seeds {
            while param_seed.len() <= *idx {
                param_seed.push(None);
            }
            let merged = match param_seed[*idx].take() {
                None => seed.clone(),
                Some(mut existing) => {
                    existing.caps |= seed.caps;
                    for o in &seed.origins {
                        push_origin_bounded(&mut existing.origins, *o);
                    }
                    existing.uses_summary |= seed.uses_summary;
                    existing
                }
            };
            param_seed[*idx] = Some(merged);
        }
    }
    let receiver_seed: Option<VarTaint> = receiver.and_then(|rv| {
        state.get(rv).map(|taint| VarTaint {
            caps: taint.caps,
            origins: taint.origins.iter().map(|o| populate_span(*o)).collect(),
            uses_summary: false,
        })
    });

    // Detect callback arguments: when a call argument refers to a known function
    // name (resolvable to a FuncKey in the local summaries index), record the
    // mapping so the callee's analysis can resolve calls through the parameter.
    //
    // The binding value is a full `FuncKey` rather than a leaf string so the
    // child transfer can look up `callee_bodies` / `ssa_summaries` / local
    // summaries by canonical identity.
    let mut callback_bindings: HashMap<String, FuncKey> = HashMap::new();
    for block in &callee_body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let SsaOp::Param { index } = &inst.op {
                if let Some(param_name) = inst.var_name.as_ref() {
                    if *index < args.len() {
                        for v in &args[*index] {
                            if let Some(arg_var_name) = caller_ssa
                                .value_defs
                                .get(v.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref())
                            {
                                let norm = callee_leaf_name(arg_var_name);
                                let hint_raw = callee_container_hint(arg_var_name);
                                let hint = if hint_raw.is_empty() {
                                    None
                                } else {
                                    Some(hint_raw)
                                };
                                if let Some(target_key) = resolve_local_func_key(
                                    transfer.local_summaries,
                                    transfer.lang,
                                    transfer.namespace,
                                    norm,
                                    hint,
                                ) {
                                    if transfer
                                        .callee_bodies
                                        .is_some_and(|cb| cb.contains_key(&target_key))
                                    {
                                        callback_bindings.insert(param_name.clone(), target_key);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let cb_ref = if callback_bindings.is_empty() {
        None
    } else {
        Some(&callback_bindings)
    };
    let param_seed_slice: Option<&[Option<VarTaint>]> = if param_seed.is_empty() {
        None
    } else {
        Some(param_seed.as_slice())
    };
    // INVARIANT (`inline_cache` correctness across JS/TS pass-2 rounds):
    // `global_seed` MUST remain `None` on the child transfer.  The
    // per-file [`InlineCache`] is reused across all iterations of the
    // pass-2 convergence loop in `taint::mod::analyse_multi_body`; the
    // cache is keyed by `(FuncKey, ArgTaintSig)` only, so if the
    // inlined callee could read from a caller's `global_seed`, which
    // is refined each round, the same cache key could map to two
    // different return shapes across rounds, producing a
    // non-reproducible fixed point.
    //
    // Today the invariant is preserved here (global_seed: None) so
    // cache reuse is safe without calling
    // [`inline_cache_clear_epoch`].  If a future refactor threads
    // `global_seed` into inline analysis, it MUST also clear the
    // inline cache at pass-2 round boundaries.  The test
    // `inline_analyse_callee_does_not_thread_global_seed` in
    // `ssa_transfer/tests.rs` fails loudly if this invariant is
    // broken.
    let child_transfer = SsaTaintTransfer {
        lang: transfer.lang,
        namespace: transfer.namespace,
        interner: transfer.interner,
        local_summaries: transfer.local_summaries,
        global_summaries: transfer.global_summaries,
        interop_edges: transfer.interop_edges,
        owner_body_id: BodyId(0),
        parent_body_id: None,
        global_seed: None,
        param_seed: param_seed_slice,
        receiver_seed: receiver_seed.as_ref(),
        const_values: Some(&callee_body.opt.const_values),
        type_facts: Some(&callee_body.opt.type_facts),
        xml_parser_config: Some(&callee_body.opt.xml_parser_config),
        xpath_config: Some(&callee_body.opt.xpath_config),
        ssa_summaries: transfer.ssa_summaries,
        extra_labels: transfer.extra_labels,
        base_aliases: Some(&callee_body.opt.alias_result),
        callee_bodies: None, // no recursion into further inline analysis
        inline_cache: None,
        context_depth: transfer.context_depth + 1,
        callback_bindings: cb_ref,
        points_to: Some(&callee_body.opt.points_to),
        dynamic_pts: None, // no inter-procedural container propagation at k>1
        import_bindings: transfer.import_bindings,
        promisify_aliases: transfer.promisify_aliases,
        module_aliases: None, // callee body has its own const_values; module aliases not propagated
        static_map: None, // static-map seeding is caller-body local, not propagated to inlined callees
        auto_seed_handler_params: transfer.auto_seed_handler_params,
        cross_file_bodies: transfer.cross_file_bodies,
        // Inline analysis re-lowers the callee in its own body-local
        // location space; pointer facts are body-relative, so we don't
        // forward the caller's facts. `PointsToSummary` is the
        // cross-call substitute.
        pointer_facts: None,
        // The inlined callee body lives in another file with its own
        // import view; the caller's `cross_package_imports` would
        // resolve the callee's local names against the wrong package
        // boundary. Each `CalleeSsaBody` carries its own map populated
        // at lowering time from the source file's
        // [`crate::cfg::FileCfg::resolved_imports`], so we can forward
        // the *callee's* view here for transitive Phase 09 step 0.7
        // resolution. SQLite-cached bodies (loaded with `node_meta`
        // populated and `body_graph: None`) carry an empty map; we then
        // recover the callee's import view from
        // [`crate::summary::GlobalSummaries::get_cross_package_imports`]
        // (populated in pass 1 from each file's resolved imports), so
        // indexed-mode scans see the same step 0.7 hits as in-memory
        // scans for transitive cross-package IPA inside the inlined
        // frame.
        cross_package_imports: if !callee_body.cross_package_imports.is_empty() {
            Some(callee_body.cross_package_imports.as_ref())
        } else {
            transfer
                .global_summaries
                .and_then(|gs| gs.get_cross_package_imports(&callee_key.namespace))
                .map(|arc| arc.as_ref())
        },
        entry_kind: None,
    };

    // Use the callee's own body graph for inline analysis (per-body CFGs
    // have body-local NodeIndex spaces, so the caller's graph is wrong).
    let callee_cfg = callee_body.body_graph.as_ref().unwrap_or(cfg);
    let (_, callee_block_states, callee_block_exit_states) =
        run_ssa_taint_full_with_exits(&callee_body.ssa, callee_cfg, &child_transfer);

    // Extract the structural return shape from return-block exit states.
    // `block_exit_states` lets the extractor consult each return-block
    // predecessor's own exit state, which is needed to recover PathFacts
    // that would otherwise be diluted by the return-block entry join
    // (see the "merged return block" pattern the Rust SSA lowering
    // produces for `if cond { return X } Y`).
    let empty_induction = HashSet::new();
    let shape = extract_inline_return_taint(
        &callee_body.ssa,
        callee_cfg,
        &child_transfer,
        &callee_block_states,
        &callee_block_exit_states,
        &empty_induction,
    );

    // Cache the structural shape under the canonical FuncKey, then
    // re-attribute to this call site's actual arg/receiver origins.
    {
        let mut cache = cache_ref.borrow_mut();
        cache.insert((callee_key, sig), shape.clone());
    }

    Some(apply_cached_shape(
        &shape,
        args,
        receiver,
        state,
        call_inst.cfg_node,
    ))
}

/// Per-NodeIndex provenance bits for the callee's Param/SelfParam ops.
///
/// Multiple synthetic `Param` ops can share the same `cfg_node` (the
/// lowering emits them all at the function entry; see
/// [`crate::ssa::lower::reorder_external_vars`]).  When that happens, an
/// origin whose `node` points at the shared entry cannot be attributed to
/// a single param position from node identity alone.  This struct unions
/// the provenance of every Param/SelfParam sitting on the same node.
///
/// Over-attribution is safe: at apply time, set-bit indices beyond the
/// caller's actual argument count are skipped, and set bits whose param
/// contributed no taint union an empty set of caller origins.
#[derive(Copy, Clone, Debug, Default)]
struct CalleeParamNodeBits {
    /// Bit i = a `Param { index: i }` op sits on this node.
    params: u64,
    /// At least one `SelfParam` op sits on this node.
    receiver: bool,
}

/// Extract the structural shape of the return value taint from an
/// inline-analyzed callee.
///
/// Replays `transfer_block` on converged return-block states and classifies
/// each contributing origin as either **callee-internal** (originated from a
/// `Source`/`CatchParam` op inside the callee body) or **caller-seeded**
/// (propagated through a `Param`/`SelfParam` op; its `node` points at the
/// callee's Param NodeIndex).
///
/// Caller-seeded origins are *not* baked into the cached shape, their
/// identity depends on the caller's argument chain, which varies across call
/// sites with matching cap signatures.  Instead, the origin position is
/// recorded as a bit in [`ReturnShape::param_provenance`] (or the
/// `receiver_provenance` flag), and the actual caller origins are re-unioned
/// in by [`apply_cached_shape`] on each cache hit.
///
/// Callee-internal origins *are* baked in: they carry `source_span` from the
/// callee CFG (stable across callers) and a placeholder `node` that the
/// applying caller overwrites with its own call-site NodeIndex.
fn extract_inline_return_taint(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
    block_states: &[Option<SsaTaintState>],
    block_exit_states: &[Option<SsaTaintState>],
    induction_vars: &HashSet<SsaValue>,
) -> CachedInlineShape {
    // Collect all param SSA values to separate from derived values
    let param_values: HashSet<SsaValue> = ssa
        .blocks
        .iter()
        .flat_map(|b| b.phis.iter().chain(b.body.iter()))
        .filter(|i| matches!(i.op, SsaOp::Param { .. }))
        .map(|i| i.value)
        .collect();

    // Map callee Param/SelfParam NodeIndex → union of provenance bits so
    // we can identify caller-seeded origins by inspecting `orig.node`
    // (which was rewritten to the Param's cfg_node in
    // `transfer_inst::SsaOp::Param`).  Multiple Param ops may share a
    // cfg_node (synthetic external-var params emitted at the entry), so
    // a HashMap<NodeIndex, single-value> would lose information; we
    // union provenance bits per node instead.
    let mut param_node_map: HashMap<NodeIndex, CalleeParamNodeBits> = HashMap::new();
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            match &inst.op {
                SsaOp::Param { index } => {
                    let entry = param_node_map.entry(inst.cfg_node).or_default();
                    if *index < 64 {
                        entry.params |= 1u64 << *index;
                    }
                }
                SsaOp::SelfParam => {
                    let entry = param_node_map.entry(inst.cfg_node).or_default();
                    entry.receiver = true;
                }
                _ => {}
            }
        }
    }

    // Callee-internal origins carry their span from the callee CFG (lazily
    // filled when missing) but have `node` set to a placeholder, the
    // applying call site fills in its own call-site NodeIndex via
    // `apply_cached_shape`.
    //
    // `node` is initialized to `NodeIndex::end()` (the max-u32 sentinel) so
    // a forgotten override is loud (indexing it later panics) rather than
    // silently rendering wrong spans.
    let placeholder_node = NodeIndex::end();
    let prep_internal = |o: &TaintOrigin| -> TaintOrigin {
        let mut out = *o;
        if out.source_span.is_none() {
            if let Some(info) = cfg.node_weight(o.node) {
                out.source_span = Some(info.classification_span());
            }
        }
        out.node = placeholder_node;
        out
    };

    // Internal origins all share `placeholder_node`, so the standard
    // [`push_origin_bounded`] (which dedups by node) would collapse them
    // to one entry.  Dedup by `(source_span, source_kind)` here and
    // account for truncation explicitly so the engine-note signal
    // matches the rest of the pipeline.
    let push_internal = |target: &mut SmallVec<[TaintOrigin; 2]>, orig: &TaintOrigin| {
        let new_orig = prep_internal(orig);
        if target
            .iter()
            .any(|o| o.source_span == new_orig.source_span && o.source_kind == new_orig.source_kind)
        {
            return;
        }
        if target.len() < effective_max_origins() {
            target.push(new_orig);
        } else {
            ORIGINS_TRUNCATION_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            record_engine_note(crate::engine_notes::EngineNote::OriginsTruncated { dropped: 1 });
        }
    };

    let mut derived_caps = Cap::empty();
    let mut derived_internal: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut derived_params: u64 = 0;
    let mut derived_receiver: bool = false;

    let mut param_caps = Cap::empty();
    let mut param_internal: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut param_params: u64 = 0;
    let mut param_receiver: bool = false;

    // Join of the return value's [`PathFact`] across every return block.
    // Seeded with `None` (no observation) and widened conservatively to
    // [`PathFact::top`] if any return block gives Top or the value is
    // unobservable.  Only set to a non-Top fact when every observed return
    // path proves it.
    let mut return_path_fact_acc: Option<crate::abstract_interp::PathFact> = None;

    // Per-return-block PathFact observations.  Each entry records one
    // return block's PathFact under its own predicate gate so match-arm-
    // sensitive callers can pick the arm-specific fact.  The joined
    // fallback in `return_path_fact_acc` stays the default for callers
    // that cannot distinguish paths.
    let mut per_return_path_entries: SmallVec<
        [crate::summary::ssa_summary::PathFactReturnEntry; 2],
    > = SmallVec::new();

    let classify_and_push = |orig: &TaintOrigin,
                             internal: &mut SmallVec<[TaintOrigin; 2]>,
                             provenance: &mut u64,
                             receiver_prov: &mut bool| {
        match param_node_map.get(&orig.node) {
            Some(bits) => {
                *provenance |= bits.params;
                if bits.receiver {
                    *receiver_prov = true;
                }
            }
            None => {
                push_internal(internal, orig);
            }
        }
    };

    for (bid, block) in ssa.blocks.iter().enumerate() {
        let ret_val = match &block.terminator {
            Terminator::Return(rv) => rv.as_ref().copied(),
            _ => continue,
        };
        if let Some(entry_state) = &block_states[bid] {
            let exit = transfer_block(
                block,
                cfg,
                ssa,
                transfer,
                entry_state.clone(),
                induction_vars,
                None,
            );

            if let Some(rv) = ret_val {
                // Explicit return value: use ONLY its taint.
                if let Some(taint) = exit.get(rv) {
                    if param_values.contains(&rv) {
                        param_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut param_internal,
                                &mut param_params,
                                &mut param_receiver,
                            );
                        }
                    } else {
                        derived_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut derived_internal,
                                &mut derived_params,
                                &mut derived_receiver,
                            );
                        }
                    }
                }
                // Collect the return value's PathFact.  For return blocks
                // with a single predecessor (or no predecessors) the
                // replayed `exit` state is sufficient.  For multi-predecessor
                // return blocks the entry state's AbstractState has already
                // been diluted by the join, so we additionally replay
                // `transfer_block` once per predecessor seeded from that
                // predecessor's `block_exit_states` entry, yielding a
                // predecessor-specific exit whose PathFact on `rv` still
                // carries that path's narrowing.  The per-predecessor facts
                // are then joined to describe the callee-intrinsic
                // (Top-seeded) return narrowing.
                //
                // Additionally collect per-block observations
                // (`block_fact`, `variant_inner_fact`) so the cached
                // shape's `return_path_facts` lets match-arm-sensitive
                // callers pick one path's fact without going through the
                // dilutive join.
                let single_pred = block.preds.len() <= 1;
                let mut block_outer_fact: Option<crate::abstract_interp::PathFact> = None;
                let mut block_variant_inner: Option<crate::abstract_interp::PathFact> = None;
                if single_pred {
                    if let Some(ref abs) = exit.abstract_state {
                        let fact = abs.get(rv).path;
                        block_outer_fact = Some(fact);
                        block_variant_inner = detect_variant_inner_fact(rv, ssa, &exit);
                    }
                } else {
                    for pred in &block.preds {
                        let pred_idx = pred.0 as usize;
                        if let Some(pred_exit) =
                            block_exit_states.get(pred_idx).and_then(|o| o.as_ref())
                        {
                            let per_pred_exit = transfer_block(
                                block,
                                cfg,
                                ssa,
                                transfer,
                                pred_exit.clone(),
                                induction_vars,
                                None,
                            );
                            if let Some(ref abs) = per_pred_exit.abstract_state {
                                let fact = abs.get(rv).path;
                                block_outer_fact = Some(match block_outer_fact {
                                    None => fact,
                                    Some(prev) => prev.join(&fact),
                                });
                                let inner_this = detect_variant_inner_fact(rv, ssa, &per_pred_exit);
                                block_variant_inner = match (block_variant_inner, inner_this) {
                                    (Some(a), Some(b)) => Some(a.join(&b)),
                                    (Some(a), None) => Some(a),
                                    (None, Some(b)) => Some(b),
                                    (None, None) => None,
                                };
                            }
                        }
                    }
                }

                // Pick this block's contribution to the joined
                // `return_path_fact`.  When the rv is a one-arg variant
                // constructor (structurally: upper-camel-case leaf, 1 arg,
                // no receiver), the *inner* fact is what a destructuring
                // caller would see on the match-bound variable, the outer
                // variant-wrapper fact is semantically irrelevant because
                // `Option<String>` / `Result<String, _>` / `Box<String>`
                // values are not themselves path values.  Summary-level
                // unwrapping keeps the joined fact precise for the common
                // "`sanitize(...) -> Option<String>`; `let safe = match …
                // { Some(s) => s, None => return }`" idiom without
                // teaching the CFG/SSA layer about per-arm path
                // narrowing.
                //
                // Additionally, a return path whose rv carries no data
                // (nullary variant like `None`, or a constant `null` /
                // `nil`) is skipped from the joined fact: a
                // destructuring caller cannot extract a path value
                // from that path, so it is semantically unreachable at
                // any path-typed sink.  Skipping avoids diluting an
                // otherwise proven narrowing on the data-producing
                // arms.
                let rv_carries_no_data = is_non_data_return(rv, ssa);
                let block_contribution = if rv_carries_no_data {
                    None
                } else {
                    block_variant_inner
                        .clone()
                        .or_else(|| block_outer_fact.clone())
                };
                if let Some(fact) = block_contribution {
                    return_path_fact_acc = Some(match return_path_fact_acc.clone() {
                        None => fact,
                        Some(prev) => prev.join(&fact),
                    });
                }

                // Emit a per-return-path entry when we have a fact for
                // this block.  The predicate hash and known-true/false
                // come from the *entry* predicate gate (the exit
                // replay's predicates describe the gate under which
                // this return is reached).  Per-path entries carry both
                // the outer `path_fact` and the optional
                // `variant_inner_fact` so match-arm-sensitive callers
                // can distinguish the two.
                if let Some(outer) = block_outer_fact {
                    let (predicate_hash, known_true, known_false) =
                        summary_extract::summarise_return_predicates(&exit);

                    let entry = crate::summary::ssa_summary::PathFactReturnEntry {
                        predicate_hash,
                        known_true,
                        known_false,
                        path_fact: outer,
                        variant_inner_fact: block_variant_inner,
                    };
                    crate::summary::ssa_summary::merge_path_fact_return_paths(
                        &mut per_return_path_entries,
                        &[entry],
                    );
                }
            } else {
                // Return(None): implicit return / empty body.
                // Fall back to collecting all live values.
                for (val, taint) in &exit.values {
                    if param_values.contains(val) {
                        param_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut param_internal,
                                &mut param_params,
                                &mut param_receiver,
                            );
                        }
                    } else {
                        derived_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut derived_internal,
                                &mut derived_params,
                                &mut derived_receiver,
                            );
                        }
                    }
                }
            }
        }
    }

    // Prefer derived caps; fall back to param-return caps for passthrough functions.
    let (final_caps, final_internal, final_params, final_receiver) = if !derived_caps.is_empty() {
        (
            derived_caps,
            derived_internal,
            derived_params,
            derived_receiver,
        )
    } else {
        (param_caps, param_internal, param_params, param_receiver)
    };

    let return_path_fact =
        return_path_fact_acc.unwrap_or_else(crate::abstract_interp::PathFact::top);

    // Only keep per-return-path entries when at least one entry carries
    // meaningful signal (non-Top path_fact or a variant_inner_fact).  A
    // list of all-Top entries adds bytes on disk without helping a
    // caller pick a path.  Additionally require ≥2 distinct entries ,
    // a single-entry list is no finer than the joined `return_path_fact`.
    let return_path_facts = if per_return_path_entries.len() >= 2
        && per_return_path_entries
            .iter()
            .any(|e| !e.path_fact.is_top() || e.variant_inner_fact.is_some())
    {
        per_return_path_entries
    } else {
        SmallVec::new()
    };

    // Even when the callee produces no return taint and no param/receiver
    // provenance, a non-Top PathFact on the return is still meaningful
    // (it tells callers "this helper's return is sanitised along a path
    // axis").  Keep the shape when *any* of the four signals is present.
    if final_caps.is_empty()
        && final_params == 0
        && !final_receiver
        && final_internal.is_empty()
        && return_path_fact.is_top()
        && return_path_facts.is_empty()
    {
        return CachedInlineShape(None);
    }

    CachedInlineShape(Some(ReturnShape {
        caps: final_caps,
        internal_origins: final_internal,
        param_provenance: final_params,
        receiver_provenance: final_receiver,
        uses_summary: true, // inline analysis is a form of summary
        return_path_fact,
        return_path_facts,
    }))
}

/// Structural predicate: does `rv` represent a "non-data" return ,
/// a value that cannot carry path-typed content on this return path?
///
/// Recognises the common failure-arm idioms without hard-coding
/// specific identifier names:
///   * [`SsaOp::Const`] whose text is a recognised nullary tag
///     (`None`, `null`, `nil`, `NULL`, `()`, `Err`, `Nothing`, …) ,
///     tree-sitter-rust emits `None` as a constant path identifier
///     rather than a call; across other languages `null` / `nil`
///     cover the equivalents.
///   * [`SsaOp::Call`] with *zero* arguments and no receiver whose
///     callee leaf segment looks like a Rust-grammar variant /
///     struct constructor (ASCII upper-case start, alphanumeric /
///     underscore body), covers user-defined nullary variants like
///     `Nothing` or `Default` without naming them.  Zero-arg
///     constructors carry no attacker-controlled content by
///     definition, so they are provably not a path-typed payload.
///
/// Returns `false` for taint-carrying returns (calls with arguments,
/// string literals that could be interpreted as paths, identifiers
/// that resolve to user input, etc.); skipping them would lose
/// soundness of path-safety narrowing.
fn is_non_data_return(rv: SsaValue, ssa: &SsaBody) -> bool {
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if inst.value != rv {
                continue;
            }
            match &inst.op {
                SsaOp::Const(Some(text)) => {
                    // Match the nullary sentinels used across the
                    // supported languages.  Intentionally narrow ,
                    // any non-sentinel constant may be a path
                    // literal that must participate in the join.
                    let trimmed = text.trim();
                    return matches!(
                        trimmed,
                        "None"
                            | "NONE"
                            | "null"
                            | "NULL"
                            | "nil"
                            | "undefined"
                            | "Nothing"
                            | "()"
                            | ""
                    );
                }
                SsaOp::Call {
                    callee,
                    args,
                    receiver,
                    ..
                } => {
                    if receiver.is_none()
                        && args.is_empty()
                        && crate::abstract_interp::path_domain::is_structural_variant_ctor(callee)
                    {
                        return true;
                    }
                    return false;
                }
                _ => return false,
            }
        }
    }
    false
}

/// Structural detector for "return value is a one-argument variant
/// constructor" at the callee's exit.
///
/// Returns `Some(inner_fact)` when:
///   * `rv` is defined by [`SsaOp::Call`] in `ssa`;
///   * the call's callee leaf segment is a Rust-grammar variant / type
///     constructor (upper-camel-case start, alphanumeric/underscore
///     tail, see
///     [`crate::abstract_interp::path_domain::is_structural_variant_ctor`]);
///   * the call has no receiver and exactly one positional argument
///     group whose size is 1 (a single SSA value);
///
/// where `inner_fact` is the [`PathFact`] on that inner argument's SSA
/// value at the callee's exit state.  Name-agnostic: `Some`, `Ok`,
/// `Err`, `Box::new`, and any user-defined single-field enum variant
/// or tuple struct constructor all participate on the same footing.
pub(super) fn detect_variant_inner_fact(
    rv: SsaValue,
    ssa: &SsaBody,
    exit: &state::SsaTaintState,
) -> Option<crate::abstract_interp::PathFact> {
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if inst.value != rv {
                continue;
            }
            let SsaOp::Call {
                callee,
                args,
                receiver,
                ..
            } = &inst.op
            else {
                return None;
            };
            if receiver.is_some() {
                return None;
            }
            if !crate::abstract_interp::path_domain::is_structural_variant_ctor(callee) {
                return None;
            }
            // Single positional argument in the first group.  SSA
            // lowering appends an implicit chained-call uses group
            // after the positional ones, so we cannot read positional
            // arity from `args.len()` alone, however the *first*
            // group still captures the positional arg 0's contributing
            // SsaValues.  Join PathFacts across every value in that
            // group so chained inner calls (`Some(s.to_string())`
            // surfaces both `s` and `s.to_string`'s result) contribute
            // their most precise narrowing.
            let group = args.first()?;
            if group.is_empty() {
                return None;
            }
            let abs = exit.abstract_state.as_ref()?;
            let mut joined: Option<crate::abstract_interp::PathFact> = None;
            for &v in group {
                let fact = abs.get(v).path;
                if fact.is_top() {
                    continue;
                }
                joined = Some(match joined {
                    None => fact,
                    Some(prev) => prev.join(&fact),
                });
            }
            return joined;
        }
    }
    None
}

/// Re-attribute a [`CachedInlineShape`] to a specific call site.
///
/// Called on every inline-analysis return (both cache miss and cache hit) so
/// that `InlineResult.return_taint.origins` always reflect the *current*
/// caller's argument chain.  See the module-level note on cache-vs-origin
/// attribution.
///
/// # Attribution rules
///
/// * **Internal origins** (recorded by the callee's `Source` ops): cloned
///   with `node` overwritten to `call_site_node`; `source_span` preserved
///   from the callee CFG.
/// * **Param-provenance bits**: for each set bit `i`, union caller's arg
///   origins at position `i` into the result.  Receiver provenance does the
///   same for `receiver`.
/// * **Truncation**: the combined origin set is capped at
///   [`effective_max_origins`]; when any origins are dropped,
///   [`EngineNote::OriginsTruncated`] is recorded via
///   [`record_engine_note`].
fn apply_cached_shape(
    shape: &CachedInlineShape,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    call_site_node: NodeIndex,
) -> InlineResult {
    let Some(ret) = shape.0.as_ref() else {
        return InlineResult {
            return_taint: None,
            return_path_fact: crate::abstract_interp::PathFact::top(),
            return_path_facts: SmallVec::new(),
        };
    };

    let cap = effective_max_origins();
    let mut origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut dropped: u32 = 0;

    let push =
        |origins: &mut SmallVec<[TaintOrigin; 2]>, dropped: &mut u32, new_orig: TaintOrigin| {
            if origins.iter().any(|o| {
                o.node == new_orig.node
                    && o.source_span == new_orig.source_span
                    && o.source_kind == new_orig.source_kind
            }) {
                return;
            }
            if origins.len() < cap {
                origins.push(new_orig);
            } else {
                *dropped += 1;
            }
        };

    // 1. Callee-internal origins: rewrite `node` to the current call site.
    for orig in &ret.internal_origins {
        let mut o = *orig;
        o.node = call_site_node;
        push(&mut origins, &mut dropped, o);
    }

    // 2. Caller-attributed origins from param-provenance bits.
    let mut bits = ret.param_provenance;
    while bits != 0 {
        let idx = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        if let Some(arg_vals) = args.get(idx) {
            for v in arg_vals {
                if let Some(taint) = state.get(*v) {
                    for orig in &taint.origins {
                        push(&mut origins, &mut dropped, *orig);
                    }
                }
            }
        }
    }

    // 3. Receiver-attributed origins (SelfParam provenance).
    if ret.receiver_provenance {
        if let Some(rv) = receiver {
            if let Some(taint) = state.get(*rv) {
                for orig in &taint.origins {
                    push(&mut origins, &mut dropped, *orig);
                }
            }
        }
    }

    if dropped > 0 {
        // Mirror the counter increment the shared helper does, so the
        // global `origins_truncation_count()` observability hook covers
        // this site too.
        ORIGINS_TRUNCATION_COUNT.fetch_add(dropped as usize, std::sync::atomic::Ordering::Relaxed);
        record_engine_note(crate::engine_notes::EngineNote::OriginsTruncated { dropped });
    }

    // If the return taint is empty (no caps, no origins) we still need to
    // surface the PathFact contribution; represent "no return taint" with
    // `None` to preserve the existing InlineResult invariant while letting
    // callers apply the path fact regardless.
    let return_taint = if ret.caps.is_empty() && origins.is_empty() {
        None
    } else {
        Some(VarTaint {
            caps: ret.caps,
            origins,
            uses_summary: ret.uses_summary,
        })
    };
    InlineResult {
        return_taint,
        return_path_fact: ret.return_path_fact.clone(),
        return_path_facts: ret.return_path_facts.clone(),
    }
}

/// Apply a callee's [`FieldPointsToSummary`] field writes at a caller
/// call site.
///
/// For each `(param_idx, field_names)` in
/// [`FieldPointsToSummary::param_field_writes`], substitute the callee
/// `Param(callee, i)` with the caller's `pt(arg_i)` and union the
/// argument's taint into each `(loc, field_id)` cell on the caller's
/// `field_taint`.
///
/// * `param_idx == u32::MAX` is the receiver sentinel, resolve via
///   the call's `receiver` SsaValue rather than positional args.
/// * `field_name == "<elem>"` translates to [`FieldId::ELEM`] without
///   going through the caller's interner, matches the wire-format
///   convention from
///   [`crate::pointer::extract_field_points_to`].
/// * Any other field name is *looked up* (read-only) in the caller's
///   [`FieldInterner`].  Names the caller never referenced are skipped
///   , no FieldProj read in the caller could observe such a cell.
/// * `pt(arg)` saturated to `{Top}` is conservatively skipped (matches
///   the W1/W2 hooks' over-approximation policy).
///
/// Strict-additive: when [`FieldPointsToSummary::overflow`] is `true`
/// the helper does nothing, the conservative interpretation is "every
/// param touches every field on every other param", which would
/// require a body-wide field cell flood the lattice cannot
/// efficiently represent.  The bit is informational; consumers
/// already fall back to today's pre-W3 behaviour.
fn apply_field_points_to_writes(
    summary: &crate::summary::points_to::FieldPointsToSummary,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &mut SsaTaintState,
    ssa: &SsaBody,
    pf: &crate::pointer::PointsToFacts,
    interner: &crate::state::symbol::SymbolInterner,
) {
    if summary.is_empty() || summary.overflow {
        return;
    }
    for (param_idx, field_names) in &summary.param_field_writes {
        // Resolve the caller-side SSA values for the arg position.
        let caller_vals: SmallVec<[SsaValue; 2]> = if *param_idx == u32::MAX {
            match receiver {
                Some(rv) => smallvec::smallvec![*rv],
                None => continue,
            }
        } else {
            let idx = *param_idx as usize;
            match args.get(idx) {
                Some(group) if !group.is_empty() => group.clone(),
                _ => continue,
            }
        };

        // Compute combined arg taint from every contributing SSA value.
        let mut combined_caps = crate::labels::Cap::empty();
        let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
        let mut combined_summary = false;
        // W4: combine validation channels across the caller-side SSA
        // values for this argument position.  Vacuous AND for empty
        // values is `true`, but `caller_vals` here is non-empty (we
        // filtered above), so the AND fold is meaningful.
        let mut combined_must = true;
        let mut combined_may = false;
        for &v in &caller_vals {
            if let Some(t) = state.get(v) {
                combined_caps |= t.caps;
                combined_summary |= t.uses_summary;
                for o in &t.origins {
                    push_origin_bounded(&mut combined_origins, *o);
                }
            }
            let (am, av) = ssa_value_validated_bits(v, ssa, interner, state);
            combined_must &= am;
            combined_may |= av;
        }
        if combined_caps.is_empty() {
            continue;
        }
        let cell_taint = VarTaint {
            caps: combined_caps,
            origins: combined_origins,
            uses_summary: combined_summary,
        };

        // For each field name, intern through the caller's FieldInterner
        // (read-only) and apply to every caller pt(arg_v) loc.
        for name in field_names {
            let fid = if name == "<elem>" {
                crate::ssa::ir::FieldId::ELEM
            } else {
                match ssa.field_interner.lookup(name) {
                    Some(id) => id,
                    None => continue,
                }
            };
            for &v in &caller_vals {
                let pt = pf.pt(v);
                if pt.is_empty() || pt.is_top() {
                    continue;
                }
                for loc in pt.iter() {
                    let key = crate::taint::ssa_transfer::state::FieldTaintKey { loc, field: fid };
                    state.add_field(key, cell_taint.clone(), combined_must, combined_may);
                }
            }
        }
    }
}

/// W4: container ELEM read counterpart.  When the call is a
/// recognised container read, walks `pt(receiver)`'s `(loc, ELEM)`
/// cells and:
///
/// * Unions their `taint.caps` into the call result's value taint
///   (additive, preserves any caps already set by upstream
///   `try_container_propagation` / heap analysis).
/// * AND-intersects the cells' `validated_must`; OR-unions
///   `validated_may`; seeds the call result's symbol-level bits
///   accordingly.
///
/// Strict-additive: skips when no cell exists, when `pt(receiver)`
/// saturates / is empty, or when no contributing cell is found.
fn apply_container_elem_read_w4(
    inst: &SsaInst,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    let SsaOp::Call {
        callee, receiver, ..
    } = &inst.op
    else {
        return;
    };
    let (Some(pf), Some(rcv)) = (transfer.pointer_facts, *receiver) else {
        return;
    };
    if !crate::pointer::is_container_read_callee_pub(callee) {
        return;
    }
    let pt = pf.pt(rcv);
    if pt.is_empty() || pt.is_top() {
        return;
    }
    let mut elem_caps = Cap::empty();
    let mut elem_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut elem_summary = false;
    let mut cell_must_all: Option<bool> = None;
    let mut cell_may_any = false;
    for loc in pt.iter() {
        let key = crate::taint::ssa_transfer::state::FieldTaintKey {
            loc,
            field: crate::ssa::ir::FieldId::ELEM,
        };
        if let Some(cell) = state.get_field(key) {
            elem_caps |= cell.taint.caps;
            elem_summary |= cell.taint.uses_summary;
            for o in &cell.taint.origins {
                push_origin_bounded(&mut elem_origins, *o);
            }
            cell_must_all = Some(match cell_must_all {
                Some(prev) => prev && cell.validated_must,
                None => cell.validated_must,
            });
            cell_may_any |= cell.validated_may;
        }
    }
    if cell_must_all.is_none() {
        return;
    }
    if !elem_caps.is_empty() {
        let cur = state.get(inst.value).cloned();
        let merged = match cur {
            Some(mut acc) => {
                acc.caps |= elem_caps;
                acc.uses_summary |= elem_summary;
                for o in &elem_origins {
                    push_origin_bounded(&mut acc.origins, *o);
                }
                acc
            }
            None => VarTaint {
                caps: elem_caps,
                origins: elem_origins,
                uses_summary: elem_summary,
            },
        };
        state.set(inst.value, merged);
    }
    if let Some(name) = ssa
        .value_defs
        .get(inst.value.0 as usize)
        .and_then(|vd| vd.var_name.as_deref())
    {
        if let Some(sym) = transfer.interner.get(name) {
            if cell_must_all == Some(true) {
                state.validated_must.insert(sym);
            }
            if cell_may_any {
                state.validated_may.insert(sym);
            }
        }
    }
}

/// W4: look up the symbol-keyed `validated_must` / `validated_may`
/// flags for an SSA value via its `var_name`.  Returns `(false,
/// false)` when the value has no name, when the name isn't interned,
/// or when the symbol bits aren't set.
fn ssa_value_validated_bits(
    v: SsaValue,
    ssa: &SsaBody,
    interner: &crate::state::symbol::SymbolInterner,
    state: &SsaTaintState,
) -> (bool, bool) {
    let name = match ssa
        .value_defs
        .get(v.0 as usize)
        .and_then(|vd| vd.var_name.as_deref())
    {
        Some(n) => n,
        None => return (false, false),
    };
    match interner.get(name) {
        Some(sym) => (
            state.validated_must.contains(sym),
            state.validated_may.contains(sym),
        ),
        None => (false, false),
    }
}

/// Phase 03: handle JS/TS Promise-callback method calls (`.then(cb)`,
/// `.catch(cb)`, `.finally(cb)`).
///
/// Returns `true` when the call was recognised as a Promise callback and
/// fully handled here (caller returns from the Call arm without further
/// processing).  Returns `false` for any other call.
///
/// Semantics:
///   * `p.then(cb)` — `cb`'s first parameter receives `p`'s resolved-value
///     taint; result of `then(cb)` carries `cb`'s return taint plus a
///     conservative copy of `p`'s taint (subsequent `.then` calls in a
///     chain re-feed it).
///   * `p.catch(cb)` — same shape as `.then`.  The receiver may have
///     resolved or rejected, but at the taint level we treat both
///     identically (caps are coarse enough that a rejection-only flow
///     does not need a separate channel).
///   * `p.finally(cb)` — `cb` takes no value parameter; result is `p`'s
///     taint unchanged.
fn try_apply_promise_callback(
    inst: &SsaInst,
    info: &crate::cfg::NodeInfo,
    callee: &str,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &mut SsaTaintState,
    transfer: &SsaTaintTransfer,
    cfg: &Cfg,
    caller_ssa: &SsaBody,
) -> bool {
    let leaf = crate::callgraph::callee_leaf_name(callee);
    if !crate::labels::is_promise_callback_method(transfer.lang.as_str(), leaf) {
        return false;
    }

    // Upstream Promise taint = receiver taint + every non-callback arg's
    // taint.  When the upstream is a chained expression
    // (`Promise.resolve(req.body).then(cb)`), tree-sitter's receiver field
    // resolves to the chain-root identifier (`Promise` here), which has no
    // useful taint; the chained subexpression's taint instead surfaces in
    // the implicit-uses arg group emitted by SSA `build_call_args`.
    // Unioning both channels covers the named-promise (`p.then(cb)`),
    // chained (`Promise.resolve(x).then(cb)`), and `await`-wrapped
    // (`await p.then(cb)` lowered to `Assign` over the call result) shapes.
    let mut receiver_taint = VarTaint {
        caps: Cap::empty(),
        origins: SmallVec::new(),
        uses_summary: false,
    };
    if let Some(rv) = receiver {
        if let Some(t) = state.get(*rv) {
            receiver_taint.caps |= t.caps;
            for o in &t.origins {
                push_origin_bounded(&mut receiver_taint.origins, *o);
            }
            receiver_taint.uses_summary |= t.uses_summary;
        }
    }
    for (idx, arg_group) in args.iter().enumerate() {
        if idx == 0 {
            // Skip the callback argument itself; its taint is the function
            // reference, not the value flowed into the callback.
            continue;
        }
        for &v in arg_group {
            if let Some(t) = state.get(v) {
                receiver_taint.caps |= t.caps;
                for o in &t.origins {
                    push_origin_bounded(&mut receiver_taint.origins, *o);
                }
                receiver_taint.uses_summary |= t.uses_summary;
            }
        }
    }
    // Chained-receiver shape (`Promise.resolve(req.body).then(cb)`): the inner
    // `Promise.resolve` collapses into the outer `.then` CFG node, so the
    // resolved-value Source label rides on the `.then` node's labels rather
    // than on a separate SSA op the receiver/args reach.  Union those Source
    // caps so the chained shape seeds the callback's param[0] the same way
    // the named-promise shape does.  Synthesise a minimal origin pointing
    // at the `.then` node so the seed carries provenance.
    let label_source_caps = info
        .taint
        .labels
        .iter()
        .filter_map(|l| match l {
            DataLabel::Source(bits) => Some(*bits),
            _ => None,
        })
        .fold(Cap::empty(), |acc, b| acc | b);
    if !label_source_caps.is_empty() {
        receiver_taint.caps |= label_source_caps;
        let synthetic_origin = TaintOrigin {
            node: inst.cfg_node,
            source_kind: crate::labels::infer_source_kind(label_source_caps, callee),
            source_span: None,
        };
        if !receiver_taint
            .origins
            .iter()
            .any(|o| o.node == inst.cfg_node)
        {
            push_origin_bounded(&mut receiver_taint.origins, synthetic_origin);
        }
    }
    let receiver_taint: Option<VarTaint> = if receiver_taint.caps.is_empty() {
        None
    } else {
        Some(receiver_taint)
    };

    // Combine receiver taint into the result so chain-style `.then().then()`
    // continues to flow even when the callback's body is opaque or absent
    // (e.g. trailing `.then(console.log)`).  For `finally`, callback has no
    // value param and the chain just forwards `p`.
    let mut combined_caps = Cap::empty();
    let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut combined_summary = false;
    if let Some(ref rt) = receiver_taint {
        combined_caps |= rt.caps;
        for o in &rt.origins {
            push_origin_bounded(&mut combined_origins, *o);
        }
        combined_summary |= rt.uses_summary;
    }

    if !matches!(leaf, "finally") {
        // Pull the callback function out of arg[0]; the .finally callback
        // has no resolved-value parameter so its inline analysis does not
        // need a seed and we leave the callback opaque (chain just
        // forwards `p`).
        if let Some(cb_arg) = args.first() {
            for &cb_v in cb_arg {
                let cb_name = caller_ssa
                    .value_defs
                    .get(cb_v.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref());
                let Some(name) = cb_name else { continue };
                // Promise callbacks accept only the resolved value as
                // arg[0]; build synthetic args so the existing
                // `arg_uses → param_seed` path still runs (constants,
                // origin chain truncation, abstract-state seeding).
                // The dedicated `promise_callback_seeds` channel then
                // unions the receiver's taint into param[0]'s entry
                // state for callbacks whose declared arity is zero
                // (e.g. `() => doStuff()` reading from a closed-over
                // promise field).
                let synthetic_args: Vec<SmallVec<[SsaValue; 2]>> = Vec::new();
                let seeds: smallvec::SmallVec<[(usize, VarTaint); 1]> =
                    if let Some(ref rt) = receiver_taint {
                        smallvec::smallvec![(0, rt.clone())]
                    } else {
                        smallvec::SmallVec::new()
                    };
                if let Some(result) = inline_analyse_callee_with_seeds(
                    name,
                    &synthetic_args,
                    &None,
                    state,
                    transfer,
                    cfg,
                    caller_ssa,
                    inst,
                    seeds.as_slice(),
                ) {
                    if let Some(rt) = result.return_taint {
                        combined_caps |= rt.caps;
                        for o in &rt.origins {
                            push_origin_bounded(&mut combined_origins, *o);
                        }
                        combined_summary |= rt.uses_summary;
                    }
                }
            }
        }
    }

    // Source/sanitizer labels on the .then/.catch node itself stay
    // honoured: a custom rule that taints `then` (rare but possible) or
    // sanitises it should still apply.
    for lbl in &info.taint.labels {
        match lbl {
            DataLabel::Source(bits) => {
                combined_caps |= *bits;
                let source_kind = crate::labels::infer_source_kind(*bits, callee);
                let origin = TaintOrigin {
                    node: inst.cfg_node,
                    source_kind,
                    source_span: None,
                };
                if !combined_origins.iter().any(|o| o.node == inst.cfg_node) {
                    combined_origins.push(origin);
                }
            }
            DataLabel::Sanitizer(bits) => {
                combined_caps &= !*bits;
            }
            _ => {}
        }
    }

    if combined_caps.is_empty() {
        state.remove(inst.value);
    } else {
        state.set(
            inst.value,
            VarTaint {
                caps: combined_caps,
                origins: combined_origins,
                uses_summary: combined_summary,
            },
        );
    }
    true
}

/// Phase 03: handle JS/TS `Promise.resolve|all|allSettled|race(...)`.
///
/// For all four shapes the conservative approximation is: result = union
/// of every argument's taint.  `Promise.all` would in principle produce
/// a per-element-tainted array, but downstream destructuring already
/// taints all bindings via the existing destructuring handling, so the
/// scalar union is precise enough at the recall-gap level.
fn try_apply_promise_combinator(
    inst: &SsaInst,
    info: &crate::cfg::NodeInfo,
    callee: &str,
    args: &[SmallVec<[SsaValue; 2]>],
    state: &mut SsaTaintState,
    transfer: &SsaTaintTransfer,
) -> bool {
    if crate::labels::is_promise_combinator(transfer.lang.as_str(), callee).is_none() {
        return false;
    }

    let mut caps = Cap::empty();
    let mut origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut uses_summary = false;
    for arg_group in args {
        for &v in arg_group {
            if let Some(taint) = state.get(v) {
                caps |= taint.caps;
                uses_summary |= taint.uses_summary;
                for o in &taint.origins {
                    push_origin_bounded(&mut origins, *o);
                }
            }
        }
    }

    // Honour custom Source/Sanitizer labels on the Promise.* call node.
    for lbl in &info.taint.labels {
        match lbl {
            DataLabel::Source(bits) => {
                caps |= *bits;
                let source_kind = crate::labels::infer_source_kind(*bits, callee);
                let origin = TaintOrigin {
                    node: inst.cfg_node,
                    source_kind,
                    source_span: None,
                };
                if !origins.iter().any(|o| o.node == inst.cfg_node) {
                    origins.push(origin);
                }
            }
            DataLabel::Sanitizer(bits) => caps &= !*bits,
            _ => {}
        }
    }

    if caps.is_empty() {
        state.remove(inst.value);
    } else {
        state.set(
            inst.value,
            VarTaint {
                caps,
                origins,
                uses_summary,
            },
        );
    }
    true
}

/// Transfer a single SSA instruction.
pub(super) fn transfer_inst(
    inst: &SsaInst,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    let info = &cfg[inst.cfg_node];

    // Cross-file abstract return fact from callee resolution.
    // Set inside the Call arm, applied after transfer_abstract to override Top.
    let mut callee_return_abstract: Option<crate::abstract_interp::AbstractValue> = None;

    match &inst.op {
        SsaOp::Source => {
            // Apply source labels from NodeInfo
            let mut source_caps = Cap::empty();
            for lbl in &info.taint.labels {
                if let DataLabel::Source(bits) = lbl {
                    source_caps |= *bits;
                }
            }
            if !source_caps.is_empty() {
                let callee = info.call.callee.as_deref().unwrap_or("");
                let source_kind = crate::labels::infer_source_kind(source_caps, callee);
                let origin = TaintOrigin {
                    node: inst.cfg_node,
                    source_kind,
                    source_span: None,
                };
                state.set(
                    inst.value,
                    VarTaint {
                        caps: source_caps,
                        origins: SmallVec::from_elem(origin, 1),
                        uses_summary: false,
                    },
                );
            }
        }

        SsaOp::CatchParam => {
            let origin = TaintOrigin {
                node: inst.cfg_node,
                source_kind: SourceKind::CaughtException,
                source_span: None,
            };
            state.set(
                inst.value,
                VarTaint {
                    caps: Cap::all(),
                    origins: SmallVec::from_elem(origin, 1),
                    uses_summary: false,
                },
            );
        }

        SsaOp::Call {
            callee,
            args,
            receiver,
            ..
        } => {
            // Excluded callees (e.g. router.get, app.post) should not propagate
            // taint through their return value, they are framework scaffolding,
            // not data-flow operations.
            if crate::labels::is_excluded(transfer.lang.as_str(), callee.as_bytes()) {
                return;
            }

            // Phase 03 Promise plumbing: handle `.then(cb)`/`.catch(cb)`/
            // `.finally(cb)` and `Promise.resolve|all|allSettled|race(...)`
            // before the rest of the Call arm.  Returning early avoids
            // re-classifying these as ordinary calls (no summary, no sink),
            // which would otherwise drop the receiver/element taint flow.
            if try_apply_promise_callback(inst, info, callee, args, receiver, state, transfer, cfg, ssa)
            {
                return;
            }
            if try_apply_promise_combinator(inst, info, callee, args, state, transfer) {
                return;
            }

            // Phase 08 — `URL.searchParams.set/append`: writing a key/value
            // pair on the searchParams view mutates the underlying URL.
            // The receiver of the Call is the searchParams projection
            // (TypeKind::Url alias via `is_url_identity_field`); walking
            // back through the FieldProj chain reaches the original URL
            // SSA value and any intermediate projections.  Union the
            // arg-side taint into each of those values so a downstream
            // `fetch(u)` / `axios.get(u)` sees the URL as tainted.
            if let Some(rv) = *receiver {
                let leaf = crate::callgraph::callee_leaf_name(callee);
                if matches!(leaf, "set" | "append") {
                    let receiver_kind = transfer
                        .type_facts
                        .and_then(|tf| tf.get_type(rv))
                        .cloned()
                        .or_else(|| {
                            state
                                .path_env
                                .as_ref()
                                .and_then(|env| env.get(rv).types.as_singleton())
                        });
                    if matches!(
                        receiver_kind,
                        Some(crate::ssa::type_facts::TypeKind::Url)
                    ) {
                        let mut arg_caps = Cap::empty();
                        let mut arg_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                        let mut arg_uses_summary = false;
                        for arg_group in args.iter() {
                            for &v in arg_group {
                                if let Some(t) = state.get(v) {
                                    arg_caps |= t.caps;
                                    arg_uses_summary |= t.uses_summary;
                                    for o in &t.origins {
                                        push_origin_bounded(&mut arg_origins, *o);
                                    }
                                }
                            }
                        }
                        if !arg_caps.is_empty() {
                            // Walk the FieldProj receiver chain (and any
                            // Rust-style nested call receivers) so every
                            // SSA value that aliases the URL — `u`,
                            // `u.searchParams`, etc. — picks up the new
                            // taint, not just the immediate set receiver.
                            let chain = receiver_candidates_for_type_lookup(
                                rv,
                                Some(ssa),
                                transfer.lang,
                            );
                            for v in chain {
                                let combined = match state.get(v) {
                                    Some(prev) => {
                                        let mut origins = prev.origins.clone();
                                        for o in &arg_origins {
                                            push_origin_bounded(&mut origins, *o);
                                        }
                                        VarTaint {
                                            caps: prev.caps | arg_caps,
                                            origins,
                                            uses_summary: prev.uses_summary | arg_uses_summary,
                                        }
                                    }
                                    None => VarTaint {
                                        caps: arg_caps,
                                        origins: arg_origins.clone(),
                                        uses_summary: arg_uses_summary,
                                    },
                                };
                                state.set(v, combined);
                            }
                        }
                    }
                }
            }

            // Chain-wrapper sanitiser detection.  Computed up-front so
            // both the container-element-write hook and the outer-
            // callee taint suppression block below can consult it.
            // Walks `info.arg_callees` for the chain shape
            // `outer(... wrapper(<source>) ...)`, collecting any
            // sanitiser caps the wrapper's summary or label exposes.
            // The set is empty when there is no chain wrapper or when
            // none of the wrappers expose sanitisation.
            //
            // Argument attribution: when `find_classifiable_inner_call`
            // overrode the callee to an inner Source, the source can be
            // either (a) a direct argument call (`outer(escape(x),
            // source())`) or (b) nested inside one wrapper
            // (`outer(escape(source(x)))`).  Crediting any wrapper's
            // sanitizer caps when the source sits in a different argument
            // position would suppress real taint flow.
            //
            //   * `source_arg_pos = Some(N)` — the source call is the
            //     immediate callee of arg N (`arg_callees[N] == callee`).
            //     No other-arg wrapper can sanitize it.  Credit nothing.
            //   * `source_arg_pos = None` — the source is nested inside
            //     some arg's wrapper.  Credit only when exactly one arg
            //     has a sanitizing wrapper, since that one must be the
            //     parent of the nested source.  Multiple sanitizing
            //     wrappers across different positions is ambiguous; stay
            //     conservative and credit nothing.
            let caller_func_for_chain = info.ast.enclosing_func.as_deref().unwrap_or("");
            let mut chain_wrapper_sanitizer_caps = Cap::empty();
            if !info.arg_callees.is_empty() {
                let source_arg_pos = info
                    .arg_callees
                    .iter()
                    .position(|c| c.as_deref() == Some(callee.as_str()));
                let mut per_arg_sanitizer_caps: SmallVec<[Cap; 4]> = SmallVec::new();
                for (idx, maybe_callee) in info.arg_callees.iter().enumerate() {
                    if Some(idx) == source_arg_pos {
                        continue;
                    }
                    let Some(wrap_callee) = maybe_callee else {
                        continue;
                    };
                    if Some(wrap_callee.as_str()) == info.call.outer_callee.as_deref() {
                        continue;
                    }
                    let mut caps_here = Cap::empty();
                    if let Some(resolved) = resolve_callee_hinted(
                        transfer,
                        wrap_callee,
                        caller_func_for_chain,
                        info.call.call_ordinal,
                        None,
                    ) {
                        caps_here |= resolved.sanitizer_caps;
                    } else {
                        let labels = crate::labels::classify_all(
                            transfer.lang.as_str(),
                            wrap_callee,
                            transfer.extra_labels,
                        );
                        for lbl in &labels {
                            if let DataLabel::Sanitizer(bits) = lbl {
                                caps_here |= *bits;
                            }
                        }
                    }
                    if !caps_here.is_empty() {
                        per_arg_sanitizer_caps.push(caps_here);
                    }
                }
                if source_arg_pos.is_none() && per_arg_sanitizer_caps.len() == 1 {
                    chain_wrapper_sanitizer_caps = per_arg_sanitizer_caps[0];
                }
            }

            // Container element-write hook. Runs before other Call-arm
            // processing so `try_container_propagation`'s early-return
            // can't bypass us. Writes only into `(loc, ELEM)` cells on
            // `field_taint`, strictly additive.
            //
            // Each pushed value's `validated_must`/`validated_may` flow
            // through: cell `must = AND` over args (every writer must be
            // must-validated), `may = OR` over args. Anonymous SSA temps
            // contribute `false/false` and break the `must` invariant.
            //
            // Two callee shapes:
            //   * Method-style write (`receiver.push(val)`) — `receiver`
            //     channel resolves the container, value args start at
            //     position 0.
            //   * Go `append` builtin (or chain shape with
            //     `outer_callee == "append"`) — no receiver channel,
            //     `args[0]` is the slice itself, value args start at
            //     position 1.
            if let Some(pf) = transfer.pointer_facts {
                let go_append_chain = transfer.lang == Lang::Go
                    && receiver.is_none()
                    && (callee == "append" || info.call.outer_callee.as_deref() == Some("append"));
                // For Go append, args[0] is the input slice whose
                // points-to set may be empty when the slice was just
                // initialised with a composite literal (`cmds :=
                // []string{}`).  The call result (inst.value) carries
                // the fresh allocation site that pointer analysis
                // attaches to every Call op, and downstream uses of
                // the slice flow through that result, so it is the
                // authoritative container identity.  Fall back to
                // args[0] when the result has no pt set yet.
                let resolved_recv: Option<SsaValue> = if let Some(rcv) = *receiver {
                    Some(rcv)
                } else if go_append_chain {
                    let result_v = inst.value;
                    let result_pt = pf.pt(result_v);
                    if !result_pt.is_empty() && !result_pt.is_top() {
                        Some(result_v)
                    } else {
                        args.first().and_then(|a| a.first().copied())
                    }
                } else {
                    None
                };
                let value_arg_start = if go_append_chain { 1 } else { 0 };
                let write_callee_match = if go_append_chain {
                    true
                } else {
                    crate::pointer::is_container_write_callee(callee)
                };
                if let (Some(rcv), true) = (resolved_recv, write_callee_match) {
                    let pt = pf.pt(rcv);
                    if !pt.is_empty() && !pt.is_top() {
                        let mut elem_caps = Cap::empty();
                        let mut elem_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                        let mut elem_summary = false;
                        let mut elem_must_all = true; // AND over args (vacuously true for empty args)
                        let mut elem_may_any = false; // OR over args
                        let mut saw_any_arg = false;
                        for arg_group in args.iter().skip(value_arg_start) {
                            for &arg_v in arg_group {
                                saw_any_arg = true;
                                if let Some(t) = state.get(arg_v) {
                                    elem_caps |= t.caps;
                                    elem_summary |= t.uses_summary;
                                    for o in &t.origins {
                                        push_origin_bounded(&mut elem_origins, *o);
                                    }
                                }
                                let (am, av) =
                                    ssa_value_validated_bits(arg_v, ssa, transfer.interner, state);
                                elem_must_all &= am;
                                elem_may_any |= av;
                            }
                        }
                        // Chain-shape Go append: the inner Source label
                        // fires on this same call instruction, so its
                        // caps are not yet on any positional arg's SSA
                        // value at this point.  Pull them in directly
                        // from the source labels so the W4 cell sees
                        // the real source caps; without this the cell
                        // is empty for the chain shape and the index-
                        // read taint flow appears clean for the wrong
                        // reason.
                        if go_append_chain {
                            for lbl in &info.taint.labels {
                                if let DataLabel::Source(bits) = lbl {
                                    elem_caps |= *bits;
                                    saw_any_arg = true;
                                }
                            }
                            // A chain-shape sanitising wrapper around the
                            // source counts as the validation that the
                            // ELEM cell needs.  Each entry in
                            // `info.arg_callees` whose summary or label
                            // exposes non-empty `sanitizer_caps`
                            // contributes to validation, the cell's
                            // must/may bits flip on so the index-read
                            // counterpart sees the value as validated.
                            if !chain_wrapper_sanitizer_caps.is_empty() {
                                elem_must_all = true;
                                elem_may_any = true;
                            }
                        }
                        // Vacuous AND: a zero-arg container write supplies
                        // no validation source, so coerce must to false.
                        if !saw_any_arg {
                            elem_must_all = false;
                        }
                        if !elem_caps.is_empty() {
                            let cell = VarTaint {
                                caps: elem_caps,
                                origins: elem_origins,
                                uses_summary: elem_summary,
                            };
                            for loc in pt.iter() {
                                let key = crate::taint::ssa_transfer::state::FieldTaintKey {
                                    loc,
                                    field: crate::ssa::ir::FieldId::ELEM,
                                };
                                state.add_field(key, cell.clone(), elem_must_all, elem_may_any);
                            }
                        }
                    }
                }
            }

            // Check for source labels first
            let mut return_bits = Cap::empty();
            let mut return_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

            // Phase 08 / Phase 14 — URL-builder path-arg taint propagation.
            // Per-language `(base, path)` URL builders that don't carry a
            // label rule and have no summary: without an explicit
            // propagation pass the constructed URL value would arrive
            // untainted at the downstream HTTP sink and the SSRF would be
            // missed.  The arg-position table lives in
            // [`crate::ssa::type_facts::url_builder_arg_indices`] —
            // generalised in Phase 14 from the JS/TS-only Phase-08
            // constructor recognition to cover Python `urljoin`, Go
            // `url.JoinPath`, Java `new URL(URL, spec)`, Ruby `URI.join`.
            //
            // Origin-locked suppression (when the base arg is a literal)
            // lives in the abstract domain
            // (`StringFact::from_url_with_base`) and runs in
            // `is_string_safe_for_ssrf`, so propagating the taint here is
            // safe: the prefix-lock fact still suppresses the sink for
            // the two-arg form.
            if let Some((path_idx, _base_idx)) =
                crate::ssa::type_facts::url_builder_arg_indices(
                    transfer.lang,
                    callee,
                    info.call.outer_callee.as_deref(),
                    info.call.is_constructor,
                )
            {
                if let Some(path_group) = args.get(path_idx) {
                    for &v in path_group {
                        if let Some(t) = state.get(v) {
                            return_bits |= t.caps;
                            for o in &t.origins {
                                push_origin_bounded(&mut return_origins, *o);
                            }
                        }
                    }
                }
            }

            // Network-fetch source suppression: a Call that carries BOTH
            // a Source label and a Sink(SSRF) label is a network-fetch
            // primitive (e.g. PHP `file_get_contents`, `curl_exec`,
            // Python `requests.get`, JS `axios.get`).  When invoked with
            // a hardcoded URL whose prefix passes `is_string_safe_for_ssrf`
            // (a fully-formed `scheme://host/path`), the developer has
            // explicitly bound the endpoint at compile time, the SSRF
            // sink suppression already trusts this prefix-lock to
            // silence the SSRF concern, and the same trust applies on
            // the source side: the response body is developer-chosen,
            // not attacker-chosen.  Suppressing the Source label here
            // mirrors the existing sink suppression so a single
            // hardcoded-URL fetch does not create a phantom
            // `taint-unsanitised-flow` finding when its result is
            // echoed/printed later in the same scope.
            let is_network_fetch_source = info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Source(_)))
                && info
                    .taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SSRF)));
            // Detect a hardcoded URL via three channels:
            //   1. `info.string_prefix`, populated by the JS/TS template-
            //      literal extractor and inline call shapes.
            //   2. AbstractState `StringFact` on the first positional arg ,
            //      populated by const propagation for plain string literals.
            //   3. As a last resort when `info.call.first_arg_text` is
            //      populated with a hardcoded literal, extracted at CFG
            //      construction time for network-fetch primitive callees.
            let url_prefix_safe_via_node = info
                .string_prefix
                .as_deref()
                .map(|p| {
                    let synthetic = crate::abstract_interp::StringFact::from_prefix(p);
                    is_string_safe_for_ssrf(&synthetic)
                })
                .unwrap_or(false);
            let url_prefix_safe_via_abs = state.abstract_state.as_ref().is_some_and(|abs| {
                args.first().is_some_and(|first_arg| {
                    !first_arg.is_empty()
                        && first_arg
                            .iter()
                            .all(|v| is_string_safe_for_ssrf(&abs.get(*v).string))
                })
            });
            let url_prefix_safe_via_first_arg_text = is_network_fetch_source
                && info
                    .call
                    .arg_string_literals
                    .first()
                    .and_then(|v| v.as_deref())
                    .map(|s| {
                        let synthetic = crate::abstract_interp::StringFact::from_prefix(s);
                        is_string_safe_for_ssrf(&synthetic)
                    })
                    .unwrap_or(false);
            let url_is_hardcoded_safe = is_network_fetch_source
                && (url_prefix_safe_via_node
                    || url_prefix_safe_via_abs
                    || url_prefix_safe_via_first_arg_text);

            for lbl in &info.taint.labels {
                if let DataLabel::Source(bits) = lbl {
                    if url_is_hardcoded_safe {
                        // Skip Source propagation, see network-fetch
                        // source suppression rationale above.
                        continue;
                    }
                    return_bits |= *bits;
                    let callee_str = info.call.callee.as_deref().unwrap_or("");
                    let source_kind = crate::labels::infer_source_kind(*bits, callee_str);
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                        source_span: None,
                    };
                    if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                        return_origins.push(origin);
                    }
                }
            }

            // Output-parameter source tainting (C/C++): for known APIs that
            // write to a buffer argument (fgets, getline, recv, etc.), taint
            // the argument SSA values at the registered output positions.
            if !return_bits.is_empty() {
                if let Some(positions) =
                    crate::labels::output_param_source_positions(transfer.lang.as_str(), callee)
                {
                    for &pos in positions {
                        if let Some(arg_group) = args.get(pos) {
                            for &arg_v in arg_group {
                                state.set(
                                    arg_v,
                                    VarTaint {
                                        caps: return_bits,
                                        origins: return_origins.clone(),
                                        uses_summary: false,
                                    },
                                );
                            }
                        }
                    }
                }
            }

            // Check for sanitizer labels
            let mut sanitizer_bits = Cap::empty();
            for lbl in &info.taint.labels {
                if let DataLabel::Sanitizer(bits) = lbl {
                    sanitizer_bits |= *bits;
                }
            }

            // Call-site replace sanitizer detection.  Recognises
            // `s.replace*(pat, rep)` / `strings.ReplaceAll(s, pat, rep)` /
            // `str_replace($pat, $rep, $s)` shapes whose pattern is a
            // concrete shell/HTML/SQL escape literal and treats the call
            // as a sanitizer for the corresponding caps.  Mirrors the
            // semantics that label-rule sanitizers already provide.
            if let Some(extra) = crate::symex::strings::detect_call_site_replace_sanitizer(
                callee,
                transfer.lang,
                &info.call.arg_string_literals,
            ) {
                sanitizer_bits |= extra;
            }

            // Resolve callee summary, always attempt, even when explicit
            // labels are present. Labels take precedence for source caps, but
            // summary propagation and sanitizer behaviour must still apply
            // (matches legacy `apply_call()` semantics).
            let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
            let has_source_label = info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Source(_)));

            let mut resolved_callee = false;

            // Context-sensitive inline analysis: attempt before summary fallback.
            // Only for intra-file calls when context sensitivity is enabled.
            // Only claims resolution when the inline result produces non-empty
            // return taint, otherwise falls through to summary for cases like
            // receiver-only method calls where summary propagation is needed.
            if transfer.inline_cache.is_some() && transfer.context_depth < 1 {
                if let Some(result) =
                    inline_analyse_callee(callee, args, receiver, state, transfer, cfg, ssa, inst)
                {
                    if let Some(ref ret) = result.return_taint {
                        resolved_callee = true;
                        return_bits |= ret.caps;
                        for orig in &ret.origins {
                            push_origin_bounded(&mut return_origins, *orig);
                        }
                    }
                    // PathFact propagation from inline analysis: when the
                    // callee's body narrowed its return value's [`PathFact`]
                    // (e.g. a `sanitize(s) -> Option<String>` helper whose
                    // `Some` arm is gated by `s.contains("..")` rejection),
                    // meet that fact into the call-result's abstract state
                    // so downstream FILE_IO sinks see the sanitised axis.
                    //
                    // Uses meet rather than set so any caller-side narrowing
                    // from constant propagation or local transfer wins over
                    // callee-derived Top axes.
                    if !result.return_path_fact.is_top() {
                        if let Some(ref mut abs) = state.abstract_state {
                            let mut av = abs.get(inst.value);
                            av.path = <crate::abstract_interp::PathFact as crate::state::lattice::AbstractDomain>::meet(
                                &av.path,
                                &result.return_path_fact,
                            );
                            if !av.is_top() {
                                abs.set(inst.value, av);
                            }
                        }
                    }
                }
            }

            // Inter-procedural container fields: populated from resolve_callee
            // even when inline analysis already handled return taint, since inline
            // analysis doesn't model cross-parameter container stores.
            let mut resolved_container_to_return: Vec<usize> = Vec::new();
            let mut resolved_container_store: Vec<(usize, usize)> = Vec::new();
            // Captured alongside container fields because the
            // callee_summary gets moved when the main taint branch takes it
            // below.  We only need the points_to summary itself, clone it
            // out before the move so application can still read it.
            let mut resolved_points_to: crate::summary::points_to::PointsToSummary =
                crate::summary::points_to::PointsToSummary::empty();

            // Resolve callee summary (used for both taint propagation and container fields)
            // Pass arity (positional-arg count) so same-name/different-arity
            // overloads are not conflated during cross-file resolution.
            //
            // Use `info.call.arg_uses.len()` rather than `args.len()`: `args`
            // may include an extra "implicit" trailing group built by SSA
            // lowering to surface chained-call taint (see `build_call_args` in
            // `ssa/lower.rs`), which inflates `args.len()` beyond the real
            // positional arity.  The CFG's `arg_uses` is the authoritative
            // positional-arg list.
            //
            // Fallback: certain TypeScript call shapes — notably calls
            // inside template-string substitutions (`${fn(arg)}`) — get
            // their `arg_uses` dropped by CFG lowering even though the
            // call's positional `args` are intact.  When that happens
            // the strict `Some(0)` arity hint silently fails to match
            // any callee that takes ≥1 arg, swallowing summary
            // resolution.  Detect the asymmetry and pass `None` so
            // `resolve_local_func_key_query`'s unique-name fallback
            // can still pick up the lone candidate.
            let arity_hint = if info.call.arg_uses.is_empty() && !args.is_empty() {
                None
            } else {
                Some(info.call.arg_uses.len())
            };
            // Type-aware resolution: when the SSA receiver value has a
            // known abstract type (HttpClient, URL, …), feed that into
            // the resolver as an authoritative `receiver_type`.  This
            // causes qualified-first resolution to prefer
            // `{Type}::{name}` over any same-leaf collision in the
            // global summary table.
            let callee_summary = resolve_callee_typed(
                transfer,
                callee,
                caller_func,
                info.call.call_ordinal,
                arity_hint,
                *receiver,
            );

            // Capture container fields and return type regardless of whether
            // inline analysis handled the call
            if let Some(ref resolved) = callee_summary {
                resolved_container_to_return = resolved.param_container_to_return.clone();
                resolved_container_store = resolved.param_to_container_store.clone();
                resolved_points_to = resolved.points_to.clone();

                // Cross-call field-points-to application: walk the
                // callee's `field_points_to.param_field_writes`; for
                // each `(param_idx, field_names)` substitute the
                // callee's param with the caller's `pt(arg_i)` and
                // union the caller's argument taint into each
                // `(loc, field_id)` cell on `field_taint`.
                //
                // Receiver flow uses sentinel `param_idx == u32::MAX`.
                // Field names are looked up in the *caller's*
                // `field_interner`, names the caller never referenced
                // are skipped. The `"<elem>"` sentinel translates to
                // [`FieldId::ELEM`].
                if let Some(pf) = transfer.pointer_facts {
                    apply_field_points_to_writes(
                        &resolved.field_points_to,
                        args,
                        receiver,
                        state,
                        ssa,
                        pf,
                        transfer.interner,
                    );
                }

                // Capture abstract return for post-transfer injection
                callee_return_abstract = resolved.return_abstract.clone();

                // Apply per-parameter abstract transfers.
                //
                // For each (param_idx, transfer) in the callee's summary,
                // apply the transfer to the caller's current abstract value
                // of the argument at that position.  Join the per-parameter
                // contributions (disjunctive: any transfer's output is a
                // valid over-approximation of the return), then `meet` with
                // the baseline `return_abstract` (both facts must hold).
                //
                // Runs regardless of whether inline analysis already
                // resolved the call: inline re-analyses taint only; abstract
                // values are not threaded into or out of the callee body on
                // that path, so abstract transfer remains the summary-level
                // channel for propagating intervals / string prefixes across
                // a cross-file call.
                if !resolved.abstract_transfer.is_empty() {
                    let mut synthesised: Option<crate::abstract_interp::AbstractValue> = None;
                    for (idx, transfer) in &resolved.abstract_transfer {
                        if transfer.is_top() {
                            continue;
                        }
                        let arg_abs = if let Some(group) = args.get(*idx) {
                            let mut joined: Option<crate::abstract_interp::AbstractValue> = None;
                            for &v in group {
                                let av = state
                                    .abstract_state
                                    .as_ref()
                                    .map(|a| a.get(v))
                                    .unwrap_or_else(crate::abstract_interp::AbstractValue::top);
                                joined = Some(match joined {
                                    None => av,
                                    Some(prev) => prev.join(&av),
                                });
                            }
                            joined.unwrap_or_else(crate::abstract_interp::AbstractValue::top)
                        } else {
                            crate::abstract_interp::AbstractValue::top()
                        };
                        let applied = transfer.apply(&arg_abs);
                        if applied.is_top() {
                            continue;
                        }
                        synthesised = Some(match synthesised {
                            None => applied,
                            Some(prev) => prev.join(&applied),
                        });
                    }
                    if let Some(synth) = synthesised {
                        callee_return_abstract = match callee_return_abstract.take() {
                            Some(base) => {
                                let m = base.meet(&synth);
                                // Fall back to whichever side is non-bottom
                                // (meet can contradict when the callee's
                                // baseline and the caller-side transfer
                                // describe disjoint facts, rare, but sound
                                // to widen back to the less restrictive).
                                if m.is_bottom() {
                                    Some(synth.join(&base))
                                } else {
                                    Some(m)
                                }
                            }
                            None => Some(synth),
                        };
                    }
                }

                // Cross-file type propagation: if the callee has a known return
                // type (from SSA summary), inject it into the caller's path env
                // so downstream type-qualified resolution can use it.
                if let Some(ref rtype) = resolved.return_type {
                    if let Some(ref mut env) = state.path_env {
                        use crate::constraint::domain::{TypeSet, ValueFact};
                        let mut fact = ValueFact::top();
                        fact.types = TypeSet::singleton(rtype);
                        env.refine(inst.value, &fact);
                    }
                }

                // Validated-flow propagation through callee summaries.
                //
                // Runs regardless of whether inline analysis already
                // resolved the call: inline analysis re-runs the
                // callee's taint with caller-side seeds but does not
                // surface the callee's symbol-keyed
                // `validated_must` / `validated_may` state into the
                // caller, so the summary-level signal is the only
                // channel for propagating helper-validation across
                // a function boundary.
                //
                // When the callee's body validates a parameter on
                // every return path that carries the param's caps
                // (regex allowlist, type check, validation call, …),
                // a normal-returning call site is the validating arm
                // by construction: control could not reach the
                // post-call instruction unless the helper's
                // predicate(s) accepted the argument.  Mark each
                // tainted argument's `var_name` and the call's
                // result `var_name` in the caller's
                // `validated_must` / `validated_may` sets so
                // subsequent sinks observe `all_validated = true`,
                // the same way an inline `if (!regex.test(x)) throw`
                // validates the surviving branch.  Closes the
                // helper-validator propagation gap surfaced by
                // CVE-2026-25544 (Payload `sanitizeValue` SQLi).
                if !resolved.validated_params_to_return.is_empty() {
                    propagate_validated_params_to_return(
                        inst,
                        args,
                        ssa,
                        transfer.interner,
                        state,
                        &resolved.validated_params_to_return,
                    );
                }
            }

            // When find_classifiable_inner_call overrides the callee (e.g.
            // `storeInto(req.query.input, items)` → callee="req.query.input"),
            // the outer_callee preserves the original. Resolve it too for
            // container fields that depend on the wrapping function's summary.
            if resolved_container_store.is_empty() {
                if let Some(ref oc) = info.call.outer_callee {
                    if let Some(ref resolved) = resolve_callee_hinted(
                        transfer,
                        oc,
                        caller_func,
                        info.call.call_ordinal,
                        arity_hint,
                    ) {
                        if resolved_container_to_return.is_empty() {
                            resolved_container_to_return =
                                resolved.param_container_to_return.clone();
                        }
                        resolved_container_store = resolved.param_to_container_store.clone();
                    }
                }
            }

            if !resolved_callee && let Some(resolved) = callee_summary {
                resolved_callee = true;

                // Source caps from summary: only when no explicit Source label
                if !has_source_label && !resolved.source_caps.is_empty() {
                    return_bits |= resolved.source_caps;
                    let source_kind =
                        crate::labels::infer_source_kind(resolved.source_caps, callee);
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                        source_span: None,
                    };
                    if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                        return_origins.push(origin);
                    }
                }

                // Per-parameter predicate-consistent transforms.
                //
                // When the summary carries `param_return_paths`, apply a
                // per-parameter effective sanitizer narrowed by the caller's
                // current predicate state.  This recovers callee-internal
                // path splits that the coarse `resolved.sanitizer_caps`
                // union would erase (`if validated { return sanitised }
                // else { return raw }` can be resolved to "strip all
                // sanitised bits" when the caller validated the input).
                //
                // Falls back to the aggregate path when:
                //   * `param_return_paths` is empty (single-path callee or
                //     non-SSA resolution);
                //   * the parameter has no entry (no per-path decomposition
                //     was recorded for this param);
                //   * no paths are predicate-compatible (conservative: keep
                //     the aggregate sanitizer bits).
                let mut aggregate_sanitizer_applied = false;

                // Propagation: ALWAYS apply
                if resolved.propagates_taint {
                    // Only use positional filtering when original arg_uses is populated
                    let effective_params = if info.call.arg_uses.is_empty() {
                        &[] as &[usize]
                    } else {
                        &resolved.propagating_params
                    };

                    if !resolved.param_return_paths.is_empty() && !effective_params.is_empty() {
                        // Per-parameter application: each propagating param
                        // contributes taint narrowed by its own per-path
                        // sanitizer.  Origins are still aggregated across
                        // params, they name source anchors, not transforms.
                        let mut any_origin_added = false;
                        for &param_idx in effective_params {
                            let arg_caps_origins =
                                collect_args_taint(args, receiver, state, &[param_idx]);
                            let arg_caps = arg_caps_origins.0;
                            let arg_origins = arg_caps_origins.1;
                            let param_sanitizer =
                                effective_param_sanitizer(&resolved, param_idx, state);
                            return_bits |= arg_caps & !param_sanitizer;
                            for orig in &arg_origins {
                                if push_origin_bounded(&mut return_origins, *orig) {
                                    any_origin_added = true;
                                }
                            }
                        }
                        aggregate_sanitizer_applied = true;
                        // Sentinel reference to silence unused on cold paths.
                        let _ = any_origin_added;
                    } else {
                        let (prop_caps, prop_origins) =
                            collect_args_taint(args, receiver, state, effective_params);
                        return_bits |= prop_caps;
                        for orig in &prop_origins {
                            push_origin_bounded(&mut return_origins, *orig);
                        }
                    }
                }

                // Summary sanitizer: apply the aggregate only when per-param
                // path narrowing above did not already strip per-argument.
                if !aggregate_sanitizer_applied {
                    return_bits &= !resolved.sanitizer_caps;
                }

                // Validated-flow propagation through callee summaries.
                //
                // When the callee's body validates a parameter on every
                // return path (regex allowlist, type check, validation
                // call, etc. — see
                // [`crate::summary::ssa_summary::SsaFuncSummary::validated_params_to_return`]),
                // a normal-returning call site is the validating arm by
                // construction: control could not reach the post-call
                // instruction unless the helper's predicate(s) accepted
                // the argument.  Mark each tainted argument's `var_name`
                // and the call's result `var_name` in the caller's
                // `validated_must` / `validated_may` sets so subsequent
                // sinks observe `all_validated = true`, the same way an
                // inline `if (!regex.test(x)) throw` validates the
                // surviving branch.  Closes the helper-validator
                // propagation gap surfaced by CVE-2026-25544 (Payload
                // `sanitizeValue` SQLi).
            }

            // Type-qualified receiver resolution: when normal callee resolution
            // failed and explicit labels are absent, try constructing a type-qualified
            // callee name from the receiver's inferred type (e.g., client.send →
            // HttpClient.send when client is typed as HttpClient).
            if !resolved_callee && info.taint.labels.is_empty() {
                if let Some(rv) = receiver {
                    if transfer.type_facts.is_some() || state.path_env.is_some() {
                        let tq_labels = resolve_type_qualified_labels(
                            callee,
                            *rv,
                            transfer.type_facts,
                            state.path_env.as_ref(),
                            transfer.lang,
                            transfer.extra_labels,
                            Some(ssa),
                        );
                        for lbl in &tq_labels {
                            match lbl {
                                DataLabel::Source(bits) if !has_source_label => {
                                    return_bits |= *bits;
                                    let source_kind =
                                        crate::labels::infer_source_kind(*bits, callee);
                                    let origin = TaintOrigin {
                                        node: inst.cfg_node,
                                        source_kind,
                                        source_span: None,
                                    };
                                    if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                                        return_origins.push(origin);
                                    }
                                }
                                DataLabel::Sanitizer(bits) => {
                                    sanitizer_bits |= *bits;
                                }
                                DataLabel::Sink(_) => {
                                    // Sink detection is handled separately in
                                    // collect_block_events via resolve_sink_caps_typed
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            // Apply explicit sanitizer labels.  When a callee summary has
            // already resolved the call, `return_bits` reflects the summary's
            // precise propagation + sanitization; re-unioning `use_caps` here
            // would restore taint the summary already stripped and clobber
            // any cross-procedural sanitization (e.g. an interprocedural
            // path-traversal sanitizer whose caller also carries a label-only
            // sanitizer matching on callee name).  Only collect `use_caps`
            // when no summary applied, that is the original pure-label
            // sanitizer-wrapper code path.
            if !sanitizer_bits.is_empty() {
                if !resolved_callee {
                    let (use_caps, use_origins) = collect_args_taint(args, receiver, state, &[]);
                    return_bits |= use_caps;
                    for orig in &use_origins {
                        push_origin_bounded(&mut return_origins, *orig);
                    }
                }
                return_bits &= !sanitizer_bits;

                // UNAUTHORIZED_ID models a caller-supplied id that must
                // clear an ownership/membership guard. Sanitizers for
                // this cap don't pass inputs through a return value ,
                // the ownership proof is the side effect. Strip the bit
                // from each argument's SSA value so downstream uses see
                // it cleared. Isolated to UNAUTHORIZED_ID; other caps
                // keep return-only sanitizer semantics.
                if sanitizer_bits.contains(Cap::UNAUTHORIZED_ID) {
                    strip_cap_from_call_args(args, receiver, state, Cap::UNAUTHORIZED_ID);
                }
            } else if !resolved_callee {
                // Container operation propagation (push/pop/get/set/etc.)
                // Try the primary callee first, then fall back to outer_callee
                // (set when find_classifiable_inner_call overrides the callee,
                // e.g. `parts.add(req.getParameter("input"))`, callee is
                // "req.getParameter" but outer_callee is "parts.add").
                let mut container_handled = try_container_propagation(
                    inst, info, args, receiver, state, transfer, callee, ssa,
                );
                if !container_handled {
                    if let Some(ref oc) = info.call.outer_callee {
                        container_handled = try_container_propagation(
                            inst, info, args, receiver, state, transfer, oc, ssa,
                        );
                    }
                }
                if container_handled {
                    // When this call node is also a Source (e.g. items.push(req.query.item)
                    // where req.query.item triggers a Source label on the call), merge
                    // the source taint into the container receiver too.
                    if !return_bits.is_empty() {
                        let recv_callee = info.call.outer_callee.as_deref().unwrap_or(callee);
                        if let Some(container_val) =
                            find_container_receiver(recv_callee, receiver, args, ssa, transfer.lang)
                        {
                            // Also store into heap objects when available
                            if let Some(pts) = lookup_pts(transfer, container_val) {
                                state.heap.store_set(
                                    &pts,
                                    HeapSlot::Elements,
                                    return_bits,
                                    &return_origins,
                                );
                            }
                            merge_taint_into(state, container_val, return_bits, &return_origins);
                        }
                    }
                    // Fall through to write return_bits to inst.value if non-empty
                    if return_bits.is_empty() {
                        // Container ELEM read counterpart fires for
                        // container_handled calls with no source label
                        // (e.g. `cmd := arr.shift()`) whose taint comes
                        // from the cell rather than an inline source.
                        apply_container_elem_read_w4(inst, ssa, transfer, state);
                        return;
                    }
                } else {
                    // Curl special case: propagate URL taint to handle
                    if try_curl_url_propagation(inst, info, args, state) {
                        return;
                    }

                    // Arg-to-arg propagation for known C/C++ functions (e.g.,
                    // inet_pton). When an input arg is tainted, propagate to
                    // all SSA values in the output arg positions.
                    if let Some(prop) =
                        crate::labels::arg_propagation(transfer.lang.as_str(), callee)
                    {
                        let mut input_caps = Cap::empty();
                        let mut input_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                        for &from_pos in prop.from_args {
                            if let Some(arg_group) = args.get(from_pos) {
                                for &v in arg_group {
                                    if let Some(taint) = state.get(v) {
                                        input_caps |= taint.caps;
                                        for orig in &taint.origins {
                                            push_origin_bounded(&mut input_origins, *orig);
                                        }
                                    }
                                }
                            }
                        }
                        if !input_caps.is_empty() {
                            for &to_pos in prop.to_args {
                                if let Some(arg_group) = args.get(to_pos) {
                                    for &arg_v in arg_group {
                                        state.set(
                                            arg_v,
                                            VarTaint {
                                                caps: input_caps,
                                                origins: input_origins.clone(),
                                                uses_summary: false,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // No labels and no summary, default propagation (gen/kill)
                    let (use_caps, use_origins) = collect_args_taint(args, receiver, state, &[]);
                    if return_bits.is_empty() {
                        return_bits = use_caps;
                        return_origins = use_origins;
                    }

                    // Validated-flow propagation through unresolved external
                    // calls.  When every tainted argument's symbol is already
                    // in `validated_must` at the call site, the call result
                    // is derived solely from validated values, so its symbol
                    // inherits the same `validated_must` / `validated_may`
                    // status.  Without this, helper-validated taint that
                    // crosses an external boundary (`db.execute(sanitisedSql)`,
                    // `fetch(safeUrl)`, …) re-emerges as unvalidated taint at
                    // the next sink (`res.json(result)`), reproducing the
                    // residual finding in the patched fixture for
                    // CVE-2026-25544 even though the SQL injection itself is
                    // suppressed.
                    if !return_bits.is_empty() {
                        let mut all_args_validated = true;
                        let mut any_tainted_arg = false;
                        let check_value = |v: SsaValue, state: &SsaTaintState| -> Option<bool> {
                            // Returns Some(true) if validated_must, Some(false)
                            // if tainted-but-not-validated, None if not tainted.
                            let taint = state.get(v)?;
                            if taint.caps.is_empty() {
                                return None;
                            }
                            let name = ssa
                                .value_defs
                                .get(v.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref())?;
                            let sym = transfer.interner.get(name)?;
                            Some(state.validated_must.contains(sym))
                        };
                        for arg_group in args {
                            for &v in arg_group {
                                if let Some(is_validated) = check_value(v, state) {
                                    any_tainted_arg = true;
                                    if !is_validated {
                                        all_args_validated = false;
                                        break;
                                    }
                                }
                            }
                            if !all_args_validated {
                                break;
                            }
                        }
                        if all_args_validated {
                            if let Some(rv) = receiver {
                                if let Some(is_validated) = check_value(*rv, state) {
                                    any_tainted_arg = true;
                                    if !is_validated {
                                        all_args_validated = false;
                                    }
                                }
                            }
                        }
                        if any_tainted_arg && all_args_validated {
                            if let Some(name) = ssa
                                .value_defs
                                .get(inst.value.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref())
                            {
                                if let Some(sym) = transfer.interner.get(name) {
                                    state.validated_must.insert(sym);
                                    state.validated_may.insert(sym);
                                }
                            }
                        }
                    }
                }
            }

            // Receiver-side validator strip.  Some method-call validators
            // raise on failure rather than transforming a return value,
            // so the canonical `Sanitizer` mechanism (which clears the
            // return) is the wrong shape.  After the call returns, the
            // *receiver* (and any args carrying the same equivalence
            // class) is proven to satisfy the validated property.  Strip
            // the registered cap from receiver+args here so that
            // `path.relative_to(base)` clears `Cap::FILE_IO` from
            // `path` for downstream uses.  Motivated by CVE-2024-23334
            // (aiohttp StaticResource symlink-bypass): the patched code
            // calls `filepath.relative_to(self._directory)` inside a
            // try/except and serves `filepath` afterwards.
            if let Some(cap) =
                crate::labels::lookup_receiver_validator(transfer.lang.as_str(), callee)
            {
                strip_cap_from_call_args(args, receiver, state, cap);
            }

            // Alias-aware sanitization: propagate through must-aliased field paths
            if !sanitizer_bits.is_empty() {
                if let Some(aliases) = transfer.base_aliases {
                    if !aliases.is_empty() {
                        propagate_sanitization_to_aliases(
                            inst,
                            state,
                            sanitizer_bits,
                            aliases,
                            ssa,
                        );
                    }
                }
            }

            // Inter-procedural container identity propagation:
            // If callee returns the same container it received, propagate
            // the caller's points-to set for that argument to the call result.
            // Uses precise positional matching: param indices correspond to
            // call-site argument positions (ensured by lower_to_ssa_with_params).
            if !resolved_container_to_return.is_empty() {
                if let Some(dyn_ref) = transfer.dynamic_pts {
                    let mut container_pts_list: SmallVec<[PointsToSet; 2]> = SmallVec::new();
                    for &param_idx in &resolved_container_to_return {
                        if let Some(arg_group) = args.get(param_idx) {
                            for &arg_v in arg_group {
                                if let Some(pts) = lookup_pts(transfer, arg_v) {
                                    container_pts_list.push(pts);
                                }
                            }
                        }
                    }
                    if !container_pts_list.is_empty() {
                        let mut dyn_pts = dyn_ref.borrow_mut();
                        for pts in &container_pts_list {
                            match dyn_pts.get(&inst.value) {
                                Some(existing) => {
                                    let merged = existing.union(pts);
                                    dyn_pts.insert(inst.value, merged);
                                }
                                None => {
                                    dyn_pts.insert(inst.value, pts.clone());
                                }
                            }
                        }
                    }
                }
            }

            // Inter-procedural container store propagation:
            // If callee stores src_param taint into container_param's container,
            // use precise positional matching: param indices correspond to
            // call-site argument positions (ensured by lower_to_ssa_with_params).
            if !resolved_container_store.is_empty() {
                for &(src_param, container_param) in &resolved_container_store {
                    // Collect container pts at the specific arg position
                    let mut container_pts: SmallVec<[PointsToSet; 2]> = SmallVec::new();
                    if let Some(arg_group) = args.get(container_param) {
                        for &v in arg_group {
                            if let Some(pts) = lookup_pts(transfer, v) {
                                container_pts.push(pts);
                            }
                        }
                    }
                    if container_pts.is_empty() {
                        continue;
                    }
                    // Collect source taint at the specific arg position
                    let mut src_caps = Cap::empty();
                    let mut src_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                    if let Some(arg_group) = args.get(src_param) {
                        for &v in arg_group {
                            if let Some(taint) = state.get(v) {
                                src_caps |= taint.caps;
                                for orig in &taint.origins {
                                    push_origin_bounded(&mut src_origins, *orig);
                                }
                            }
                        }
                    }
                    // When the primary callee is a Source (e.g. req.query.input
                    // overrode storeInto as the callee), the source taint is
                    // produced as the call's return, not yet in args. Use
                    // return_bits as the source taint for the container store.
                    if src_caps.is_empty() && !return_bits.is_empty() {
                        src_caps = return_bits;
                        src_origins = return_origins.clone();
                    }
                    // Store source taint into container's heap objects
                    if !src_caps.is_empty() {
                        for pts in &container_pts {
                            state
                                .heap
                                .store_set(pts, HeapSlot::Elements, src_caps, &src_origins);
                        }
                    }
                }
            }

            // Parameter-granularity points-to summary application.
            //
            // Extends the container-store channel above (which catches
            // `arr.push(v)` / `map.set(k, v)`) to direct field writes like
            // `obj.x = val` that `classify_container_op` does not recognise.
            // The callee's `PointsToSummary` records May-alias edges between
            // parameter positions and the return; at the call site we replay
            // each edge against the caller's taint state.
            //
            //   * `Param(src) → Param(dst)`, union caller-arg[src]'s taint
            //     into caller-arg[dst]'s heap slot.  Sound because the
            //     callee *may* have stored data derived from arg[src] into
            //     an alias of arg[dst]; the caller must assume any later
            //     read from arg[dst] could surface that taint.
            //   * `Param(src) → Return`, union caller-arg[src]'s points-to
            //     set into the call's return value, giving the result the
            //     same heap identity as its input argument.  Overlaps with
            //     `param_container_to_return`; both channels are idempotent
            //     so re-propagation is safe.
            //
            // Fresh-container factory synthesis: when the callee's
            // `PointsToSummary` marks a return path as a fresh allocation
            // (container literal or known constructor not tracing to any
            // parameter), synthesise a `HeapObjectId` keyed on the call's
            // SSA value and seed it into `dynamic_pts`.  This closes the
            // factory-pattern cross-file gap, `const bag = makeBag()`
            // gives `bag` a stable heap identity so subsequent
            // `fillBag(bag, …)` / `bag[0]` operations have a heap cell
            // to store into or read from.
            //
            // Strictly additive: the existing `Param(i) → Return` edge
            // handling below joins the caller's argument pts when the
            // function also returns a parameter on some path, so a mixed
            // factory (`if (x) return []; else return arg`) carries both
            // the synthetic fresh cell and the aliased argument cells.
            if resolved_points_to.returns_fresh_alloc
                && let Some(dyn_ref) = transfer.dynamic_pts
            {
                let fresh = PointsToSet::singleton(HeapObjectId(inst.value));
                let mut dyn_pts = dyn_ref.borrow_mut();
                match dyn_pts.get(&inst.value) {
                    Some(existing) => {
                        let merged = existing.union(&fresh);
                        dyn_pts.insert(inst.value, merged);
                    }
                    None => {
                        dyn_pts.insert(inst.value, fresh);
                    }
                }
            }

            // Overflow (the callee's alias graph exceeded
            // `MAX_ALIAS_EDGES`): conservatively treat *every* parameter
            // as aliasing every other parameter and the return.
            if resolved_points_to.overflow || !resolved_points_to.edges.is_empty() {
                use crate::summary::points_to::AliasPosition;

                // Effective edge set: when overflow is signalled, synthesise
                // the conservative all-pairs graph instead of reading the
                // possibly-truncated edge vector.
                type ParamToParamEdges = SmallVec<[(usize, usize); 8]>;
                type ParamToReturnEdges = SmallVec<[usize; 4]>;
                let (param_to_param_edges, param_to_return_edges): (
                    ParamToParamEdges,
                    ParamToReturnEdges,
                ) = if resolved_points_to.overflow {
                    let n = args.len();
                    let mut p2p: SmallVec<[(usize, usize); 8]> = SmallVec::new();
                    let mut p2r: SmallVec<[usize; 4]> = SmallVec::new();
                    for i in 0..n {
                        p2r.push(i);
                        for j in 0..n {
                            if i != j {
                                p2p.push((i, j));
                            }
                        }
                    }
                    (p2p, p2r)
                } else {
                    let mut p2p: SmallVec<[(usize, usize); 8]> = SmallVec::new();
                    let mut p2r: SmallVec<[usize; 4]> = SmallVec::new();
                    for edge in &resolved_points_to.edges {
                        match (edge.source, edge.target) {
                            (AliasPosition::Param(s), AliasPosition::Param(t)) => {
                                p2p.push((s as usize, t as usize));
                            }
                            (AliasPosition::Param(s), AliasPosition::Return) => {
                                p2r.push(s as usize);
                            }
                            // Return → Param / Return → Return are not emitted
                            // by the points-to analysis; ignore defensively.
                            _ => {}
                        }
                    }
                    (p2p, p2r)
                };

                // Apply Param → Param edges: caller-arg[src] taint into
                // caller-arg[dst]'s heap objects *and* directly onto the
                // destination SSA value.  Store-into-heap handles later
                // container-style reads from `dst`'s pts set; the direct
                // taint ensures field reads expressed as `Assign uses=[dst]`
                // (the common case when the caller's heap analysis did
                // not register an allocation site for `dst`) still surface
                // the aliased taint.
                //
                // The loop must borrow `state` mutably (for the heap
                // store and the direct taint merge), so it is written
                // inline instead of split across helper closures.
                for (src, dst) in &param_to_param_edges {
                    // Collect src arg taint.
                    let mut src_caps = Cap::empty();
                    let mut src_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                    if let Some(arg_vals) = args.get(*src) {
                        for &v in arg_vals {
                            if let Some(taint) = state.get(v) {
                                src_caps |= taint.caps;
                                for orig in &taint.origins {
                                    push_origin_bounded(&mut src_origins, *orig);
                                }
                            }
                        }
                    }
                    if src_caps.is_empty() {
                        continue;
                    }
                    // Collect dst arg points-to for heap-level
                    // propagation (cloned out so the mutable
                    // `state.heap` borrow below is independent of the
                    // immutable PTS lookup).
                    let mut dst_pts: SmallVec<[PointsToSet; 2]> = SmallVec::new();
                    let mut dst_ssa_vals: SmallVec<[SsaValue; 2]> = SmallVec::new();
                    if let Some(arg_vals) = args.get(*dst) {
                        for &v in arg_vals {
                            dst_ssa_vals.push(v);
                            if let Some(pts) = lookup_pts(transfer, v) {
                                dst_pts.push(pts);
                            }
                        }
                    }
                    for pts in &dst_pts {
                        state
                            .heap
                            .store_set(pts, HeapSlot::Elements, src_caps, &src_origins);
                    }
                    // Direct-taint the dst SSA value(s).  Required when
                    // the caller's heap analysis has no allocation site
                    // for `dst` (common for plain class constructors in
                    // Python / JS / Java without fine-grained
                    // points-to).  Without this, later reads expressed
                    // as Assigns over `dst` would see no taint.
                    for dv in &dst_ssa_vals {
                        merge_taint_into(state, *dv, src_caps, &src_origins);
                    }
                }

                // Apply Param → Return edges: the call result inherits the
                // source argument's points-to set.  Re-runs the same
                // channel `resolved_container_to_return` drives a few
                // lines above, safe (idempotent union), and catches
                // cases where the callee returned a param through a
                // non-identity chain (e.g. `return Box::new(x)`).
                if !param_to_return_edges.is_empty()
                    && let Some(dyn_ref) = transfer.dynamic_pts
                {
                    for src in &param_to_return_edges {
                        let mut src_pts: SmallVec<[PointsToSet; 2]> = SmallVec::new();
                        if let Some(arg_vals) = args.get(*src) {
                            for &v in arg_vals {
                                if let Some(pts) = lookup_pts(transfer, v) {
                                    src_pts.push(pts);
                                }
                            }
                        }
                        if src_pts.is_empty() {
                            continue;
                        }
                        let mut dyn_pts = dyn_ref.borrow_mut();
                        for pts in &src_pts {
                            match dyn_pts.get(&inst.value) {
                                Some(existing) => {
                                    let merged = existing.union(pts);
                                    dyn_pts.insert(inst.value, merged);
                                }
                                None => {
                                    dyn_pts.insert(inst.value, pts.clone());
                                }
                            }
                        }
                    }
                }
            }

            // Alias-aware taint propagation: when a.field becomes tainted and
            // a/b are base aliases, b.field should also be tainted.
            if !return_bits.is_empty() {
                if let Some(aliases) = transfer.base_aliases {
                    if !aliases.is_empty() {
                        propagate_taint_to_aliases(
                            inst,
                            state,
                            return_bits,
                            &return_origins,
                            aliases,
                            ssa,
                        );
                    }
                }
            }

            // Outer-callee taint suppression: when find_classifiable_inner_call
            // overrode the callee (e.g. transform(req.query.data) → callee becomes
            // "req.query.data" Source, outer_callee="transform"), the Source label
            // produces return_bits. Check if the wrapper function blocks taint:
            // if its SSA summary shows no propagation, no source_caps, and no
            // container identity return, the return value is independent of its
            // arguments, clear return_bits.  Additionally apply the wrapper's
            // sanitizer caps (StripBits transforms) so a sanitising wrapper
            // like `validate(<source>)` clears the relevant cap bits even
            // when the wrapper still propagates other taint.
            if !return_bits.is_empty() && has_source_label {
                if let Some(ref oc) = info.call.outer_callee {
                    if let Some(ref oc_sum) = resolve_callee_hinted(
                        transfer,
                        oc,
                        caller_func,
                        info.call.call_ordinal,
                        arity_hint,
                    ) {
                        if !oc_sum.propagates_taint && oc_sum.source_caps.is_empty() {
                            // Outer callee blocks taint: no param→return flow,
                            // no internal sources reaching return.
                            return_bits = Cap::empty();
                            return_origins.clear();
                        } else if !oc_sum.sanitizer_caps.is_empty() {
                            return_bits &= !oc_sum.sanitizer_caps;
                        }
                    }
                }
            }

            // Chain-wrapper sanitizer suppression: when the chain shape
            // `outer(... wrapper(<source>) ...)` puts a sanitising wrapper
            // function between the inner Source and the outer call,
            // mark the call result's symbol as validated so any
            // downstream sink event over the same value fires with
            // `all_validated = true`, suppressing the taint finding and
            // (via [`record_path_safe_suppressed_span`]) the
            // `state-unauthed-access` finding on the same span.
            // `chain_wrapper_sanitizer_caps` is computed up-front above
            // so the container-element-write hook can also consult it.
            if has_source_label && !chain_wrapper_sanitizer_caps.is_empty() {
                if let Some(name) = ssa
                    .value_defs
                    .get(inst.value.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    if let Some(sym) = transfer.interner.get(name) {
                        state.validated_must.insert(sym);
                        state.validated_may.insert(sym);
                    }
                }
            }

            // JS/TS array-method validator-callback narrowing.  When a
            // call shape matches `<arr>.filter(<recognised-validator>)`
            // (or `find` / `findLast`), strip the caps that flowed into
            // `return_bits` from the receiver — the result holds only
            // elements the validator approved.  Strict-additive: the
            // helper is a no-op when the callback name does not match
            // the BooleanTrueIsValid bucket, leaving the default
            // propagation result unchanged.  See
            // [`try_array_method_validator_callback_narrowing`] for the
            // motivating CVE pair.
            try_array_method_validator_callback_narrowing(
                inst,
                info,
                callee,
                args,
                &mut return_bits,
                &mut return_origins,
                state,
                transfer,
                ssa,
            );

            // Constructor cap narrowing: a `new X(...)` call returns an object
            // instance, not a string. Caps that name a string-shaped sink
            // pattern (path argument, format string, URL component, JSON
            // input) cannot fire on a wrapper object, so they must not
            // survive the construction. Without this narrowing, a tainted
            // argument to `new SdkClient(secret)` propagates `Cap::all()`
            // into the wrapper, every method call on the wrapper inherits
            // those bits via receiver propagation, and any downstream
            // `fs.write*` / `printf` / `JSON.parse` on a string property
            // returned by an SDK method (e.g. `client.create().id`) flags
            // a phantom flow that has no real path-traversal etc. payload.
            //
            // Caps preserved (legitimately travel through wrappers):
            //   - SHELL_ESCAPE / SQL_QUERY / CODE_EXEC / DESERIALIZE: a
            //     wrapper that captures a tainted command/query string can
            //     replay it via methods, the bit must survive the wrap.
            //   - SSRF / DATA_EXFIL: URL/payload concerns persist on URL or
            //     content-bearing objects.
            //   - UNAUTHORIZED_ID: ownership obligation persists on a
            //     wrapper that carries a request-bound identifier.
            //   - ENV_VAR: provenance marker, never a sink trigger by
            //     itself.
            //   - HTML_ESCAPE: kept for safety, conservative dual concern
            //     (a wrapper used as a string in template rendering).
            //   - CRYPTO: kept conservatively.
            //
            // Caps stripped on construction:
            //   - FILE_IO: path strings only.
            //   - FMT_STRING: printf-style format args only.
            //   - URL_ENCODE: URL components only.
            //   - JSON_PARSE: parser inputs only.
            if info.call.is_constructor && !return_bits.is_empty() {
                let strip = Cap::FILE_IO | Cap::FMT_STRING | Cap::URL_ENCODE | Cap::JSON_PARSE;
                return_bits &= !strip;
                if return_bits.is_empty() {
                    return_origins.clear();
                }
            }

            // Write result
            if return_bits.is_empty() {
                state.remove(inst.value);
            } else {
                state.set(
                    inst.value,
                    VarTaint {
                        caps: return_bits,
                        origins: return_origins,
                        uses_summary: resolved_callee,
                    },
                );
            }
        }

        SsaOp::Assign(uses) => {
            // Check for sanitizer labels
            let mut sanitizer_bits = Cap::empty();
            for lbl in &info.taint.labels {
                if let DataLabel::Sanitizer(bits) = lbl {
                    sanitizer_bits |= *bits;
                }
            }

            // Collect taint from operands.  Equality-with-constant comparisons
            // (`x === 'literal'`) produce a boolean result that carries no
            // attacker-controlled data, so skip unioning operand caps into the
            // result.  Source/sanitizer labels on this same node still apply
            // normally below.
            let mut combined_caps = Cap::empty();
            let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            let mut inherited_summary = false;

            if !info.is_eq_with_const {
                for &use_val in uses {
                    if let Some(taint) = state.get(use_val) {
                        combined_caps |= taint.caps;
                        inherited_summary |= taint.uses_summary;
                        for orig in &taint.origins {
                            push_origin_bounded(&mut combined_origins, *orig);
                        }
                    }
                }
            }

            // Synthetic field-write inheritance.  When SSA lowering emits
            // `u_new = Assign(rhs)` to model `u.f = rhs` (an obj-update
            // synth), `u_new` represents the same logical object after the
            // field write, it retains every other field's taint.  The
            // base-only Assign uses include only the rhs, so without this
            // step a clean rhs (`u.Path = "/foo"`) would zero out every
            // tainted field on the prior `u`.  Owncast CVE-2023-3188 hit
            // this: `requestURL.Path = "/.well-known/webfinger"` killed the
            // tainted host carried by `requestURL` from `url.Parse(tainted)`.
            if let Some((receiver, _fid)) = ssa.field_writes.get(&inst.value).copied() {
                if let Some(taint) = state.get(receiver) {
                    combined_caps |= taint.caps;
                    inherited_summary |= taint.uses_summary;
                    for orig in &taint.origins {
                        push_origin_bounded(&mut combined_origins, *orig);
                    }
                }
            }

            // Apply sanitizer
            combined_caps &= !sanitizer_bits;

            // Alias-aware sanitization: propagate through must-aliased field paths
            if !sanitizer_bits.is_empty() {
                if let Some(aliases) = transfer.base_aliases {
                    if !aliases.is_empty() {
                        propagate_sanitization_to_aliases(
                            inst,
                            state,
                            sanitizer_bits,
                            aliases,
                            ssa,
                        );
                    }
                }
            }

            // Check for source labels
            for lbl in &info.taint.labels {
                if let DataLabel::Source(bits) = lbl {
                    combined_caps |= *bits;
                    let callee_str = info.call.callee.as_deref().unwrap_or("");
                    let source_kind = crate::labels::infer_source_kind(*bits, callee_str);
                    let origin = TaintOrigin {
                        node: inst.cfg_node,
                        source_kind,
                        source_span: None,
                    };
                    push_origin_bounded(&mut combined_origins, origin);
                }
            }

            // Alias-aware taint propagation
            if !combined_caps.is_empty() {
                if let Some(aliases) = transfer.base_aliases {
                    if !aliases.is_empty() {
                        propagate_taint_to_aliases(
                            inst,
                            state,
                            combined_caps,
                            &combined_origins,
                            aliases,
                            ssa,
                        );
                    }
                }
            }

            if combined_caps.is_empty() {
                state.remove(inst.value);
            } else {
                state.set(
                    inst.value,
                    VarTaint {
                        caps: combined_caps,
                        origins: combined_origins.clone(),
                        uses_summary: inherited_summary,
                    },
                );
            }

            // Synthetic base-update Assign emitted by SSA lowering for
            // `obj.f = rhs`. The side-table maps this synth assign's
            // value → (prior_receiver, FieldId), so we lift it into a
            // field WRITE: union rhs taint into every `(loc, field)`
            // cell for non-Top `loc ∈ pt(prior_receiver)`.
            if let Some(pf) = transfer.pointer_facts {
                if let Some((receiver, fid)) = ssa.field_writes.get(&inst.value).copied() {
                    let pt = pf.pt(receiver);
                    if !pt.is_empty() && !pt.is_top() && !combined_caps.is_empty() {
                        let rhs_taint = VarTaint {
                            caps: combined_caps,
                            origins: combined_origins.clone(),
                            uses_summary: inherited_summary,
                        };
                        // W4: validation channels lift from the rhs's
                        // symbol-level bits.  An anonymous SSA temp on
                        // the rhs has no name → contributes (false,
                        // false), matching "no validation".  An Assign
                        // with multiple operands ANDs `must` (every
                        // operand must be must-validated for the cell)
                        // and ORs `may`.
                        let mut must_all = true;
                        let mut may_any = false;
                        let mut saw_use = false;
                        if let SsaOp::Assign(uses) = &inst.op {
                            for &u in uses {
                                saw_use = true;
                                let (am, av) =
                                    ssa_value_validated_bits(u, ssa, transfer.interner, state);
                                must_all &= am;
                                may_any |= av;
                            }
                        }
                        if !saw_use {
                            must_all = false;
                        }
                        for loc in pt.iter() {
                            let key = crate::taint::ssa_transfer::state::FieldTaintKey {
                                loc,
                                field: fid,
                            };
                            state.add_field(key, rhs_taint.clone(), must_all, may_any);
                        }
                    }
                }
            }
        }

        SsaOp::Const(_) | SsaOp::Nop => {
            // No taint, this is the kill mechanism for `x = "literal"` after
            // `x = source()`.  The fresh SsaValue carries zero caps.
        }

        SsaOp::Param { .. } | SsaOp::SelfParam => {
            // Seeding order for inbound taint on this body's param:
            //   1. Per-call-site seed (inline analysis only).
            //      `param_seed[index]` for `Param { index }`, or
            //      `receiver_seed` for `SelfParam`.  Takes precedence
            //      because it reflects the exact caller argument taint
            //      for this specific call.
            //   2. Lexical-scope seed (`global_seed`), read in ancestor
            //      order: parent body first, then the top-level scope
            //      (`BodyId(0)`) to pick up re-keyed JS/TS combined_exit
            //      entries (see `filter_seed_to_toplevel`).
            //
            // `SelfParam` receives the same treatment as positional `Param`:
            // both represent inbound values whose taint comes from the
            // surrounding scope.
            let mut seeded_from_scope = false;

            // Step 1: per-call-site seed for inline analysis.
            let per_call_taint: Option<&VarTaint> = match &inst.op {
                SsaOp::Param { index } => transfer
                    .param_seed
                    .and_then(|ps| ps.get(*index))
                    .and_then(|slot| slot.as_ref()),
                SsaOp::SelfParam => transfer.receiver_seed,
                _ => None,
            };
            if let Some(taint) = per_call_taint {
                let remapped_origins: SmallVec<[TaintOrigin; 2]> = taint
                    .origins
                    .iter()
                    .map(|o| TaintOrigin {
                        node: inst.cfg_node,
                        source_kind: o.source_kind,
                        source_span: o.source_span,
                    })
                    .collect();
                state.set(
                    inst.value,
                    VarTaint {
                        caps: taint.caps,
                        origins: remapped_origins,
                        uses_summary: true,
                    },
                );
                seeded_from_scope = true;
            }

            // Step 2: lexical-scope seed via ancestor-chain lookup.
            if !seeded_from_scope {
                if let Some(seed) = &transfer.global_seed {
                    if let Some(var_name) = ssa
                        .value_defs
                        .get(inst.value.0 as usize)
                        .and_then(|vd| vd.var_name.as_deref())
                    {
                        // Ancestor chain: parent body first (for direct
                        // lexical captures), then BodyId(0) (for JS/TS
                        // pass-2 re-keyed entries).  Deduplicated so a
                        // body whose parent is already the top-level
                        // only looks up once.
                        let mut ancestors: SmallVec<[BodyId; 2]> = SmallVec::new();
                        if let Some(pid) = transfer.parent_body_id {
                            ancestors.push(pid);
                        }
                        if !ancestors.contains(&BodyId(0)) {
                            ancestors.push(BodyId(0));
                        }

                        for body_id in ancestors {
                            let key = BindingKey::new(var_name, body_id);
                            if let Some(taint) = seed_lookup(seed, &key) {
                                // Remap origins to this body's Param cfg_node:
                                // the meaningful anchor where taint enters
                                // this body.  Preserve source_span for
                                // diagnostics (captured in
                                // extract_ssa_exit_state).
                                let remapped_origins: SmallVec<[TaintOrigin; 2]> = taint
                                    .origins
                                    .iter()
                                    .map(|o| TaintOrigin {
                                        node: inst.cfg_node,
                                        source_kind: o.source_kind,
                                        source_span: o.source_span,
                                    })
                                    .collect();
                                state.set(
                                    inst.value,
                                    VarTaint {
                                        caps: taint.caps,
                                        origins: remapped_origins,
                                        uses_summary: true,
                                    },
                                );
                                seeded_from_scope = true;
                                break;
                            }
                        }
                    }
                }
            }

            // Handler-param auto-seed: formal parameters whose names imply
            // user input (e.g. `userInput`, `payload`, `cmd`) start tainted
            // so downstream sinks still fire when a function has no
            // registered caller (typical for controller methods, handler
            // dispatch functions, and stream lambda bodies). Skipped in
            // summary-extraction mode so baseline probes keep their
            // intrinsic-source contract. Gate is set by the caller, e.g.
            // always-on for JS/TS, only AnonymousFunction bodies for Java.
            //
            // The `Param` branch fires for both real formal parameters and
            // synthetic externals injected by lowering for free / closure-
            // captured variables (`SsaBody.synthetic_externals`).  Only real
            // formals should receive the heuristic seed: a closure capturing
            // an out-of-scope `userId` / `cmd` / `payload` is NOT a handler
            // entry point — the variable is supplied by the enclosing scope
            // and seeding it here produces phantom sources anchored to the
            // function's declaration line.
            if transfer.auto_seed_handler_params
                && !seeded_from_scope
                && matches!(&inst.op, SsaOp::Param { .. })
                && !ssa.synthetic_externals.contains(&inst.value)
            {
                if let Some(var_name) = ssa
                    .value_defs
                    .get(inst.value.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    // Direct match: the Param's name itself is a handler
                    // identifier (e.g. `input`, `cmd`, `userId`).
                    //
                    // Root-prefix match: dotted-path Params produced by
                    // lowering for member-expression uses inside the body
                    // (`input.cmd` — an unbacked phantom Param) inherit the
                    // seed when their *root* is a handler-param formal.
                    // Without this, the field-aware suppression downstream
                    // sees `input.cmd` as a "clean field" and strips
                    // `input`'s taint, even though `input.cmd` is just a
                    // structural projection of the auto-seeded formal.
                    let root_is_handler = var_name
                        .split_once('.')
                        .map(|(root, _)| crate::labels::is_js_ts_handler_param_name(root))
                        .unwrap_or(false);
                    if crate::labels::is_js_ts_handler_param_name(var_name) || root_is_handler {
                        let origin = TaintOrigin {
                            node: inst.cfg_node,
                            source_kind: SourceKind::UserInput,
                            source_span: None,
                        };
                        state.set(
                            inst.value,
                            VarTaint {
                                caps: Cap::all(),
                                origins: SmallVec::from_elem(origin, 1),
                                uses_summary: false,
                            },
                        );
                    }
                }
            }
        }

        SsaOp::Phi(_) => {
            // Phis processed separately above, shouldn't appear in body
        }

        SsaOp::Undef => {
            // Undef is a phi-operand sentinel that lives in block 0's
            // body so it has a valid `value_defs` entry. It contributes
            // no taint: leave `state` unchanged so the phi operand
            // lookup (`state.get(operand_val)`) returns `None` for
            // predecessors whose incoming edge carries no definition.
        }

        SsaOp::FieldProj {
            receiver, field, ..
        } => {
            // Field projection: pass the receiver's full taint record
            // through to the projected value. Untainted receiver →
            // untainted projection (no entry inserted).
            let mut combined: Option<VarTaint> = state.get(*receiver).cloned();

            // W4: collect cell validation channels alongside taint.
            // `must` AND-intersects across the contributing cells; a
            // single un-validated cell wins because it represents a
            // path on which the projection isn't validated.  `may`
            // OR-unions.
            let mut cell_must_all: Option<bool> = None;
            let mut cell_may_any = false;

            // When per-body PointsToFacts are available, also union
            // taint from each `(loc, field)` cell for `loc ∈ pt(receiver)`.
            // Carries cross-method field flow within a single body.
            if let Some(pf) = transfer.pointer_facts {
                let pt = pf.pt(*receiver);
                if !pt.is_empty() && !pt.is_top() {
                    for loc in pt.iter() {
                        // Read the specific `(loc, *field)` cell first
                        // (per-field-name flow from cross-call writes).
                        // When it's absent, fall back to the
                        // `(loc, ANY_FIELD)` wildcard, populated by the
                        // [`ContainerOp::Writeback`] handler for sinks
                        // like `json.NewDecoder(r.Body).Decode(&dest)`
                        // that taint every field of the destination
                        // wholesale.  The fallback is gated on
                        // specific-field absence so existing field-cell
                        // semantics are bit-identical when the writer
                        // used a named field. ANY_FIELD is distinct
                        // from `ELEM` (container-element wildcard) to
                        // avoid a struct-with-`length`-field reading
                        // taint from a sibling array's `push` writes.
                        let mut hit_specific = false;
                        for field_id in [*field, crate::ssa::ir::FieldId::ANY_FIELD].iter().copied()
                        {
                            if field_id == crate::ssa::ir::FieldId::ANY_FIELD && hit_specific {
                                break;
                            }
                            if field_id == crate::ssa::ir::FieldId::ANY_FIELD
                                && *field == crate::ssa::ir::FieldId::ANY_FIELD
                            {
                                continue;
                            }
                            let key = crate::taint::ssa_transfer::state::FieldTaintKey {
                                loc,
                                field: field_id,
                            };
                            if let Some(cell) = state.get_field(key) {
                                if field_id == *field {
                                    hit_specific = true;
                                }
                                let t = cell.taint.clone();
                                cell_must_all = Some(match cell_must_all {
                                    Some(prev) => prev && cell.validated_must,
                                    None => cell.validated_must,
                                });
                                cell_may_any |= cell.validated_may;
                                combined = Some(match combined {
                                    Some(mut acc) => {
                                        acc.caps |= t.caps;
                                        acc.uses_summary |= t.uses_summary;
                                        // A7 audit: route the cell's origins
                                        // through `push_origin_bounded` so the
                                        // cap-driven survivor selection (sorted
                                        // by `origin_sort_key`, deterministic
                                        // truncation when over cap, observability
                                        // counter increments) applies the same
                                        // way as the per-SSA-value lattice.  The
                                        // pre-A7 inline walk only deduped by
                                        // node and silently grew past
                                        // `effective_max_origins` when the cell
                                        // had a wider origin set than the cap.
                                        for o in &t.origins {
                                            push_origin_bounded(&mut acc.origins, *o);
                                        }
                                        acc
                                    }
                                    None => {
                                        // First contribution: still apply the
                                        // bounded-push so a cell built up
                                        // above-cap upstream gets re-bounded
                                        // here at read time.  `push_origin_bounded`
                                        // dedups by node, sorts deterministically.
                                        let mut bounded: SmallVec<[TaintOrigin; 2]> =
                                            SmallVec::new();
                                        for o in &t.origins {
                                            push_origin_bounded(&mut bounded, *o);
                                        }
                                        VarTaint {
                                            caps: t.caps,
                                            origins: bounded,
                                            uses_summary: t.uses_summary,
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            }

            if let Some(t) = combined {
                state.set(inst.value, t);
            }

            // W4: seed the projected value's symbol-level validation
            // bits from the cells that fed it.  This is the read-side
            // counterpart to the W1 / W2 / W3 cell-write hooks: if
            // every cell that contributed to this projection was
            // must-validated, the projected value is must-validated;
            // any may-validated cell sets may.  Skipped when no cell
            // contributed (`cell_must_all == None`).
            if let Some(must_all) = cell_must_all {
                if let Some(name) = ssa
                    .value_defs
                    .get(inst.value.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                {
                    if let Some(sym) = transfer.interner.get(name) {
                        if must_all {
                            state.validated_must.insert(sym);
                        }
                        if cell_may_any {
                            state.validated_may.insert(sym);
                        }
                    }
                }
            }
        }
    }

    // Container read counterpart, post-match. Also invoked inline
    // before container-handled early-returns inside the Call arm.
    if matches!(&inst.op, SsaOp::Call { .. }) {
        apply_container_elem_read_w4(inst, ssa, transfer, state);
    }

    // Constraint propagation through instructions
    if let Some(ref mut env) = state.path_env {
        match &inst.op {
            SsaOp::Assign(uses) if uses.len() == 1 => {
                // Copy: propagate facts from source to destination
                let src_fact = env.get(uses[0]);
                if !src_fact.is_top() {
                    env.refine(inst.value, &src_fact);
                    env.assert_equal(inst.value, uses[0]);
                }
                // Cast/assertion type narrowing.
                //
                // If this Assign's CFG node is a cast/type-assertion expression,
                // narrow the destination value's type in PathEnv.
                //
                // Semantics vary by language:
                // - Java casts: runtime-checked, type is reliably narrowed
                // - TypeScript `as`: compile-time assertion only, not runtime proof
                // - Go type assertions: runtime-checked (direct form)
                //
                // In ALL cases: taint is preserved. Narrowing the type does NOT
                // erase taint, a tainted value cast to String is still tainted.
                let node_info = &cfg[inst.cfg_node];
                if let Some(ref cast_type) = node_info.cast_target_type {
                    if let Some(kind) = crate::constraint::solver::parse_type_name(cast_type) {
                        let mut fact = constraint::ValueFact::top();
                        fact.types = constraint::TypeSet::singleton(&kind);
                        fact.null = constraint::Nullability::NonNull;
                        env.refine(inst.value, &fact);
                    }
                }
            }
            SsaOp::Const(Some(text)) => {
                // Constant: seed fact from literal value
                if let Some(cv) = constraint::ConstValue::parse_literal(text) {
                    let mut fact = constraint::ValueFact::top();
                    fact.exact = Some(cv.clone());
                    match &cv {
                        constraint::ConstValue::Int(i) => {
                            fact.lo = Some(*i);
                            fact.hi = Some(*i);
                            fact.types = constraint::TypeSet::singleton(
                                &crate::ssa::type_facts::TypeKind::Int,
                            );
                            fact.null = constraint::Nullability::NonNull;
                        }
                        constraint::ConstValue::Bool(b) => {
                            fact.bool_state = if *b {
                                constraint::BoolState::True
                            } else {
                                constraint::BoolState::False
                            };
                            fact.types = constraint::TypeSet::singleton(
                                &crate::ssa::type_facts::TypeKind::Bool,
                            );
                            fact.null = constraint::Nullability::NonNull;
                        }
                        constraint::ConstValue::Null => {
                            fact.null = constraint::Nullability::Null;
                            fact.types = constraint::TypeSet::singleton(
                                &crate::ssa::type_facts::TypeKind::Null,
                            );
                        }
                        constraint::ConstValue::Str(_) => {
                            fact.types = constraint::TypeSet::singleton(
                                &crate::ssa::type_facts::TypeKind::String,
                            );
                            fact.null = constraint::Nullability::NonNull;
                        }
                    }
                    env.refine(inst.value, &fact);
                }
            }
            _ => {
                // All other ops: no constraint propagation (conservative)
            }
        }
    }

    // Forward abstract value transfer
    if let Some(ref mut abs) = state.abstract_state {
        transfer_abstract(inst, cfg, abs, Some(transfer.lang));
    }

    // Cross-file abstract return injection.
    // Applied after transfer_abstract so summary-provided facts override the
    // default Top that transfer_abstract assigns to unknown callees.
    if let Some(ref abs_val) = callee_return_abstract {
        if let Some(ref mut abs) = state.abstract_state {
            abs.set(inst.value, abs_val.clone());
        }
    }
}

/// Resolve a URL builder's `(base)` arg to a concrete origin string when
/// either (a) the call site recorded a syntactic string literal at
/// `base_idx`, or (b) the SSA value at that arg position carries an
/// abstract-string singleton domain (typical for
/// `const BASE = "https://..."; new URL(path, BASE)`).
///
/// Returning `Some(s)` means the prefix-lock arm can seed the result's
/// [`StringFact`] via [`StringFact::from_url_with_base`].
fn url_builder_concrete_base(
    info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    abs: &AbstractState,
    base_idx: usize,
) -> Option<String> {
    if let Some(s) = info
        .call
        .arg_string_literals
        .get(base_idx)
        .and_then(|s| s.as_deref())
    {
        return Some(s.to_string());
    }
    let bv = args.get(base_idx).and_then(|g| g.first().copied())?;
    let dom = abs.get(bv).string.domain?;
    if dom.len() == 1 {
        Some(dom.into_iter().next().expect("len==1 guards index"))
    } else {
        None
    }
}

/// Compute abstract values for an SSA instruction.
///
/// Propagates interval and string domain facts forward through constants,
/// copies, binary arithmetic, and concatenation. Conservative (Top) for
/// unknown operations (calls, sources, params).
///
/// `lang` is consulted only for language-specific transfer rules (currently
/// Rust path primitives, `fs::canonicalize`, `.starts_with`, etc.); `None`
/// disables them and matches the pre-PathFact behaviour exactly.
fn transfer_abstract(inst: &SsaInst, cfg: &Cfg, abs: &mut AbstractState, lang: Option<Lang>) {
    use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, PathFact, StringFact};
    use crate::cfg::BinOp;

    let info = &cfg[inst.cfg_node];
    match &inst.op {
        SsaOp::Const(Some(text)) => {
            let trimmed = text.trim();
            // Try integer
            if let Ok(n) = trimmed.parse::<i64>() {
                abs.set(
                    inst.value,
                    AbstractValue {
                        interval: IntervalFact::exact(n),
                        string: StringFact::top(),
                        bits: BitFact::from_const(n),
                        path: PathFact::top(),
                    },
                );
            } else if is_string_const(trimmed) {
                let s = strip_string_quotes(trimmed);
                // String literal: derive PathFact axes from the *literal*
                // content.  An empty string has no `..` segment and no
                // absolute root, both axes proven safe, so a Const `""`
                // (Python / JS / TS / Java rejection-arm sentinel) carries a
                // path-safe fact even without a per-language allocator
                // recogniser like Rust's `String::new()`.  Non-empty
                // literals also surface their own dotdot/absolute axes
                // when the literal text proves them.
                let mut pf = PathFact::top();
                if !s.contains("..") {
                    pf = pf.with_dotdot_cleared();
                }
                if !(s.starts_with('/') || s.starts_with('\\')) {
                    pf = pf.with_absolute_cleared();
                }
                abs.set(
                    inst.value,
                    AbstractValue {
                        interval: IntervalFact::top(),
                        string: StringFact::exact(&s),
                        bits: BitFact::top(),
                        path: pf,
                    },
                );
            }
            // Bool/Null/other: leave as Top
        }

        // Template-literal / string-prefix override: when the RHS is
        // `\`scheme://host/…${x}\`` or `"scheme://host/" + x`, seed the
        // result's StringFact prefix regardless of interpolation arity. Taint
        // still flows through the normal taint lattice; the prefix is only
        // consumed by `is_string_safe_for_ssrf` to suppress SSRF sinks on
        // fixed-host URLs. Placed before the arithmetic/copy arms so it wins
        // over the default Top StringFact.
        SsaOp::Assign(_) if info.string_prefix.is_some() => {
            let prefix = info.string_prefix.as_deref().unwrap();
            abs.set(
                inst.value,
                AbstractValue {
                    interval: IntervalFact::top(),
                    string: StringFact::from_prefix(prefix),
                    bits: BitFact::top(),
                    path: PathFact::top(),
                },
            );
        }

        // Same prefix-from-CFG override for Call instructions whose result is
        // the variable binding (e.g. `url = wrapper('lit' + userPath)`).  The
        // CFG node carries `string_prefix` extracted from the call's first
        // positional argument; without this arm the Call result's StringFact
        // is Top and downstream SSRF suppression (`is_call_abstract_safe`
        // looking at `axios.get(url)`'s own first arg) cannot read the lock.
        // Mirrors the same passthrough-heuristic that the
        // `is_call_abstract_safe` node-attached check at the sink site
        // already relies on.
        SsaOp::Call { .. } if info.string_prefix.is_some() => {
            let prefix = info.string_prefix.as_deref().unwrap();
            abs.set(
                inst.value,
                AbstractValue {
                    interval: IntervalFact::top(),
                    string: StringFact::from_prefix(prefix),
                    bits: BitFact::top(),
                    path: PathFact::top(),
                },
            );
        }

        SsaOp::Assign(uses) if uses.len() == 1 => {
            // Single-use Assign with bin_op + literal operand.
            // When a binary expression like `x & 0x07` has one identifier use
            // and one numeric literal, the SSA sees only the identifier (1 use).
            // Use bin_op_const from the CFG node to reconstruct the full binary
            // operation for abstract transfer.
            if let (Some(bin_op), Some(const_val)) = (info.bin_op, info.bin_op_const) {
                let var_abs = abs.get(uses[0]);
                let const_abs = AbstractValue {
                    interval: IntervalFact::exact(const_val),
                    string: StringFact::top(),
                    bits: BitFact::from_const(const_val),
                    path: PathFact::top(),
                };
                let result_interval = match bin_op {
                    BinOp::Add => var_abs.interval.add(&const_abs.interval),
                    BinOp::Sub => var_abs.interval.sub(&const_abs.interval),
                    BinOp::Mul => var_abs.interval.mul(&const_abs.interval),
                    BinOp::Div => var_abs.interval.div(&const_abs.interval),
                    BinOp::Mod => var_abs.interval.modulo(&const_abs.interval),
                    BinOp::BitAnd => var_abs.interval.bit_and(&const_abs.interval),
                    BinOp::BitOr => var_abs.interval.bit_or(&const_abs.interval),
                    BinOp::BitXor => var_abs.interval.bit_xor(&const_abs.interval),
                    BinOp::LeftShift => var_abs.interval.left_shift(&const_abs.interval),
                    BinOp::RightShift => var_abs.interval.right_shift(&const_abs.interval),
                    BinOp::Eq
                    | BinOp::NotEq
                    | BinOp::Lt
                    | BinOp::LtEq
                    | BinOp::Gt
                    | BinOp::GtEq => IntervalFact {
                        lo: Some(0),
                        hi: Some(1),
                    },
                };
                let result_bits = match bin_op {
                    BinOp::BitAnd => var_abs.bits.bit_and(&const_abs.bits),
                    BinOp::BitOr => var_abs.bits.bit_or(&const_abs.bits),
                    BinOp::BitXor => var_abs.bits.bit_xor(&const_abs.bits),
                    BinOp::LeftShift => var_abs.bits.left_shift(&const_abs.interval),
                    BinOp::RightShift => var_abs.bits.right_shift(&const_abs.interval),
                    _ => BitFact::top(),
                };
                let val = AbstractValue {
                    interval: result_interval,
                    string: StringFact::top(),
                    bits: result_bits,
                    path: PathFact::top(),
                };
                if !val.is_top() {
                    abs.set(inst.value, val);
                }
            } else {
                // Copy: propagate abstract value (including bits)
                let src = abs.get(uses[0]);
                if !src.is_top() {
                    abs.set(inst.value, src);
                }
            }
        }

        SsaOp::Assign(uses) if uses.len() == 2 => {
            let lhs_abs = abs.get(uses[0]);
            let rhs_abs = abs.get(uses[1]);

            if let Some(bin_op) = info.bin_op {
                // Known operator → apply interval transfer
                let result_interval = match bin_op {
                    BinOp::Add => lhs_abs.interval.add(&rhs_abs.interval),
                    BinOp::Sub => lhs_abs.interval.sub(&rhs_abs.interval),
                    BinOp::Mul => lhs_abs.interval.mul(&rhs_abs.interval),
                    BinOp::Div => lhs_abs.interval.div(&rhs_abs.interval),
                    BinOp::Mod => lhs_abs.interval.modulo(&rhs_abs.interval),
                    BinOp::BitAnd => lhs_abs.interval.bit_and(&rhs_abs.interval),
                    BinOp::BitOr => lhs_abs.interval.bit_or(&rhs_abs.interval),
                    BinOp::BitXor => lhs_abs.interval.bit_xor(&rhs_abs.interval),
                    BinOp::LeftShift => lhs_abs.interval.left_shift(&rhs_abs.interval),
                    BinOp::RightShift => lhs_abs.interval.right_shift(&rhs_abs.interval),
                    // Comparisons produce boolean 0/1
                    BinOp::Eq
                    | BinOp::NotEq
                    | BinOp::Lt
                    | BinOp::LtEq
                    | BinOp::Gt
                    | BinOp::GtEq => IntervalFact {
                        lo: Some(0),
                        hi: Some(1),
                    },
                };
                // For Add: also handle string concatenation (+ is overloaded)
                let result_string = if bin_op == BinOp::Add {
                    lhs_abs.string.concat(&rhs_abs.string)
                } else {
                    StringFact::top()
                };
                // Bitwise transfer via BitFact subdomain
                let result_bits = match bin_op {
                    BinOp::BitAnd => lhs_abs.bits.bit_and(&rhs_abs.bits),
                    BinOp::BitOr => lhs_abs.bits.bit_or(&rhs_abs.bits),
                    BinOp::BitXor => lhs_abs.bits.bit_xor(&rhs_abs.bits),
                    BinOp::LeftShift => lhs_abs.bits.left_shift(&rhs_abs.interval),
                    BinOp::RightShift => lhs_abs.bits.right_shift(&rhs_abs.interval),
                    _ => BitFact::top(),
                };
                let val = AbstractValue {
                    interval: result_interval,
                    string: result_string,
                    bits: result_bits,
                    path: PathFact::top(),
                };
                if !val.is_top() {
                    abs.set(inst.value, val);
                }
            } else {
                // Unknown operator: conservative for interval and bits,
                // but still propagate string concat (prefix from LHS, suffix from RHS)
                let string_result = lhs_abs.string.concat(&rhs_abs.string);
                if !string_result.is_top() {
                    abs.set(
                        inst.value,
                        AbstractValue {
                            interval: IntervalFact::top(),
                            string: string_result,
                            bits: BitFact::top(),
                            path: PathFact::top(),
                        },
                    );
                }
            }
        }

        // Phase 08 / Phase 14 — `(base, path)` URL builder origin-lock.
        // When the base arg is a literal (read off
        // `info.call.arg_string_literals[base_idx]`) or a const-bound
        // identifier whose abstract `StringFact.domain` is a singleton
        // (e.g. `const BASE = "https://api.cal.com"; new URL(path, BASE)`),
        // seed the result's [`StringFact`] with
        // `from_url_with_base(base, path_string)` so the locked-host
        // prefix survives even when the path component carries arbitrary
        // taint. `is_string_safe_for_ssrf` honours the prefix and
        // suppresses the SSRF sink at the downstream HTTP call. The
        // arg-position table lives in
        // [`crate::ssa::type_facts::url_builder_arg_indices`] — covers
        // JS/TS `new URL(path, base)`, Python `urljoin(base, path)`,
        // Go `url.JoinPath(base, ...)`, Java `new URL(URL, spec)`,
        // Ruby `URI.join(base, path)`.
        SsaOp::Call { callee, args, .. }
            if lang
                .and_then(|l| {
                    crate::ssa::type_facts::url_builder_arg_indices(
                        l,
                        callee,
                        info.call.outer_callee.as_deref(),
                        info.call.is_constructor,
                    )
                })
                .is_some_and(|(_p, base_idx)| {
                    url_builder_concrete_base(info, args, abs, base_idx).is_some()
                }) =>
        {
            let lang_u = lang.expect("guard ensures lang.is_some()");
            let (path_idx, base_idx) = crate::ssa::type_facts::url_builder_arg_indices(
                lang_u,
                callee,
                info.call.outer_callee.as_deref(),
                info.call.is_constructor,
            )
            .expect("guard ensures Some");
            let base = url_builder_concrete_base(info, args, abs, base_idx)
                .expect("guard ensures Some");
            let path_string = args
                .get(path_idx)
                .and_then(|g| g.first().copied())
                .map(|pv| abs.get(pv).string)
                .unwrap_or_else(StringFact::top);
            abs.set(
                inst.value,
                AbstractValue {
                    interval: IntervalFact::top(),
                    string: StringFact::from_url_with_base(&base, &path_string),
                    bits: BitFact::top(),
                    path: PathFact::top(),
                },
            );
        }

        // Phase 14 — single-arg URL/URI constructor StringFact passthrough.
        // `new URL(spec)` (Java/JS), plus the static factory list in
        // [`crate::ssa::type_facts::is_url_single_arg_factory`] — when the
        // single argument's StringFact carries a locked-host prefix
        // (typically from a literal+tainted concat), propagate it onto
        // the constructed URL value so a downstream receiver sink like
        // `u.openStream()` / `u.openConnection()` can consult the prefix
        // through `is_abstract_safe_for_sink`.  Strictly additive: the
        // 2-arg `(base, path)` shape is handled by the
        // `url_builder_arg_indices` arm above; this single-arg arm only
        // fires when that arm doesn't.
        SsaOp::Call { callee, args, .. }
            if lang.is_some_and(|l| {
                let l_u = l;
                let is_url_ctor = info.call.is_constructor
                    && crate::ssa::type_facts::constructor_type(l_u, callee)
                        == Some(crate::ssa::type_facts::TypeKind::Url);
                let via_outer = info.call.outer_callee.as_deref().is_some_and(|oc| {
                    crate::ssa::type_facts::constructor_type(l_u, oc)
                        == Some(crate::ssa::type_facts::TypeKind::Url)
                });
                let is_static_factory =
                    crate::ssa::type_facts::is_url_single_arg_factory(l_u, callee);
                (is_url_ctor || via_outer || is_static_factory)
                    && crate::ssa::type_facts::url_builder_arg_indices(
                        l_u,
                        callee,
                        info.call.outer_callee.as_deref(),
                        info.call.is_constructor,
                    )
                    .is_none_or(|(_p, base_idx)| {
                        // Skip when the 2-arg arm above would already
                        // have fired (it consumed a literal or
                        // const-bound singleton base).
                        url_builder_concrete_base(info, args, abs, base_idx).is_none()
                    })
            }) =>
        {
            let arg_string = args
                .first()
                .and_then(|g| g.first().copied())
                .map(|pv| abs.get(pv).string)
                .unwrap_or_else(StringFact::top);
            if !arg_string.is_top() {
                abs.set(
                    inst.value,
                    AbstractValue {
                        interval: IntervalFact::top(),
                        string: arg_string,
                        bits: BitFact::top(),
                        path: PathFact::top(),
                    },
                );
            }
        }

        // Known integer-producing calls get a bounded interval so downstream
        // arithmetic transfer produces useful facts (e.g. parseInt(x) * 10).
        // Unknown calls: implicit Top (don't store).
        SsaOp::Call { callee, .. } if is_int_producing_callee(callee) => {
            abs.set(
                inst.value,
                AbstractValue {
                    interval: IntervalFact {
                        lo: Some(i32::MIN as i64),
                        hi: Some(i32::MAX as i64),
                    },
                    string: StringFact::top(),
                    bits: BitFact::top(),
                    path: PathFact::top(),
                },
            );
        }

        // Path-primitive calls, per-language classifiers map known stdlib
        // sanitisers (`fs::canonicalize`, `os.path.normpath`,
        // `path.normalize`, `filepath.Clean`, `Path.normalize()`,
        // `File.expand_path`, `realpath`, `std::filesystem::canonical`)
        // onto a PathFact effect on the result.  See
        // `crate::abstract_interp::path_domain::classify_path_primitive_for_lang`.
        //
        // Rust-only (gated by inner `matches!(lang, Some(Lang::Rust))` checks):
        //   * `s.replace("..", "")` clears the `..` axis.
        //   * Structural variant-wrapper transparency (`Some(s)` / `Ok(s)`).
        //   * Zero-arg fresh-allocator constructor (`String::new()`).
        //
        // Other supported languages get the path-primitive transfer only;
        // their grammar-specific extensions would slot in here behind a
        // similar inner gate.
        SsaOp::Call {
            callee,
            args,
            receiver,
            ..
        } if lang.is_some() => {
            // Determine the "input" SSA value: receiver for method calls,
            // first positional arg for free-function calls.
            let input_val = receiver
                .as_ref()
                .copied()
                .or_else(|| args.first().and_then(|g| g.first().copied()));
            let input_fact = input_val
                .map(|v| abs.get(v).path)
                .unwrap_or_else(PathFact::top);

            // Primary path-producing primitives, per-language dispatch.
            let lang_unwrapped = lang.expect("guard ensures lang.is_some()");
            if let Some(pf) = crate::abstract_interp::path_domain::classify_path_primitive_for_lang(
                lang_unwrapped,
                callee,
                &input_fact,
            ) {
                abs.set(inst.value, AbstractValue::with_path_fact(pf));
            } else if matches!(lang, Some(Lang::Rust)) {
                // Rust-specific: `.replace(...)` sanitiser, variant-wrapper
                // transparency, and zero-arg fresh-allocator transfer.
                // These rely on Rust grammar conventions (scoped `Type::method`,
                // upper-camel-case variant ctor) that don't generalise.
                //
                // `.replace(...)` sanitiser on a string receiver.  The Call
                // result re-binds the sanitised string; downstream
                // `Path::new` / `PathBuf::from` carries the cleared axis.
                // The literal needle is read from the first argument's
                // StringFact (exact value), which `SsaOp::Const` seeds for
                // string literals during the same pass.
                let leaf = crate::callgraph::callee_leaf_name(callee);
                let mut handled = false;
                if leaf == "replace" {
                    if let Some(first_arg) = args.first().and_then(|g| g.first()) {
                        let arg_string = abs.get(*first_arg).string;
                        let needle = arg_string
                            .domain
                            .as_ref()
                            .and_then(|d| (d.len() == 1).then(|| d[0].clone()));
                        if let Some(needle) = needle {
                            let mut new_fact = input_fact.clone();
                            let mut narrowed = false;
                            if needle == ".." {
                                new_fact = new_fact.with_dotdot_cleared();
                                narrowed = true;
                            } else if needle == "/" || needle == "\\" {
                                new_fact = new_fact.with_absolute_cleared();
                                narrowed = true;
                            }
                            if narrowed {
                                abs.set(inst.value, AbstractValue::with_path_fact(new_fact));
                                handled = true;
                            }
                        }
                    }
                }

                // Structural variant-wrapper transparency.  When a call is
                // a one-positional-argument variant / type constructor
                // (receiver-less; callee leaf begins with ASCII upper-case
                //, the
                // [`crate::abstract_interp::path_domain::is_structural_variant_ctor`]
                // gate), its result inherits the joined PathFact of every
                // SSA value the lowering recorded for that single
                // positional argument.  Covers `Some(s)`, `Ok(s)`,
                // `Err(s)`, `Box::new(s)`, and user-defined single-field
                // variants / tuple structs alike, the classification is
                // deliberately name-agnostic, so a freshly introduced
                // wrapper variant participates without code change.
                //
                // Positional arity is read from the CFG's
                // `info.call.arg_uses` (the authoritative list), not
                // from `args.len()`: SSA lowering appends an implicit
                // group of chained-call uses after the positional
                // groups, so `args.len()` over-counts.  For the
                // positional group itself we join the PathFacts across
                // all contributing SsaValues, chained calls inside the
                // argument (`Some(s.to_string())`) surface every uses'
                // value; the join picks the most precise axis each
                // value proves.
                if !handled
                    && receiver.is_none()
                    && info.call.arg_uses.len() == 1
                    && crate::abstract_interp::path_domain::is_structural_variant_ctor(callee)
                {
                    if let Some(group) = args.first() {
                        let mut joined_inner: Option<PathFact> = None;
                        for &v in group {
                            let f = abs.get(v).path;
                            if f.is_top() {
                                continue;
                            }
                            joined_inner = Some(match joined_inner {
                                None => f,
                                Some(prev) => prev.join(&f),
                            });
                        }
                        if let Some(inner_fact) = joined_inner {
                            abs.set(inst.value, AbstractValue::with_path_fact(inner_fact));
                            handled = true;
                        }
                    }
                }

                // Structural zero-argument allocator / constructor.
                // Callee is a Rust scoped identifier (contains `::`) whose
                // parent segment (e.g. `String` in `String::new`) begins
                // with ASCII upper-case, the call has no receiver and no
                // arguments, and the node carries no Source label ,
                // i.e. the helper is a fresh-allocation entry point, not
                // an external-input read.  Zero inputs ⇒ the result
                // carries no attacker-controlled path content and is
                // provably free of `..` components and absolute roots.
                // This closes the early-return path of sanitisers whose
                // rejection returns `String::new()` / `PathBuf::new()` /
                // etc., without a hard-coded allocator name list.
                if !handled
                    && receiver.is_none()
                    && args.is_empty()
                    && has_typeprefix_upper_scoped(callee)
                    && !has_source_label_on_node(info)
                {
                    let fact = PathFact::top()
                        .with_dotdot_cleared()
                        .with_absolute_cleared();
                    abs.set(inst.value, AbstractValue::with_path_fact(fact));
                }
            }
        }

        SsaOp::Source | SsaOp::CatchParam | SsaOp::Param { .. } => {
            // Untrusted / unknown: Top (no abstract knowledge)
        }

        _ => {}
    }
}

/// Re-export from type_facts for use in transfer_abstract.
fn is_int_producing_callee(callee: &str) -> bool {
    crate::ssa::type_facts::is_int_producing_callee(callee)
}

/// Structural check: does `callee` look like a Rust scoped identifier
/// whose parent segment is a type (upper-camel-case)?
///
/// Used by the zero-argument-allocator arm of `transfer_abstract` to
/// recognise `Type::new` / `Type::default` / `Type::with_capacity` /
/// `Type::empty`, and any user-defined associated allocator, as a
/// fresh-allocation site without hard-coding the leaf name.  The check
/// is deliberately conservative:
///
///   * Must contain at least one `::` separator.
///   * The segment *before* the final leaf must start with an ASCII
///     upper-case letter and contain only ASCII alphanumeric / `_`
///     characters, Rust's grammar for type identifiers.  (Module-only
///     paths like `std::env` don't qualify; the gate fires only on
///     type paths like `String::new`.)
///
/// Returns `false` on empty input or bare function calls.
fn has_typeprefix_upper_scoped(callee: &str) -> bool {
    // `peel_identity_suffix` strips trailing `.unwrap()` etc. so
    // `String::new.unwrap` normalises to `String::new`.  Fallback to the
    // raw callee when peeling produces an empty string.
    let normalised = crate::ssa::type_facts::peel_identity_suffix(callee);
    let normalised = if normalised.is_empty() {
        callee
    } else {
        normalised.as_str()
    };
    let mut segments: smallvec::SmallVec<[&str; 4]> =
        normalised.split("::").filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return false;
    }
    // Drop trailing method-style `.ident` noise from the leaf segment.
    if let Some(leaf) = segments.last_mut() {
        if let Some(dot_idx) = leaf.find('.') {
            *leaf = &leaf[..dot_idx];
        }
    }
    // Parent is the second-to-last segment.
    let parent = segments[segments.len() - 2];
    let Some(first) = parent.chars().next() else {
        return false;
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    parent
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// True when `info` carries any [`DataLabel::Source`] label.
///
/// Guards the zero-argument-allocator arm of `transfer_abstract` against
/// mis-classifying external-input readers (e.g. an environment-variable
/// getter that happens to have a scoped upper-camel-case parent
/// segment) as empty allocations.
fn has_source_label_on_node(info: &NodeInfo) -> bool {
    info.taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Source(_)))
}

/// Check if a constant text is a string literal (quoted).
fn is_string_const(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"') && text.len() >= 2)
        || (text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2)
}

/// Strip surrounding quotes from a string literal.
fn strip_string_quotes(text: &str) -> String {
    if text.len() >= 2
        && ((text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\'')))
    {
        text[1..text.len() - 1].to_string()
    } else {
        text.to_string()
    }
}

/// Collect events from a block.
fn collect_block_events(
    block: &SsaBlock,
    cfg: &Cfg,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    mut state: SsaTaintState,
    events: &mut Vec<SsaTaintEvent>,
    induction_vars: &HashSet<SsaValue>,
    pred_states: Option<&PredStates>,
) {
    // Replay phis to get accurate state (mirrors transfer_block phi handling)
    let block_idx = block.id.0 as usize;
    for phi in &block.phis {
        if let SsaOp::Phi(ref operands) = phi.op {
            let is_induction = induction_vars.contains(&phi.value);

            let mut combined_caps = Cap::empty();
            let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            let mut all_tainted_validated = true;
            let mut any_tainted = false;

            for &(pred_blk, operand_val) in operands {
                // Skip back-edge operands for induction vars
                if is_induction && pred_blk.0 >= block.id.0 {
                    continue;
                }

                // Use predecessor-specific state when available
                let operand_taint = if let Some(ps) = pred_states {
                    ps.get(&(block_idx, pred_blk.0 as usize))
                        .and_then(|pred_st| pred_st.get(operand_val))
                } else {
                    None
                };
                let operand_taint = operand_taint.or_else(|| state.get(operand_val));

                if let Some(taint) = operand_taint {
                    any_tainted = true;
                    combined_caps |= taint.caps;
                    for orig in &taint.origins {
                        push_origin_bounded(&mut combined_origins, *orig);
                    }

                    // Path sensitivity: check if this operand is validated in predecessor
                    if let Some(ps) = pred_states {
                        if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                            let var_name = ssa
                                .value_defs
                                .get(operand_val.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref());
                            if let Some(name) = var_name {
                                if let Some(sym) = transfer.interner.get(name) {
                                    if !pred_st.validated_must.contains(sym) {
                                        all_tainted_validated = false;
                                    }
                                } else {
                                    all_tainted_validated = false;
                                }
                            } else {
                                all_tainted_validated = false;
                            }
                        } else {
                            all_tainted_validated = false;
                        }
                    } else {
                        all_tainted_validated = false;
                    }
                }
            }

            if combined_caps.is_empty() {
                state.remove(phi.value);
            } else {
                state.set(
                    phi.value,
                    VarTaint {
                        caps: combined_caps,
                        origins: combined_origins,
                        uses_summary: false,
                    },
                );

                // Path sensitivity: if all tainted predecessors validated, propagate
                if any_tainted && all_tainted_validated {
                    if let Some(name) = ssa
                        .value_defs
                        .get(phi.value.0 as usize)
                        .and_then(|vd| vd.var_name.as_deref())
                    {
                        if let Some(sym) = transfer.interner.get(name) {
                            state.validated_may.insert(sym);
                            state.validated_must.insert(sym);
                        }
                    }
                }
            }
        }
    }

    // Replay abstract value phi join (from predecessor exit states).
    // Mirrors the same logic in transfer_block(), without this, abstract
    // values for phi-defined SSA values would be stale during sink suppression.
    if state.abstract_state.is_some() {
        for phi in &block.phis {
            if let SsaOp::Phi(ref operands) = phi.op {
                use crate::abstract_interp::AbstractValue;
                let is_induction = induction_vars.contains(&phi.value);
                let mut joined = AbstractValue::bottom();
                let mut any_operand = false;

                for &(pred_blk, operand_val) in operands {
                    if is_induction && pred_blk.0 >= block.id.0 {
                        continue;
                    }
                    // Skip infeasible predecessors
                    if let Some(ps) = pred_states {
                        if let Some(pred_st) = ps.get(&(block_idx, pred_blk.0 as usize)) {
                            if pred_st.path_env.as_ref().is_some_and(|e| e.is_unsat()) {
                                continue;
                            }
                        }
                    }
                    // Look up operand abstract value from predecessor exit state
                    let pred_abs = pred_states
                        .and_then(|ps| ps.get(&(block_idx, pred_blk.0 as usize)))
                        .and_then(|s| s.abstract_state.as_ref())
                        .map(|a| a.get(operand_val))
                        .unwrap_or_else(AbstractValue::top);
                    joined = joined.join(&pred_abs);
                    any_operand = true;
                }

                if any_operand {
                    if let Some(ref mut abs) = state.abstract_state {
                        abs.set(phi.value, joined);
                    }
                }
            }
        }
    }

    // Process body with sink detection
    for inst in &block.body {
        transfer_inst(inst, cfg, ssa, transfer, &mut state);

        // Check for sink
        let info = &cfg[inst.cfg_node];
        if info.all_args_literal {
            continue;
        }

        // Parameterized SQL queries are safe, skip sink detection.
        if info.parameterized_query {
            continue;
        }

        let sink_info = resolve_sink_info(info, transfer);
        let mut sink_caps = sink_info.caps;

        // [detectors.data_exfil] enabled toggle.  When the detector class is
        // disabled per-project, strip Cap::DATA_EXFIL from sink_caps so no
        // taint-data-exfiltration event is emitted regardless of which gate
        // would have fired.  Strict-additive: defaults to enabled, no effect
        // for projects that don't opt in.
        if !crate::utils::detector_options::current().data_exfil.enabled {
            sink_caps &= !Cap::DATA_EXFIL;
        }

        // Receiver-type-incompatibility stripping.  When the receiver's type
        // proves a structurally-attached cap cannot apply (e.g. an
        // `LdapClient` receiver carrying an `HTML_ESCAPE` Sink label that was
        // attached to the CFG node by a `*.send`/`*.json`-style suffix
        // matcher), drop the offending bits *before* the type-qualified-
        // resolution branch below, so that branch is reachable on the
        // remaining empty `sink_caps` and can re-anchor a precise sink class
        // (`LdapClient.search` → `Cap::LDAP_INJECTION`).  Both the
        // flow-sensitive type from `path_env` and the static type from
        // `type_facts` are consulted; the static path is what enables
        // closure-captured receivers (parent body → child body via
        // [`crate::taint::inject_external_type_facts`]) to participate.
        if let SsaOp::Call {
            receiver: Some(rv), ..
        } = &inst.op
        {
            if let Some(ref env) = state.path_env {
                if let Some(kind) = env.get(*rv).types.as_singleton() {
                    sink_caps &= !receiver_incompatible_sink_caps(&kind, sink_caps);
                }
            }
            if let Some(tf) = transfer.type_facts {
                if let Some(kind) = tf.get_type(*rv) {
                    sink_caps &= !receiver_incompatible_sink_caps(kind, sink_caps);
                }
            }
        }

        // Type-qualified sink resolution: when normal sink resolution found nothing,
        // try using the receiver's inferred type to construct a qualified callee name.
        // For known type-qualified ORM raw-SQL methods (`TypeOrmRepo.query` et al.),
        // also capture the restricted payload-arg list so bind-array taint at arg 1+
        // does not fire.
        let mut tq_payload_args: Option<&'static [usize]> = None;
        if sink_caps.is_empty() {
            if let SsaOp::Call {
                callee,
                receiver: Some(rv),
                ..
            } = &inst.op
            {
                if transfer.type_facts.is_some() || state.path_env.is_some() {
                    let (tq_labels, tq_args) = resolve_type_qualified_labels_with_args(
                        callee,
                        *rv,
                        transfer.type_facts,
                        state.path_env.as_ref(),
                        transfer.lang,
                        transfer.extra_labels,
                        Some(ssa),
                    );
                    for lbl in &tq_labels {
                        if let DataLabel::Sink(bits) = lbl {
                            sink_caps |= *bits;
                        }
                    }
                    tq_payload_args = tq_args;
                }
            }
        }

        // Module alias resolution: when the receiver was assigned from require()
        // of a known module (e.g., `const lib = require("http")`), substitute
        // the module name into the callee for label matching.
        // Example: `lib.request(url)` with lib→"http" tries "http.request".
        if sink_caps.is_empty() {
            if let SsaOp::Call {
                callee,
                receiver: Some(rv),
                ..
            } = &inst.op
            {
                if let Some(aliases) = transfer.module_aliases {
                    if let Some(module_names) = aliases.get(rv) {
                        if let Some(dot_pos) = callee.find('.') {
                            let method = &callee[dot_pos + 1..];
                            let lang_str = transfer.lang.as_str();
                            for module_name in module_names {
                                let qualified = format!("{}.{}", module_name, method);
                                let labels = crate::labels::classify_all(
                                    lang_str,
                                    &qualified,
                                    transfer.extra_labels,
                                );
                                for lbl in &labels {
                                    if let DataLabel::Sink(bits) = lbl {
                                        sink_caps |= *bits;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ADD XXE on opt-in. When the receiver was constructed
        // with an explicit external-entity opt-in
        // (`new XMLParser({ processEntities: true })`,
        // `lxml.etree.XMLParser(resolve_entities=True)`), the subsequent
        // `parser.parse(xml)` is an XXE flow even though the callee
        // carries no flat XXE rule (fast-xml-parser and lxml are
        // XXE-safe by default).  Runs BEFORE the empty check below so a
        // previously-empty sink_caps becomes non-empty and downstream
        // emission proceeds.  The complementary `xxe_safe` suppress path
        // still runs after this; a call where the receiver was both
        // opt-in AND later hardened by a setter results in net-zero
        // (suppress strips what we added).
        if let SsaOp::Call {
            receiver: Some(rv),
            callee: callee_str,
            ..
        } = &inst.op
        {
            if let Some(xc) = transfer.xml_parser_config {
                if xc.is_unsafe_explicit(*rv) {
                    let suffix = callee_str
                        .rsplit(['.', ':'])
                        .next()
                        .unwrap_or(callee_str.as_str());
                    // `feed` covers Python lxml incremental parsing
                    // (`parser.feed(body); parser.close()`).
                    if matches!(suffix, "parse" | "parseString" | "parseFromString" | "feed") {
                        sink_caps |= Cap::XXE;
                    }
                }
            }
        }

        // Phase 03: Promise-callback synthetic source_to_callback.  When
        // the call is `p.then(cb)` / `p.catch(cb)` with a tainted
        // receiver, the callback's first parameter receives the
        // resolved-value taint.  Synthesise a single-entry
        // `source_to_callback = [(0, receiver_caps)]` so the
        // existing callback-pattern detector below pairs `cb`'s
        // `param_to_sink` with the receiver's caps and emits the
        // sink finding.
        let synthetic_promise_callback: Option<(usize, Cap)> = match &inst.op {
            SsaOp::Call {
                callee,
                receiver,
                args,
                ..
            } => {
                let leaf = crate::callgraph::callee_leaf_name(callee);
                if crate::labels::is_promise_callback_method(transfer.lang.as_str(), leaf)
                    && !matches!(leaf, "finally")
                {
                    let mut recv_caps = Cap::empty();
                    if let Some(rv) = receiver {
                        if let Some(t) = state.get(*rv) {
                            recv_caps |= t.caps;
                        }
                    }
                    // Chained-receiver shape (`Promise.resolve(req.body).then(cb)`):
                    // the inner Promise.resolve call collapses into the outer
                    // .then node so there is no separate Call op for it.  The
                    // resolved-value taint instead surfaces in the implicit-uses
                    // arg group emitted by `build_call_args`.  Union those caps
                    // (skipping arg[0], which is the callback function itself,
                    // not the resolved value) so the named-promise and chained
                    // shapes share one source_to_callback synthesis path.
                    for (idx, arg_group) in args.iter().enumerate() {
                        if idx == 0 {
                            continue;
                        }
                        for &v in arg_group {
                            if let Some(t) = state.get(v) {
                                recv_caps |= t.caps;
                            }
                        }
                    }
                    // Same chained shape: when the inner `Promise.resolve`
                    // collapses into the `.then` node, its Source label is
                    // attached directly to the `.then` node's labels rather
                    // than to a separate SSA op whose value the receiver/args
                    // would expose.  Union those Source caps so the callback
                    // pattern fires uniformly across named and chained shapes.
                    for lbl in &info.taint.labels {
                        if let DataLabel::Source(bits) = lbl {
                            recv_caps |= *bits;
                        }
                    }
                    if recv_caps.is_empty() {
                        None
                    } else {
                        Some((0usize, recv_caps))
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
        if sink_caps.is_empty() {
            // Callback pattern: check if callee has source_to_callback and the
            // actual callback argument has a matching param_to_sink.
            if let SsaOp::Call { callee, .. } = &inst.op {
                let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
                // Use arg_uses.len() for arity (see transfer_inst's Call arm).
                let resolved = resolve_callee_hinted(
                    transfer,
                    callee,
                    caller_func,
                    info.call.call_ordinal,
                    Some(info.call.arg_uses.len()),
                );
                // Collect source_to_callback entries: real summary (if any)
                // plus the Phase 03 synthetic entry for promise callbacks.
                let mut s2c: SmallVec<[(usize, Cap); 2]> = SmallVec::new();
                if let Some(ref r) = resolved {
                    for &e in &r.source_to_callback {
                        s2c.push(e);
                    }
                }
                if let Some(entry) = synthetic_promise_callback {
                    if !s2c.iter().any(|&(i, _)| i == entry.0) {
                        s2c.push(entry);
                    }
                }
                if !s2c.is_empty() {
                    for &(cb_idx, src_caps) in &s2c {
                        // Two channels for resolving the callback's name:
                        //   1. `info.arg_callees` — populated when the
                        //      argument is a tree-sitter call/function node;
                        //      the typical path for inline arrow callbacks
                        //      and for native CallFn/CallMethod arguments.
                        //   2. SSA `value_defs.var_name` of the argument
                        //      itself — a plain identifier reference such as
                        //      `p.then(cb)` doesn't classify as a Call AST
                        //      node so `arg_callees[0]` is `None`, but the
                        //      lowered SSA value carries the identifier text
                        //      via `var_name`.  Falling back to it lets
                        //      Phase 03 promise-callback synthesis resolve
                        //      the named-callback shape.
                        let arg_callees_name: Option<String> = info
                            .arg_callees
                            .get(cb_idx)
                            .and_then(|ac| ac.clone());
                        let ssa_var_name: Option<String> = if let SsaOp::Call { args, .. } =
                            &inst.op
                        {
                            args.get(cb_idx).and_then(|grp| {
                                grp.iter().find_map(|v| {
                                    ssa.value_defs
                                        .get(v.0 as usize)
                                        .and_then(|vd| vd.var_name.clone())
                                        .filter(|n| !n.contains('.') && !n.is_empty())
                                })
                            })
                        } else {
                            None
                        };
                        let cb_callee_owned = arg_callees_name.or(ssa_var_name);
                        if let Some(cb_callee) = cb_callee_owned.as_deref() {
                            // First try the standard summary-based resolution
                            // path (covers user-defined functions and built-ins
                            // that landed in label-derived summaries upstream).
                            // If that yields no matching sink caps, fall back
                            // to gated-sink classification on the callback
                            // callee's name — gated sinks (e.g.
                            // `child_process.exec` post-fix) carry their
                            // payload positions in the gate, not in any
                            // summary, and the callback pipeline still needs
                            // those positions to pair source caps against
                            // param_to_sink.
                            let cb_resolved = resolve_callee(transfer, cb_callee, caller_func, 0);
                            let mut matching_sink_caps = Cap::empty();
                            let cb_param_to_sink_sites: Vec<(usize, SmallVec<[SinkSite; 1]>)> =
                                if let Some(ref r) = cb_resolved {
                                    matching_sink_caps = r
                                        .param_to_sink
                                        .iter()
                                        .filter(|(_, caps)| !(src_caps & *caps).is_empty())
                                        .fold(Cap::empty(), |acc, (_, c)| acc | *c);
                                    r.param_to_sink_sites.clone()
                                } else {
                                    vec![]
                                };
                            if matching_sink_caps.is_empty() {
                                // Gate-fallback: classify_gated_sink yields the
                                // callback callee's payload positions + sink
                                // caps directly when the name matches a gated
                                // sink rule.
                                let lang_str = transfer.lang.as_str();
                                let gates = crate::labels::classify_gated_sink(
                                    lang_str,
                                    cb_callee,
                                    |_| None,
                                    |_| None,
                                    |_| false,
                                );
                                for gm in gates.iter() {
                                    if let DataLabel::Sink(bits) = gm.label {
                                        if !(src_caps & bits).is_empty() {
                                            matching_sink_caps |= bits;
                                        }
                                    }
                                }
                            }
                            if !matching_sink_caps.is_empty() {
                                let source_kind =
                                    crate::labels::infer_source_kind(src_caps, callee);
                                let origin = TaintOrigin {
                                    node: inst.cfg_node,
                                    source_kind,
                                    source_span: None,
                                };
                                // Pick callback-path sink sites.
                                // The callback callee's `param_to_sink_sites`
                                // drives attribution when available; cap-only
                                // fallback yields `primary_sink_site = None`.
                                let cb_tainted: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)> =
                                    vec![(
                                        inst.value,
                                        src_caps & matching_sink_caps,
                                        SmallVec::from_elem(origin, 1),
                                    )];
                                let cb_sites = pick_primary_sink_sites_from_resolved(
                                    matching_sink_caps,
                                    &cb_param_to_sink_sites,
                                );
                                emit_ssa_taint_events(
                                    events,
                                    inst.cfg_node,
                                    cb_tainted,
                                    matching_sink_caps,
                                    false,
                                    None,
                                    true,
                                    cb_sites,
                                );
                            }
                        }
                    }
                }
            }
            continue;
        }

        if sink_caps.is_empty() {
            continue;
        }

        // XXE config-fact suppression.  A parse-class sink whose receiver
        // was provably hardened (`setFeature(FEATURE_SECURE_PROCESSING,
        // true)`, `setExpandEntityReferences(false)`, etc.) is not an XXE
        // flow. Drop the bit before downstream sink emission.  Runs after
        // type-qualified resolution / module alias resolution so the XXE
        // bit added by `XmlParser.parse` resolution is visible here.
        if sink_caps.intersects(Cap::XXE) {
            if let SsaOp::Call {
                receiver: Some(rv), ..
            } = &inst.op
            {
                if let Some(xc) = transfer.xml_parser_config {
                    if crate::ssa::xml_config::xxe_safe(Some(*rv), xc) {
                        sink_caps &= !Cap::XXE;
                    }
                }
            }
        }
        if sink_caps.is_empty() {
            continue;
        }

        // XPath resolver-binding suppression.  An XPath `evaluate` /
        // `compile` sink whose receiver was provably bound to an
        // `XPathVariableResolver` is treated as parameterised and the
        // XPATH_INJECTION bit is stripped.  Mirrors the XXE config-fact
        // shape above.  Only fires when the receiver also carries
        // `TypeKind::XPathClient` (gates the suppression behind
        // type-fact disambiguation so a generic `obj.evaluate(...)`
        // matched as XPATH_INJECTION via name-only labelling does not
        // accidentally clear).
        if sink_caps.intersects(Cap::XPATH_INJECTION) {
            if let SsaOp::Call {
                receiver: Some(rv), ..
            } = &inst.op
            {
                if let Some(xpc) = transfer.xpath_config {
                    let receiver_is_xpath = transfer
                        .type_facts
                        .and_then(|tf| tf.get_type(*rv))
                        .map(|kind| matches!(kind, crate::ssa::type_facts::TypeKind::XPathClient))
                        .unwrap_or(false);
                    if receiver_is_xpath && crate::ssa::xpath_config::xpath_safe(Some(*rv), xpc) {
                        sink_caps &= !Cap::XPATH_INJECTION;
                    }
                }
            }
        }
        if sink_caps.is_empty() {
            continue;
        }

        // Prototype-pollution suppression (flow-sensitive).
        // `Object.create(null)` produces a `NullPrototypeObject`-typed
        // value; subscript writes to such an object cannot pollute
        // `Object.prototype` because there is no prototype chain.
        // Receiver SsaValue is read off the synthetic `__index_set__`
        // Call op; phi joins downgrade to `Unknown` via `TypeFact::meet`
        // so an if/else where only one branch initialises with
        // `Object.create(null)` keeps the PROTOTYPE_POLLUTION bit on
        // the unsafe path.
        if sink_caps.intersects(Cap::PROTOTYPE_POLLUTION) {
            if let SsaOp::Call {
                callee,
                receiver: Some(rv),
                ..
            } = &inst.op
            {
                if callee == "__index_set__" {
                    let receiver_is_null_proto = transfer
                        .type_facts
                        .and_then(|tf| tf.get_type(*rv))
                        .map(|kind| {
                            matches!(kind, crate::ssa::type_facts::TypeKind::NullPrototypeObject)
                        })
                        .unwrap_or(false);
                    if receiver_is_null_proto {
                        sink_caps &= !Cap::PROTOTYPE_POLLUTION;
                    }
                }
            }
        }
        if sink_caps.is_empty() {
            continue;
        }

        // Go interface satisfaction check.
        // For Go sinks that require http.ResponseWriter (e.g., fmt.Fprintf),
        // skip if the first argument's type is known to NOT satisfy the interface.
        if transfer.lang == Lang::Go {
            if let Some(ref env) = state.path_env {
                if let SsaOp::Call { args, .. } = &inst.op {
                    if let Some(first_arg_vals) = args.first() {
                        if let Some(&first_val) = first_arg_vals.first() {
                            if let Some(kind) = env.get(first_val).types.as_singleton() {
                                if crate::ssa::type_facts::GoInterfaceTable::definitely_not(
                                    &kind,
                                    "http.ResponseWriter",
                                ) && sink_caps.intersects(Cap::HTML_ESCAPE)
                                {
                                    sink_caps &= !Cap::HTML_ESCAPE;
                                }
                            }
                        }
                    }
                }
            }
        }
        if sink_caps.is_empty() {
            continue;
        }

        // Go same-request self-redirect suppression.
        //
        // `http.Redirect(w, r, url, code)` whose URL string arg is derived
        // from the same request's `*url.URL` is a same-origin redirect by
        // construction: scheme/host echo the inbound request, only the path
        // can be edited.  gin's `redirectTrailingSlash` /
        // `redirectFixedPath` / `redirectRequest` helpers all bottom out in
        // this shape (`req := c.Request; rURL := req.URL.String();
        // http.Redirect(w, req, rURL, code)`).  Without this suppression,
        // the inner `http.Redirect` records `param_to_sink` for OPEN_REDIRECT
        // and the IPA path then surfaces `taint-open-redirect` at every
        // call site that reaches `redirectTrailingSlash(c)` with a
        // tainted `c.Request.URL`.
        if transfer.lang == Lang::Go
            && sink_caps.intersects(Cap::OPEN_REDIRECT)
            && is_go_request_self_redirect(inst, info, ssa)
        {
            sink_caps &= !Cap::OPEN_REDIRECT;
        }
        if sink_caps.is_empty() {
            continue;
        }

        // Same-node Sanitizer subtraction.  When the CFG node carries both
        // Sink and Sanitizer labels for overlapping caps, the shape-based
        // synthesis pattern used by Ruby AR safe-arg-0 detection
        // (`src/cfg/mod.rs`) and the Java JPA parameterised-execute chain ,
        // the sanitizer reflexively dominates the sink and the cap should
        // not surface as a taint-flow finding.  The SSA Call arm already
        // applies same-node sanitizer to the *return* value
        // (`return_bits &= !sanitizer_bits`); without this mirror at the
        // sink-detection site, the sink still fires on the call's own
        // arguments / receiver despite the sanitizer label.
        let same_node_sanitizer_caps = info.taint.labels.iter().fold(Cap::empty(), |acc, lbl| {
            if let DataLabel::Sanitizer(caps) = lbl {
                acc | *caps
            } else {
                acc
            }
        });
        if !same_node_sanitizer_caps.is_empty() {
            sink_caps &= !same_node_sanitizer_caps;
            if sink_caps.is_empty() {
                continue;
            }
        }

        // Suppress known non-sink callees (e.g., System.out.println in Java)
        if let SsaOp::Call { callee, .. } = &inst.op {
            sink_caps = suppress_known_safe_callees(sink_caps, callee, transfer.lang, info);
            if sink_caps.is_empty() {
                continue;
            }
        }

        // Interprocedural sanitizer: subtract sanitizer caps from inner arg callees.
        // If an argument is wrapped in a call to a known sanitizer (e.g.
        // `os.system(sanitize(cmd))`), the sanitizer's caps reduce the effective
        // sink sensitivity so tainted data stripped by the inner call isn't flagged.
        for maybe_callee in &info.arg_callees {
            if let Some(inner_callee) = maybe_callee {
                let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
                if let Some(resolved) = resolve_callee(transfer, inner_callee, caller_func, 0) {
                    sink_caps &= !resolved.sanitizer_caps;
                } else {
                    // Fallback: check label classification (built-in + custom rules).
                    // This handles sanitizers that have no function summary (e.g.
                    // external libraries like `escapeHtml`, `DOMPurify.sanitize`).
                    let lang_str = transfer.lang.as_str();
                    let labels =
                        crate::labels::classify_all(lang_str, inner_callee, transfer.extra_labels);
                    for lbl in &labels {
                        if let DataLabel::Sanitizer(bits) = lbl {
                            sink_caps &= !*bits;
                        }
                    }
                }
            }
        }
        if sink_caps.is_empty() {
            continue;
        }

        // SSA-level literal suppression: if all argument SSA values are known
        // constants (from const propagation), skip sink detection.
        // Only applies to non-Call instructions (Assign to a sink), for Call
        // instructions, the CFG-level `all_args_literal` check already handles
        // chained calls more accurately.
        if !matches!(inst.op, SsaOp::Call { .. }) {
            if let Some(const_values) = transfer.const_values {
                if all_args_const(inst, const_values) {
                    continue;
                }
            }
        }

        // Type-aware sink filtering: suppress SQL injection for int-typed values.
        // Only applies to non-Call instructions to avoid interfering with
        // call-chain taint detection.
        if !matches!(inst.op, SsaOp::Call { .. }) {
            if let Some(type_facts) = transfer.type_facts {
                if is_type_safe_for_sink(inst, sink_caps, type_facts) {
                    continue;
                }
            }
        }

        // Path-sensitive type-safe sink filtering.
        // Uses flow-sensitive type constraints from PathEnv (branch narrowing,
        // casts) to suppress sinks when all argument values are proven to have
        // non-injectable types (Int, Bool).
        if !matches!(inst.op, SsaOp::Call { .. }) {
            if let Some(ref env) = state.path_env {
                if is_path_type_safe_for_sink(inst, sink_caps, env) {
                    continue;
                }
            }
        }

        // Abstract-domain-aware sink suppression.
        // Includes SSRF prefix locking and dual-gate (type + interval) for SQL/FILE_IO.
        if let Some(ref abs) = state.abstract_state {
            if is_abstract_safe_for_sink(
                inst,
                sink_caps,
                abs,
                transfer.type_facts,
                transfer.static_map,
                &state,
                ssa,
                cfg,
            ) {
                continue;
            }
        }
        // Call-site abstract suppression.
        if let SsaOp::Call { ref args, .. } = inst.op {
            if let Some(ref abs) = state.abstract_state {
                if is_call_abstract_safe(
                    inst,
                    args,
                    sink_caps,
                    abs,
                    transfer.type_facts,
                    transfer.static_map,
                    &state,
                    ssa,
                    cfg,
                ) {
                    continue;
                }
            }
        }

        // Per-gate-filter dispatch.  When the call site carries multiple
        // gated-sink classes (e.g. `fetch` is both an SSRF gate on the URL
        // arg and a `DATA_EXFIL` gate on the body / headers / json arg),
        // each filter contributes its own sink-cap mask, payload positions,
        // and destination-uses.  Iterating per-filter keeps cap attribution
        // exact: a body-only taint surfaces as a `DATA_EXFIL` event with no
        // SSRF bit, and vice versa.
        //
        // The single-filter / no-filter case takes one trip through the
        // loop with the legacy `(sink_caps, info.call.sink_payload_args,
        // info.call.destination_uses)` triple, preserving prior behavior
        // for every non-multi-gate site.
        //
        // Cross-file wrapper case: when the resolved callee summary carries
        // [`SinkInfo::param_to_gate_filters`] (the wrapper's body contains
        // an inner multi-gate sink whose per-position cap split was lifted
        // at extraction time), expand one filter pass per `(param_idx,
        // label_caps)` entry restricted to that single arg position.  This
        // preserves SSRF-vs-DATA_EXFIL attribution across a
        // `fn forward(url, body) { fetch(url, {body}) }` wrapper that is
        // NOT itself a known gated sink.
        //
        // Params NOT covered by `param_to_gate_filters` retain coverage
        // via their `param_to_sink` entry, expanded per-position so the
        // emitted event's `sink_caps` reflects the param-specific cap
        // mask rather than the aggregate union.  This matters for
        // wrappers that mix gated sinks with label-based sinks
        // (e.g. `fn dispatch(cmd, url) { execSync(cmd); fetch(url) }`),
        // where param 0 reaches a non-gated SHELL_ESCAPE sink and the
        // gate-filter list only carries the SSRF gate for param 1.
        let multi_gate = info.call.gate_filters.len() > 1;
        let summary_per_position = !multi_gate && !sink_info.param_to_gate_filters.is_empty();
        type FilterEntry<'a> = (Cap, Option<&'a [usize]>, Option<&'a [String]>);
        // Per-position dispatch source for the summary-per-position branch.
        // First, every entry from `param_to_gate_filters` (cap-narrowed by
        // the inner gate); then, for any param_to_sink index NOT mentioned
        // in `param_to_gate_filters`, an entry using that param's
        // `param_to_sink` cap mask.
        struct PerPosEntry {
            idx: [usize; 1],
            caps: Cap,
        }
        let per_position_entries: Vec<PerPosEntry> = if summary_per_position {
            let mut out: Vec<PerPosEntry> =
                Vec::with_capacity(sink_info.param_to_gate_filters.len());
            for (idx, caps) in &sink_info.param_to_gate_filters {
                out.push(PerPosEntry {
                    idx: [*idx],
                    caps: *caps,
                });
            }
            for (idx, caps) in &sink_info.param_to_sink {
                if sink_info
                    .param_to_gate_filters
                    .iter()
                    .any(|(i, _)| *i == *idx)
                {
                    continue;
                }
                out.push(PerPosEntry {
                    idx: [*idx],
                    caps: *caps,
                });
            }
            out
        } else {
            Vec::new()
        };
        let filter_iter: smallvec::SmallVec<[FilterEntry<'_>; 2]> = if multi_gate {
            info.call
                .gate_filters
                .iter()
                .map(|f| {
                    (
                        sink_caps & f.label_caps,
                        Some(f.payload_args.as_slice()),
                        f.destination_uses.as_deref(),
                    )
                })
                .collect()
        } else if summary_per_position {
            per_position_entries
                .iter()
                .map(|e| (sink_caps & e.caps, Some(e.idx.as_slice()), None))
                .collect()
        } else {
            smallvec::smallvec![(sink_caps, tq_payload_args, None)]
        };

        for (filter_caps, positions_override, destination_override) in filter_iter {
            let mut filter_caps = filter_caps;

            // Per-filter destination allowlist for DATA_EXFIL.  When this
            // filter would emit Cap::DATA_EXFIL and the call's destination
            // arg has a trusted static prefix (configured via
            // detectors.data_exfil.trusted_destinations), drop the bit
            // for this filter only.  Other gates on the same call site
            // (notably SSRF) are unaffected.  Mirrors the semantics of
            // is_call_data_exfil_destination_trusted but operates per-gate
            // so a multi-gate fetch site keeps SSRF attribution while
            // dropping DATA_EXFIL when the destination is trusted.
            if filter_caps.intersects(Cap::DATA_EXFIL) {
                if let SsaOp::Call { ref args, .. } = inst.op {
                    if let Some(ref abs) = state.abstract_state {
                        if is_call_data_exfil_destination_trusted(inst, args, abs, cfg) {
                            filter_caps &= !Cap::DATA_EXFIL;
                        }
                    }
                }
            }

            if filter_caps.is_empty() {
                continue;
            }

            // Collect tainted SSA values that flow into this sink
            let tainted = collect_tainted_sink_values(
                inst,
                info,
                &state,
                filter_caps,
                ssa,
                transfer,
                &sink_info.param_to_sink,
                positions_override,
                destination_override,
            );
            if tainted.is_empty() {
                continue;
            }

            // Compute all_validated: check if all tainted vars are validated
            let all_validated = tainted.iter().all(|(val, _, _)| {
                let var_name = ssa
                    .value_defs
                    .get(val.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref());
                if let Some(name) = var_name {
                    if let Some(sym) = transfer.interner.get(name) {
                        return state.validated_may.contains(sym);
                    }
                }
                false
            });
            let guard_kind = if all_validated {
                Some(PredicateKind::ValidationCall)
            } else {
                None
            };
            // Check if any tainted value's taint chain used summary resolution
            let any_uses_summary = tainted
                .iter()
                .any(|(val, _, _)| state.get(*val).is_some_and(|t| t.uses_summary));

            // Pick primary sink sites (if any) from the resolved callee
            // summary.  Multi-site cases emit one event per matching
            // [`SinkSite`] so each downstream Finding carries one attribution.
            let primary_sites = pick_primary_sink_sites(
                inst,
                &tainted,
                filter_caps,
                &sink_info.param_to_sink_sites,
            );
            emit_ssa_taint_events(
                events,
                inst.cfg_node,
                tainted,
                filter_caps,
                all_validated,
                guard_kind,
                any_uses_summary,
                primary_sites,
            );
        }
    }
}

// ── Primary sink-site attribution ───────────────────────────────────────

/// Pick primary [`SinkSite`]s for a summary-based sink event in the main
/// sink-detection path.
///
/// Filters `param_to_sink_sites` to entries whose:
/// 1. `param_idx` appears in the call's positional `args` and contains one
///    of the `tainted` SSA values (proves this site's parameter actually
///    carried the tainted flow), AND
/// 2. [`SinkSite`] carries resolved coordinates (`line != 0`, cap-only
///    sites are ignored), AND
/// 3. [`SinkSite::cap`] intersects `sink_caps` (the propagated cap mask).
///
/// Returns the deduped list of matching sites (`dedup_key` identity).
/// Empty ⇒ no primary attribution, caller emits a single event with
/// `primary_sink_site = None`.
fn pick_primary_sink_sites(
    inst: &SsaInst,
    tainted: &[(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)],
    sink_caps: Cap,
    param_to_sink_sites: &[(usize, SmallVec<[SinkSite; 1]>)],
) -> Vec<SinkSite> {
    if param_to_sink_sites.is_empty() || tainted.is_empty() {
        return Vec::new();
    }
    let SsaOp::Call { ref args, .. } = inst.op else {
        return Vec::new();
    };
    let mut out: Vec<SinkSite> = Vec::new();
    let mut seen: HashSet<(String, u32, u32, u32)> = HashSet::new();
    for (param_idx, sites) in param_to_sink_sites {
        let Some(arg_vals) = args.get(*param_idx) else {
            continue;
        };
        let carries_tainted = arg_vals
            .iter()
            .any(|v| tainted.iter().any(|(tv, _, _)| tv == v));
        if !carries_tainted {
            continue;
        }
        for site in sites {
            if site.line == 0 {
                continue;
            }
            if (site.cap & sink_caps).is_empty() {
                continue;
            }
            let key = (site.file_rel.clone(), site.line, site.col, site.cap.bits());
            if seen.insert(key) {
                out.push(site.clone());
            }
        }
    }
    out
}

/// Pick primary [`SinkSite`]s for the callback-pattern path, where the
/// tainted-arg positional mapping is not directly available (the callback
/// callee is resolved separately from the outer call's `args`).  Matches
/// solely on cap intersection and coordinate resolution.
fn pick_primary_sink_sites_from_resolved(
    sink_caps: Cap,
    param_to_sink_sites: &[(usize, SmallVec<[SinkSite; 1]>)],
) -> Vec<SinkSite> {
    if param_to_sink_sites.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<SinkSite> = Vec::new();
    let mut seen: HashSet<(String, u32, u32, u32)> = HashSet::new();
    for (_, sites) in param_to_sink_sites {
        for site in sites {
            if site.line == 0 {
                continue;
            }
            if (site.cap & sink_caps).is_empty() {
                continue;
            }
            let key = (site.file_rel.clone(), site.line, site.col, site.cap.bits());
            if seen.insert(key) {
                out.push(site.clone());
            }
        }
    }
    out
}

/// Emit one or more [`SsaTaintEvent`]s for a sink hit.
///
/// Multi-primary collapse: when `primary_sites` contains more than one
/// entry, one event is emitted per site so downstream findings each carry
/// a single attribution.  When `primary_sites` is empty, a single event
/// is emitted with `primary_sink_site = None` (intra-procedural sinks,
/// cap-only callee summaries, or label-based sinks).
///
/// # Invariants enforced by debug_assert!
///
/// Every [`SinkSite`] in `primary_sites` must have been filtered at the
/// pick-site to satisfy:
/// * `site.line != 0`, cap-only sites carry no primary attribution and
///   must not reach the event stream.
/// * `(site.cap & sink_caps).is_empty() == false`, the site's cap
///   intersects the propagated cap mask (it's the dangerous-bit
///   justification for the finding).
///
/// Note: `uses_summary` intentionally does not gate `primary_sites` here.
/// The taint-chain `uses_summary` flag tracks whether a callee summary
/// propagated taint along the source→sink chain, whereas a primary
/// [`SinkSite`] only requires that the *sink* itself was resolved via a
/// callee summary, an intra-file source can still reach a cross-file
/// sink, producing `uses_summary == false` alongside a populated primary.
fn emit_ssa_taint_events(
    events: &mut Vec<SsaTaintEvent>,
    sink_node: NodeIndex,
    tainted_values: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    sink_caps: Cap,
    all_validated: bool,
    guard_kind: Option<PredicateKind>,
    uses_summary: bool,
    primary_sites: Vec<SinkSite>,
) {
    // Data-integrity invariant: every surviving primary site carries
    // resolved coordinates and a cap that intersects `sink_caps`.  This is
    // the contract the pick functions enforce; the assertion defends
    // against a future caller that builds `primary_sites` by hand.
    debug_assert!(
        primary_sites
            .iter()
            .all(|s| s.line != 0 && !(s.cap & sink_caps).is_empty()),
        "primary_sites must all carry resolved coordinates and cap ∩ sink_caps ≠ ∅",
    );

    if primary_sites.is_empty() {
        events.push(SsaTaintEvent {
            sink_node,
            tainted_values,
            sink_caps,
            all_validated,
            guard_kind,
            uses_summary,
            primary_sink_site: None,
        });
        return;
    }

    for site in primary_sites {
        events.push(SsaTaintEvent {
            sink_node,
            tainted_values: tainted_values.clone(),
            sink_caps,
            all_validated,
            guard_kind,
            uses_summary,
            primary_sink_site: Some(site),
        });
    }
}

/// Collect taint from call arguments.
///
/// `args` contains **positional arguments only**, the receiver is a separate
/// channel and is passed via `receiver`.  `propagating_params` indexes directly
/// into `args` using callee positional-parameter indices (no receiver offset).
///
/// When `propagating_params` is empty, taint is collected from the receiver
/// (if any) and from all positional args.
fn collect_args_taint(
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &SsaTaintState,
    propagating_params: &[usize],
) -> (Cap, SmallVec<[TaintOrigin; 2]>) {
    let mut combined_caps = Cap::empty();
    let mut combined_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();

    if propagating_params.is_empty() {
        // Collect from all args + receiver
        if let Some(rv) = receiver {
            if let Some(taint) = state.get(*rv) {
                combined_caps |= taint.caps;
                for orig in &taint.origins {
                    push_origin_bounded(&mut combined_origins, *orig);
                }
            }
        }
        for arg_vals in args {
            for &v in arg_vals {
                if let Some(taint) = state.get(v) {
                    combined_caps |= taint.caps;
                    for orig in &taint.origins {
                        push_origin_bounded(&mut combined_origins, *orig);
                    }
                }
            }
        }
    } else {
        // Collect only from propagating param positions.  Positional only ,
        // receiver-to-return propagation is handled by `receiver_to_return` on
        // the summary, not by this path.
        for &param_idx in propagating_params {
            if let Some(arg_vals) = args.get(param_idx) {
                for &v in arg_vals {
                    if let Some(taint) = state.get(v) {
                        combined_caps |= taint.caps;
                        for orig in &taint.origins {
                            push_origin_bounded(&mut combined_origins, *orig);
                        }
                    }
                }
            }
        }
    }

    (combined_caps, combined_origins)
}

/// Strip a capability bit from every argument SSA value of a call.
/// Used by the [`DataLabel::Sanitizer`] arm when the sanitizer covers
/// [`Cap::UNAUTHORIZED_ID`], ownership/membership guards prove on
/// inputs rather than the return value. Other caps and origins are
/// untouched.
/// Apply [`SsaFuncSummary::validated_params_to_return`] at a call site.
///
/// For each parameter index `p` in `validated_params`, mark the
/// `var_name` of every tainted SSA value at `args[p]` and the call's
/// own result `inst.value` in the caller's `validated_must` /
/// `validated_may` sets.  Mirrors the symbol-keyed validation a direct
/// `if (!regex.test(x)) throw` would set on the surviving branch.
///
/// Sound because the callee summary records `validated_params_to_return`
/// only when the param's `var_name` is in `validated_must` at *every*
/// return block — a normal-returning call therefore proves the
/// validating arm.  No-op when no actual argument is tainted (avoids
/// spuriously validating untouched names downstream).
fn propagate_validated_params_to_return(
    inst: &SsaInst,
    args: &[SmallVec<[SsaValue; 2]>],
    ssa: &SsaBody,
    interner: &crate::state::symbol::SymbolInterner,
    state: &mut SsaTaintState,
    validated_params: &[usize],
) {
    let mark = |val: SsaValue, st: &mut SsaTaintState| {
        let Some(name) = ssa
            .value_defs
            .get(val.0 as usize)
            .and_then(|vd| vd.var_name.as_deref())
        else {
            return;
        };
        let Some(sym) = interner.get(name) else {
            return;
        };
        st.validated_must.insert(sym);
        st.validated_may.insert(sym);
    };

    let mut any_arg_tainted = false;
    for &p in validated_params {
        let Some(arg_vals) = args.get(p) else {
            continue;
        };
        for &v in arg_vals {
            if state.get(v).is_some_and(|t| !t.caps.is_empty()) {
                any_arg_tainted = true;
                mark(v, state);
            }
        }
    }

    if any_arg_tainted {
        mark(inst.value, state);
    }
}

fn strip_cap_from_call_args(
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &mut SsaTaintState,
    cap: Cap,
) {
    let mut targets: SmallVec<[SsaValue; 8]> = SmallVec::new();
    if let Some(rv) = receiver {
        targets.push(*rv);
    }
    for arg_vals in args {
        for &v in arg_vals {
            targets.push(v);
        }
    }
    for v in targets {
        if let Some(current) = state.get(v) {
            if !current.caps.contains(cap) {
                continue;
            }
            let mut updated = current.clone();
            updated.caps &= !cap;
            state.set(v, updated);
        }
    }
}

/// Scoped libcurl special case: when `curl_easy_setopt(handle, CURLOPT_URL, value)`
/// is called and `value` is tainted, propagate that taint to `handle`.
///
/// Mirrors `TaintTransfer::try_curl_url_propagation` from `transfer.rs`.
fn try_curl_url_propagation(
    inst: &SsaInst,
    info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    state: &mut SsaTaintState,
) -> bool {
    if info.taint.defines.is_some() {
        return false;
    }
    let callee = match info.call.callee.as_deref() {
        Some(c) if c.ends_with("curl_easy_setopt") => c,
        _ => return false,
    };
    if !info.taint.uses.iter().any(|u| u == "CURLOPT_URL") {
        return false;
    }
    // Identify handle and URL SSA values from args.
    // Layout: args[0]=handle, args[1]=CURLOPT_URL, args[2]=url_value
    // But the uses list determines which are which. We need handle = first use
    // that isn't the callee or CURLOPT_URL.
    // In SSA form, the args vec gives us positional access.
    // Handle is first arg, URL value is last arg (skip CURLOPT_URL constant).
    let handle_val = args.first().and_then(|a| a.first().copied());
    let handle_val = match handle_val {
        Some(v) => v,
        None => return false,
    };

    // Collect taint from all args except the handle (args[0])
    let mut url_caps = Cap::empty();
    let mut url_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    for arg_vals in args.iter().skip(1) {
        for &v in arg_vals {
            if let Some(taint) = state.get(v) {
                url_caps |= taint.caps;
                for orig in &taint.origins {
                    push_origin_bounded(&mut url_origins, *orig);
                }
            }
        }
    }
    // Also check info.taint.uses for identifiers that aren't callee, handle, or CURLOPT_URL
    // in case arg_uses was empty and SSA lowering put all uses into a single group
    if url_caps.is_empty() {
        // Fallback: look at all used SSA values except handle
        let used = inst_use_values(inst);
        for v in used {
            if v == handle_val {
                continue;
            }
            if let Some(taint) = state.get(v) {
                url_caps |= taint.caps;
                for orig in &taint.origins {
                    push_origin_bounded(&mut url_origins, *orig);
                }
            }
        }
    }
    if url_caps.is_empty() {
        return false;
    }
    // Merge URL taint into handle (monotone: caps OR, origins union)
    match state.get(handle_val) {
        Some(existing) => {
            let mut merged = existing.clone();
            merged.caps |= url_caps;
            for orig in &url_origins {
                push_origin_bounded(&mut merged.origins, *orig);
            }
            state.set(handle_val, merged);
        }
        None => {
            state.set(
                handle_val,
                VarTaint {
                    caps: url_caps,
                    origins: url_origins,
                    uses_summary: false,
                },
            );
        }
    }

    // Also write the inst's own value as non-tainted (no defines on this node)
    let _ = callee;
    true
}

/// Resolve a container index SSA operand to a `HeapSlot`.
///
/// Uses the current function's `const_values` (from `SsaTaintTransfer`) to
/// determine whether the index is a provably non-negative integer constant
/// within `MAX_TRACKED_INDICES`.
///
/// - Intraprocedural: guaranteed, each function's own const propagation
///   results are used.
/// - Inline callee analysis (k=1): guaranteed, `inline_analyse_callee()`
///   sets `const_values: Some(&callee_body.opt.const_values)` on the child
///   transfer, so callee-local constants are resolved.
/// - Unknown / non-integer / out-of-bounds: falls back to `HeapSlot::Elements`.
fn resolve_container_index(index_val: SsaValue, transfer: &SsaTaintTransfer) -> HeapSlot {
    use crate::ssa::heap::MAX_TRACKED_INDICES;

    if let Some(cv) = transfer.const_values {
        if let Some(crate::ssa::const_prop::ConstLattice::Int(n)) = cv.get(&index_val) {
            if *n >= 0 && (*n as u64) < MAX_TRACKED_INDICES as u64 {
                return HeapSlot::Index(*n as u64);
            }
        }
    }
    HeapSlot::Elements
}

/// Resolve the `HeapSlot` for a container operation given its `index_arg`.
///
/// When `index_arg` is `Some(idx_pos)`, applies `arg_offset` and resolves
/// the SSA value from `args`.  Otherwise returns `HeapSlot::Elements`.
fn resolve_op_slot(
    index_arg: Option<usize>,
    arg_offset: usize,
    args: &[SmallVec<[SsaValue; 2]>],
    transfer: &SsaTaintTransfer,
) -> HeapSlot {
    if let Some(idx_pos) = index_arg {
        let effective = idx_pos + arg_offset;
        if let Some(arg_vals) = args.get(effective) {
            if let Some(&v) = arg_vals.first() {
                return resolve_container_index(v, transfer);
            }
        }
    }
    HeapSlot::Elements
}

/// Handle container operations: propagate taint between receiver and arguments.
///
/// **Store** operations (push, append, set, add, insert, etc.):
///   Merge value-argument taint into receiver SSA value.
///
/// **Load** operations (pop, get, join, shift, values, etc.):
///   Propagate receiver taint to the instruction's result value.
///
/// Returns `true` if the operation was handled and the caller should skip
/// default propagation.
fn try_container_propagation(
    inst: &SsaInst,
    _info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &mut SsaTaintState,
    transfer: &SsaTaintTransfer,
    callee: &str,
    ssa: &SsaBody,
) -> bool {
    let lang = transfer.lang;
    use crate::ssa::pointsto::{ContainerOp, classify_container_op};

    let op = match classify_container_op(callee, lang) {
        Some(op) => op,
        None => return false,
    };

    // Resolve the container SSA value.
    // Languages with `Kind::CallMethod` (Java, Ruby, PHP, Rust, etc.) set
    // `receiver` explicitly. For languages like JS/TS where method calls are
    // `Kind::CallFn`, the receiver is embedded in the args. We find it by
    // looking for an SSA value whose var_name matches the receiver portion
    // of the dotted callee (e.g. "items" from "items.push").
    let resolve_container = |recv: &Option<SsaValue>| -> Option<SsaValue> {
        if let Some(v) = *recv {
            return Some(v);
        }
        // Go append: no receiver, arg 0 is the slice
        if lang == Lang::Go {
            return args.first().and_then(|a| a.first().copied());
        }
        // For dotted callees like "items.push", find the SSA value for "items"
        let dot_pos = callee.rfind('.')?;
        let receiver_name = &callee[..dot_pos];
        // Search all arg groups for an SSA value with matching var_name
        for arg_group in args {
            for &v in arg_group {
                if let Some(def) = ssa.value_defs.get(v.0 as usize) {
                    if def.var_name.as_deref() == Some(receiver_name) {
                        return Some(v);
                    }
                }
            }
        }
        None
    };

    match op {
        ContainerOp::Store {
            value_args,
            index_arg,
        } => {
            let container_val = match resolve_container(receiver) {
                Some(v) => v,
                None => return false,
            };

            // For Go `append`, args[0] is the slice itself and value args
            // follow at index 1.  For method-style container ops the receiver
            // is a separate channel on `SsaOp::Call.receiver`, so `args`
            // contains positional arguments only.
            let arg_offset = if lang == Lang::Go && receiver.is_none() {
                1usize
            } else {
                0
            };

            // Resolve index argument to HeapSlot (Index(n) or Elements).
            let slot = resolve_op_slot(index_arg, arg_offset, args, transfer);

            // Collect taint from value argument(s)
            let mut val_caps = Cap::empty();
            let mut val_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            for &arg_idx in &value_args {
                let effective_idx = arg_idx + arg_offset;
                if let Some(arg_vals) = args.get(effective_idx) {
                    for &v in arg_vals {
                        if let Some(taint) = state.get(v) {
                            val_caps |= taint.caps;
                            for orig in &taint.origins {
                                push_origin_bounded(&mut val_origins, *orig);
                            }
                        }
                    }
                }
            }

            if val_caps.is_empty() {
                return true; // Container op handled, but no taint to propagate
            }

            // When points-to info available, store through heap objects
            if let Some(pts) = lookup_pts(transfer, container_val) {
                state.heap.store_set(&pts, slot, val_caps, &val_origins);
                // For Go append, result also points to same heap objects
                if lang == Lang::Go && receiver.is_none() {
                    if let Some(ht) = state.heap.load_set(&pts, HeapSlot::Elements) {
                        state.set(
                            inst.value,
                            VarTaint {
                                caps: ht.caps,
                                origins: ht.origins,
                                uses_summary: false,
                            },
                        );
                    }
                }
                return true;
            }
            // Fallback: direct SSA value taint (no pts info for this container)
            merge_taint_into(state, container_val, val_caps, &val_origins);

            // For Go append, the result is the new slice, propagate merged taint
            if lang == Lang::Go && receiver.is_none() {
                if let Some(merged) = state.get(container_val) {
                    state.set(inst.value, merged.clone());
                }
            }

            true
        }
        ContainerOp::Load { index_arg } => {
            let container_val = match resolve_container(receiver) {
                Some(v) => v,
                None => {
                    // Java safe-lookup field fallback: when the receiver is a
                    // free identifier (no SSA value to look up) and the
                    // callee text is `<NAME>.get`, check whether `<NAME>`
                    // is a class field whose initializer is a recognised
                    // safe map (`final ... = Map.of(literal, literal,
                    // ...)`).  In that case the lookup result is bounded
                    // to the literal value set, so a tainted key cannot
                    // taint the result; leave `inst.value` untainted and
                    // claim the call as handled.
                    if lang == Lang::Java && try_java_safe_field_lookup_load(callee) {
                        return true;
                    }
                    return false;
                }
            };

            // Resolve index argument to HeapSlot.
            // For Go container ops, args[0] is the container itself (value args
            // start at 1).  For method-style calls the receiver is a separate
            // channel, so `args` holds positional arguments from index 0.
            let arg_offset = if lang == Lang::Go && receiver.is_none() {
                1usize
            } else {
                0
            };
            let slot = resolve_op_slot(index_arg, arg_offset, args, transfer);

            // When points-to info available, load from heap objects
            if let Some(pts) = lookup_pts(transfer, container_val) {
                if let Some(ht) = state.heap.load_set(&pts, slot) {
                    state.set(
                        inst.value,
                        VarTaint {
                            caps: ht.caps,
                            origins: ht.origins,
                            uses_summary: false,
                        },
                    );
                }
                return true;
            }
            // Fallback: direct SSA value taint
            if let Some(taint) = state.get(container_val) {
                state.set(inst.value, taint.clone());
            }
            true
        }
        ContainerOp::Writeback { dest_arg } => {
            // Receiver carries the source taint (e.g.
            // `json.NewDecoder(r.Body).Decode(&dest)`, the decoder's
            // receiver chain is tainted by `r.Body`).  Propagate that taint
            // into the call's destination argument so downstream sinks see
            // the flow through the decoded struct.
            //
            // Go method calls lower to `Kind::CallFn` with the receiver
            // implicit in the dotted callee text (`d.Decode`), there's no
            // explicit `receiver` channel and no slice-as-arg-0 convention
            // (unlike Go's `append`), so the existing `resolve_container`
            // helper either returns the wrong value or `None` here.  Look
            // up the receiver SSA value by var-name from the callee prefix.
            // Detect a chained-call receiver shape (`a.b(c).d(e)`) where
            // the receiver of the writeback method is itself a call
            // expression, so its return value never gets a separate SSA
            // value and there is no `var_name` to look up.
            //
            // For `json.NewDecoder(r.Body).Decode(emoji)` the callee text
            // is `"json.NewDecoder(r.Body).Decode"`: parens appear inside
            // the dotted prefix.  In that case we fall back to unioning
            // the taint of every implicit-arg group (the synth-source
            // bindings produced by `walk_chain_inner_call_args`) and
            // treating that as the receiver taint.
            let chain_shape = {
                let dot_pos = callee.rfind('.');
                match dot_pos {
                    Some(p) => callee[..p].contains('('),
                    None => false,
                }
            };
            let recv_val = if let Some(v) = *receiver {
                Some(v)
            } else if !chain_shape && let Some(dot_pos) = callee.rfind('.') {
                let recv_name = &callee[..dot_pos];
                let mut found = None;
                'outer: for arg_group in args {
                    for &v in arg_group {
                        if let Some(def) = ssa.value_defs.get(v.0 as usize) {
                            if def.var_name.as_deref() == Some(recv_name) {
                                found = Some(v);
                                break 'outer;
                            }
                        }
                    }
                }
                if found.is_none() {
                    // Receiver isn't in args (Go CallFn).  Search the SSA
                    // body for a value whose var_name matches the receiver.
                    for (idx, def) in ssa.value_defs.iter().enumerate() {
                        if def.var_name.as_deref() == Some(recv_name) {
                            found = Some(SsaValue(idx as u32));
                            break;
                        }
                    }
                }
                found
            } else {
                None
            };
            let recv_taint = if let Some(v) = recv_val {
                if let Some(t) = state.get(v) {
                    t.clone()
                } else if chain_shape {
                    // Receiver SSA value found but carries no direct
                    // taint, fall through to chain-shape arg union.
                    let mut caps = Cap::empty();
                    let mut origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                    for (idx, arg_group) in args.iter().enumerate() {
                        if idx == dest_arg {
                            continue;
                        }
                        for &v in arg_group {
                            if let Some(t) = state.get(v) {
                                caps |= t.caps;
                                for orig in &t.origins {
                                    push_origin_bounded(&mut origins, *orig);
                                }
                            }
                        }
                    }
                    if caps.is_empty() {
                        return true;
                    }
                    VarTaint {
                        caps,
                        origins,
                        uses_summary: false,
                    }
                } else {
                    return true; // claimed but receiver carries no taint
                }
            } else if chain_shape {
                // Sum taint across every arg group except the destination
                // arg.  In the chained shape, synth-source bindings
                // emitted by `walk_chain_inner_call_args` land in the
                // implicit-arg slot (`info.taint.uses` → `args[N]`); the
                // dest_arg itself is the writeback's destination, never
                // a source.
                let mut caps = Cap::empty();
                let mut origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
                for (idx, arg_group) in args.iter().enumerate() {
                    if idx == dest_arg {
                        continue;
                    }
                    for &v in arg_group {
                        if let Some(t) = state.get(v) {
                            caps |= t.caps;
                            for orig in &t.origins {
                                push_origin_bounded(&mut origins, *orig);
                            }
                        }
                    }
                }
                if caps.is_empty() {
                    return true;
                }
                VarTaint {
                    caps,
                    origins,
                    uses_summary: false,
                }
            } else {
                if std::env::var("NYX_DEBUG_WRITEBACK").is_ok() {
                    eprintln!("  writeback: no receiver SSA value for callee {callee:?}");
                }
                return false;
            };
            // For method-call form, the receiver is implicit in the callee
            // string and `args` holds positional args starting at 0.  Taint
            // the destination at three layers: (1) the SSA-value level so
            // downstream uses of the pointer itself see taint; (2) the
            // heap-Elements slot via the simpler-tier `lookup_pts` channel;
            // and (3) the field-cell channel via `pointer_facts.pt(v)` with
            // [`FieldId::ELEM`] as a tainted-at-all-fields wildcard so
            // subsequent `dest.Field` projections (which read through the
            // higher-tier `pointer_facts.pt(receiver)` channel, see the
            // `SsaOp::FieldProj` arm) inherit the taint.  Without (3), CVE
            // shapes like `json.NewDecoder(r.Body).Decode(&dest)` followed
            // by `os.Remove(filepath.Join(_, dest.Name))` left the dest
            // field channel empty even though the heap was tainted; the
            // [`FieldId::ELEM`] wildcard bridges the two channels and is
            // read back by the `FieldProj` arm's ELEM fallback.
            if let Some(arg_vals) = args.get(dest_arg) {
                for &v in arg_vals {
                    merge_taint_into(state, v, recv_taint.caps, &recv_taint.origins);
                    if let Some(pts) = lookup_pts(transfer, v) {
                        state.heap.store_set(
                            &pts,
                            crate::ssa::heap::HeapSlot::Elements,
                            recv_taint.caps,
                            &recv_taint.origins,
                        );
                    }
                    if let Some(pf) = transfer.pointer_facts {
                        let pt_arg = pf.pt(v);
                        if !pt_arg.is_empty() && !pt_arg.is_top() {
                            let cell_taint = recv_taint.clone();
                            for loc in pt_arg.iter() {
                                let key = crate::taint::ssa_transfer::state::FieldTaintKey {
                                    loc,
                                    field: crate::ssa::ir::FieldId::ANY_FIELD,
                                };
                                state.add_field(key, cell_taint.clone(), false, false);
                            }
                        }
                    }
                }
            }
            true
        }
    }
}

/// Find the container receiver SSA value for a container operation.
/// Reuses the same logic as `try_container_propagation`'s resolve_container.
fn find_container_receiver(
    callee: &str,
    receiver: &Option<SsaValue>,
    args: &[SmallVec<[SsaValue; 2]>],
    ssa: &SsaBody,
    lang: Lang,
) -> Option<SsaValue> {
    if let Some(v) = *receiver {
        return Some(v);
    }
    if lang == Lang::Go {
        return args.first().and_then(|a| a.first().copied());
    }
    let dot_pos = callee.rfind('.')?;
    let receiver_name = &callee[..dot_pos];
    for arg_group in args {
        for &v in arg_group {
            if let Some(def) = ssa.value_defs.get(v.0 as usize) {
                if def.var_name.as_deref() == Some(receiver_name) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Look up points-to set for an SSA value, checking both the static
/// pre-pass result and the dynamic inter-procedural set.
fn lookup_pts(transfer: &SsaTaintTransfer, v: SsaValue) -> Option<PointsToSet> {
    if let Some(pts_result) = transfer.points_to {
        if let Some(pts) = pts_result.get(v) {
            return Some(pts.clone());
        }
    }
    if let Some(dyn_ref) = transfer.dynamic_pts {
        if let Some(pts) = dyn_ref.borrow().get(&v) {
            return Some(pts.clone());
        }
    }
    None
}

/// Merge taint caps and origins into an existing SSA value's taint (monotone).
fn merge_taint_into(
    state: &mut SsaTaintState,
    target: SsaValue,
    caps: Cap,
    origins: &SmallVec<[TaintOrigin; 2]>,
) {
    match state.get(target) {
        Some(existing) => {
            let mut merged = existing.clone();
            merged.caps |= caps;
            for orig in origins {
                push_origin_bounded(&mut merged.origins, *orig);
            }
            state.set(target, merged);
        }
        None => {
            state.set(
                target,
                VarTaint {
                    caps,
                    origins: origins.clone(),
                    uses_summary: false,
                },
            );
        }
    }
}

/// Resolve sink caps from labels or callee summary.
/// Resolved sink information: aggregate caps plus optional per-parameter detail.
struct SinkInfo {
    caps: Cap,
    /// When non-empty, only these caller argument positions flow to sinks.
    /// Each entry is (param_index, per_param_sink_caps).
    /// Empty = check all arguments (label-based sinks, or no per-param info).
    param_to_sink: Vec<(usize, Cap)>,
    /// Per-parameter [`SinkSite`] records carried from the callee summary,
    /// mirroring `param_to_sink` by parameter index.  Empty for label-based
    /// sinks and for cap-only summaries that do not retain source
    /// coordinates.  Used to attribute findings to the dangerous
    /// callee-internal instruction.
    param_to_sink_sites: Vec<(usize, SmallVec<[SinkSite; 1]>)>,
    /// Per-parameter gate-filter cap masks lifted from the callee's
    /// inner multi-gate sink call sites. Mirrors
    /// [`crate::summary::ssa_summary::SsaFuncSummary::param_to_gate_filters`].
    /// When non-empty, the dispatcher in [`collect_block_events`]
    /// expands one filter pass per `(param_idx, label_caps)` entry so
    /// a wrapper carrying multiple gate classes (e.g. SSRF on the URL
    /// arg + DATA_EXFIL on the body arg) attributes findings per cap
    /// instead of joining them.
    param_to_gate_filters: Vec<(usize, Cap)>,
}

fn resolve_sink_info(info: &NodeInfo, transfer: &SsaTaintTransfer) -> SinkInfo {
    let label_sink_caps = info.taint.labels.iter().fold(Cap::empty(), |acc, lbl| {
        if let DataLabel::Sink(caps) = lbl {
            acc | *caps
        } else {
            acc
        }
    });
    if !label_sink_caps.is_empty() {
        return SinkInfo {
            caps: label_sink_caps,
            param_to_sink: vec![],
            param_to_sink_sites: vec![],
            param_to_gate_filters: vec![],
        };
    }

    let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
    // The sink-label path needs an arity hint so we do not match a
    // same-name/different-arity overload in another namespace.
    // `arg_uses.len()` is the positional-argument count, the receiver is a
    // separate channel on `info.call.receiver`, not prepended to `arg_uses`.
    let arity_hint = if info.call.arg_uses.is_empty() {
        None
    } else {
        Some(info.call.arg_uses.len())
    };
    let primary = info.call.callee.as_ref().and_then(|c| {
        resolve_callee_hinted(transfer, c, caller_func, info.call.call_ordinal, arity_hint)
    });
    if let Some(r) = primary.filter(|r| !r.sink_caps.is_empty()) {
        return SinkInfo {
            caps: r.sink_caps,
            param_to_sink: r.param_to_sink,
            param_to_sink_sites: r.param_to_sink_sites,
            param_to_gate_filters: r.param_to_gate_filters,
        };
    }

    // Fallback: when first_member_label rebound `info.call.callee` to an
    // inner source path (e.g. `helper(req.body.uri)` → callee="req.body.uri",
    // outer_callee="helper"), the inner-name lookup misses the actual
    // wrapper's summary. Retry with `outer_callee` so the wrapper's
    // `param_to_sink` summary fires for cross-function sink propagation.
    // Strict-additive: only fires when the primary inner-callee resolution
    // produced no sink caps; any positive primary result wins.  Motivated
    // by CVE-2025-64430.
    if let Some(oc) = info.call.outer_callee.as_ref() {
        if let Some(r) = resolve_callee_hinted(
            transfer,
            oc,
            caller_func,
            info.call.call_ordinal,
            arity_hint,
        )
        .filter(|r| !r.sink_caps.is_empty())
        {
            return SinkInfo {
                caps: r.sink_caps,
                param_to_sink: r.param_to_sink,
                param_to_sink_sites: r.param_to_sink_sites,
                param_to_gate_filters: r.param_to_gate_filters,
            };
        }
    }

    SinkInfo {
        caps: Cap::empty(),
        param_to_sink: vec![],
        param_to_sink_sites: vec![],
        param_to_gate_filters: vec![],
    }
}

/// Collect tainted SSA values at a sink instruction.
///
/// When `param_to_sink` is non-empty, only arguments at those positions are
/// checked, enables per-parameter sink precision from cross-file summaries.
///
/// `positions_override` and `destination_override`, when `Some`, supersede
/// `info.call.sink_payload_args` and `info.call.destination_uses` for this
/// call.  Used by the multi-gate sink dispatch in [`collect_block_events`]
/// to attribute taint per-cap when a callee carries several gates (e.g.
/// `fetch` SSRF on the URL position vs `DATA_EXFIL` on the body position).
#[allow(clippy::too_many_arguments)]
fn collect_tainted_sink_values(
    inst: &SsaInst,
    info: &NodeInfo,
    state: &SsaTaintState,
    sink_caps: Cap,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    param_to_sink: &[(usize, Cap)],
    positions_override: Option<&[usize]>,
    destination_override: Option<&[String]>,
) -> Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)> {
    let mut result = Vec::new();

    // Helper: check heap taint for an SSA value that may point to container(s).
    // At sinks we use Elements to conservatively see all indexed taint.
    let check_heap_taint =
        |v: SsaValue, result: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>| {
            if let Some(pts) = lookup_pts(transfer, v) {
                if let Some(ht) = state.heap.load_set(&pts, HeapSlot::Elements) {
                    let effective = ht.caps & sink_caps;
                    if !effective.is_empty() && !result.iter().any(|&(rv, _, _)| rv == v) {
                        result.push((v, ht.caps, ht.origins));
                    }
                }
            }
        };

    // Collect SSA values used by this instruction
    let used_values = inst_use_values(inst);

    // Priority 1: gated sink filtering (CFG-level sink_payload_args, or a
    // multi-gate per-filter override).  The position list indexes into
    // positional args (no receiver offset); the receiver is a separate
    // channel via `SsaOp::Call.receiver`.
    //
    // Destination-aware narrowing: when a destination filter is set,
    // restrict sink-taint checks to SSA values whose `var_name` matches one
    // of the listed destination field identifiers. This silences
    // `fetch({url: fixed, body: tainted})` while still firing on
    // `fetch({url: tainted, body: fixed})`.
    let positions: Option<&[usize]> = positions_override.or(info.call.sink_payload_args.as_deref());
    let destination_filter: Option<&[String]> =
        destination_override.or(info.call.destination_uses.as_deref());
    if let Some(positions) = positions {
        if let SsaOp::Call { args, .. } = &inst.op {
            for &pos in positions {
                if let Some(arg_vals) = args.get(pos) {
                    for &v in arg_vals {
                        if let Some(names) = destination_filter {
                            // Only proceed when this SSA value corresponds to
                            // a declared destination field identifier.
                            let var_name = ssa.def_of(v).var_name.as_deref();
                            let matches = var_name.is_some_and(|vn| names.iter().any(|n| n == vn));
                            if !matches {
                                continue;
                            }
                        }
                        if let Some(taint) = state.get(v) {
                            if (taint.caps & sink_caps) != Cap::empty() {
                                result.push((v, taint.caps, taint.origins.clone()));
                            }
                        }
                        check_heap_taint(v, &mut result);
                    }
                }
            }
            apply_field_aware_suppression(&mut result, inst, info, state, sink_caps, ssa);
            apply_arg_type_safe_suppression(
                &mut result,
                sink_caps,
                transfer.type_facts,
                inst,
                info,
            );
            return result;
        }
    }

    // Priority 2: summary-based per-parameter sink filtering.
    // `param_to_sink` indices refer to the callee's positional parameter
    // positions and map directly onto `args`.  The receiver channel is
    // handled via `receiver_to_sink` in the summary.
    if !param_to_sink.is_empty() {
        if let SsaOp::Call { args, .. } = &inst.op {
            for &(param_idx, per_param_caps) in param_to_sink {
                let effective_caps = per_param_caps & sink_caps;
                if effective_caps.is_empty() {
                    continue;
                }
                if let Some(arg_vals) = args.get(param_idx) {
                    for &v in arg_vals {
                        if let Some(taint) = state.get(v) {
                            if (taint.caps & effective_caps) != Cap::empty()
                                && !result.iter().any(|&(rv, _, _)| rv == v)
                            {
                                result.push((v, taint.caps, taint.origins.clone()));
                            }
                        }
                        check_heap_taint(v, &mut result);
                    }
                }
            }
            apply_field_aware_suppression(&mut result, inst, info, state, sink_caps, ssa);
            apply_arg_type_safe_suppression(
                &mut result,
                sink_caps,
                transfer.type_facts,
                inst,
                info,
            );
            return result;
        }
    }

    // Priority 3: aggregate fallback, check all used values
    for v in used_values {
        if let Some(taint) = state.get(v) {
            if (taint.caps & sink_caps) != Cap::empty() {
                result.push((v, taint.caps, taint.origins.clone()));
            }
        }
        check_heap_taint(v, &mut result);
    }

    apply_field_aware_suppression(&mut result, inst, info, state, sink_caps, ssa);
    apply_arg_type_safe_suppression(&mut result, sink_caps, transfer.type_facts, inst, info);
    result
}

/// Drop tainted argument SSA values from the per-call sink-emission set
/// when their inferred [`crate::ssa::type_facts::TypeKind`] proves the
/// value is payload-incompatible with `sink_caps` (e.g. an `Int`-tagged
/// value reaching a `HEADER_INJECTION` sink: numeric scalars, the
/// safe-string conversions in
/// [`crate::ssa::type_facts::is_safe_string_producing_callee`], and
/// `length()` / `size()` numeric-property reads cannot encode CRLF or
/// any sink-class metacharacter).
///
/// Mirrors the non-call sink path's
/// [`crate::ssa::type_facts::is_type_safe_for_sink`] gate at line 7317
/// of the main analyser, applied here on Call instructions so the
/// shared suppression rule covers idiomatic Java mitigation patterns
/// (`res.setHeader("X-Count", Integer.toString(payload.size()))`,
/// `res.setHeader("X-Class", loaded.getClass().getName())`) without
/// special-casing the sink callee.
fn apply_arg_type_safe_suppression(
    result: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    sink_caps: Cap,
    _type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    inst: &SsaInst,
    info: &NodeInfo,
) {
    use crate::ssa::type_facts::is_safe_string_producing_callee;
    if result.is_empty() {
        return;
    }
    // Type-suppression mask. An arg whose enclosing call is a "safe
    // string" producer (numeric/boolean to-string conversion or a
    // class-name accessor) emits a string provably free of the
    // metacharacters that drive these injection classes.  The same
    // mask the shared
    // [`crate::ssa::type_facts::is_type_safe_for_sink`] gate uses for
    // `Int` / `Bool` values, applied here at Call sinks against the
    // arg-level callee text instead of the value-level type kind.
    let type_suppressible = Cap::SQL_QUERY
        | Cap::FILE_IO
        | Cap::SHELL_ESCAPE
        | Cap::HTML_ESCAPE
        | Cap::SSRF
        | Cap::DATA_EXFIL
        | Cap::HEADER_INJECTION
        | Cap::OPEN_REDIRECT;
    let sink_fully_type_suppressible =
        !sink_caps.is_empty() && (sink_caps & !type_suppressible).is_empty();
    if !sink_fully_type_suppressible {
        return;
    }
    // Identify SSA values whose enclosing arg position has an inner
    // call to a safe-string producer
    // ([`is_safe_string_producing_callee`]).  The CFG/SSA pipeline does
    // not lower nested method invocations into separate Call SSA ops
    // (the outer call's arg list captures the inner receiver's SSA
    // value directly), so the only place to recover "this arg came
    // from `Integer.toString` / `Class.getName` / ..." is the
    // `info.arg_callees` text recorded by `extract_arg_callees`.
    //
    // Strict-additive: we only suppress when the entire arg expression
    // IS a safe-string-producing call, not when a tainted value flows
    // through a string concat ,  the latter is a real SQLi shape
    // (`"SELECT ... LIMIT " + intExpr`) and must keep firing.
    let SsaOp::Call { args, .. } = &inst.op else {
        return;
    };
    let mut safe_string_values: std::collections::HashSet<SsaValue> =
        std::collections::HashSet::new();
    for (pos, arg_vals) in args.iter().enumerate() {
        let safe = info
            .arg_callees
            .get(pos)
            .and_then(|c| c.as_deref())
            .map(is_safe_string_producing_callee)
            .unwrap_or(false);
        if safe {
            for &v in arg_vals {
                safe_string_values.insert(v);
            }
        }
    }
    if safe_string_values.is_empty() {
        return;
    }
    result.retain(|(v, _, _)| !safe_string_values.contains(v));
}

/// Suppress plain-ident taint when a dotted-path field value used by the same
/// instruction is untainted. Prevents false positives from base-ident bleed
/// (e.g. `obj.safe = "const"; sink(obj.safe)` where `obj` is tainted).
fn apply_field_aware_suppression(
    result: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    inst: &SsaInst,
    info: &NodeInfo,
    state: &SsaTaintState,
    sink_caps: Cap,
    ssa: &SsaBody,
) {
    if result.is_empty() {
        return;
    }
    let all_used = inst_use_values(inst);
    result.retain(|(v, _, _)| {
        let Some(base) = ssa.def_of(*v).var_name.as_deref() else {
            return true;
        };
        // Only suppress plain idents (no dots)
        if base.contains('.') {
            return true;
        }
        let prefix = format!("{}.", base);
        // Collect callee-like names to exclude from field suppression.
        // Method call expressions like "items.join" (from inner calls within
        // this node's arguments) should NOT be treated as field accesses.
        let callee_name = match &inst.op {
            SsaOp::Call { callee, .. } => Some(callee.as_str()),
            _ => None,
        };
        // Collect all field values matching "base.X" (excluding method-call
        // expressions and the callee itself).
        //
        // Phantom Param ops with dotted var_names (e.g. `u.String` for the
        // method ref in `u.String()`) represent free-identifier references
        // hoisted by SSA lowering, not real data field accesses.  Owncast
        // CVE-2023-3188 hit this: `http.DefaultClient.Get(u.String())`
        // includes both `u` (tainted) and `u.String` (untainted phantom)
        // as uses; treating `u.String` as a clean field of `u` suppressed
        // the SSRF.  But JS object-field FP guards (e.g.
        // `db.query(obj.safeField)` with `obj.unsafeField` tainted) need
        // the opposite, `obj.safeField` is a real field access and SHOULD
        // count as a clean field.  The CFG distinguishes the two via
        // `arg_callees`: when an argument expression is itself a call, its
        // callee text is recorded; pure member-access args leave the slot
        // `None`.  Skip phantoms whose var_name appears as an arg_callee
        // (the Go case), keep phantoms representing field reads (the JS
        // case) so suppression still fires.
        let field_values: SmallVec<[SsaValue; 4]> = all_used
            .iter()
            .copied()
            .filter(|&u| {
                if u == *v {
                    return false;
                }
                let uname = match ssa.def_of(u).var_name.as_deref() {
                    Some(n) => n,
                    None => return false,
                };
                if !uname.starts_with(&prefix) {
                    return false;
                }
                if callee_name.is_some_and(|cn| uname == cn) {
                    return false;
                }
                if is_likely_method_expression(uname) {
                    return false;
                }
                if is_phantom_param_value(u, ssa)
                    && info.arg_callees.iter().any(|c| c.as_deref() == Some(uname))
                {
                    return false;
                }
                true
            })
            .collect();
        // Suppress base only if there ARE field values AND ALL of them
        // are untainted for the relevant sink caps.
        let all_fields_clean = !field_values.is_empty()
            && field_values.iter().all(|&u| match state.get(u) {
                None => true,
                Some(t) => (t.caps & sink_caps).is_empty(),
            });
        !all_fields_clean
    });
}

/// Check whether an SSA value is defined by a phantom `Param` op (a free
/// identifier like `u.String` hoisted by SSA lowering, not a real positional
/// parameter).  Used by field-aware suppression to skip method/function
/// references that share a base name with a tainted variable.
fn is_phantom_param_value(v: SsaValue, ssa: &SsaBody) -> bool {
    let def = ssa.def_of(v);
    let block = &ssa.blocks[def.block.0 as usize];
    block
        .phis
        .iter()
        .chain(block.body.iter())
        .find(|inst| inst.value == v)
        .is_some_and(|inst| matches!(inst.op, SsaOp::Param { .. } | SsaOp::SelfParam))
}

/// Check if a dotted var_name looks like a method call expression rather than
/// a field access. E.g., "items.join" where "join" is a method name, vs
/// "obj.data" which is a field access.
///
/// Used by field-aware suppression to avoid treating method call expressions
/// as untainted field accesses (which would incorrectly suppress base-ident taint).
fn is_likely_method_expression(name: &str) -> bool {
    // Check if the dotted name matches any Call callee in the SSA body,
    // or if its suffix is a known function/method name.
    let suffix = name.rsplit('.').next().unwrap_or(name);
    // Common method names that are unlikely to be data field names.
    // This is a heuristic; it doesn't need to be exhaustive because
    // false negatives just mean slightly more conservative (no suppression).
    matches!(
        suffix,
        "push"
            | "pop"
            | "shift"
            | "unshift"
            | "join"
            | "split"
            | "concat"
            | "slice"
            | "splice"
            | "map"
            | "filter"
            | "reduce"
            | "forEach"
            | "find"
            | "some"
            | "every"
            | "get"
            | "set"
            | "has"
            | "delete"
            | "add"
            | "remove"
            | "clear"
            | "keys"
            | "values"
            | "entries"
            | "toString"
            | "valueOf"
            | "send"
            | "write"
            | "end"
            | "render"
            | "redirect"
            | "append"
            | "extend"
            | "insert"
            | "update"
            | "items"
            | "call"
            | "apply"
            | "bind"
            | "then"
            | "catch"
            | "trim"
            | "replace"
            | "match"
            | "search"
            | "test"
            | "log"
            | "warn"
            | "error"
            | "info"
            | "debug"
            | "execute"
            | "query"
            | "fetch"
            | "request"
    )
}

/// Get all SSA values used by an instruction.
fn inst_use_values(inst: &SsaInst) -> Vec<SsaValue> {
    match &inst.op {
        SsaOp::Phi(operands) => operands.iter().map(|(_, v)| *v).collect(),
        SsaOp::Assign(uses) => uses.to_vec(),
        SsaOp::Call { args, receiver, .. } => {
            let mut vals = Vec::new();
            if let Some(rv) = receiver {
                vals.push(*rv);
            }
            for arg in args {
                vals.extend(arg.iter());
            }
            vals
        }
        SsaOp::FieldProj { receiver, .. } => vec![*receiver],
        SsaOp::Source
        | SsaOp::Const(_)
        | SsaOp::Param { .. }
        | SsaOp::SelfParam
        | SsaOp::CatchParam
        | SsaOp::Nop
        | SsaOp::Undef => Vec::new(),
    }
}

// ── Go same-request self-redirect detection ────────────────────────────

/// Detect Go `http.Redirect(w, r, urlExpr, code)` whose URL string arg is
/// derived from the same `*http.Request`'s `URL` (e.g. `r.URL.String()`,
/// `r.URL.RequestURI()`, `r.URL.EscapedPath()`).  Such a redirect echoes
/// the inbound request's URL with at most path-only edits, so scheme/host
/// are same-origin by construction and `Cap::OPEN_REDIRECT` cannot fire.
///
/// Recognition is purely syntactic over the SSA call's args:
///   * arg 1 (the `*Request`) and arg 2 (the URL string) are correlated
///     through the FieldProj `URL` accessor on a shared receiver chain.
///   * arg 2's defining op is a Call to a `*url.URL` accessor whose
///     return is a string derived from the URL.
///
/// gin's `redirectTrailingSlash` / `redirectFixedPath` / `redirectRequest`
/// helpers are the canonical shape; the same gate applies to any
/// hand-written `http.Redirect(w, r, r.URL.String(), code)` form.
fn is_go_request_self_redirect(inst: &SsaInst, info: &NodeInfo, ssa: &SsaBody) -> bool {
    let callee = match info.call.callee.as_deref() {
        Some(c) => c,
        None => return false,
    };
    if !callee.eq_ignore_ascii_case("http.Redirect") {
        return false;
    }
    let SsaOp::Call { ref args, .. } = inst.op else {
        return false;
    };
    // `http.Redirect(w, r, url, code)` is the canonical 4-arg shape, but
    // SSA construction sometimes folds the package-qualifier into an extra
    // arg-0 phantom group (5-arg shape); both keep `r`/`url` at indices
    // 1/2.  Accept either.
    let req_arg_idx = 1usize;
    let url_arg_idx = 2usize;
    if args.len() <= url_arg_idx {
        return false;
    }
    let url_v = match args[url_arg_idx].first() {
        Some(&v) => v,
        None => return false,
    };
    // Resolve the request's canonical name.  Prefer the SSA-level value
    // when args[1] is populated; fall back to the CFG's `arg_uses` row,
    // which records the syntactic identifier list for arg position 1
    // even when SSA didn't lift the reference into a tracked value.
    let (req_v_opt, req_name) = match args[req_arg_idx].first() {
        Some(&v) => (Some(v), ssa_canonical_var_name(v, ssa)),
        None => (
            None,
            info.call
                .arg_uses
                .get(req_arg_idx)
                .and_then(|row| row.first())
                .cloned(),
        ),
    };
    is_request_url_method_value(url_v, req_v_opt, req_name.as_deref(), ssa)
}

/// Walk through `Assign` hops to find the canonical "name" of an SSA
/// value: prefer the leading use's `var_name` when the def is an Assign
/// chain; otherwise fall back to the value's own `var_name`.
fn ssa_canonical_var_name(v: SsaValue, ssa: &SsaBody) -> Option<String> {
    let mut cur = v;
    for _ in 0..8 {
        let def = ssa.def_of(cur);
        if let Some(name) = def.var_name.as_deref() {
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
        let def_inst = find_inst_for_value(cur, ssa)?;
        if let SsaOp::Assign(uses) = &def_inst.op {
            if let Some(&first) = uses.first() {
                if first == cur {
                    return None;
                }
                cur = first;
                continue;
            }
        }
        return None;
    }
    None
}

/// Return true when `url_v` traces (through up to a few Assign hops) to
/// either of two equivalent SSA shapes that read a `*url.URL` accessor on
/// the same request:
///   1. Decomposed chain — `Call("String"|"RequestURI"|...)` whose
///      receiver is `FieldProj(req, "URL")` (chained-method shape, kicks
///      in for `r.URL.String()`-style method calls).
///   2. Flat chain — `Call("<req>.URL.<accessor>", rcv=None)` (no
///      decomposition), used by SSA lowering for plain field reads
///      (`r.URL.Path`) and short method chains alike.
///
/// Match success means: arg 1 (the `*Request`) and arg 2 (the URL string)
/// are correlated through the same request's `URL` field, so the redirect
/// destination is same-origin by construction.
fn is_request_url_method_value(
    url_v: SsaValue,
    req_v: Option<SsaValue>,
    req_name: Option<&str>,
    ssa: &SsaBody,
) -> bool {
    let mut cur = url_v;
    for _ in 0..8 {
        let Some(def_inst) = find_inst_for_value(cur, ssa) else {
            return false;
        };
        match &def_inst.op {
            SsaOp::Assign(uses) if uses.len() == 1 => {
                cur = uses[0];
            }
            SsaOp::Call {
                callee,
                receiver: Some(rcv),
                ..
            } => {
                if !is_url_accessor_method(callee) {
                    return false;
                }
                let Some(rcv_def) = find_inst_for_value(*rcv, ssa) else {
                    return false;
                };
                let SsaOp::FieldProj {
                    receiver: inner_recv,
                    field,
                    ..
                } = rcv_def.op
                else {
                    return false;
                };
                if ssa.field_interner.resolve(field) != "URL" {
                    return false;
                }
                if Some(inner_recv) == req_v {
                    return true;
                }
                let inner_name = ssa_canonical_var_name(inner_recv, ssa);
                return match (inner_name.as_deref(), req_name) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };
            }
            SsaOp::Call {
                callee,
                receiver: None,
                ..
            } => {
                // Flat chain shape: callee text is `<root>.URL.<accessor>`.
                let req_name = match req_name {
                    Some(n) => n,
                    None => return false,
                };
                let prefix = format!("{req_name}.URL.");
                if !callee.starts_with(&prefix) {
                    return false;
                }
                let suffix = &callee[prefix.len()..];
                // Reject deeper chains (e.g. `<root>.URL.X.Y`) so the
                // gate stays scoped to direct URL accessors.
                if suffix.contains('.') {
                    return false;
                }
                return is_url_accessor_method(suffix);
            }
            _ => return false,
        }
    }
    false
}

/// Bare-method names on `*url.URL` whose return is a string derived from
/// the URL value.  Recognised for the same-request self-redirect gate.
fn is_url_accessor_method(callee: &str) -> bool {
    matches!(
        callee,
        "String" | "RequestURI" | "EscapedPath" | "Path" | "RawPath" | "RawQuery"
    )
}

/// Locate the [`SsaInst`] that defines `v` within its declared block.
/// Returns `None` only when the SSA body is malformed (the instruction
/// table and `value_defs` table disagree on which block defines `v`).
fn find_inst_for_value(v: SsaValue, ssa: &SsaBody) -> Option<&SsaInst> {
    let def = ssa.def_of(v);
    let block = ssa.block(def.block);
    block
        .phis
        .iter()
        .chain(block.body.iter())
        .find(|inst| inst.value == v)
}

// ── Alias-Aware Sanitization ────────────────────────────────────────────

/// After sanitizing `inst`, propagate the sanitization to must-aliased field paths.
///
/// When `alias.data` is sanitized and `alias` and `obj` are base aliases (from
/// copy propagation), this function also sanitizes `obj.data` in the taint state.
/// For plain idents (no dot), sanitizing `alias` also sanitizes `obj`.
fn propagate_sanitization_to_aliases(
    inst: &SsaInst,
    state: &mut SsaTaintState,
    sanitizer_bits: Cap,
    aliases: &crate::ssa::alias::BaseAliasResult,
    ssa: &SsaBody,
) {
    let var_name = match inst.var_name.as_deref() {
        Some(n) => n,
        None => return,
    };

    // Split into base and suffix: "alias.data" → ("alias", ".data"); "alias" → ("alias", "")
    let (base, suffix) = match var_name.find('.') {
        Some(pos) => (&var_name[..pos], &var_name[pos..]),
        None => (var_name, ""),
    };

    let alias_bases = match aliases.aliases_of(base) {
        Some(bases) => bases,
        None => return,
    };

    // Collect SsaValues to sanitize (avoid borrowing state while iterating).
    let to_sanitize: SmallVec<[SsaValue; 8]> = state
        .values
        .iter()
        .filter_map(|&(v, ref t)| {
            if t.caps.is_empty() {
                return None;
            }
            let vdef_name = ssa.value_defs.get(v.0 as usize)?.var_name.as_deref()?;

            // For each alias base, check if the value's var_name matches
            // the aliased field path.
            for alias_base in alias_bases {
                if alias_base == base {
                    continue; // skip self, already sanitized
                }
                let target = if suffix.is_empty() {
                    // Plain ident: look for exact match on alias base
                    alias_base.as_str()
                } else {
                    // Can't construct target without allocation; check inline
                    ""
                };

                if suffix.is_empty() {
                    if vdef_name == target {
                        return Some(v);
                    }
                } else {
                    // Dotted path: check if vdef_name == "{alias_base}{suffix}"
                    if vdef_name.len() == alias_base.len() + suffix.len()
                        && vdef_name.starts_with(alias_base.as_str())
                        && vdef_name.ends_with(suffix)
                    {
                        return Some(v);
                    }
                }
            }
            None
        })
        .collect();

    for v in to_sanitize {
        if let Some(taint) = state.get(v) {
            let new_caps = taint.caps & !sanitizer_bits;
            if new_caps.is_empty() {
                state.remove(v);
            } else {
                state.set(
                    v,
                    VarTaint {
                        caps: new_caps,
                        origins: taint.origins.clone(),
                        uses_summary: taint.uses_summary,
                    },
                );
            }
        }
    }
}

// ── Alias-Aware Taint Propagation ───────────────────────────────────────

/// After taint assignment to `inst`, propagate taint to must-aliased field paths.
///
/// When `obj.data` receives taint and `obj` and `alias` are base aliases (from
/// copy propagation), this function also taints `alias.data` in the taint state.
/// For plain idents (no dot), tainting `obj` also taints `alias`.
///
/// Uses only the existing `BaseAliasResult` alias groups, no new alias inference.
fn propagate_taint_to_aliases(
    inst: &SsaInst,
    state: &mut SsaTaintState,
    taint_caps: Cap,
    taint_origins: &SmallVec<[TaintOrigin; 2]>,
    aliases: &crate::ssa::alias::BaseAliasResult,
    ssa: &SsaBody,
) {
    let var_name = match inst.var_name.as_deref() {
        Some(n) => n,
        None => return,
    };

    // Split into base and suffix: "obj.data" → ("obj", ".data"); "obj" → ("obj", "")
    let (base, suffix) = match var_name.find('.') {
        Some(pos) => (&var_name[..pos], &var_name[pos..]),
        None => (var_name, ""),
    };

    let alias_bases = match aliases.aliases_of(base) {
        Some(bases) => bases,
        None => return,
    };

    // Collect SsaValues to taint. Iterate value_defs (not state.values) because
    // target alias values may not yet be in the taint state.
    let to_taint: SmallVec<[SsaValue; 8]> = ssa
        .value_defs
        .iter()
        .enumerate()
        .filter_map(|(idx, vdef)| {
            let vdef_name = vdef.var_name.as_deref()?;
            for alias_base in alias_bases {
                if alias_base == base {
                    continue; // skip self, already tainted
                }
                if suffix.is_empty() {
                    // Plain ident: look for exact match on alias base
                    if vdef_name == alias_base.as_str() {
                        return Some(SsaValue(idx as u32));
                    }
                } else {
                    // Dotted path: check if vdef_name == "{alias_base}{suffix}"
                    if vdef_name.len() == alias_base.len() + suffix.len()
                        && vdef_name.starts_with(alias_base.as_str())
                        && vdef_name.ends_with(suffix)
                    {
                        return Some(SsaValue(idx as u32));
                    }
                }
            }
            None
        })
        .collect();

    for v in to_taint {
        if let Some(existing) = state.get(v) {
            // Union caps and origins into existing taint
            let merged_caps = existing.caps | taint_caps;
            let mut merged_origins = existing.origins.clone();
            for orig in taint_origins {
                push_origin_bounded(&mut merged_origins, *orig);
            }
            state.set(
                v,
                VarTaint {
                    caps: merged_caps,
                    origins: merged_origins,
                    uses_summary: existing.uses_summary,
                },
            );
        } else {
            // No existing taint, set fresh
            state.set(
                v,
                VarTaint {
                    caps: taint_caps,
                    origins: taint_origins.clone(),
                    uses_summary: false,
                },
            );
        }
    }
}

// ── SSA-Level Precision Helpers ──────────────────────────────────────────

/// Check if all argument SSA values of a call instruction are known constants.
fn all_args_const(
    inst: &SsaInst,
    const_values: &HashMap<SsaValue, crate::ssa::const_prop::ConstLattice>,
) -> bool {
    let used = inst_use_values(inst);
    if used.is_empty() {
        return false; // no args → not a call or nothing to suppress
    }
    used.iter().all(|v| {
        matches!(
            const_values.get(v),
            Some(
                crate::ssa::const_prop::ConstLattice::Str(_)
                    | crate::ssa::const_prop::ConstLattice::Int(_)
                    | crate::ssa::const_prop::ConstLattice::Bool(_)
                    | crate::ssa::const_prop::ConstLattice::Null
            )
        )
    })
}

/// Try to resolve a callee using the receiver's inferred type.
///
/// When the callee string is `"client.send"` and the receiver SSA value is typed
/// as `HttpClient`, constructs `"HttpClient.send"` and checks label rules.
/// Returns the matched labels (source/sanitizer/sink) if any.
///
/// Resolution order:
/// 1. Static type from [`TypeFactResult`] (constructor/const inference)
/// 2. Flow-sensitive type from [`PathEnv`] (branch narrowing, casts)
fn resolve_type_qualified_labels(
    callee: &str,
    receiver: SsaValue,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    path_env: Option<&constraint::PathEnv>,
    lang: Lang,
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa: Option<&SsaBody>,
) -> SmallVec<[DataLabel; 2]> {
    // Candidate method names: the last segment after `.`, plus segments peeled
    // back through trailing identity-preserving methods (`unwrap`, `expect`,
    // `await`, etc.).  For chain text like `conn.execute(&sql, []).unwrap` the
    // direct last segment is `unwrap`; the real sink verb is `execute`.
    // `normalize_chained_call_for_classify` strips paren groups; the walk
    // peels back through identity methods.
    let method_candidates = method_candidates_from_chain(callee, lang);

    // Receiver candidates: the immediate SSA receiver, plus any ancestor
    // reached by walking back through intermediate `SsaOp::Call.receiver`
    // chains (Rust parses `conn.execute(&sql, []).unwrap()` as one outer
    // call whose receiver is another call, and so on).  We stop once we find
    // a typed value or run out of receivers.
    let receiver_candidates = receiver_candidates_for_type_lookup(receiver, ssa, lang);

    // 1. Try static type first (existing behavior)
    if let Some(tf) = type_facts {
        for rv in &receiver_candidates {
            if let Some(receiver_type) = tf.get_type(*rv) {
                if let Some(prefix) = receiver_type.label_prefix() {
                    for method in &method_candidates {
                        let qualified = format!("{}.{}", prefix, method);
                        let labels =
                            crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
                        if !labels.is_empty() {
                            return labels;
                        }
                    }
                }
            }
        }
    }

    // 2. Try flow-sensitive type from PathEnv
    if let Some(env) = path_env {
        for rv in &receiver_candidates {
            let types = env.get(*rv).types;
            if let Some(kind) = types.as_singleton() {
                if let Some(prefix) = kind.label_prefix() {
                    for method in &method_candidates {
                        let qualified = format!("{}.{}", prefix, method);
                        let labels =
                            crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
                        if !labels.is_empty() {
                            return labels;
                        }
                    }
                }
            }
        }
    }

    SmallVec::new()
}

/// Sibling of [`resolve_type_qualified_labels`] used at sink-firing time.
///
/// Returns the resolved sink labels plus, when the matched qualified
/// callee has a known restricted payload arg list (Phase 07 ORM raw-SQL
/// receiver methods such as `TypeOrmRepo.query`), the static slice
/// describing which positional args carry the SQL payload. The caller
/// uses this slice to override `positions_override` so taint flowing
/// only into the bind-array argument (arg 1+) does not fire.
#[allow(clippy::too_many_arguments)]
fn resolve_type_qualified_labels_with_args(
    callee: &str,
    receiver: SsaValue,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    path_env: Option<&constraint::PathEnv>,
    lang: Lang,
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa: Option<&SsaBody>,
) -> (SmallVec<[DataLabel; 2]>, Option<&'static [usize]>) {
    let method_candidates = method_candidates_from_chain(callee, lang);
    let receiver_candidates = receiver_candidates_for_type_lookup(receiver, ssa, lang);

    if let Some(tf) = type_facts {
        for rv in &receiver_candidates {
            if let Some(receiver_type) = tf.get_type(*rv) {
                if let Some(prefix) = receiver_type.label_prefix() {
                    for method in &method_candidates {
                        let qualified = format!("{}.{}", prefix, method);
                        let labels =
                            crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
                        if !labels.is_empty() {
                            let payload =
                                crate::labels::type_qualified_sink_payload_args(&qualified);
                            return (labels, payload);
                        }
                    }
                }
            }
        }
    }

    if let Some(env) = path_env {
        for rv in &receiver_candidates {
            let types = env.get(*rv).types;
            if let Some(kind) = types.as_singleton() {
                if let Some(prefix) = kind.label_prefix() {
                    for method in &method_candidates {
                        let qualified = format!("{}.{}", prefix, method);
                        let labels =
                            crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
                        if !labels.is_empty() {
                            let payload =
                                crate::labels::type_qualified_sink_payload_args(&qualified);
                            return (labels, payload);
                        }
                    }
                }
            }
        }
    }

    (SmallVec::new(), None)
}

/// Walk back through `SsaOp::Call.receiver` and `SsaOp::FieldProj.receiver`
/// chains to collect candidate SSA values for type-fact lookup.
///
/// Two motivating shapes:
/// - Rust chained methods: `conn.execute(x).unwrap()` is one outer call
///   whose receiver is itself a call. The stable base identifier
///   (`conn`) is several `Call.receiver` hops up.
/// - `FieldProj` decomposition: `c.client.send(req)` lowers through
///   `v_client = FieldProj(v_c, "client")`, so the typed root (`c`)
///   sits one `FieldProj.receiver` hop above `v_client`.
///
/// FieldProj walking runs for every language. Call-receiver walking is
/// Rust-only, other languages handle method nesting at AST level.
fn receiver_candidates_for_type_lookup(
    start: SsaValue,
    ssa: Option<&SsaBody>,
    lang: Lang,
) -> SmallVec<[SsaValue; 4]> {
    let mut out: SmallVec<[SsaValue; 4]> = SmallVec::new();
    out.push(start);
    let Some(body) = ssa else {
        return out;
    };
    let mut current = start;
    for _ in 0..8 {
        // Find the instruction defining `current`.
        let mut next_receiver: Option<SsaValue> = None;
        'scan: for block in &body.blocks {
            for inst in block.phis.iter().chain(block.body.iter()) {
                if inst.value == current {
                    match &inst.op {
                        // FieldProj receiver chain, universal.
                        SsaOp::FieldProj { receiver, .. } => {
                            next_receiver = Some(*receiver);
                        }
                        // Chain through nested Call receivers.  Rust:
                        // `conn.execute(x).unwrap()` parsed as one outer
                        // call.  JS/TS: `getUrl().searchParams.set(k, v)`,
                        // where the FieldProj walks `searchParams →
                        // <call result>` and we want to keep walking
                        // through the `getUrl()` call to surface the
                        // original URL receiver value (Phase 09 deferred
                        // fix).
                        SsaOp::Call {
                            receiver: Some(rv), ..
                        } if matches!(
                            lang,
                            Lang::Rust | Lang::JavaScript | Lang::TypeScript
                        ) =>
                        {
                            next_receiver = Some(*rv);
                        }
                        _ => {}
                    }
                    break 'scan;
                }
            }
        }
        match next_receiver {
            Some(rv) if !out.contains(&rv) => {
                out.push(rv);
                current = rv;
            }
            _ => break,
        }
    }
    out
}

/// Extract candidate method names from a chained-call callee text.
///
/// Tree-sitter constructs `a.foo(x).bar()` as nested method-call nodes.  The
/// CFG records the outermost callee text (here `a.foo(x).bar`), which means
/// the last `.`-segment is the terminal method (`bar`).  When the terminal
/// is an identity-preserving method (`.unwrap()`, `.expect()`, `.await`,
/// `.clone()`, etc.), the *real* sink verb is the preceding segment.  This
/// helper walks back through identity methods to return all plausible
/// terminals in priority order (most-specific first).
fn method_candidates_from_chain(callee: &str, lang: Lang) -> SmallVec<[String; 4]> {
    let mut out: SmallVec<[String; 4]> = SmallVec::new();
    // Normalize: strip `(...)` groups so we index into `.`-segments directly.
    // Use the same normalization used for label classification so this mirrors
    // matcher behavior.
    let normalized = crate::labels::normalize_chained_call_for_classify(callee);
    let segments: Vec<&str> = normalized.split('.').collect();
    if segments.is_empty() {
        return out;
    }
    // Walk from the end, peeling identity methods.
    let mut i = segments.len();
    while i > 0 {
        let seg = segments[i - 1];
        if !seg.is_empty() {
            out.push(seg.to_string());
        }
        if matches!(lang, Lang::Rust) && crate::ssa::type_facts::is_identity_method(seg) {
            i -= 1;
            continue;
        }
        break;
    }
    out
}

/// Suppress sinks from known non-sink callees (e.g., `System.out.println` in Java).
///
/// These are callees whose suffix matches a broad sink rule but whose
/// receiver is known to be safe (console output, not HTTP response).
fn suppress_known_safe_callees(
    sink_caps: Cap,
    callee: &str,
    lang: Lang,
    info: &NodeInfo,
) -> Cap {
    match lang {
        Lang::Java => {
            if callee.starts_with("System.out.") || callee.starts_with("System.err.") {
                sink_caps & !Cap::HTML_ESCAPE
            } else {
                sink_caps
            }
        }
        // Go `fmt.Fprintf` / `fmt.Fprint` / `fmt.Fprintln` carry an HTML_ESCAPE
        // sink label because they CAN write to an `http.ResponseWriter`.  When
        // the writer (positional arg 0) is a known non-response stream
        // (stderr/stdout/discard/gin's package-level debug writers), the call
        // is a logging side effect, not a response-rendering sink, and the
        // HTML_ESCAPE bit should be stripped.  Without this strip, gin's own
        // `defer func() { debugPrintError(err) }()` shape lights up as
        // `taint-unsanitised-flow` because `debugPrintError` summarises as
        // param 0 → `fmt.Fprintf` HTML_ESCAPE through the IPA path.
        Lang::Go => {
            if !sink_caps.intersects(Cap::HTML_ESCAPE) {
                return sink_caps;
            }
            let is_fprintf = matches!(callee, "fmt.Fprintf" | "fmt.Fprint" | "fmt.Fprintln");
            if !is_fprintf {
                return sink_caps;
            }
            let Some(first_arg) = info.call.arg_uses.first() else {
                return sink_caps;
            };
            if first_arg.iter().any(|s| is_go_non_response_writer(s.as_str())) {
                sink_caps & !Cap::HTML_ESCAPE
            } else {
                sink_caps
            }
        }
        _ => sink_caps,
    }
}

/// Recognise Go writer identifiers that are categorically not
/// `http.ResponseWriter` and therefore should not host an XSS sink for
/// `fmt.Fprintf` / `fmt.Fprint` / `fmt.Fprintln`.  The set covers the
/// stdlib stdout/stderr/discard streams plus gin's package-level
/// `DefaultWriter` / `DefaultErrorWriter` (both are `io.Writer` aliases for
/// `os.Stdout` / `os.Stderr`).  Both qualified (`gin.DefaultErrorWriter`)
/// and bare (`DefaultErrorWriter`, intra-package) shapes match.
fn is_go_non_response_writer(text: &str) -> bool {
    matches!(
        text,
        "os.Stderr"
            | "os.Stdout"
            | "io.Discard"
            | "ioutil.Discard"
            | "DefaultErrorWriter"
            | "DefaultWriter"
            | "gin.DefaultErrorWriter"
            | "gin.DefaultWriter"
    )
}

/// Check if a sink is type-safe (e.g., SQL injection or path traversal with int-typed argument).
///
/// Suppresses findings when all argument values are known to be integer-typed,
/// since integer values cannot carry SQL injection or path traversal payloads.
/// Delegates to the shared [`crate::ssa::type_facts::is_type_safe_for_sink`]
/// helper so the structural `cfg-unguarded-sink` analysis agrees on the
/// suppression rule.
fn is_type_safe_for_sink(
    inst: &SsaInst,
    sink_caps: Cap,
    type_facts: &crate::ssa::type_facts::TypeFactResult,
) -> bool {
    let used = inst_use_values(inst);
    crate::ssa::type_facts::is_type_safe_for_sink(&used, sink_caps, type_facts)
}

// ── Centralized Type-Sink Compatibility Helpers ──────────────────────────

/// Check if a [`TypeKind`] is safe for a given sink capability.
///
/// Returns `true` if the type cannot carry the payload required by the sink.
/// Policy: Int/Bool values cannot carry injection payloads (SQL, code, path).
/// String-typed values CAN carry injection payloads, casts to String do NOT
/// make a value safe.
fn type_safe_for_taint_sink(kind: &crate::ssa::type_facts::TypeKind, cap: Cap) -> bool {
    use crate::ssa::type_facts::TypeKind;
    match kind {
        TypeKind::Int | TypeKind::Bool => {
            cap.intersects(Cap::SQL_QUERY | Cap::FILE_IO | Cap::CODE_EXEC | Cap::SHELL_ESCAPE)
        }
        _ => false,
    }
}

/// Check if a receiver type is incompatible with a sink label's requirements.
///
/// Returns the Cap bits that should be REMOVED because the receiver type
/// proves the sink doesn't apply. For example, `HTML_ESCAPE` sinks require
/// an HTTP-response-like receiver, if the receiver is known to be
/// Int/Bool/String, `HTML_ESCAPE` doesn't apply.
fn receiver_incompatible_sink_caps(kind: &crate::ssa::type_facts::TypeKind, sink_caps: Cap) -> Cap {
    use crate::ssa::type_facts::TypeKind;
    let mut remove = Cap::empty();
    // HTML_ESCAPE / OPEN_REDIRECT / HEADER_INJECTION all require an HTTP
    // response-like receiver: each is a write-side rule that fires when
    // attacker data is rendered into / written onto the response stream
    // (`*.send` / `*.redirect` / `*.setHeader` / etc.).  Receivers proven
    // to be a different class — directory-service connections (LDAP),
    // database connections, file handles, in-memory collections, query-
    // builder objects, URL values, HTTP clients (request-side), and so on
    // — cannot host these sinks even when a same-named matcher
    // (`*.send`, `*.set`, `*.append`) attaches the label by suffix.
    let response_like_caps = Cap::HTML_ESCAPE | Cap::OPEN_REDIRECT | Cap::HEADER_INJECTION;
    if sink_caps.intersects(response_like_caps) {
        match kind {
            TypeKind::HttpResponse => {}               // compatible
            TypeKind::Unknown | TypeKind::Object => {} // could be response
            _ => {
                remove |= sink_caps & response_like_caps;
            }
        }
    }
    // LDAP_INJECTION strictly requires a directory-service receiver.
    // Non-LdapClient receivers carrying the cap by accident (e.g. a
    // generic `*.search` suffix matcher firing on a Vec/HashMap) get the
    // bit stripped.  Unknown/Object stay untouched so type-fact gaps
    // don't silently drop real sinks.
    if sink_caps.intersects(Cap::LDAP_INJECTION) {
        match kind {
            TypeKind::LdapClient => {}                 // compatible
            TypeKind::Unknown | TypeKind::Object => {} // could be ldap
            _ => {
                remove |= Cap::LDAP_INJECTION;
            }
        }
    }
    // Injection sinks require string-like payload
    if type_safe_for_taint_sink(kind, sink_caps) {
        remove |= sink_caps & (Cap::SQL_QUERY | Cap::FILE_IO | Cap::CODE_EXEC);
    }
    remove
}

/// Check if all argument values of an instruction have types that are safe
/// for the given sink (path-sensitive, via [`PathEnv`]).
fn is_path_type_safe_for_sink(inst: &SsaInst, sink_caps: Cap, env: &constraint::PathEnv) -> bool {
    let type_suppressible = Cap::SQL_QUERY | Cap::FILE_IO | Cap::CODE_EXEC;
    if !sink_caps.intersects(type_suppressible) {
        return false;
    }
    let used = inst_use_values(inst);
    if used.is_empty() {
        return false;
    }
    used.iter().all(|v| match env.get(*v).types.as_singleton() {
        Some(ref kind) => type_safe_for_taint_sink(kind, sink_caps),
        None => false, // Multiple possible types → not safe
    })
}

// ── Abstract-Domain Sink Suppression ────────────────────────────────────

/// Check if abstract domain facts prove a sink is safe.
///
/// SSRF: string prefix with locked host.
/// SQL_QUERY / FILE_IO: dual gate, type-proven Int AND bounded interval on all
/// tainted leaf values. Traces back through Assign chains to find original
/// tainted data (e.g., `parseInt(x)` inside `"SELECT ..." + parseInt(x) * 10`).
///
/// NOTE: FILE_IO string prefix suppression intentionally omitted.
/// A prefix like "/app/static/" does not prevent path traversal
/// (e.g., "/app/static/../../etc/passwd"). The string domain cannot
/// prove absence of "../" in the attacker-controlled suffix.
fn is_abstract_safe_for_sink(
    inst: &SsaInst,
    sink_caps: Cap,
    abs: &AbstractState,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    static_map: Option<&crate::ssa::static_map::StaticMapResult>,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> bool {
    let used = inst_use_values(inst);
    if used.is_empty() {
        return false;
    }

    // SSRF, string prefix with locked host
    if sink_caps.intersects(Cap::SSRF) {
        // Inline template-literal prefix attached to the CFG node directly
        // (covers sinks whose URL is a template literal argument without an
        // intermediate Assign to seed the abstract domain).
        let node_info = &cfg[inst.cfg_node];
        if let Some(prefix) = node_info.string_prefix.as_deref() {
            let synthetic = crate::abstract_interp::StringFact::from_prefix(prefix);
            if is_string_safe_for_ssrf(&synthetic) {
                return true;
            }
        }
        if used
            .iter()
            .all(|v| is_string_safe_for_ssrf(&abs.get(*v).string))
        {
            return true;
        }
    }

    // DATA_EXFIL, destination allowlist via configured trusted prefixes.
    // Mirrors the SSRF prefix-lock above but consults the user-configured
    // [detectors.data_exfil] table's trusted_destinations key.  Strict-
    // additive: when no destinations are configured this is a no-op.
    if sink_caps.intersects(Cap::DATA_EXFIL)
        && is_inst_data_exfil_destination_trusted(inst, abs, cfg)
    {
        return true;
    }

    // SHELL_ESCAPE, static-map finite-domain safety.  When every tainted
    // payload value is proved by the static-HashMap-lookup analysis to come
    // from a bounded set of metacharacter-free literals, the call cannot
    // carry shell injection regardless of how the attacker influenced the
    // lookup key.  Only fires when the value appears in `static_map.finite_
    // string_values`, not for arbitrary single-literal exact facts, those
    // already have their own constant-argument suppression path and we
    // must not over-apply shell-safety to unrelated const-prop bare-string
    // artefacts (e.g. Python `commands = []`).
    if sink_caps.intersects(Cap::SHELL_ESCAPE) && is_static_map_shell_safe(&used, static_map) {
        return true;
    }

    // HTML_ESCAPE / FILE_IO type-only gate: an integer's decimal
    // representation is always digits (with optional leading `-`), which
    // never contain HTML metacharacters (`<`, `>`, `"`, `'`, `&`, `/`,
    // `:`) nor path metacharacters (`/`, `\`, `.`).  Magnitude is
    // irrelevant — a large value doesn't introduce metachars, so both
    // sink classes use a type-only leaf check rather than the SQL/SHELL
    // dual gate below.  Closes the sudo-rs RUSTSEC-2023-0069 patched FP
    // where `let uid: u32 = user.parse()?; path.push(uid.to_string())`
    // was flagged as a path-traversal FILE_IO sink despite the SSA
    // value being unambiguously typed as a numeric uid.
    if sink_caps.intersects(Cap::HTML_ESCAPE | Cap::FILE_IO) {
        if let Some(tf) = type_facts {
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
            if !leaves.is_empty() && leaves.iter().all(|v| tf.is_int(*v)) {
                return true;
            }
        }
    }

    // Dual gate: SQL_QUERY / SHELL_ESCAPE with proven Int type AND bounded
    // interval.  Both conditions required: type proves the value IS an
    // integer (not a string that happened to parse), interval proves it's
    // bounded (not arbitrary).  Traces through Assign chains so
    // "const_string + tainted_int" is caught.  SQL_QUERY keeps the bound
    // requirement because RUSTSEC-2024-0363-style binary-protocol overflow
    // requires a 4 GiB+ payload; SHELL_ESCAPE keeps it because a
    // multi-line decimal can still trip newline-sensitive shell parsing.
    if sink_caps.intersects(Cap::SQL_QUERY | Cap::SHELL_ESCAPE) {
        if let Some(tf) = type_facts {
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
            if !leaves.is_empty()
                && leaves
                    .iter()
                    .all(|v| tf.is_int(*v) && abs.get(*v).interval.is_proven_bounded())
            {
                return true;
            }
        }
    }

    // PathFact gate: FILE_IO with every tainted leaf's PathFact
    // proving `dotdot = No && absolute = No`.  Sanitisers documented in
    // rs-safe-0** (Rust `.contains("..")` rejection, `fs::canonicalize`
    // + `starts_with` guard, `Component::Normal` iterator filter) flow
    // through to the leaf values via PathFact; this check is the single
    // point at which the axis conjunction suppresses the sink.
    if sink_caps.intersects(Cap::FILE_IO) && is_path_safe_for_sink(inst, state, ssa, cfg, abs) {
        return true;
    }

    false
}

/// Check every tainted leaf flowing into `inst`'s used values carries a
/// PathFact proving it cannot perform path traversal.
///
/// Core gate for the rs-safe-0** FP closure plus the canonicalised+rooted
/// shape (see [`PathFact::is_path_traversal_safe`]).  Traces through
/// Assign chains so `Path::new(sanitised)` still resolves to the
/// sanitised string's fact.
fn is_path_safe_for_sink(
    inst: &SsaInst,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
    abs: &AbstractState,
) -> bool {
    let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
    if leaves.is_empty() {
        return false;
    }
    let safe = leaves
        .iter()
        .all(|v| abs.get(*v).path.is_path_traversal_safe());
    if safe {
        // Publish the suppression to the file-level set so the
        // state-analysis pass can suppress `state-unauthed-access` on
        // the same sink, once the taint engine has proved the
        // user-controlled input cannot escape into a privileged
        // location, the auth concern is structurally reduced.
        let span = cfg[inst.cfg_node].ast.span;
        crate::taint::ssa_transfer::state::record_path_safe_suppressed_span(span);
    }
    safe
}

/// Check if call arguments prove a sink is safe via abstract domain.
fn is_call_abstract_safe(
    inst: &SsaInst,
    args: &[SmallVec<[SsaValue; 2]>],
    sink_caps: Cap,
    abs: &AbstractState,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    static_map: Option<&crate::ssa::static_map::StaticMapResult>,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> bool {
    // SSRF, check if the URL argument (first arg) has a safe prefix.
    if sink_caps.intersects(Cap::SSRF) {
        // Inline template-literal prefix from the call AST itself
        // (e.g. `axios.get(\`https://host/…${x}\`)` has no intermediate Assign
        // to seed a StringFact, check the node-attached prefix directly).
        let node_info = &cfg[inst.cfg_node];
        if let Some(prefix) = node_info.string_prefix.as_deref() {
            let synthetic = crate::abstract_interp::StringFact::from_prefix(prefix);
            if is_string_safe_for_ssrf(&synthetic) {
                return true;
            }
        }
        if let Some(first_arg) = args.first() {
            if !first_arg.is_empty()
                && first_arg
                    .iter()
                    .all(|v| is_string_safe_for_ssrf(&abs.get(*v).string))
            {
                return true;
            }
        }
    }

    // DATA_EXFIL, destination-allowlist match.  Mirrors the SSRF arm above
    // for the Call path.  Strict-additive: a no-op when
    // detectors.data_exfil.trusted_destinations is empty.
    if sink_caps.intersects(Cap::DATA_EXFIL)
        && is_call_data_exfil_destination_trusted(inst, args, abs, cfg)
    {
        return true;
    }

    // SHELL_ESCAPE, static-map finite-domain safety on every non-empty arg
    // group.  Mirrors the non-Call path so suppression fires regardless of
    // which branch the sink detector took.
    if sink_caps.intersects(Cap::SHELL_ESCAPE) && !args.is_empty() {
        let all_values: Vec<SsaValue> = args.iter().flat_map(|g| g.iter().copied()).collect();
        if !all_values.is_empty() && is_static_map_shell_safe(&all_values, static_map) {
            return true;
        }
    }

    // HTML_ESCAPE / FILE_IO type-only gate (same as non-Call path): digits
    // never contain HTML metacharacters or path-traversal metacharacters
    // regardless of magnitude, so an integer payload is safe for these
    // sink classes without requiring a bounded interval.  Closes the
    // RUSTSEC-2023-0069 patched FP for cross-function summary-resolved
    // path sinks like `open_for_user(uid)`.
    if sink_caps.intersects(Cap::HTML_ESCAPE | Cap::FILE_IO) {
        if let Some(tf) = type_facts {
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
            if !leaves.is_empty() && leaves.iter().all(|v| tf.is_int(*v)) {
                return true;
            }
        }
    }

    // Dual gate for Call sinks: SQL_QUERY / SHELL_ESCAPE keep the bounded-
    // interval requirement (see is_abstract_safe_for_sink for the
    // rationale).
    if sink_caps.intersects(Cap::SQL_QUERY | Cap::SHELL_ESCAPE) {
        if let Some(tf) = type_facts {
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg);
            if !leaves.is_empty()
                && leaves
                    .iter()
                    .all(|v| tf.is_int(*v) && abs.get(*v).interval.is_proven_bounded())
            {
                return true;
            }
        }
    }

    // PathFact gate (Call path): mirrors non-Call suppression so the gate
    // fires regardless of which sink-detection branch produces the event.
    if sink_caps.intersects(Cap::FILE_IO) && is_path_safe_for_sink(inst, state, ssa, cfg, abs) {
        return true;
    }

    false
}

/// Maximum backwards trace depth through Assign chains.
const MAX_TRACE_DEPTH: usize = 8;

/// Trace backwards through Assign chains to find the leaf tainted SSA values.
///
/// When a tainted value is a binary operation (e.g., string concatenation of
/// `"SELECT ..." + offset`), the concat result is String-typed but the tainted
/// operand (`offset`) may be Int-typed and bounded. This function finds those
/// leaf tainted values so dual-gate suppression can check them directly.
fn trace_tainted_leaf_values(
    inst: &SsaInst,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> SmallVec<[SsaValue; 4]> {
    let mut leaves = SmallVec::new();
    let used = inst_use_values(inst);
    for &v in &used {
        if state.get(v).is_some() {
            trace_single_leaf(v, state, ssa, cfg, &mut leaves, 0);
        }
    }
    leaves
}

fn trace_single_leaf(
    v: SsaValue,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
    leaves: &mut SmallVec<[SsaValue; 4]>,
    depth: usize,
) {
    if depth >= MAX_TRACE_DEPTH || leaves.len() >= 16 {
        leaves.push(v);
        return;
    }
    // Find the instruction defining v by scanning its block.
    let vd = &ssa.value_defs[v.0 as usize];
    let block = &ssa.blocks[vd.block.0 as usize];
    let inst = match block.body.iter().find(|i| i.value == v) {
        Some(i) => i,
        None => {
            // Phi or not found in body, treat as leaf
            leaves.push(v);
            return;
        }
    };
    // Numeric-length reads (`arr.length`, `map.size`, `vec.len()`, ...) yield
    // an integer whose decimal representation cannot contain injection
    // metacharacters.  Treat the result as a leaf so the dual-gate / HTML-
    // escape type check sees the Int-typed length value rather than tracing
    // through to the underlying container (which is typically String-typed
    // and would defeat suppression).
    if cfg
        .node_weight(inst.cfg_node)
        .is_some_and(|ni| ni.is_numeric_length_access)
    {
        leaves.push(v);
        return;
    }
    match &inst.op {
        SsaOp::Assign(uses) if uses.len() >= 2 => {
            // Numeric binary operations (bitwise, arithmetic except Add, comparisons)
            // always produce integers, treat the result as a leaf rather than tracing
            // through to the string-typed operands. Add is excluded because it may be
            // string concatenation.
            let bin_op = cfg.node_weight(inst.cfg_node).and_then(|ni| ni.bin_op);
            let is_numeric_op = matches!(
                bin_op,
                Some(
                    crate::cfg::BinOp::Sub
                        | crate::cfg::BinOp::Mul
                        | crate::cfg::BinOp::Div
                        | crate::cfg::BinOp::Mod
                        | crate::cfg::BinOp::BitAnd
                        | crate::cfg::BinOp::BitOr
                        | crate::cfg::BinOp::BitXor
                        | crate::cfg::BinOp::LeftShift
                        | crate::cfg::BinOp::RightShift
                        | crate::cfg::BinOp::Eq
                        | crate::cfg::BinOp::NotEq
                        | crate::cfg::BinOp::Lt
                        | crate::cfg::BinOp::LtEq
                        | crate::cfg::BinOp::Gt
                        | crate::cfg::BinOp::GtEq
                )
            );
            if is_numeric_op {
                leaves.push(v);
                return;
            }

            let mut found = false;
            for &u in uses {
                if state.get(u).is_some() {
                    trace_single_leaf(u, state, ssa, cfg, leaves, depth + 1);
                    found = true;
                }
            }
            if !found {
                leaves.push(v);
            }
        }
        SsaOp::Call { callee, args, .. } if is_stringify_callee(callee) => {
            // String-producing conversion of already-bounded values.  Trace
            // through the arguments so the dual-gate check sees the upstream
            // Int/bounded leaves.  Examples: `x.to_string()`, `format!(...)`.
            let mut found = false;
            for arg in args {
                for &u in arg {
                    if state.get(u).is_some() {
                        trace_single_leaf(u, state, ssa, cfg, leaves, depth + 1);
                        found = true;
                    }
                }
            }
            if !found {
                leaves.push(v);
            }
        }
        SsaOp::Call { callee, .. } if crate::ssa::type_facts::is_int_producing_callee(callee) => {
            // Int-producing conversion (`str.parse::<u32>()`, `Atoi`,
            // `parseInt`, ...).  Tracing past the Call would land on the
            // String-typed source and defeat the type-only HTML/FILE_IO
            // suppression below — but the Call's *result* is unambiguously
            // numeric, so the value itself is the right leaf.  Mirrors the
            // is_numeric_length_access stop-leaf at the top of this fn.
            leaves.push(v);
        }
        SsaOp::Call { args, .. } => {
            // For a Call whose node is not itself a Source (so the Call
            // introduces no fresh attacker-controlled taint), trace through
            // the arguments to find the upstream tainted leaves.  The Call's
            // return taint is a function of its args under this
            // classification, so the leaves are the Call's inputs.  Source-
            // labeled Calls keep the default leaf behavior, tracing past
            // them would erase the Source and over-suppress.
            let is_source = cfg
                .node_weight(inst.cfg_node)
                .map(|ni| {
                    ni.taint
                        .labels
                        .iter()
                        .any(|l| matches!(l, crate::labels::DataLabel::Source(_)))
                })
                .unwrap_or(false);
            // PathFact-proven sanitisation: when the abstract state has
            // recorded a non-Top [`PathFact`] on this Call's result ,
            // typically because cross-function inline analysis narrowed
            // the return path's `dotdot` / `absolute` axis, the Call
            // is the *proof point*.  Tracing past it would land on the
            // upstream source (whose PathFact is still Top) and defeat
            // the narrowing.  Push the Call result as a leaf so
            // `is_path_safe_for_sink` reads the proven fact directly.
            //
            // Strictly additive, only fires when the abstract domain
            // proves a non-Top fact, so source-labeled Calls (already
            // caught above) and unrelated calls fall back to the
            // existing trace-through-args behaviour.
            let proves_path_safe = state.abstract_state.as_ref().is_some_and(|abs_state| {
                let f = abs_state.get(v).path;
                !f.is_top() && f.is_path_traversal_safe()
            });
            if is_source || proves_path_safe {
                leaves.push(v);
            } else {
                let mut found = false;
                for arg in args {
                    for &u in arg {
                        if state.get(u).is_some() {
                            trace_single_leaf(u, state, ssa, cfg, leaves, depth + 1);
                            found = true;
                        }
                    }
                }
                if !found {
                    leaves.push(v);
                }
            }
        }
        SsaOp::Assign(uses) if uses.len() == 1 => {
            // Single-use Assign: pass through to the source value's leaf.
            // Covers the common pattern where SSA lowering emits both a Call
            // form carrying a sink expression and an outer Assign that binds
            // the Call's value to the defined variable, without this, the
            // Assign's tracing stops at the wrapped Call (String-typed by
            // default) and loses the Int / bounded leaf already known through
            // the Call's args.
            let u = uses[0];
            if state.get(u).is_some() {
                trace_single_leaf(u, state, ssa, cfg, leaves, depth + 1);
            } else {
                leaves.push(v);
            }
        }
        _ => {
            leaves.push(v);
        }
    }
}

/// Call verbs that convert a value to a String without introducing attacker-
/// controlled metacharacters.  Used by [`trace_single_leaf`] to peek past the
/// String-typed result when the upstream value is Int/bounded.
///
/// Normalizes the callee (strips `(…)` groups) and peels trailing identity
/// methods so chains like `.to_string().as_str()` resolve correctly.
fn is_stringify_callee(callee: &str) -> bool {
    let base = crate::ssa::type_facts::peel_identity_suffix(callee);
    let suffix = base.rsplit(['.', ':']).next().unwrap_or(&base);
    matches!(
        suffix,
        "to_string" | "to_owned" | "format" | "String" | "str"
    )
}

/// Return `true` when every value in `values` was proved by the static-map
/// analysis to be drawn from a finite set of metacharacter-free literals.
/// Returns `false` when `static_map` is `None`, when any value is missing,
/// or when any value's bounded set contains a shell metacharacter, the
/// predicate is conservative, so a missing entry never suppresses.
/// Java-only suppression for the free-identifier `<FIELD>.get(key)` shape.
///
/// When a class field is initialized with `Map.of(literal, literal, ...)`
/// and the consumer references it via the bare field name (no `this.` /
/// no SSA-resolved receiver) the receiver lookup in `try_container_
/// propagation` fails, leaving the engine to fall back to default
/// arg-to-result propagation.  This walks the callee text — required to
/// be a single-segment `<FIELD>.get` — and consults the per-file
/// safe-lookup map populated by the build_cfg pre-pass.  Returns `true`
/// when the lookup is safe to suppress.
fn try_java_safe_field_lookup_load(callee: &str) -> bool {
    let Some(dot_pos) = callee.rfind('.') else {
        return false;
    };
    let receiver_name = &callee[..dot_pos];
    let method = &callee[dot_pos + 1..];
    if method != "get" {
        return false;
    }
    if receiver_name.is_empty() || receiver_name.contains('.') || receiver_name.contains('(') {
        return false;
    }
    crate::cfg::safe_fields::safe_lookup_field_values(receiver_name).is_some()
}

fn is_static_map_shell_safe(
    values: &[SsaValue],
    static_map: Option<&crate::ssa::static_map::StaticMapResult>,
) -> bool {
    let Some(sm) = static_map else {
        return false;
    };
    if values.is_empty() {
        return false;
    }
    values.iter().all(|v| match sm.finite_string_values.get(v) {
        Some(set) if !set.is_empty() => set
            .iter()
            .all(|s| crate::abstract_interp::string_domain::is_shell_safe_literal(s)),
        _ => false,
    })
}

/// `DATA_EXFIL` destination-allowlist match.
///
/// Returns `true` when `prefix` (the proven static prefix of an outbound
/// destination URL, sourced from either the abstract string domain or an
/// inline literal seen by CFG) starts with one of the user-configured
/// trusted destinations.  Used by the abstract sink-suppression code to
/// drop the [`Cap::DATA_EXFIL`] bit on legitimate forwarding pipelines
/// (telemetry, internal APIs, analytics) without affecting other caps on
/// the same call.
///
/// Match semantics: a trusted destination entry is treated as a string
/// prefix.  An empty entry never matches (empty prefix would match
/// every URL, which is never a useful allowlist).  Entries should be
/// origin-pinned (e.g. `https://api.internal/`) so partial-host
/// collisions cannot occur.
fn is_string_prefix_trusted_destination(prefix: &str, trusted: &[String]) -> bool {
    if prefix.is_empty() {
        return false;
    }
    trusted
        .iter()
        .any(|t| !t.is_empty() && prefix.starts_with(t.as_str()))
}

/// Check whether the call site's destination argument (positional arg 0) is
/// a known trusted destination per
/// [`crate::utils::detector_options::DataExfilDetectorOptions::trusted_destinations`].
///
/// Returns `true` when the URL argument has a static prefix matching one
/// of the configured trusted entries.  Three sources are consulted in
/// order:
///
/// 1. The CFG node's syntactic literal (`info.call.arg_string_literals[0]`),
///    populated for any positional argument that is a syntactic string
///    literal at the call site.  Catches the common case
///    `fetch('https://api.internal/...', {...})` whose URL never enters
///    the abstract domain because it is not bound to an identifier.
/// 2. The inline template-literal prefix attached to the call node
///    directly (matches the SSRF prefix-lock fallback).
/// 3. The abstract string-domain prefix of arg 0's SSA value group.
///    Catches identifier-bound URLs like
///    `let url = \`https://api.internal/${id}\`; fetch(url, {...})`.
///
/// Returns `false` when no trusted destinations are configured.
fn is_call_data_exfil_destination_trusted(
    inst: &SsaInst,
    args: &[SmallVec<[SsaValue; 2]>],
    abs: &AbstractState,
    cfg: &Cfg,
) -> bool {
    let opts = crate::utils::detector_options::current();
    let trusted = &opts.data_exfil.trusted_destinations;
    if trusted.is_empty() {
        return false;
    }
    let node_info = &cfg[inst.cfg_node];
    if let Some(Some(lit)) = node_info.call.arg_string_literals.first() {
        if is_string_prefix_trusted_destination(lit, trusted) {
            return true;
        }
    }
    if let Some(prefix) = node_info.string_prefix.as_deref() {
        if is_string_prefix_trusted_destination(prefix, trusted) {
            return true;
        }
    }
    if let Some(first_arg) = args.first() {
        if !first_arg.is_empty()
            && first_arg.iter().all(|v| {
                abs.get(*v)
                    .string
                    .prefix
                    .as_deref()
                    .is_some_and(|p| is_string_prefix_trusted_destination(p, trusted))
            })
        {
            return true;
        }
    }
    false
}

/// Non-Call variant of [`is_call_data_exfil_destination_trusted`]: used by
/// [`is_abstract_safe_for_sink`] where the destination is read off the
/// instruction's own used SSA values rather than a positional Call arg
/// list.  Falls back to the node-attached `string_prefix` when no abstract
/// fact is available.
fn is_inst_data_exfil_destination_trusted(inst: &SsaInst, abs: &AbstractState, cfg: &Cfg) -> bool {
    let opts = crate::utils::detector_options::current();
    let trusted = &opts.data_exfil.trusted_destinations;
    if trusted.is_empty() {
        return false;
    }
    let node_info = &cfg[inst.cfg_node];
    if let Some(prefix) = node_info.string_prefix.as_deref() {
        if is_string_prefix_trusted_destination(prefix, trusted) {
            return true;
        }
    }
    let used = inst_use_values(inst);
    if used.is_empty() {
        return false;
    }
    used.iter().all(|v| {
        abs.get(*v)
            .string
            .prefix
            .as_deref()
            .is_some_and(|p| is_string_prefix_trusted_destination(p, trusted))
    })
}

/// SSRF safety: prefix includes scheme + full host + path separator.
///
/// Soundness: if the prefix contains `scheme://host/`, the attacker cannot
/// control the destination host. They can only influence the path/query,
/// which is not SSRF.
fn is_string_safe_for_ssrf(sf: &crate::abstract_interp::StringFact) -> bool {
    let prefix = match &sf.prefix {
        Some(p) => p.as_str(),
        None => return false,
    };
    // Absolute-path prefix (e.g. "/projects/..."), internal redirect, not open redirect.
    // The leading "/" locks the path to the same origin; the attacker cannot control the scheme
    // or host, so this is not an SSRF vector.
    if prefix.starts_with('/') {
        return true;
    }
    if let Some(after_scheme) = prefix.find("://") {
        let host_and_rest = &prefix[after_scheme + 3..];
        if let Some(slash_pos) = host_and_rest.find('/') {
            return slash_pos > 0; // non-empty host + path separator
        }
    }
    false
}

/// Resolve a bare or qualified callee string to a local [`FuncKey`] by
/// scanning `local_summaries` (already FuncKey-keyed).
///
/// Resolution is deliberately identity-aware:
///
/// 1. Filter by `(lang, namespace, name)`, these always participate in the
///    identity hash, so the candidate set is guaranteed to be the
///    same-file same-leaf-name definitions.
/// 2. If `container_hint` is supplied (e.g. the `obj` in `obj.method`),
///    narrow to candidates whose [`FuncKey::container`] matches.
/// 3. If exactly one candidate remains, return its key.
///
/// Returns `None` when zero or multiple candidates remain, callers should
/// then fall through to their own ambiguity policy instead of accidentally
/// picking an arbitrary definition.
/// Split a raw callee string into a `(namespace_qualifier, receiver_var)`
/// pair.
///
/// * `"env::var"`    → `(Some("env"), None)`
/// * `"std::io::File::open"` → `(Some("File"), None)`, leaf's immediate
///   container is kept so qualified lookup can match
///   `File::open`.  Deeper module prefixes are discarded here; the call
///   graph's Rust-specific resolver handles full paths via the use map.
/// * `"obj.method"` → `(None, Some("obj"))`
/// * `"a.b.method"` → `(None, Some("b"))`, immediate object hop.
/// * `"foo"`         → `(None, None)`
///
/// `::` is treated as a namespace separator and produces a
/// `namespace_qualifier`; `.` is treated as a method receiver and
/// produces a `receiver_var`.  When both separators appear, the
/// last-used one wins, matching the leaf-extraction rule in
/// [`callee_leaf_name`].
fn split_qualifier(raw: &str) -> (Option<&str>, Option<&str>) {
    if let Some(pos) = raw.rfind("::") {
        let prefix = &raw[..pos];
        let last = prefix.rsplit("::").next().unwrap_or(prefix);
        return (if last.is_empty() { None } else { Some(last) }, None);
    }
    if let Some(pos) = raw.rfind('.') {
        let prefix = &raw[..pos];
        let last = prefix.rsplit('.').next().unwrap_or(prefix);
        return (None, if last.is_empty() { None } else { Some(last) });
    }
    (None, None)
}

/// Look up the caller's own container by matching its name in
/// `local_summaries`.  Used so bare self-calls (`foo()` inside a class
/// method) prefer same-class candidates over free functions.
fn caller_container_for(transfer: &SsaTaintTransfer, caller_func: &str) -> Option<String> {
    if caller_func.is_empty() {
        return None;
    }
    let mut containers: Vec<&str> = transfer
        .local_summaries
        .keys()
        .filter(|k| k.lang == transfer.lang && k.name == caller_func)
        .map(|k| k.container.as_str())
        .filter(|c| !c.is_empty())
        .collect();
    containers.sort();
    containers.dedup();
    if containers.len() == 1 {
        Some(containers[0].to_string())
    } else {
        None
    }
}

/// Query-based equivalent of [`resolve_local_func_key`].
///
/// Prefers `receiver_type` → `namespace_qualifier` → `caller_container`
/// in that order before falling back to a uniqueness check on the leaf
/// name.  Keeps behaviour parity with the top-level resolver so
/// intra-file lookups apply the same qualified-first policy.
pub(crate) fn resolve_local_func_key_query(
    local_summaries: &FuncSummaries,
    q: &CalleeQuery<'_>,
) -> Option<FuncKey> {
    let all: Vec<&FuncKey> = local_summaries
        .keys()
        .filter(|k| k.name == q.name && k.lang == q.caller_lang)
        .collect();
    if all.is_empty() {
        return None;
    }

    let arity_matches = |k: &FuncKey| match q.arity {
        Some(a) => k.arity == Some(a),
        None => true,
    };

    let pick_with_container = |container: &str| -> Option<FuncKey> {
        if container.is_empty() {
            return None;
        }
        let narrowed: Vec<&FuncKey> = all
            .iter()
            .copied()
            .filter(|k| k.container == container)
            .filter(|k| arity_matches(k))
            .collect();
        if narrowed.len() == 1 {
            Some(narrowed[0].clone())
        } else {
            None
        }
    };

    if let Some(rt) = q.receiver_type {
        if let Some(k) = pick_with_container(rt) {
            return Some(k);
        }
        // Authoritative miss, do not silently pick a different container.
        return None;
    }

    if let Some(nq) = q.namespace_qualifier {
        if let Some(k) = pick_with_container(nq) {
            return Some(k);
        }
    }

    if let Some(cc) = q.caller_container {
        if let Some(k) = pick_with_container(cc) {
            return Some(k);
        }
    }

    let arity_filtered: Vec<&FuncKey> = all.iter().copied().filter(|k| arity_matches(k)).collect();
    if arity_filtered.len() == 1 {
        return Some(arity_filtered[0].clone());
    }

    if let Some(rv) = q.receiver_var {
        if let Some(k) = pick_with_container(rv) {
            return Some(k);
        }
    }

    // Bare-call free-function preference, mirrors
    // `GlobalSummaries::resolve_callee` step 5.5.  When the call is
    // syntactically bare (no receiver, no namespace qualifier, no
    // authoritative receiver type) and exactly one arity-matched local
    // candidate is a free function (empty container), it is the
    // unambiguous target: class methods cannot be invoked with
    // bare-call syntax from outside their own class (self-calls are
    // handled by the `caller_container` branch above).
    if q.receiver_type.is_none() && q.namespace_qualifier.is_none() && q.receiver_var.is_none() {
        let empty: Vec<&FuncKey> = arity_filtered
            .iter()
            .copied()
            .filter(|k| k.container.is_empty())
            .collect();
        if empty.len() == 1 {
            return Some(empty[0].clone());
        }
    }

    None
}

pub(crate) fn resolve_local_func_key(
    local_summaries: &FuncSummaries,
    lang: Lang,
    _namespace: &str,
    leaf_name: &str,
    container_hint: Option<&str>,
) -> Option<FuncKey> {
    // `local_summaries` is file-local; every entry shares the same namespace
    // (raw file path from `build_cfg`). We do not filter by namespace here so
    // callers can pass whichever form they have (raw or normalized).
    let mut candidates: Vec<&FuncKey> = local_summaries
        .keys()
        .filter(|k| k.name == leaf_name && k.lang == lang)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() > 1 {
        if let Some(container) = container_hint {
            let narrowed: Vec<&FuncKey> = candidates
                .iter()
                .copied()
                .filter(|k| k.container == container)
                .collect();
            if narrowed.len() == 1 {
                return Some(narrowed[0].clone());
            }
            candidates = narrowed;
        }
    }
    if candidates.len() == 1 {
        Some(candidates[0].clone())
    } else {
        None
    }
}

// ── Callee Resolution (mirrors TaintTransfer::resolve_callee) ───────────

struct ResolvedSummary {
    source_caps: Cap,
    sanitizer_caps: Cap,
    sink_caps: Cap,
    /// Per-parameter sink caps: (param_index, caps). When non-empty, only
    /// arguments at these positions flow to internal sinks, enables positional
    /// and capability-aware filtering instead of aggregate-only detection.
    param_to_sink: Vec<(usize, Cap)>,
    /// Per-parameter [`SinkSite`] records mirroring `param_to_sink` by index.
    /// Populated when the underlying summary carried source-coordinate
    /// context (SSA and global `FuncSummary` paths).  Empty for label,
    /// local-summary, and interop paths where no [`SinkSite`] was
    /// retained; in that case `param_to_sink` alone still drives sink
    /// detection.
    param_to_sink_sites: Vec<(usize, SmallVec<[SinkSite; 1]>)>,
    /// Per-parameter gate-filter cap masks lifted from the callee's
    /// inner multi-gate sink call sites.  Mirrors
    /// [`crate::summary::ssa_summary::SsaFuncSummary::param_to_gate_filters`].
    ///
    /// Each `(param_idx, label_caps)` entry says "this caller-side
    /// parameter flows to a callee-internal gated sink whose narrowed
    /// caps are `label_caps`".  When non-empty, the multi-gate dispatch
    /// in [`collect_block_events`] expands one filter pass per entry so
    /// the emitted event's `sink_caps` reflect the gate-specific cap
    /// rather than the aggregate union, preserving SSRF-vs-DATA_EXFIL
    /// (and similar) attribution through wrapper functions.
    ///
    /// Empty for label, local-summary, FuncSummary, and interop paths,
    /// these forms do not retain per-gate cap detail.
    param_to_gate_filters: Vec<(usize, Cap)>,
    propagates_taint: bool,
    propagating_params: Vec<usize>,
    /// Parameter indices whose container identity flows to return value.
    param_container_to_return: Vec<usize>,
    /// (src_param, container_param) pairs: src taint stored into container.
    param_to_container_store: Vec<(usize, usize)>,
    /// Inferred return type from cross-file SSA summary.
    return_type: Option<crate::ssa::type_facts::TypeKind>,
    /// Abstract domain fact for the return value.
    return_abstract: Option<crate::abstract_interp::AbstractValue>,
    /// Internal source taint flows to a call of parameter N with these caps.
    source_to_callback: Vec<(usize, Cap)>,
    /// How receiver (`self`/`this`) taint flows to the return value.
    /// Matches `SsaFuncSummary::receiver_to_return` semantics.
    #[allow(dead_code)]
    receiver_to_return: Option<crate::summary::ssa_summary::TaintTransform>,
    /// Caps that receiver taint reaches at internal sinks.
    #[allow(dead_code)]
    receiver_to_sink: Cap,
    /// Per-parameter abstract-domain transfer channels.
    ///
    /// Populated only when the callee was resolved via an SSA summary
    /// (`convert_ssa_to_resolved`).  The label, local-summary, interop
    /// and coarse `FuncSummary` paths carry `Vec::new()` because those
    /// forms do not record abstract-domain behaviour.  Applied at the
    /// call site to synthesise an abstract return value from the
    /// caller's knowledge of each argument.
    abstract_transfer: Vec<(usize, crate::abstract_interp::AbstractTransfer)>,
    /// Per-parameter return-path decomposition.
    ///
    /// Populated only when the callee was resolved via an SSA summary
    /// and the summary carries ≥2 distinct return-path predicate gates.
    /// When present, summary application at the call site consults the
    /// caller's [`SsaTaintState::predicates`] and applies only entries
    /// whose predicate gate is consistent with the caller's validated
    /// set, recovering callee-internal path splits that the aggregate
    /// [`Self::sanitizer_caps`] / [`Self::propagating_params`] view
    /// otherwise erases.  Empty for non-SSA resolution paths.
    param_return_paths: Vec<(
        usize,
        smallvec::SmallVec<[crate::summary::ssa_summary::ReturnPathTransform; 2]>,
    )>,
    /// Parameter-granularity points-to summary.
    ///
    /// Populated only via `convert_ssa_to_resolved`; other resolution
    /// paths leave it empty (they do not derive alias edges).  Empty /
    /// default means "no aliasing beyond what param_to_container_store
    /// already captures", the caller treats the call as a pure
    /// taint-through-signature edge.
    points_to: crate::summary::points_to::PointsToSummary,
    /// Field-granularity per-parameter points-to summary. Populated
    /// only via `convert_ssa_to_resolved` when the SSA summary carries
    /// `field_points_to` records. Applied at the caller call site by
    /// `apply_field_points_to_writes`.
    field_points_to: crate::summary::points_to::FieldPointsToSummary,
    /// Parameter indices whose taint flow to the return is fully
    /// validated by a dominating predicate inside the callee on every
    /// return path.  Mirrors
    /// [`crate::summary::ssa_summary::SsaFuncSummary::validated_params_to_return`].
    /// Populated only via `convert_ssa_to_resolved`; other resolution
    /// paths leave it empty (label / coarse-FuncSummary forms cannot
    /// express per-path predicate validation).
    validated_params_to_return: Vec<usize>,
}

fn resolve_callee(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
) -> Option<ResolvedSummary> {
    resolve_callee_hinted(transfer, callee, caller_func, call_ordinal, None)
}

/// Like [`resolve_callee`] but accepts an `arity_hint` that narrows the
/// candidate set to functions with a matching parameter count.
///
/// Used by the call-graph / SSA-transfer paths when the caller knows the
/// number of positional arguments at this site, this eliminates false
/// resolution to same-name siblings with different arities (e.g.
/// `encode(x)` vs `encode(x, opts)` in the same namespace).
fn resolve_callee_hinted(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
) -> Option<ResolvedSummary> {
    resolve_callee_full(
        transfer,
        callee,
        caller_func,
        call_ordinal,
        arity_hint,
        None,
    )
}

/// Like [`resolve_callee_hinted`] but accepts an authoritative
/// `receiver_type` (class/impl name) derived from the SSA receiver
/// value's [`TypeKind::label_prefix`].  When supplied, qualified
/// lookup uses this name first and refuses to fall through to a
/// leaf-name collision on miss (see
/// [`GlobalSummaries::resolve_callee`] step 1).
fn resolve_callee_typed(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
    receiver: Option<SsaValue>,
) -> Option<ResolvedSummary> {
    let receiver_type = receiver_type_prefix(transfer, receiver);
    resolve_callee_full(
        transfer,
        callee,
        caller_func,
        call_ordinal,
        arity_hint,
        receiver_type,
    )
}

/// Extract a qualified receiver-type name (e.g. `"HttpClient"`) for the
/// SSA receiver value, when type facts can infer it.  Returns `None`
/// for built-in `Int`/`String`/unknown types that have no class prefix.
fn receiver_type_prefix(
    transfer: &SsaTaintTransfer,
    receiver: Option<SsaValue>,
) -> Option<&'static str> {
    let v = receiver?;
    let tf = transfer.type_facts?;
    let kind = tf.get_type(v)?;
    kind.label_prefix()
}

fn resolve_callee_full(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
    receiver_type: Option<&str>,
) -> Option<ResolvedSummary> {
    // Use leaf name for map/index lookups (FuncKey.name is always leaf).
    let normalized = callee_leaf_name(callee);
    // Split the raw callee into structured qualifier hints.  A `::`
    // prefix is a namespace qualifier (authoritative-ish); a `.`
    // prefix is the syntactic receiver variable, which we treat as a
    // soft hint.
    let (namespace_qualifier, receiver_var) = split_qualifier(callee);

    // -2) Import alias resolution: if the callee matches an aliased import
    // (e.g. `fetchUserCmd` → `getInput` from `./source`), resolve using the
    // original exported name instead.  This fires before all other resolution
    // so that downstream steps see the canonical symbol name.
    if let Some(bindings) = transfer.import_bindings {
        if let Some(binding) = bindings.get(normalized) {
            // Recursively resolve using the original name, preserving the
            // arity hint (the import alias does not change call arity).
            return resolve_callee_hinted(
                transfer,
                &binding.original,
                caller_func,
                call_ordinal,
                arity_hint,
            );
        }
    }

    // -1) Callback resolution: if the callee name matches a parameter that was
    // bound to a specific function at the call site, resolve that function instead.
    if let Some(cb) = transfer.callback_bindings {
        if let Some(real_key) = cb.get(normalized) {
            // Try to resolve the actual function via FuncKey-keyed SSA summaries
            if let Some(ssa_sums) = transfer.ssa_summaries {
                if let Some(ssa_sum) = ssa_sums.get(real_key) {
                    return Some(convert_ssa_to_resolved_for_caller(
                        ssa_sum,
                        Some(transfer.namespace),
                    ));
                }
            }
            // Try local summaries (already FuncKey-keyed)
            if let Some(ls) = transfer.local_summaries.get(real_key) {
                return Some(ResolvedSummary {
                    source_caps: ls.source_caps,
                    sanitizer_caps: ls.sanitizer_caps,
                    sink_caps: ls.sink_caps,
                    param_to_sink: ls
                        .tainted_sink_params
                        .iter()
                        .map(|&i| (i, ls.sink_caps))
                        .collect(),
                    param_to_sink_sites: vec![],
                    propagates_taint: !ls.propagating_params.is_empty(),
                    propagating_params: ls.propagating_params.clone(),
                    param_container_to_return: vec![],
                    param_to_container_store: vec![],
                    return_type: None,
                    return_abstract: None,
                    source_to_callback: vec![],

                    receiver_to_return: None,

                    receiver_to_sink: Cap::empty(),

                    abstract_transfer: vec![],
                    param_return_paths: vec![],
                    points_to: Default::default(),
                    field_points_to: Default::default(),
                    param_to_gate_filters: vec![],
                    validated_params_to_return: vec![],
                });
            }
            // Try label classification for the bound function (by leaf name).
            // Consult both flat rules (`classify_all`) and gated sinks: a
            // callback bound to a gated sink (e.g. passing
            // `child_process.exec` directly as the callback) still needs to
            // surface its `Sink` capability so the source/callback pairing
            // logic can match `param_to_sink` against the caller's source.
            // The gate's `payload_args` translate directly into
            // `param_to_sink` index entries.
            let labels = crate::labels::classify_all(
                transfer.lang.as_str(),
                &real_key.name,
                transfer.extra_labels,
            );
            let gate_matches = crate::labels::classify_gated_sink(
                transfer.lang.as_str(),
                &real_key.name,
                |_| None,
                |_| None,
                |_| false,
            );
            if !labels.is_empty() || !gate_matches.is_empty() {
                let mut source_caps = Cap::empty();
                let mut sanitizer_caps = Cap::empty();
                let mut sink_caps = Cap::empty();
                let mut param_to_sink: Vec<(usize, Cap)> = vec![];
                for lbl in &labels {
                    match lbl {
                        DataLabel::Source(bits) => source_caps |= *bits,
                        DataLabel::Sanitizer(bits) => sanitizer_caps |= *bits,
                        DataLabel::Sink(bits) => sink_caps |= *bits,
                    }
                }
                for gm in gate_matches.iter() {
                    if let DataLabel::Sink(bits) = gm.label {
                        sink_caps |= bits;
                        // Map the gate's payload_args to per-param sink entries
                        // so source-to-callback pairing can match by index.
                        // Skip the dynamic-activation sentinel — without a
                        // concrete arity we can't enumerate positions here.
                        if gm.payload_args != crate::labels::ALL_ARGS_PAYLOAD {
                            for &idx in gm.payload_args {
                                param_to_sink.push((idx, bits));
                            }
                        }
                    }
                }
                return Some(ResolvedSummary {
                    source_caps,
                    sanitizer_caps,
                    sink_caps,
                    param_to_sink,
                    param_to_sink_sites: vec![],
                    propagates_taint: false,
                    propagating_params: vec![],
                    param_container_to_return: vec![],
                    param_to_container_store: vec![],
                    return_type: None,
                    return_abstract: None,
                    source_to_callback: vec![],

                    receiver_to_return: None,

                    receiver_to_sink: Cap::empty(),

                    abstract_transfer: vec![],
                    param_return_paths: vec![],
                    points_to: Default::default(),
                    field_points_to: Default::default(),
                    param_to_gate_filters: vec![],
                    validated_params_to_return: vec![],
                });
            }
        }
    }

    // Caller-container hint: when the caller lives inside a class/impl,
    // its own container resolves bare self-calls correctly instead of
    // collapsing into an unrelated same-leaf definition.
    let caller_container_opt = caller_container_for(transfer, caller_func);
    let caller_container: Option<&str> = caller_container_opt.as_deref();

    // Build the structured query once and reuse across the same-language
    // resolution steps (0.5 and 2).
    let build_query = || CalleeQuery {
        name: normalized,
        caller_lang: transfer.lang,
        caller_namespace: transfer.namespace,
        caller_container,
        receiver_type,
        namespace_qualifier,
        receiver_var,
        arity: arity_hint,
    };

    // 0) Precise SSA summaries (intra-file, per-parameter transforms).
    //
    // Resolve the callee string to a local `FuncKey` via the already-
    // FuncKey-keyed `local_summaries` index, then consult `ssa_summaries` by
    // the same key.  This preserves container/arity/disambig identity so two
    // same-name definitions in the same file never share an SSA summary.
    //
    // Namespace fallback: `lower_all_functions_from_bodies` rewrites
    // every SSA summary key's `namespace` to the caller-relative
    // namespace (for cross-file consistency in `GlobalSummaries`),
    // while `local_summaries` keys keep the raw file path that
    // `build_cfg` wrote.  When the exact-key lookup misses, fall back
    // to a namespace-tolerant scan that matches every other FuncKey
    // field (lang/container/name/arity/disambig/kind), this recovers
    // intra-file SSA summary lookups in single-file or non-indexed
    // scans where the two namespaces disagree by construction.
    if let Some(ssa_sums) = transfer.ssa_summaries {
        if let Some(key) = resolve_local_func_key_query(transfer.local_summaries, &build_query()) {
            if let Some(ssa_sum) = ssa_sums.get(&key) {
                return Some(convert_ssa_to_resolved(ssa_sum));
            }
            if let Some((_, ssa_sum)) = ssa_sums.iter().find(|(k, _)| {
                k.lang == key.lang
                    && k.container == key.container
                    && k.name == key.name
                    && k.arity == key.arity
                    && k.disambig == key.disambig
                    && k.kind == key.kind
            }) {
                return Some(convert_ssa_to_resolved(ssa_sum));
            }
        }
    }

    // 0.5) Cross-file SSA summaries (GlobalSummaries.ssa_by_key) with
    // optional class-hierarchy fan-out.
    //
    // When the call has an authoritative receiver type AND
    // `GlobalSummaries::install_hierarchy` has been called AND the
    // type has recorded sub-types whose `method` overrides exist, the
    // taint engine sees ALL implementers, not just the super-type's
    // own definition.  This is the runtime counterpart of the
    // call-graph builder's `resolve_with_hierarchy` step, without
    // it, virtual dispatch through a super-type silently lost
    // sub-type sources / sinks.
    if let Some(gs) = transfer.global_summaries {
        let widened = gs.resolve_callee_widened(&build_query());
        match widened.len() {
            0 => {}
            1 => {
                if let Some(ssa_sum) = gs.get_ssa(&widened[0]) {
                    return Some(convert_ssa_to_resolved_for_caller(
                        ssa_sum,
                        Some(transfer.namespace),
                    ));
                }
            }
            _ => {
                // Hierarchy fan-out: union per-implementer SSA
                // summaries with "any-impl" semantics so the caller
                // sees taint from every reachable concrete target.
                let mut accum: Option<ResolvedSummary> = None;
                let mut covered: usize = 0;
                for key in &widened {
                    if let Some(ssa_sum) = gs.get_ssa(key) {
                        let r =
                            convert_ssa_to_resolved_for_caller(ssa_sum, Some(transfer.namespace));
                        accum = Some(match accum {
                            None => r,
                            Some(a) => merge_resolved_summaries_fanout(a, r),
                        });
                        covered += 1;
                    }
                }
                if covered > 0 {
                    tracing::debug!(
                        callee = %callee,
                        impls = covered,
                        widened_total = widened.len(),
                        "hierarchy fan-out: SSA summaries unioned at call site"
                    );
                    return accum;
                }
                // None of the widened keys had SSA summaries, fall
                // through to step 2 (FuncSummary path) which may have
                // hierarchy-widened FuncSummary entries.
            }
        }
    }

    // 0.7) Cross-package import resolution (Phase 09).
    //
    // When the callee leaf name matches an import binding the resolver
    // resolved to a concrete `(file, exported_name)` pair, look up the
    // canonical [`FuncKey`] in [`GlobalSummaries::ssa_by_key`].  This
    // closes the recall gap on `import { foo } from '@scope/pkg'` shapes
    // where `foo` lives in another package's namespace and the same-name
    // narrowing in step 0.5 can't reach it (the caller's namespace ≠ the
    // callee's namespace).
    //
    // The pre-built map carries the target's `(lang, namespace, name)`
    // triple but leaves arity / container / disambig / kind unset because
    // the resolver doesn't inspect the export's signature.  We narrow
    // candidates by those three fields plus the call-site arity hint when
    // available; if exactly one survives, claim resolution.  On miss or
    // ambiguity we fall through to the existing flat paths.
    if let (Some(map), Some(gs)) = (transfer.cross_package_imports, transfer.global_summaries) {
        if let Some(target) = map.get(normalized) {
            // Indexed candidate lookup: the
            // `(lang, namespace, name)` triple narrows to the small
            // set of SSA keys that share the import target's leaf
            // name.  Replaces the prior `O(|ssa_by_key|)` scan over
            // every persisted SSA key with a single hash probe plus
            // an iteration over only the matching bucket.
            let candidates =
                gs.ssa_keys_by_qualified(target.lang, &target.namespace, &target.name);
            let mut hit: Option<&FuncKey> = None;
            let mut ambiguous = false;
            for k in candidates {
                if !k.container.is_empty() {
                    continue;
                }
                if let Some(want) = arity_hint
                    && k.arity != Some(want)
                {
                    continue;
                }
                if hit.replace(k).is_some() {
                    ambiguous = true;
                    break;
                }
            }
            if !ambiguous && let Some(k) = hit {
                if let Some(ssa_sum) = gs.get_ssa(k) {
                    tracing::debug!(
                        callee = %callee,
                        target_namespace = %target.namespace,
                        target_name = %target.name,
                        "cross-package SSA summary hit (step 0.7)"
                    );
                    return Some(convert_ssa_to_resolved_for_caller(
                        ssa_sum,
                        Some(transfer.namespace),
                    ));
                }
            }
        }
    }

    // 1) Local (same-file), lookup via canonical FuncKey using the
    // same qualified-first policy as the global resolver.
    if let Some(key) = resolve_local_func_key_query(transfer.local_summaries, &build_query()) {
        if let Some(ls) = transfer.local_summaries.get(&key) {
            return Some(ResolvedSummary {
                source_caps: ls.source_caps,
                sanitizer_caps: ls.sanitizer_caps,
                sink_caps: ls.sink_caps,
                param_to_sink: ls
                    .tainted_sink_params
                    .iter()
                    .map(|&i| (i, ls.sink_caps))
                    .collect(),
                param_to_sink_sites: vec![],
                propagates_taint: !ls.propagating_params.is_empty(),
                propagating_params: ls.propagating_params.clone(),
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                param_to_gate_filters: vec![],
                validated_params_to_return: vec![],
            });
        }
    } else {
        // Multiple same-name local candidates with no disambiguating
        // container hint: refuse to pick one rather than fall through to a
        // less precise global summary that might be the wrong definition.
        let ambiguous_local = transfer
            .local_summaries
            .keys()
            .filter(|k| k.name == normalized && k.lang == transfer.lang)
            .count()
            > 1;
        if ambiguous_local {
            return None;
        }
    }

    // 2) Global same-language (FuncSummary path) with class-hierarchy
    // fan-out.  Same semantics as step 0.5 but on coarse FuncSummary
    // entries, the SSA path missed because no implementer had an SSA
    // summary, so we widen the FuncSummary lookup symmetrically.
    if let Some(gs) = transfer.global_summaries {
        let widened = gs.resolve_callee_widened(&build_query());
        let convert = |fs: &crate::summary::FuncSummary| ResolvedSummary {
            source_caps: fs.source_caps(),
            sanitizer_caps: fs.sanitizer_caps(),
            sink_caps: fs.sink_caps(),
            param_to_sink: fs
                .tainted_sink_params
                .iter()
                .map(|&i| (i, fs.sink_caps()))
                .collect(),
            // Carry [`SinkSite`]s from the global FuncSummary
            // so cross-file findings can attribute to the
            // callee-internal dangerous instruction.
            param_to_sink_sites: fs.param_to_sink.clone(),
            propagates_taint: fs.propagates_any(),
            propagating_params: fs.propagating_params.clone(),
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
            source_to_callback: vec![],
            receiver_to_return: None,
            receiver_to_sink: Cap::empty(),
            abstract_transfer: vec![],
            param_return_paths: vec![],
            points_to: Default::default(),
            field_points_to: Default::default(),
            param_to_gate_filters: vec![],
            validated_params_to_return: vec![],
        };
        match widened.len() {
            0 => {}
            1 => {
                if let Some(fs) = gs.get(&widened[0]) {
                    return Some(convert(fs));
                }
            }
            _ => {
                let mut accum: Option<ResolvedSummary> = None;
                let mut covered: usize = 0;
                for key in &widened {
                    if let Some(fs) = gs.get(key) {
                        let r = convert(fs);
                        accum = Some(match accum {
                            None => r,
                            Some(a) => merge_resolved_summaries_fanout(a, r),
                        });
                        covered += 1;
                    }
                }
                if covered > 0 {
                    tracing::debug!(
                        callee = %callee,
                        impls = covered,
                        widened_total = widened.len(),
                        "hierarchy fan-out: FuncSummaries unioned at call site"
                    );
                    return accum;
                }
            }
        }
    }

    // 3) Interop edges
    for edge in transfer.interop_edges {
        if edge.from.caller_lang == transfer.lang
            && edge.from.caller_namespace == transfer.namespace
            && edge.from.callee_symbol == callee
            && (edge.from.caller_func.is_empty() || edge.from.caller_func == caller_func)
            && (edge.from.ordinal == 0 || edge.from.ordinal == call_ordinal)
            && let Some(gs) = transfer.global_summaries
            && let Some(fs) = gs.get_for_interop(&edge.to)
        {
            return Some(ResolvedSummary {
                source_caps: fs.source_caps(),
                sanitizer_caps: fs.sanitizer_caps(),
                sink_caps: fs.sink_caps(),
                param_to_sink: fs
                    .tainted_sink_params
                    .iter()
                    .map(|&i| (i, fs.sink_caps()))
                    .collect(),
                param_to_sink_sites: fs.param_to_sink.clone(),
                propagates_taint: fs.propagates_any(),
                propagating_params: fs.propagating_params.clone(),
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
                source_to_callback: vec![],

                receiver_to_return: None,

                receiver_to_sink: Cap::empty(),

                abstract_transfer: vec![],
                param_return_paths: vec![],
                points_to: Default::default(),
                field_points_to: Default::default(),
                param_to_gate_filters: vec![],
                validated_params_to_return: vec![],
            });
        }
    }

    None
}

/// Compute the effective sanitizer bits that apply at the call site for a
/// specific parameter, narrowed by the caller's predicate state.
///
/// When the resolved summary carries `param_return_paths` for `param_idx`:
/// filter the entries by predicate consistency with the caller's current
/// `SsaTaintState` (`validated_must` + `predicates`).  Compatible entries
/// are joined with the **intersection-of-strip-bits** rule: the caller does
/// not know which return path the callee took, so only bits stripped on
/// EVERY compatible path can be considered cleared.
///
/// Falls back to `resolved.sanitizer_caps` (the aggregate) when:
///   * the summary has no per-path data for this parameter;
///   * every path is predicate-compatible (the narrowing adds no information);
///   * no path is predicate-compatible (conservative: keep aggregate).
fn effective_param_sanitizer(
    resolved: &ResolvedSummary,
    param_idx: usize,
    state: &SsaTaintState,
) -> Cap {
    use crate::summary::ssa_summary::TaintTransform;

    let paths = match resolved
        .param_return_paths
        .iter()
        .find(|(i, _)| *i == param_idx)
    {
        Some((_, p)) => p,
        None => return resolved.sanitizer_caps,
    };

    // Caller-side predicate envelope: union of known_true / known_false bits
    // observed across the caller's tracked variables.  A path is
    // compatible if its required bits (known_true / known_false) do not
    // contradict this envelope.
    let mut caller_kt: u8 = 0;
    let mut caller_kf: u8 = 0;
    for (_, pred) in &state.predicates {
        caller_kt |= pred.known_true;
        caller_kf |= pred.known_false;
    }

    let mut compatible: smallvec::SmallVec<[&_; 2]> = smallvec::SmallVec::new();
    for path in paths {
        // Contradiction tests:
        //   * path demands bit B true while caller has evidence B is false
        //   * path demands bit B false while caller has evidence B is true
        // In either case the caller cannot possibly be on this return path.
        if path.known_true & caller_kf != 0 {
            continue;
        }
        if path.known_false & caller_kt != 0 {
            continue;
        }
        compatible.push(path);
    }

    if compatible.is_empty() {
        // No path applies, the caller's predicate state contradicts every
        // recorded return.  Fall back to the aggregate rather than
        // synthesise a sanitiser from zero data.
        return resolved.sanitizer_caps;
    }

    // Intersection of strip-bits across compatible paths.  Identity
    // contributes the empty set (nothing stripped); AddBits contributes
    // nothing to the sanitiser either.
    let mut common = Cap::all();
    let mut saw_any = false;
    for path in &compatible {
        match &path.transform {
            TaintTransform::StripBits(bits) => {
                common &= *bits;
                saw_any = true;
            }
            TaintTransform::Identity => {
                common = Cap::empty();
                saw_any = true;
            }
            TaintTransform::AddBits(_) => {
                // AddBits doesn't contribute to sanitation; the intersection
                // is still taken over zero strip contribution.
                common = Cap::empty();
                saw_any = true;
            }
        }
    }
    if !saw_any {
        resolved.sanitizer_caps
    } else {
        common
    }
}

/// Convert an `SsaFuncSummary` to the existing `ResolvedSummary` format.
fn convert_ssa_to_resolved(
    ssa_sum: &crate::summary::ssa_summary::SsaFuncSummary,
) -> ResolvedSummary {
    convert_ssa_to_resolved_for_caller(ssa_sum, None)
}

fn convert_ssa_to_resolved_for_caller(
    ssa_sum: &crate::summary::ssa_summary::SsaFuncSummary,
    caller_namespace: Option<&str>,
) -> ResolvedSummary {
    use crate::summary::ssa_summary::TaintTransform;

    let propagating_params: Vec<usize> = ssa_sum
        .param_to_return
        .iter()
        .map(|(idx, _)| *idx)
        .collect();

    // Compute effective sanitizer caps: union of StripBits across all params
    let mut sanitizer_caps = Cap::empty();
    for (_, transform) in &ssa_sum.param_to_return {
        if let TaintTransform::StripBits(bits) = transform {
            sanitizer_caps |= *bits;
        }
    }

    // Compute effective sink caps: union across all params
    let sink_caps = ssa_sum.total_param_sink_caps();
    let param_to_sink = ssa_sum.param_to_sink_caps();
    // Carry the full SinkSite lists through so the taint engine can
    // attribute cross-file findings to the callee-internal sink.  Sites
    // with coordinates of `(0, 0)` (cap-only, no tree/bytes context at
    // extraction time) remain in the list but contribute no primary
    // location, the emission site filters by `SinkSite::line != 0`.
    //
    // Strip same-file sites when `caller_namespace` is supplied: the
    // caller's own taint analysis already produces a finding at the
    // callee's internal sink (e.g. closure body's `eval(q)` finding at
    // pass-1 lexical containment), so promoting `primary_location` at
    // the call site to the same line collides with that finding under
    // [`crate::commands::scan::deduplicate_taint_flows`] and silently
    // drops the call-site finding.  Cross-file sites are preserved
    // (the other file's analysis can't be deduped against this one).
    let param_to_sink_sites = if let Some(caller_ns) = caller_namespace {
        ssa_sum
            .param_to_sink
            .iter()
            .map(|(idx, sites)| {
                let filtered: SmallVec<[crate::summary::SinkSite; 1]> = sites
                    .iter()
                    .filter(|s| s.file_rel.is_empty() || s.file_rel != caller_ns)
                    .cloned()
                    .collect();
                (*idx, filtered)
            })
            .filter(|(_, sites)| !sites.is_empty())
            .collect()
    } else {
        ssa_sum.param_to_sink.clone()
    };

    ResolvedSummary {
        source_caps: ssa_sum.source_caps,
        sanitizer_caps,
        sink_caps,
        param_to_sink,
        param_to_sink_sites,
        propagates_taint: !propagating_params.is_empty(),
        propagating_params,
        param_container_to_return: ssa_sum.param_container_to_return.clone(),
        param_to_container_store: ssa_sum.param_to_container_store.clone(),
        return_type: ssa_sum.return_type.clone(),
        return_abstract: ssa_sum.return_abstract.clone(),
        source_to_callback: ssa_sum.source_to_callback.clone(),
        receiver_to_return: ssa_sum.receiver_to_return.clone(),
        receiver_to_sink: ssa_sum.receiver_to_sink,
        abstract_transfer: ssa_sum.abstract_transfer.clone(),
        param_return_paths: ssa_sum.param_return_paths.clone(),
        points_to: ssa_sum.points_to.clone(),
        field_points_to: ssa_sum.field_points_to.clone(),
        param_to_gate_filters: ssa_sum.param_to_gate_filters.clone(),
        validated_params_to_return: ssa_sum.validated_params_to_return.to_vec(),
    }
}

/// Merge two [`ResolvedSummary`] values into a single "any-implementer"
/// summary suitable for use at a virtual-dispatch call site whose
/// receiver static type fans out to multiple concrete implementers via
/// [`crate::callgraph::TypeHierarchyIndex`].
///
/// Semantics, designed to keep the engine sound under fan-out:
///
/// * **Caps that *grow* the taint signal**
///   (`source_caps`, `sink_caps`, `receiver_to_sink`,
///   `propagates_taint`), **OR**.  Any implementer that introduces
///   the cap is a valid runtime target, so the union conservatively
///   covers every dispatch outcome.
/// * **`sanitizer_caps`**, **AND**.  Only bits sanitized by *every*
///   implementer can be considered cleared at the call site, since
///   the dispatch could land on the implementer that doesn't
///   sanitize.
/// * **Per-parameter vectors** (`param_to_sink`, `propagating_params`,
///   `param_container_to_return`, `param_to_container_store`,
///   `source_to_callback`), **union**.  An impl that contributes a
///   propagation/sink at parameter N is a valid runtime path; missing
///   impls do not subtract.
/// * **`param_to_sink_sites`**, concatenated per-parameter (dedup
///   on `SinkSite::PartialEq`).  Each site is independently
///   emittable; the dedup avoids reporting the same callee-internal
///   sink twice.
/// * **SSA-precision fields** (`return_type`, `return_abstract`,
///   `receiver_to_return`, `abstract_transfer`, `param_return_paths`,
///   `points_to`), **drop on disagreement**.  These describe the
///   precise behavior of *one* function body; merging two
///   incompatible bodies yields a meaningless composite.  Identity
///   is preserved when both sides agree exactly (string equality or
///   PartialEq), keeping single-impl cases lossless.
fn merge_resolved_summaries_fanout(
    mut acc: ResolvedSummary,
    r: ResolvedSummary,
) -> ResolvedSummary {
    // Caps + booleans
    acc.source_caps |= r.source_caps;
    acc.sanitizer_caps &= r.sanitizer_caps;
    acc.sink_caps |= r.sink_caps;
    acc.propagates_taint |= r.propagates_taint;
    acc.receiver_to_sink |= r.receiver_to_sink;

    // param_to_sink: union per-parameter caps
    for (idx, caps) in r.param_to_sink {
        if let Some(slot) = acc.param_to_sink.iter_mut().find(|(i, _)| *i == idx) {
            slot.1 |= caps;
        } else {
            acc.param_to_sink.push((idx, caps));
        }
    }

    // param_to_sink_sites: union per-parameter site lists with PartialEq
    // dedup, so the same callee-internal sink isn't reported twice when
    // multiple impls share an inherited definition.
    for (idx, sites) in r.param_to_sink_sites {
        if let Some(slot) = acc.param_to_sink_sites.iter_mut().find(|(i, _)| *i == idx) {
            for site in sites {
                if !slot.1.iter().any(|s| s == &site) {
                    slot.1.push(site);
                }
            }
        } else {
            acc.param_to_sink_sites.push((idx, sites));
        }
    }

    // propagating_params: union (any propagator wins)
    for p in r.propagating_params {
        if !acc.propagating_params.contains(&p) {
            acc.propagating_params.push(p);
        }
    }
    for p in r.param_container_to_return {
        if !acc.param_container_to_return.contains(&p) {
            acc.param_container_to_return.push(p);
        }
    }
    for pair in r.param_to_container_store {
        if !acc.param_to_container_store.contains(&pair) {
            acc.param_to_container_store.push(pair);
        }
    }

    // source_to_callback: union per-parameter caps (mirrors param_to_sink)
    for (idx, caps) in r.source_to_callback {
        if let Some(slot) = acc.source_to_callback.iter_mut().find(|(i, _)| *i == idx) {
            slot.1 |= caps;
        } else {
            acc.source_to_callback.push((idx, caps));
        }
    }

    // param_to_gate_filters: dedup-union (idx, caps) pairs.  Each
    // implementer may carry its own per-position cap split; the union
    // preserves cap attribution from any implementer reachable via
    // virtual dispatch.
    for (idx, caps) in r.param_to_gate_filters {
        if !acc
            .param_to_gate_filters
            .iter()
            .any(|&(i, c)| i == idx && c == caps)
        {
            acc.param_to_gate_filters.push((idx, caps));
        }
    }

    // SSA-precision fields: drop on any disagreement.
    if acc.return_type != r.return_type {
        acc.return_type = None;
    }
    if acc.return_abstract != r.return_abstract {
        acc.return_abstract = None;
    }
    if acc.receiver_to_return != r.receiver_to_return {
        acc.receiver_to_return = None;
    }
    if acc.abstract_transfer != r.abstract_transfer {
        acc.abstract_transfer = Vec::new();
    }
    if acc.param_return_paths != r.param_return_paths {
        acc.param_return_paths = Vec::new();
    }
    if acc.points_to != r.points_to {
        acc.points_to = Default::default();
    }

    acc
}
