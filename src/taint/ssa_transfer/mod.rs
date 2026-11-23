//! Block-level SSA taint worklist — the sole taint engine for all 10 languages.
//!
//! Drives a forward dataflow fixpoint over [`crate::ssa::SsaBody`] blocks
//! (`run_ssa_taint` / `run_ssa_taint_full`), propagating `SsaTaintState` through
//! `transfer_inst` with branch-aware narrowing, k=1 context-sensitive inlining
//! (`inline`), gated-sink detection (`events`), and interprocedural summary
//! extraction (`summary_extract`). Submodules: `events`, `inline`, `state`,
//! `summary_extract`.

#![allow(
    clippy::if_same_then_else,
    clippy::manual_flatten,
    clippy::needless_range_loop,
    clippy::only_used_in_recursion,
    clippy::single_match,
    clippy::too_many_arguments,
    clippy::unnecessary_map_or
)]

mod call_text;
mod events;
mod inline;
mod operands;
mod state;
mod summary_extract;

#[cfg(test)]
mod tests;

use call_text::{CallTextFacts, call_text_facts};
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
pub(crate) use summary_extract::{MAX_PROBE_PARAMS, detect_path_confined_return};
pub use summary_extract::{extract_ssa_func_summary, extract_ssa_func_summary_full};

use crate::abstract_interp::AbstractState;
use crate::callgraph::{callee_container_hint, callee_leaf_name};
use crate::cfg::{BodyId, CalleeNesting, Cfg, FuncSummaries, NodeInfo};
use crate::constraint;
use crate::interop::InteropEdge;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule, SourceKind};
use crate::ssa::heap::{HeapObjectId, HeapSlot, PointsToResult, PointsToSet};
use crate::ssa::ir::*;
use crate::ssa::type_facts::InputValidatorPolarity;
use crate::state::lattice::Lattice;
use crate::state::symbol::SymbolInterner;
use crate::summary::{CallReceiver, CalleeQuery, GlobalSummaries, SinkSite};
use crate::symbol::{FuncKey, Lang};
use crate::taint::domain::{PredicateSummary, TaintOrigin, VarTaint, predicate_kind_bit};
use crate::taint::path_state::{PredicateKind, classify_condition_with_target};
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;

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
    pub const_values: Option<&'a crate::ssa::const_prop::ConstValues>,
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
    /// to detect handler-style flows that have no registered caller, and
    /// leaves it off for bodies with a known caller, whose inbound taint
    /// arrives through summaries and inlining instead.
    pub auto_seed_handler_params: bool,
    /// Cross-file callee bodies sourced from
    /// [`GlobalSummaries`].  Populated in pass 2 to enable
    /// context-sensitive inline re-analysis across file boundaries the
    /// same way `callee_bodies` enables it intra-file.  `None` preserves
    /// non-cross-file behaviour for unit tests and non-cross-file
    /// construction sites.
    pub cross_file_bodies: Option<&'a crate::summary::GlobalSummaries>,
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
    /// Per-formal "bound from the request" flag, indexed by
    /// `SsaOp::Param.index` (see `BodyMeta::param_route_capture`).
    /// Used by the entry-kind seeding pass for Flask, Sinatra, FastAPI,
    /// Spring and JAX-RS to restrict `Source(UserInput)` painting to
    /// formals that are path captures (Python, Ruby) or request-bound
    /// (Java).  `None` preserves the "seed every Param" behaviour for entry
    /// kinds without per-formal gating (Express, Gin, AppRoute, ...).
    pub param_route_capture: Option<&'a [bool]>,
    /// True when the transfer is driving a per-parameter probe inside
    /// [`crate::taint::ssa_transfer::summary_extract::extract_ssa_func_summary`]
    /// rather than the pass-2 emission path.  The probes record chain-hop
    /// sites onto the function's [`crate::summary::ssa_summary::SsaFuncSummary`];
    /// pass-2 emission gates the same sites against the
    /// `from_chain || file_rel != caller_namespace` predicate so single-hop
    /// intra-file helpers keep call-site emission.  Probes set this flag
    /// so `pick_primary_sink_sites` always promotes a deeper-callee site
    /// into `event.primary_sink_site`, regardless of file boundary, so
    /// `crate::taint::ssa_transfer::summary_extract` can flip
    /// `from_chain=true` and persist the chain hop.  Default: false.
    pub recording_summary: bool,
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
    // `block_exit_states` is discarded here, so skip building it entirely —
    // that elides one full `SsaTaintState` clone per block pop on the entire
    // main taint path (summary extraction + main analysis + sink augmentation,
    // all 10 languages).  See `run_ssa_taint_internal`'s `track_exit_states`.
    let result = run_ssa_taint_internal(ssa, cfg, transfer, false);
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
    let result = run_ssa_taint_internal(ssa, cfg, transfer, true);
    (result.events, result.block_states, result.block_exit_states)
}

/// Request-bound flag of a Spring / JAX-RS entry `Param` (see
/// `BodyMeta::param_route_capture`).  A formal reads its own flag.  A Param
/// past the formals is a dotted projection of one (`dto.name`) and takes the
/// flag of its root formal.  Without flags every Param counts as bound.
fn java_param_is_request_bound(
    ssa: &SsaBody,
    inst: &SsaInst,
    param_index: Option<usize>,
    flags: Option<&[bool]>,
) -> bool {
    let Some(flags) = flags else {
        return true;
    };
    let Some(index) = param_index else {
        return false;
    };
    if let Some(&bound) = flags.get(index) {
        return bound;
    }
    let Some((root, _)) = inst.var_name.as_deref().and_then(|n| n.split_once('.')) else {
        return false;
    };
    ssa.blocks[ssa.entry.0 as usize]
        .body
        .iter()
        .find_map(|i| match i.op {
            SsaOp::Param { index } if i.var_name.as_deref() == Some(root) => {
                flags.get(index).copied()
            }
            _ => None,
        })
        .unwrap_or(false)
}

fn run_ssa_taint_internal(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
    // When `false`, the per-block exit states are never stored into
    // `block_exit_states` (it stays all-`None`).  The dominant callers
    // (`run_ssa_taint_full`: summary extraction, main analysis, and
    // parent/child sink augmentation) discard `block_exit_states`, so
    // filling it means cloning the full `SsaTaintState` once per block pop
    // for a value that is thrown away.  Only `run_ssa_taint_full_with_exits`
    // (the k=1 inline-callee return-shape extractor and the debug endpoint)
    // consults it, and it passes `true`.  When `true`, the exit state is
    // *moved* into `block_exit_states` after its last borrow rather than
    // cloned, so even the tracking path pays no clone here.
    track_exit_states: bool,
) -> SsaTaintRunResult {
    let num_blocks = ssa.blocks.len();

    // Callee resolutions are reused across the worklist visits and the event
    // replay of this run.
    let _resolve_memo = ResolveMemoScope::enter(transfer);

    // Path-confinement gates: computed once for the whole body so the per-call
    // confinement passes (and their string-grammar name checks) are skipped in
    // both the worklist and the event-collection replays when the file has no
    // confiner summary.  See [`ConfinementGates`].
    let confinement = compute_confinement_gates(transfer);

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
    // Entry-kind seeding paints framework handler formals as
    // adversary-controlled.  Suppress entirely when the body lives in a
    // test file: closures with the right shape (`func(c *gin.Context)`,
    // `func(req, res)`, etc.) appear in unit tests as scaffolding, not
    // as request-reachable production routes.  Painting their formals
    // as Source surfaces every internal sink the test exercises as a
    // finding whose "attacker" is the test author.
    let body_in_test_file = !transfer.namespace.is_empty()
        && crate::ast::is_test_file(std::path::Path::new(transfer.namespace));
    if !body_in_test_file
        && let (Some(entry_kind), Some(state)) = (
            transfer.entry_kind.as_ref(),
            block_states[ssa.entry.0 as usize].as_mut(),
        )
    {
        use crate::entry_points::EntryKind;
        let source_kind = SourceKind::UserInput;
        // (skip_self_param, only_param_index, seed_at_all) —
        // `only_param_index = Some(i)` restricts seeding to the `i`-th
        // non-self formal Param op (counted in SSA insertion order).
        // `None` seeds every Param.  `seed_at_all = false` skips seeding
        // entirely; the engine relies on existing label rules instead.
        let (skip_self, only_index, seed_at_all): (bool, Option<usize>, bool) = match entry_kind {
            // Param-only handlers.  Every named formal is a candidate; the
            // per-formal gates below narrow Flask, Sinatra, FastAPI, Spring,
            // JAX-RS and the Rust frameworks to the request-bound ones.
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
            | EntryKind::RocketRoute => (true, None, true),
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
            // Gin (`*gin.Context`), echo (`echo.Context`), fiber
            // (`*fiber.Ctx`), iris (`iris.Context`) — `c.Query` /
            // `c.Param` / `c.PostForm` / `c.QueryArray` /
            // `c.PostFormArray` / `c.QueryParam` are classified as
            // `Source(Cap::all())` by the framework-aware label rules
            // in `src/labels/go.rs` (gated on `DetectedFramework::Gin`).
            // The receiver-method calls flow that taint through to
            // local variables without painting the bare `c` object,
            // which avoids the FP shape where excluded lifecycle
            // methods (`c.AbortWithStatus`, `c.Set`, `c.Next`) get
            // re-classified as sinks consuming an adversary-painted
            // receiver.  Same precedent as Express above.
            EntryKind::GinRoute => (true, None, false),
            // net/http `(w http.ResponseWriter, r *http.Request)` —
            // `r.FormValue` / `r.URL.Query` / `r.URL.Query.Get` /
            // `r.Header.Get` / `r.Header.Values` / `r.Body` /
            // `r.Cookie` / `r.Cookies` are classified as
            // `Source(Cap::all())` by the global Go label rules.
            // The access-path label rules carry every adversary byte
            // through to local variables.  Painting the bare `r`
            // object as `Source(Cap::all())` would re-fire excluded
            // methods like `r.Context()` and `r.WithContext(...)` as
            // structural sinks, mirroring the Express FP risk.
            EntryKind::GoNetHttp => (true, Some(1), false),
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
            // A dotted free name rooted at a seeded FastAPI body model
            // (`item.name` for `item: Item`) is a field of that formal, not a
            // free variable, so it carries the formal's taint.
            let body_model_field = matches!(entry_kind, EntryKind::FastApiRoute { .. })
                && is_body_model_field(ssa, transfer, inst.value);
            if ssa.synthetic_externals.contains(&inst.value) && !body_model_field {
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
            // Rust framework handlers (axum / actix-web / Rocket):
            // skip seeding when the formal isn't a recognised typed
            // extractor.  `param_types` is recovered at CFG
            // construction time via `rust_type_to_kind`, which only
            // matches `Query<T>` / `Json<T>` / `Form<T>` / `Path<T>`
            // / `web::*` wrappers (Hard Rule 3 — bare primitives and
            // denylist wrappers like `State<T>`, `Extension<T>`,
            // `Pool<T>`, `Db<T>` return `None`).  The downstream
            // type-fact pass propagates the recovered `TypeKind` onto
            // the SSA `Param` value, so `type_facts.get_type(value)`
            // returning `None` means "no extractor wrapper" → don't
            // paint as adversary input.  Without this gate, lifting
            // scoped lowering for Rust handlers would FP-fire every
            // database / shared-state sink that accepts a DI handle.
            if !is_self
                && matches!(
                    entry_kind,
                    EntryKind::AxumHandler | EntryKind::ActixHandler | EntryKind::RocketRoute,
                )
            {
                // Treat both missing facts and the explicit `Unknown`
                // bottom element as "no extractor wrapper".
                // `analyze_types_with_param_types` materialises
                // `Some(&TypeKind::Unknown)` for every Param whose
                // `BodyMeta.param_types` entry was None (denylist
                // wrappers like `State<T>` / `Extension<T>`, bare
                // primitives, unrecognised user types), so excluding
                // `is_some` alone would still let them through.
                let seed_extractor = transfer
                    .type_facts
                    .and_then(|tf| tf.get_type(inst.value))
                    .is_some_and(|t| !matches!(t, crate::ssa::type_facts::TypeKind::Unknown));
                if !seed_extractor {
                    continue;
                }
            }
            if !is_self
                && matches!(
                    entry_kind,
                    EntryKind::FlaskRoute { .. } | EntryKind::SinatraRoute { .. }
                )
            {
                // Python Flask handlers carry path-bound captures
                // (`@app.route("/u/<name>")` + `def view(name):`) alongside
                // implicit globals (`request`, `g`) and DI-injected
                // formals (webargs, dependency injection). Only the
                // path-bound captures qualify as adversary input.
                //
                // Ruby Sinatra handlers (`get "/u/:name" do |name| ... end`)
                // share the same per-formal model: the block formal `name`
                // is path-bound; other formals are unusual but possible
                // (`do |name, captures| ...`) and must come from a
                // recognised capture in the route pattern to seed.
                //
                // `BodyMeta.param_route_capture` is populated at CFG
                // construction time from `extract_route_path_captures`;
                // formals not in the capture set fall back to existing
                // label rules (`request.json()`, `params['x']`, ...)
                // for source attribution.
                let seed_capture = param_index
                    .and_then(|idx| {
                        transfer
                            .param_route_capture
                            .and_then(|m| m.get(idx).copied())
                    })
                    .unwrap_or(false);
                if !seed_capture {
                    continue;
                }
            }
            if !is_self && matches!(entry_kind, EntryKind::FastApiRoute { .. }) {
                // FastAPI / Starlette handlers mix four formal shapes:
                //   - path captures (`@app.get("/u/{name}")` + `name: str`)
                //   - request-bound formals (`q: str`, `q: str = Query(None)`,
                //     `q: Annotated[int, Query()]`, `item: Item` for a
                //     Pydantic model)
                //   - DI handles (`db: Session = Depends(get_db)`,
                //     `session: SessionDep`)
                //   - implicit globals (`request: Request`)
                //
                // Seed only when the formal is either a path capture
                // (`param_route_capture[idx]`) OR classified as request-bound.
                // `classify_param_type_python` populates `BodyMeta.param_types`
                // with `Some(TypeKind)` for a scalar, container or same-file
                // Pydantic annotation on a FastAPI route and for the
                // `Query()` / `Body()` / ... markers; everything else
                // (`Session`, `Request`, `Depends(..)` defaults, unknown
                // dependency aliases, unannotated) returns `None`.
                // `analyze_types_with_param_types` then materialises
                // `Some(&TypeKind::Unknown)` for `None` entries, so the gate
                // must reject both missing facts and explicit `Unknown`.
                let seed_capture = param_index
                    .and_then(|idx| {
                        transfer
                            .param_route_capture
                            .and_then(|m| m.get(idx).copied())
                    })
                    .unwrap_or(false);
                let seed_extractor = transfer
                    .type_facts
                    .and_then(|tf| tf.get_type(inst.value))
                    .is_some_and(|t| !matches!(t, crate::ssa::type_facts::TypeKind::Unknown));
                if !seed_capture && !seed_extractor && !body_model_field {
                    continue;
                }
            }
            if !is_self
                && matches!(
                    entry_kind,
                    EntryKind::SpringMapping { .. } | EntryKind::JaxRsResource
                )
                && !java_param_is_request_bound(
                    ssa,
                    inst,
                    param_index,
                    transfer.param_route_capture,
                )
            {
                // Spring and JAX-RS inject infrastructure objects next to the
                // request-bound formals: the servlet response and request,
                // `HttpSession`, `Model`, `Principal`,
                // `@AuthenticationPrincipal`, `@Context SecurityContext`, ...
                // Painting those makes a constant `resp.getWriter().write(..)`
                // or `resp.addCookie(..)` fire on the receiver alone.
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
        if let Some(env) = entry_state.path_env.as_mut() {
            if let (Some(cv), Some(tf)) = (transfer.const_values, transfer.type_facts) {
                Arc::make_mut(env).seed_from_optimization(cv, tf);
            }
        }
    }

    // Seed entry block's AbstractState from optimization results
    if let Some(ref mut entry_state) = block_states[ssa.entry.0 as usize] {
        if let Some(ref mut abs) = entry_state.abstract_state {
            if let Some(cv) = transfer.const_values {
                use crate::abstract_interp::{AbstractValue, ConstFacts};
                use crate::ssa::const_prop::ConstLattice;
                // The body's constants go into one table shared by every
                // block's state, not into each state's own entries: they are
                // fixed per body, so copying them would only crowd out the
                // facts the flow derives.
                let mut facts: Vec<(SsaValue, AbstractValue)> = Vec::new();
                for (v, cl) in cv.iter() {
                    match cl {
                        ConstLattice::Int(n) => facts.push((v, int_const_value(*n))),
                        ConstLattice::Str(s) => facts.push((v, string_const_value(s))),
                        _ => {}
                    }
                }
                if !facts.is_empty() {
                    // COW fork: an entry block with no const-prop facts keeps
                    // sharing its `initial()` Arc.
                    let abs = Arc::make_mut(abs);
                    let seeded = std::mem::replace(abs, AbstractState::empty())
                        .with_constants(Arc::new(ConstFacts::from_facts(facts)));
                    *abs = seeded;
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
            confinement,
        );

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
                            joined.abstract_state = Some(Arc::new(widened));
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

        // Store the block's exit state ONLY for callers that consult it
        // (`track_exit_states`).  This is the last use of `exit_state`, so it
        // is *moved* here rather than cloned — the store used to sit before
        // `compute_succ_states` / the exception-edge loop and paid a full
        // `SsaTaintState::clone` on every block pop; those consumers borrow
        // `exit_state`, so deferring the store past them lets it be moved.
        // `block_exit_states[bid]` is write-once and read only after the
        // worklist converges, so this reorder is output-identical.
        if track_exit_states {
            block_exit_states[bid] = Some(exit_state);
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
            confinement,
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
    let confinement = compute_confinement_gates(transfer);
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
                confinement,
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
///
/// `exporter_declared` is the sorted list of names the exporting body
/// binds itself (formals and locals, see `BodyMeta::declared_names`).
/// Such a binding is private to the exporter and can never be the
/// top-level variable of the same name, so it is not exported.  An
/// empty slice disables the check.
pub fn filter_seed_to_toplevel(
    seed: &HashMap<BindingKey, VarTaint>,
    toplevel: &HashSet<BindingKey>,
    exporter_declared: &[String],
) -> HashMap<BindingKey, VarTaint> {
    let toplevel_names: HashSet<&str> = toplevel.iter().map(|k| k.name.as_str()).collect();
    let mut out: HashMap<BindingKey, VarTaint> = HashMap::new();
    for (key, taint) in seed.iter() {
        if !toplevel_names.contains(key.name.as_str()) {
            continue;
        }
        let root = key.name.split('.').next().unwrap_or(key.name.as_str());
        if exporter_declared
            .binary_search_by(|d| d.as_str().cmp(root))
            .is_ok()
        {
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
    // Which path-confinement post-conditions can fire for this body (computed
    // once per body via `compute_confinement_gates`); skips the per-call string
    // work when no confiner summary exists.  See [`ConfinementGates`].
    confinement: ConfinementGates,
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
                        Arc::make_mut(abs).set(phi.value, joined);
                    }
                }
            }
        }
    }

    // Process body
    for inst in &block.body {
        transfer_inst(inst, cfg, ssa, transfer, &mut state);
        // Assert-guard path confinement (CVE-2021-21234): if this call is to a
        // helper whose SSA summary records `asserts_path_confined_params` (a
        // `void` guard that `Assert.isTrue(p.startsWith(base))`-throws unless
        // its path arg is contained under a fixed prefix), strip `Cap::FILE_IO`
        // from the confined arguments.  Runs *after* `transfer_inst` so the
        // clearing lands on the args' current caps, and *before* the same
        // block's later sink call (`streamContent(path, …)`) reads them.
        if confinement.assert {
            apply_call_post_confinement(inst, ssa, transfer, &mut state);
        }
        // Path-safety-validator rejection confinement (CVE-2026-53956): if this
        // call is to a path-safety-named validator whose summary records
        // `result_reject_guard_params`, strip `Cap::FILE_IO` from the rejected
        // arguments so a downstream `path.join(segment)` -> `fs::write` does not
        // fire on the `?`-guarded value.
        if confinement.path_validator {
            apply_path_validator_confinement(inst, ssa, transfer, &mut state);
        }
        // Return-value path confinement (CVE-2020-5221): if this call is to a
        // helper whose summary records `confines_path_return`, strip
        // `Cap::FILE_IO` from the call *result* so a downstream `fopen(result)`
        // does not fire.
        if confinement.return_confiner {
            apply_call_return_confinement(inst, transfer, &mut state);
        }
    }

    state
}

/// Text-only PathFact classification of a branch condition.
///
/// Split out of [`apply_path_fact_branch_narrowing_with_aliases`] so the
/// state-independent text classification (`classify_path_rejection_axes` /
/// `classify_path_assertion` / `cond_has_pre_negated_islocal_clause`, all
/// pure `&str -> _`) can be computed once per branch node and reused across
/// worklist re-visits, while the state-dependent narrowing still runs per
/// visit.
#[derive(Clone, Debug, PartialEq)]
struct PathBranchClass {
    rejection_axes: SmallVec<[crate::abstract_interp::path_domain::PathRejection; 3]>,
    assertion: crate::abstract_interp::path_domain::PathAssertion,
    rejection_pre_negated: bool,
    /// The prefix test is Python's `is_relative_to`, which compares path
    /// components, so any root is a containment proof.
    component_wise_test: bool,
    /// The receiver of the prefix test is visibly converted to a string
    /// (`p.to_str().unwrap().starts_with(..)`, `p.toString().startsWith(..)`),
    /// so the test is a byte-prefix test even in Java and Rust.
    receiver_stringified: bool,
    /// Path-view chain on the receiver of the `startsWith` guard, when the
    /// confinement binds to the chain's root variable.
    view: Option<crate::abstract_interp::path_domain::StartsWithView>,
    /// The argument the view is compared against is attacker controlled.
    /// Text-derived here (a source call in the argument); the caller adds
    /// the state-dependent case where the root variable derives from a source.
    view_root_untrusted: bool,
}

/// Conversions that turn a path object into a plain string.
const PATH_TO_STRING_CONVERSIONS: [&str; 10] = [
    ".to_str(",
    ".to_string(",
    ".to_string_lossy(",
    ".as_str(",
    ".toString(",
    ".getPath(",
    ".getAbsolutePath(",
    ".getCanonicalPath(",
    ".getName(",
    ".display(",
];

/// Decide whether a literal or resolved root really proves containment, and
/// drop the lock when it does not.
///
/// A byte-prefix test against a root without a trailing separator also admits
/// a sibling directory (`/srv/data-x` starts with `/srv/data`), so such a
/// root is not a containment proof.  Unresolvable roots stay accepted: the
/// bytes are unknown.  A component-wise test (`Path.startsWith`,
/// `Path::starts_with`, `is_relative_to`) is exact for any root.
fn root_checked_path_class<'c>(
    class: &'c PathBranchClass,
    root_unterminated: bool,
    lang: Lang,
    receiver_is_string: impl FnOnce() -> bool,
) -> std::borrow::Cow<'c, PathBranchClass> {
    use crate::abstract_interp::path_domain::{
        OPAQUE_PREFIX_LOCK, PathAssertion, root_ends_with_separator,
    };
    let (PathAssertion::PrefixLock(root) | PathAssertion::PrefixLockUnless(root)) =
        &class.assertion
    else {
        return std::borrow::Cow::Borrowed(class);
    };
    let proves_containment_if_unterminated = class.component_wise_test
        || (matches!(lang, Lang::Java | Lang::Rust)
            && !class.receiver_stringified
            && !receiver_is_string());
    let keeps_lock = if root == OPAQUE_PREFIX_LOCK {
        !root_unterminated || proves_containment_if_unterminated
    } else {
        root_ends_with_separator(root) || proves_containment_if_unterminated
    };
    if keeps_lock {
        return std::borrow::Cow::Borrowed(class);
    }
    let mut dropped = class.clone();
    dropped.assertion = PathAssertion::None;
    std::borrow::Cow::Owned(dropped)
}

/// Classify a branch condition's text against the PathFact rejection /
/// assertion idioms.  Pure function of `cond_text`.
fn classify_path_branch(cond_text: &str) -> PathBranchClass {
    use crate::abstract_interp::path_domain::{
        classify_path_assertion, classify_path_rejection_axes, classify_starts_with_receiver_view,
        cond_has_pre_negated_islocal_clause,
    };
    let assertion = classify_path_assertion(cond_text);
    let has_root_lock = !matches!(
        assertion,
        crate::abstract_interp::path_domain::PathAssertion::None
    );
    let receiver_stringified = has_root_lock && {
        let call_at = [".starts_with(", ".startsWith("]
            .iter()
            .filter_map(|m| cond_text.find(m))
            .min();
        call_at.is_some_and(|at| {
            PATH_TO_STRING_CONVERSIONS
                .iter()
                .any(|c| cond_text[..at].contains(c))
        })
    };
    let view = classify_starts_with_receiver_view(cond_text);
    let view_root_untrusted = view.as_ref().is_some_and(|v| {
        v.root_arg_callees.iter().any(|c| {
            crate::labels::classify_all("java", c, None)
                .iter()
                .any(|l| matches!(l, DataLabel::Source(_)))
        })
    });
    PathBranchClass {
        view,
        view_root_untrusted,
        rejection_axes: classify_path_rejection_axes(cond_text),
        rejection_pre_negated: cond_has_pre_negated_islocal_clause(cond_text),
        component_wise_test: has_root_lock && cond_text.contains(".is_relative_to("),
        receiver_stringified,
        assertion,
    }
}

/// Text-only classification of a branch condition, memoized per distinct
/// condition *text* in the persistent per-thread [`COND_CLASS_CACHE`].
///
/// Every field is a deterministic function of the immutable condition text
/// (the per-node `condition_negated` flag is applied by the caller), never
/// of the mutable `SsaTaintState`.  The block-level worklist re-visits a
/// branch block once per predecessor-state change (avg ~1.4×, more for
/// loop-body branches), and the same body's worklist is re-run ~5×/file
/// (summary extraction + main analysis + parent/child sink augmentation);
/// previously each first visit re-ran `classify_condition_with_target`, the
/// `has_semantic_negation` string scan, and the three PathFact text
/// classifiers on the *same* `cond_text`.  Those `str::find` / `str::contains`
/// scans (via `StrSearcher::new`) were ≈5% of static-engine self-time on
/// mm/channels/app.  Caching the result keyed on the condition text turns
/// every re-visit — within a worklist run, across the ~5 passes, and across
/// every other body/file with the same condition idiom — into an O(1)
/// `FxHashMap` hit; only the state-application steps (which read taint state /
/// SSA defs) still run per visit.
#[derive(Clone, Debug, PartialEq)]
struct BranchCondClass {
    kind: PredicateKind,
    target_var: Option<String>,
    /// Semantic negation not captured by AST-level `condition_negated`
    /// (Python `not in`, TypeCheck `!==`/`!=`, negative-polarity validator,
    /// a predicate compared against a falsy sentinel).
    has_semantic_negation: bool,
    /// For null / empty / error checks, whether the text states the negated
    /// form (`x != null`, `err == nil`); `None` when no single predicate bit
    /// describes the condition.  See
    /// [`crate::taint::path_state::predicate_bit_negative_form`].
    bit_negated: Option<bool>,
    /// Boolean / index sentinel comparison wrapping the condition's atom.
    /// Computed for the predicate kinds above and for `Comparison`, where
    /// `ok === false` on an indirect validator result needs it.
    sentinel: crate::taint::path_state::SentinelPolarity,
    /// `x == 'lit'` / `x != 5` on a bare variable: the variable and whether
    /// the operator is `==` (see
    /// [`crate::taint::path_state::equality_literal_guard`]).  Only set for
    /// [`PredicateKind::Comparison`].
    eq_guard: Option<(String, bool)>,
    /// `u.host === X` on a variable that may hold a parsed URL (see
    /// [`crate::taint::path_state::url_host_compare`]).
    host_compare: Option<crate::taint::path_state::UrlHostCompare>,
    path: PathBranchClass,
}

/// Compute the (state-independent) classification of a branch condition.
/// Result is memoized per condition node — see [`BranchCondClass`].
fn classify_branch_cond(cond_text: &str) -> BranchCondClass {
    use crate::taint::path_state::{SentinelPolarity, sentinel_comparison_polarity};

    let (mut kind, mut target_var) = classify_condition_with_target(cond_text);
    // A predicate compared against a sentinel (`ALLOWED.includes(x) ===
    // false`, `isValid(x) == False`, `A.indexOf(x) === -1`,
    // `M[x] === undefined`) is classified by its inner atom; the comparison
    // decides which edge the atom holds on.
    let predicate_kind = matches!(
        kind,
        PredicateKind::ValidationCall
            | PredicateKind::AllowlistCheck
            | PredicateKind::TypeCheck
            | PredicateKind::RelativeUrlValidated
            | PredicateKind::LeadingSlashCheck
            | PredicateKind::ProtocolRelativeCheck
            | PredicateKind::ShellMetaValidated
            | PredicateKind::RedirectValidator
            | PredicateKind::HostDenylistRejected
    );
    let sentinel = if predicate_kind || kind == PredicateKind::Comparison {
        sentinel_comparison_polarity(cond_text)
    } else {
        SentinelPolarity::NoComparison
    };
    if predicate_kind && sentinel == SentinelPolarity::Opaque {
        kind = PredicateKind::Unknown;
        target_var = None;
    }
    // `has_semantic_negation` only consults the lowercased text for the
    // AllowlistCheck / TypeCheck kinds, so compute the (allocating) lowercase
    // lazily: most conditions are neither and skip it entirely.
    let base_negation = match kind {
        PredicateKind::AllowlistCheck => cond_text.to_ascii_lowercase().contains(" not in "),
        // The `!=` scan stands in for `typeof x !== 'number'`.  When the
        // `!=` belongs to a sentinel comparison (`isinstance(x, int) !=
        // True`) the sentinel already accounts for it.
        PredicateKind::TypeCheck if sentinel == SentinelPolarity::NoComparison => {
            let lower = cond_text.to_ascii_lowercase();
            lower.contains("!==") || lower.contains("!=")
        }
        PredicateKind::ValidationCall => {
            crate::taint::path_state::is_negative_polarity_validation_callee(cond_text)
        }
        _ => false,
    };
    let bit_negated = crate::taint::path_state::predicate_bit_negative_form(kind, cond_text);
    let has_semantic_negation =
        base_negation ^ (predicate_kind && sentinel == SentinelPolarity::Flip);
    let eq_guard = if kind == PredicateKind::Comparison {
        crate::taint::path_state::equality_literal_guard(cond_text)
    } else {
        None
    };
    BranchCondClass {
        kind,
        target_var,
        has_semantic_negation,
        bit_negated,
        sentinel,
        eq_guard,
        host_compare: crate::taint::path_state::url_host_compare(cond_text),
        path: classify_path_branch(cond_text),
    }
}

/// Escape hatch: `NYX_DISABLE_COND_MEMO=1` forces every branch-condition
/// classification to recompute instead of consulting [`COND_CLASS_CACHE`].
/// Used to A/B the cached vs re-classifying path from a single binary
/// (criterion baseline, differential-correctness check) and as a safety
/// toggle.  Cached so the env read is paid once per process.  The two paths
/// are bit-identical — the cache only stores a pure function's result — so
/// this changes only performance.
fn cond_class_memo_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var("NYX_DISABLE_COND_MEMO")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    })
}

thread_local! {
    /// Persistent per-thread cache of the text-only branch-condition
    /// classification ([`BranchCondClass`]), keyed by the condition *text* —
    /// the sole input to [`classify_branch_cond`].
    ///
    /// Keyed on text, **not** on the CFG condition node index: the `Cfg` is
    /// per-body (`taint/mod.rs` binds `let cfg = &body.graph`), so node
    /// indices collide across the file's functions and a node-index key would
    /// return one function's classification for another's condition.  The
    /// condition *text* is the collision-free invariant and is identical
    /// across every worklist re-visit, every pass, every function, and every
    /// file that contains the same condition idiom (`if err != nil`,
    /// `if (x == null)`, …), so the cache captures all of that reuse.
    ///
    /// session-0015 used a worklist-local `FxHashMap<u32, BranchCondClass>`
    /// (rebuilt empty per `run_ssa_taint_internal` call), which only caught
    /// re-visits within one worklist run; the first visit of every branch in
    /// every one of the ~5 passes/file still re-ran the string scans.  This
    /// per-thread cache classifies each distinct condition text once for the
    /// whole scan.  Lives across files via the rayon worker thread (each file
    /// is processed start-to-finish on one worker); correctness is independent
    /// of cache state because the stored value is a pure function of the key.
    static COND_CLASS_CACHE: RefCell<rustc_hash::FxHashMap<String, BranchCondClass>> =
        RefCell::new(rustc_hash::FxHashMap::default());
}

/// Soft cap on [`COND_CLASS_CACHE`].  Distinct branch-condition texts are
/// bounded in practice (a handful of idioms dominate), but an XL repo could
/// accumulate many across a worker's lifetime; clearing the map when it
/// exceeds the cap bounds per-thread memory to ~`CAP` entries.  Safe: the
/// value is a pure function of the text, so a post-clear miss only forfeits a
/// future hit, never correctness.
const COND_CLASS_CACHE_CAP: usize = 1 << 16;

/// Fetch-or-compute the text-only [`BranchCondClass`] for `cond_text` via the
/// persistent per-thread [`COND_CLASS_CACHE`].  Returns an owned value (a cheap
/// clone on a hit — a small enum + one optional short `String` + an inline
/// `SmallVec`, vs the multi-`StrSearcher` recompute it replaces) so the caller
/// holds no borrow into the cache.
fn classify_branch_cond_cached(cond_text: &str) -> BranchCondClass {
    if cond_class_memo_disabled() {
        return classify_branch_cond(cond_text);
    }
    COND_CLASS_CACHE.with(|cell| {
        {
            let map = cell.borrow();
            if let Some(hit) = map.get(cond_text) {
                return hit.clone();
            }
        }
        let computed = classify_branch_cond(cond_text);
        let mut map = cell.borrow_mut();
        if map.len() >= COND_CLASS_CACHE_CAP {
            map.clear();
        }
        map.insert(cond_text.to_string(), computed.clone());
        computed
    })
}

/// Compute per-successor states with branch-aware predicate handling.
///
/// For `Branch` terminators, inspects the condition node for validation/predicate
/// info and produces specialized true/false states. For other terminators,
/// propagates the exit state uniformly.
///
/// Branch-condition classification is cached in the persistent per-thread
/// [`COND_CLASS_CACHE`] (see [`classify_branch_cond_cached`]) so the
/// per-condition string scans run once per distinct condition text for the
/// whole scan, not once per worklist re-visit / pass / body.
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
            if cond_info.condition_text.is_some() && !cond_info.condition_vars.is_empty() {
                let cond_text = cond_info.condition_text.as_deref().unwrap_or("");
                // Fetch-or-compute the text-only classification for this
                // condition.  Cached per distinct condition text in the
                // persistent per-thread `COND_CLASS_CACHE`, so the
                // `classify_condition_with_target` + `has_semantic_negation` +
                // PathFact-classifier string scans run once per condition idiom
                // for the whole scan rather than once per worklist re-visit /
                // pass / body.
                let class = classify_branch_cond_cached(cond_text);
                let kind = class.kind;

                // Determine which vars to apply validation to:
                // If we extracted a specific target, narrow to just that var
                // (if it's in condition_vars). Otherwise use all condition_vars.
                let effective_vars: Vec<String> = if let Some(ref target) = class.target_var {
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

                // Semantic negation not captured by AST-level
                // `condition_negated` (Python `not in`, TypeCheck `!==`/`!=`,
                // negative-polarity validator like `isInvalidUrl(x)`).  The
                // text scan that derives this is memoized in `class` (see
                // [`classify_branch_cond`]); only the per-node
                // `condition_negated` combination happens here.
                let effective_negated = if class.has_semantic_negation {
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
                    class.bit_negated,
                    transfer.interner,
                    ssa,
                    transfer.base_aliases,
                );
                // Apply validation/predicate to false branch
                apply_branch_predicates(
                    &mut false_state,
                    &effective_vars,
                    kind,
                    false_polarity,
                    class.bit_negated,
                    transfer.interner,
                    ssa,
                    transfer.base_aliases,
                );

                // `dir === 'asc'`: on the equal edge `dir` holds the literal.
                // A `dir === 'asc' || dir === 'desc'` chain is split into one
                // branch per clause, so the validated_must intersection at
                // the join gives exactly the allowlist semantics.
                if let Some((target, op_is_eq)) = &class.eq_guard {
                    apply_equality_literal_narrowing(
                        &mut true_state,
                        &mut false_state,
                        target,
                        *op_is_eq,
                        cond_info,
                        transfer.interner,
                    );
                }

                if let Some(hc) = &class.host_compare {
                    apply_url_host_compare_narrowing(
                        &mut true_state,
                        &mut false_state,
                        exit_state,
                        hc,
                        cond_info,
                        ssa,
                        cfg,
                        block.id,
                        transfer,
                    );
                }

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
                let mut path_class = root_checked_path_class(
                    &class.path,
                    cond_info.root_unterminated,
                    transfer.lang,
                    || {
                        // A receiver the type analysis knows is a `String`
                        // is tested byte-wise, not component-wise.
                        // Only a lone condition variable is known to be the
                        // receiver.
                        effective_vars
                            .first()
                            .filter(|_| effective_vars.len() == 1)
                            .is_some_and(|var| {
                                reaching_def_at_block_end(var, ssa, block.id).is_some_and(|v| {
                                    transfer.type_facts.is_some_and(|tf| {
                                        tf.is_type(v, &crate::ssa::type_facts::TypeKind::String)
                                    })
                                })
                            })
                    },
                );
                if path_class.view.is_some()
                    && !path_class.view_root_untrusted
                    && path_view_root_from_source(
                        &class.path,
                        &effective_vars,
                        ssa,
                        block.id,
                        cfg,
                        exit_state,
                    )
                {
                    path_class.to_mut().view_root_untrusted = true;
                }
                apply_path_fact_branch_narrowing_with_aliases(
                    &mut true_state,
                    &mut false_state,
                    &path_class,
                    &effective_vars,
                    ssa,
                    block.id,
                    transfer.base_aliases,
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
                        cond_info.condition_negated,
                        ssa,
                        block.id,
                        transfer.interner,
                        transfer.lang,
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
                //
                // `ok === false` / `ok == True` classify as Comparison; the
                // boolean sentinel says which edge holds the truthy result.
                let bool_sentinel = kind == PredicateKind::Comparison
                    && matches!(
                        class.sentinel,
                        crate::taint::path_state::SentinelPolarity::Flip
                            | crate::taint::path_state::SentinelPolarity::Same
                    );
                if bool_sentinel {
                    apply_input_validator_branch_narrowing(
                        &mut true_state,
                        &mut false_state,
                        cond_text,
                        &cond_info.condition_vars,
                        cond_info.condition_negated
                            ^ (class.sentinel == crate::taint::path_state::SentinelPolarity::Flip),
                        ssa,
                        block.id,
                        transfer.interner,
                    );
                }
                // Go comma-ok allowlist: `_, ok := allowed[cmd]; if !ok`.
                if matches!(kind, PredicateKind::Unknown | PredicateKind::NullCheck) {
                    apply_membership_result_narrowing(
                        &mut true_state,
                        &mut false_state,
                        exit_state,
                        cond_info,
                        condition.as_deref(),
                        ssa,
                        cfg,
                        block.id,
                        transfer.interner,
                    );
                }
                if matches!(
                    kind,
                    PredicateKind::Unknown | PredicateKind::NullCheck | PredicateKind::ErrorCheck
                ) {
                    apply_input_validator_branch_narrowing(
                        &mut true_state,
                        &mut false_state,
                        cond_text,
                        &cond_info.condition_vars,
                        cond_info.condition_negated,
                        ssa,
                        block.id,
                        transfer.interner,
                    );

                    // Behaviour-based path-confinement narrowing.  Recognises
                    // a gate on a helper whose SSA summary records a
                    // constant-prefix path-confinement predicate
                    // (`if (!isOptimizedDepFile(p)) return next()`), and
                    // strips `Cap::FILE_IO` from the confined argument on the
                    // surviving branch.  Lifts the inline
                    // `x.startsWith("/safe/")` narrowing through a wrapper
                    // helper recognised by behaviour (not name).
                    // Motivated by CVE-2026-39365 (Vite sourcemap traversal).
                    apply_summary_confinement_narrowing(
                        &mut true_state,
                        &mut false_state,
                        cond_text,
                        &cond_info.condition_vars,
                        cond_info.condition_negated,
                        ssa,
                        block.id,
                        transfer,
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
                        if let Some(env) = true_state.path_env.as_mut() {
                            // Full replacement: read the (possibly shared) env,
                            // build the refined copy, swap the Arc pointer. This
                            // is cheaper than `make_mut` (which would clone the
                            // shared inner only to immediately overwrite it).
                            let refined = constraint::refine_env(env, &cond_expr, true);
                            let unsat = refined.is_unsat();
                            *env = Arc::new(refined);
                            if unsat {
                                tracing::debug!(
                                    block = ?block.id,
                                    cond = cond_text,
                                    "constraint: pruned true branch (unsat)"
                                );
                            }
                        }
                        if let Some(env) = false_state.path_env.as_mut() {
                            let refined = constraint::refine_env(env, &cond_expr, false);
                            let unsat = refined.is_unsat();
                            *env = Arc::new(refined);
                            if unsat {
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
///
/// `bit_negated` says whether a null / empty / error check is written in its
/// negated form, so the recorded bit states the same fact (value is null,
/// error present, collection empty) whichever operator the code used.
/// `None` records no bit.
fn apply_branch_predicates(
    state: &mut SsaTaintState,
    condition_vars: &[String],
    kind: PredicateKind,
    polarity: bool,
    bit_negated: Option<bool>,
    interner: &SymbolInterner,
    ssa: &SsaBody,
    base_aliases: Option<&crate::ssa::alias::BaseAliasResult>,
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
    // (`x.startsWith("/") && !x.startsWith("//")` held → `x` cannot
    // redirect off-host).  Cap-aware: clear `Cap::OPEN_REDIRECT` only;
    // non-redirect sinks (XSS / SQLi / FILE_IO) downstream still fire on
    // residual taint.  The split form is handled after the predicate bits
    // below.
    if kind == PredicateKind::RelativeUrlValidated && polarity {
        for var in condition_vars {
            clear_cap_alias_aware(state, var, Cap::OPEN_REDIRECT, ssa, base_aliases);
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
            clear_cap_alias_aware(state, var, Cap::OPEN_REDIRECT, ssa, base_aliases);
        }
    }

    // RedirectValidator: TRUE branch is the validated path.  Clears
    // `Cap::OPEN_REDIRECT` only, like the URL arms above.
    if kind == PredicateKind::RedirectValidator && polarity {
        for var in condition_vars {
            clear_cap_alias_aware(state, var, Cap::OPEN_REDIRECT, ssa, base_aliases);
        }
    }

    // HostDenylistRejected: inverted polarity.  The TRUE branch is the reject
    // path (the host is internal), so the FALSE branch is the one that
    // continues.  Clears `Cap::SSRF` only; a denylist says nothing about SQL,
    // shell or file sinks.
    if kind == PredicateKind::HostDenylistRejected && !polarity {
        for var in condition_vars {
            clear_cap_alias_aware(state, var, Cap::SSRF, ssa, base_aliases);
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
            clear_cap_alias_aware(state, var, Cap::SHELL_ESCAPE, ssa, base_aliases);
        }
    }

    // PathPrefixConfined: inverted polarity, the FALSE (starts-with-prefix)
    // branch is the confined path; the TRUE (non-zero strncmp) branch is the
    // rejection path.  Cap-aware: a `strncmp(x, prefix, strlen(prefix))` guard
    // only proves `x` is confined to the fixed directory prefix, so clear
    // `Cap::FILE_IO` from the confined variable's taint and let other sink
    // classes still fire on the residual caps.  `condition_vars` is already
    // scoped to the strncmp subject via `classify_condition_with_target`.
    if kind == PredicateKind::PathPrefixConfined && !polarity {
        for var in condition_vars {
            clear_cap_alias_aware(state, var, Cap::FILE_IO, ssa, base_aliases);
        }
    }

    // Whitelisted predicate kinds: update PredicateSummary bits
    if let (Some(bit_idx), Some(negated)) = (predicate_kind_bit(kind), bit_negated) {
        let fact_holds = polarity != negated;
        for var in condition_vars {
            if let Some(sym) = interner.get(var) {
                let mut summary = state
                    .predicates
                    .binary_search_by_key(&sym, |(id, _)| *id)
                    .ok()
                    .map(|idx| state.predicates[idx].1)
                    .unwrap_or_else(PredicateSummary::empty);
                if fact_holds {
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

    // Split relative-URL check: `if (!x.startsWith('/') || x.startsWith('//'))
    // return;` (or the `&&` form) is two branches.  Clear OPEN_REDIRECT once
    // this path has seen both "starts with /" and "does not start with //";
    // either fact alone leaves `//evil.com` possible.
    if matches!(
        kind,
        PredicateKind::LeadingSlashCheck | PredicateKind::ProtocolRelativeCheck
    ) {
        use crate::taint::domain::{PRED_BIT_LEADING_SLASH, PRED_BIT_PROTOCOL_RELATIVE};
        for var in condition_vars {
            let Some(sym) = interner.get(var) else {
                continue;
            };
            let Ok(idx) = state.predicates.binary_search_by_key(&sym, |(id, _)| *id) else {
                continue;
            };
            let p = state.predicates[idx].1;
            if p.known_true & (1 << PRED_BIT_LEADING_SLASH) != 0
                && p.known_false & (1 << PRED_BIT_PROTOCOL_RELATIVE) != 0
            {
                clear_cap_alias_aware(state, var, Cap::OPEN_REDIRECT, ssa, base_aliases);
            }
        }
    }
}

/// Branch on the presence result of a map lookup (`_, ok := allowed[cmd];
/// if !ok { return }`): on the edge where `ok` holds, the key is in the map,
/// which is the same allowlist fact the inline `if !allowed[cmd]` gives.
/// The value binding of `v, ok := allowed[cmd]` is validated too, since it
/// was read out of that map.
///
/// The `ok` definition is the one reaching the branch (the pre-lowered
/// `BoolTest` operand when present), and it must be a CFG node stamped with
/// [`crate::cfg::MembershipLookup`].  A map that carries taint itself
/// (`q := r.URL.Query(); _, ok := q[k]`) is a presence check on request
/// data, not an allowlist, and narrows nothing.
#[allow(clippy::too_many_arguments)]
fn apply_membership_result_narrowing(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    exit_state: &SsaTaintState,
    cond_info: &NodeInfo,
    condition: Option<&constraint::ConditionExpr>,
    ssa: &SsaBody,
    cfg: &Cfg,
    block: BlockId,
    interner: &SymbolInterner,
) {
    let [result_name] = cond_info.condition_vars.as_slice() else {
        return;
    };
    let result_val = match condition {
        Some(constraint::ConditionExpr::BoolTest { var, .. }) => Some(*var),
        _ => reaching_def_at_block_end(result_name, ssa, block),
    };
    let Some(def) = result_val.and_then(|v| ssa.value_defs.get(v.0 as usize)) else {
        return;
    };
    if def.var_name.as_deref() != Some(result_name.as_str()) {
        return;
    }
    let Some(lookup) = cfg
        .node_weight(def.cfg_node)
        .and_then(|n| n.membership_lookup.as_ref())
    else {
        return;
    };
    if lookup.result_var != *result_name {
        return;
    }
    if reaching_def_at_block_end(&lookup.base, ssa, block)
        .is_some_and(|b| exit_state.get(b).is_some())
    {
        return;
    }
    // A map that took request-controlled keys holds whatever the request
    // asked for, so being in it proves nothing.  The map value stays clean
    // when keys are stored (the store reads no operand), so look at the
    // stores themselves.
    if lookup.filled_elsewhere
        || map_has_tainted_key_store(lookup, def.cfg_node, exit_state, ssa, cfg)
    {
        return;
    }
    let present = if cond_info.condition_negated {
        false_state
    } else {
        true_state
    };
    for name in std::iter::once(&lookup.key).chain(lookup.value_var.as_ref()) {
        if let Some(sym) = interner.get(name) {
            present.validated_must.insert(sym);
            present.validated_may.insert(sym);
        }
    }
}

/// Whether some statement in the lookup's function stores a tainted key into
/// the looked-up map.  Key identifiers with no definition in the function
/// (constants, package-level names) are not request data.  Stores made by
/// other functions are covered by [`crate::cfg::MembershipLookup::filled_elsewhere`].
fn map_has_tainted_key_store(
    lookup: &crate::cfg::MembershipLookup,
    lookup_node: NodeIndex,
    exit_state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> bool {
    let func = cfg
        .node_weight(lookup_node)
        .and_then(|n| n.ast.enclosing_func.as_deref());
    cfg.node_indices().any(|idx| {
        let n = &cfg[idx];
        if n.map_stores.is_empty()
            || n.ast.enclosing_func.as_deref() != func
            || ssa.cfg_node_map.get(&idx).is_none()
        {
            return false;
        }
        // Any definition of the key name counts: the store statement can
        // itself be lowered as a redefinition of its key (`m[k] = v` binds
        // both names in Go), so the reaching definition is not the right
        // probe.
        n.map_stores
            .iter()
            .filter(|ms| ms.base == lookup.base)
            .flat_map(|ms| ms.key_idents.iter())
            .any(|key| {
                ssa.value_defs.iter().enumerate().any(|(i, d)| {
                    d.var_name.as_deref() == Some(key.as_str())
                        && exit_state.get(SsaValue(i as u32)).is_some()
                })
            })
    })
}

/// Mark `target` validated on the edge where `target == <literal>` holds.
///
/// `target` must be one of the condition's own variables; there is no
/// all-vars fallback, so a comparison on something else (`x.length === 5`)
/// validates nothing.  `condition_negated` covers `!(x === 'a')` forms the
/// CFG has already unwrapped.
fn apply_equality_literal_narrowing(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    target: &str,
    op_is_eq: bool,
    cond_info: &NodeInfo,
    interner: &SymbolInterner,
) {
    if !cond_info.condition_vars.iter().any(|v| v == target) {
        return;
    }
    let Some(sym) = interner.get(target) else {
        return;
    };
    let equal_on_true = op_is_eq != cond_info.condition_negated;
    let st = if equal_on_true {
        true_state
    } else {
        false_state
    };
    st.validated_must.insert(sym);
    st.validated_may.insert(sym);
}

/// Clear `cap` from the taint of `var` and every SSA value that aliases it
/// on a validated branch.
///
/// "Aliases" covers three sources, matching the (formerly inline)
/// `ShellMetaValidated` handler:
///
/// 1. SSA values whose `var_name` equals `var`.
/// 2. Base aliases of `var` from copy propagation
///    (`base_aliases.aliases_of(var)`), so a value renamed away by
///    `copy_propagate` (`const t = url;`) is still reached when the
///    condition or sink references the other name.
/// 3. Transitive copy-chain operands (`collect_copy_alias_operands`) for
///    Assign/Phi copies the optimizer did not propagate away.
///
/// The two URL arms (`RelativeUrlValidated` / `HostAllowlistValidated`)
/// previously matched only source 1 against `state.values`, missing the
/// `const t = url; if (t.startsWith("/")) { res.redirect(url) }` alias shape
/// the shell arm handled, so they fired false positives on the validated
/// branch.  Sharing this helper unifies all three.
fn clear_cap_alias_aware(
    state: &mut SsaTaintState,
    var: &str,
    cap: Cap,
    ssa: &SsaBody,
    base_aliases: Option<&crate::ssa::alias::BaseAliasResult>,
) {
    let mut to_clear: SmallVec<[SsaValue; 4]> = SmallVec::new();
    let mut names: SmallVec<[&str; 4]> = smallvec::smallvec![var];
    if let Some(aliases) = base_aliases.and_then(|aliases| aliases.aliases_of(var)) {
        for alias in aliases {
            if alias.as_str() != var {
                names.push(alias.as_str());
            }
        }
    }
    for &name_to_clear in names.iter() {
        for (idx, def) in ssa.value_defs.iter().enumerate() {
            if def.var_name.as_deref() == Some(name_to_clear) {
                let val = SsaValue(idx as u32);
                to_clear.push(val);
                collect_copy_alias_operands(val, ssa, &mut to_clear);
            }
        }
    }
    to_clear.sort_by_key(|v| v.0);
    to_clear.dedup_by_key(|v| v.0);
    for val in to_clear {
        if let Some(taint) = state.get(val).cloned() {
            let new_caps = taint.caps & !cap;
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

fn collect_copy_alias_operands(root: SsaValue, ssa: &SsaBody, out: &mut SmallVec<[SsaValue; 4]>) {
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur) {
            continue;
        }
        let Some(def_inst) = find_inst_for_value(cur, ssa) else {
            continue;
        };
        match &def_inst.op {
            SsaOp::Assign(uses) if uses.len() == 1 => {
                let alias = uses[0];
                out.push(alias);
                stack.push(alias);
            }
            SsaOp::Phi(operands) => {
                for &(_, alias) in operands {
                    out.push(alias);
                    stack.push(alias);
                }
            }
            _ => {}
        }
    }
}

/// Decide whether the "null / none / no-error" outcome is the condition's
/// TRUE branch from the lowered condition text.
///
/// This must distinguish equality (`err == null` → null branch is TRUE)
/// from strict/loose inequality (`err !== null` / `err != null` → null
/// branch is the FALSE branch).  A naive `contains("== null")` is wrong
/// because `"err !== null"` contains `"== null"` as a substring (the `==`
/// of `!==` followed by ` null`), which would mark validation on the wrong
/// branch.  We therefore reject any inequality form first.
fn null_check_true_branch_is_success(lower: &str) -> bool {
    // Inequality forms put the null/none outcome on the FALSE branch.
    // Strip them before testing equality so the `==` inside `!==`/`!=`
    // cannot be mistaken for an equality comparison.
    if lower.contains("!= nil")
        || lower.contains("!= none")
        || lower.contains("is not none")
        || lower.contains("is_err")
        || lower.contains("!== null")
        || lower.contains("!= null")
    {
        return false;
    }
    lower.contains("== nil")
        || lower.contains("== none")
        || lower.contains("is none")
        || lower.contains("is_ok")
        || lower.contains("=== null")
        || lower.contains("== null")
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
/// and swapped when `condition_negated` reports a leading `!` / `not`
/// (`!r.is_ok()`).
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
    condition_negated: bool,
    ssa: &SsaBody,
    block: BlockId,
    interner: &SymbolInterner,
    lang: Lang,
) {
    if condition_vars.is_empty() {
        return;
    }
    // Determine which branch corresponds to "err is null / Ok / no error".
    // Defaults to FALSE for `err != nil`-style; flips to TRUE for
    // `err == nil`-style and `is_ok()`.  The text test reads the condition
    // under any leading `!` / `not`, which the CFG strips into
    // `condition_negated` without changing which edge is TRUE, so a
    // negated condition (`!(err == nil)`, `!r.is_ok()`) swaps the edge.
    let lower = cond_text.to_ascii_lowercase();
    let success_branch_is_true = null_check_true_branch_is_success(&lower) ^ condition_negated;

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
    if !crate::ssa::type_facts::is_int_producing_callee(Some(lang), callee) {
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
/// // → p is validated on the FALSE edge of `!ok` (ok truthy)
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
/// the *true* branch carries the validation).  `condition_negated` (a
/// leading `!` / `not`, or an `ok === false` sentinel folded in by the
/// caller) swaps the result once more.
///
/// Strict-additive: when no condition var matches, the def isn't a
/// Call, the callee isn't a recognised validator, or no arg has an
/// SSA-level var_name, the function is a no-op.
fn apply_input_validator_branch_narrowing(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    cond_text: &str,
    condition_vars: &[String],
    condition_negated: bool,
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
    let cond_text_says_null_branch_is_true = null_check_true_branch_is_success(&lower);

    let success_branch_is_true = match polarity {
        InputValidatorPolarity::ErrorReturning => cond_text_says_null_branch_is_true,
        InputValidatorPolarity::BooleanTrueIsValid => !cond_text_says_null_branch_is_true,
    };
    // The text heuristic describes the condition under any leading `!` /
    // `not`; `if (!ok) throw` holds `ok` truthy on the FALSE edge.
    let success_branch_is_true = success_branch_is_true ^ condition_negated;

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

/// Same-host guard on a parsed URL: `const u = new URL(x, base); if (u.host
/// === Y) { sink(x) }`.
///
/// On the edge where the hosts are equal, the parsed URL resolves to the host
/// `Y`, so neither `u` nor the string `x` it was parsed from can steer a
/// request or a redirect to another host.  Clears `Cap::OPEN_REDIRECT` and
/// `Cap::SSRF` from both there; every other capability keeps its taint.
///
/// The guard only counts when
/// * the subject's reaching definition is a call to the `URL` constructor
///   (a bare `.host` field comparison proves nothing), and
/// * the compared operand `Y` cannot be attacker data: no tainted variable
///   in it and no source-labelled member path (`req.query.host`).
///
/// The narrowing is skipped when either condition is unproven.
fn apply_url_host_compare_narrowing(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    exit_state: &SsaTaintState,
    hc: &crate::taint::path_state::UrlHostCompare,
    cond_info: &NodeInfo,
    ssa: &SsaBody,
    cfg: &Cfg,
    block: BlockId,
    transfer: &SsaTaintTransfer,
) {
    const CAPS: Cap = Cap::OPEN_REDIRECT.union(Cap::SSRF);
    let Some(subject_val) = reaching_def_at_block_end(&hc.subject, ssa, block) else {
        return;
    };
    let Some(def_inst) = find_inst_for_value(subject_val, ssa) else {
        return;
    };
    let SsaOp::Call { callee, args, .. } = &def_inst.op else {
        return;
    };
    if !matches!(
        callee.as_str(),
        "URL" | "new URL" | "window.URL" | "globalThis.URL" | "self.URL" | "URL.parse"
    ) {
        return;
    }

    // The other operand must not be attacker-controlled.
    let lang = transfer.lang.as_str();
    for word in hc
        .rhs
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.')))
        .filter(|w| !w.is_empty())
    {
        let mut candidate = word;
        loop {
            if matches!(
                crate::labels::classify(lang, candidate, transfer.extra_labels),
                Some(DataLabel::Source(_))
            ) {
                return;
            }
            match candidate.rsplit_once('.') {
                Some((prefix, _)) => candidate = prefix,
                None => break,
            }
        }
        let root = word.split('.').next().unwrap_or(word);
        if let Some(v) = reaching_def_at_block_end(root, ssa, block)
            && exit_state.get(v).is_some_and(|t| !t.caps.is_empty())
        {
            return;
        }
    }

    // Edge on which the comparison held.
    let eq_on_true = hc.is_eq != cond_info.condition_negated;
    let state = if eq_on_true { true_state } else { false_state };

    let mut targets: SmallVec<[SsaValue; 4]> = smallvec::smallvec![subject_val];
    // The string the URL was parsed from is pinned only when it is passed as
    // a bare name: `new URL('./' + basename(x), base)` says nothing about x.
    if let Some(parsed) = bare_name_arg(&cfg[def_inst.cfg_node], callee, args, 0) {
        targets.push(parsed);
    }
    if !host_pinned_uses_are_forwarding(&targets, def_inst.value, ssa, cfg, CAPS) {
        return;
    }
    for val in targets {
        if let Some(name) = ssa
            .value_defs
            .get(val.0 as usize)
            .and_then(|vd| vd.var_name.as_deref())
        {
            clear_cap_alias_aware(state, name, CAPS, ssa, transfer.base_aliases);
        }
        if let Some(taint) = state.get(val).cloned() {
            let caps = taint.caps & !CAPS;
            if caps.is_empty() {
                state.remove(val);
            } else {
                state.set(val, VarTaint { caps, ..taint });
            }
        }
    }
}

/// Whether `seed`, or any value computed from it, is an argument or receiver
/// of a call labelled as a sink for `caps`.
fn value_reaches_sink(seed: SsaValue, ssa: &SsaBody, cfg: &Cfg, caps: Cap) -> bool {
    let mut derived: HashSet<SsaValue> = HashSet::new();
    derived.insert(seed);
    let mut changed = true;
    while changed {
        changed = false;
        for b in &ssa.blocks {
            for inst in b.phis.iter().chain(b.body.iter()) {
                if derived.contains(&inst.value)
                    || !inst.uses_iter().iter().any(|v| derived.contains(v))
                {
                    continue;
                }
                if matches!(inst.op, SsaOp::Call { .. })
                    && cfg[inst.cfg_node]
                        .taint
                        .labels
                        .iter()
                        .any(|l| matches!(l, DataLabel::Sink(c) if c.intersects(caps)))
                {
                    return true;
                }
                derived.insert(inst.value);
                changed = true;
            }
        }
    }
    false
}

/// Whether every later use of the host-checked values only forwards them
/// unchanged to a request or redirect.
///
/// The host check pins the string that was parsed, not strings built from it:
/// `raw + '@evil.com'` after `new URL(raw)` passed the check can name another
/// host.  Because the narrowing clears taint on the checked values, any value
/// derived from them afterwards would inherit the cleared state.  So the
/// narrowing holds only when each use of a checked value (or of another SSA
/// value of the same variable) is one of
/// * the `URL` constructor call that parsed it,
/// * a phi (it only selects an operand),
/// * a property read of the parsed URL itself (`u.href`), or
/// * a call argument spelled as the checked variable's own name (never the
///   receiver) of a call that is a redirect/SSRF sink, or whose result
///   nothing consumes.
///   Concatenation, templates, method calls on the value and helper calls whose
///   result is used keep the taint.
fn host_pinned_uses_are_forwarding(
    targets: &[SsaValue],
    url_value: SsaValue,
    ssa: &SsaBody,
    cfg: &Cfg,
    caps: Cap,
) -> bool {
    let mut names: SmallVec<[&str; 4]> = SmallVec::new();
    for t in targets {
        if let Some(n) = ssa
            .value_defs
            .get(t.0 as usize)
            .and_then(|d| d.var_name.as_deref())
            && !names.contains(&n)
        {
            names.push(n);
        }
    }
    let is_checked = |v: SsaValue| {
        targets.contains(&v)
            || ssa
                .value_defs
                .get(v.0 as usize)
                .and_then(|d| d.var_name.as_deref())
                .is_some_and(|n| names.contains(&n))
    };
    let result_consumed = |res: SsaValue| {
        ssa.blocks.iter().any(|b| {
            b.phis
                .iter()
                .chain(b.body.iter())
                .any(|i| i.uses_iter().contains(&res))
        })
    };
    for b in &ssa.blocks {
        for inst in b.phis.iter().chain(b.body.iter()) {
            if inst.value == url_value || !inst.uses_iter().iter().any(|v| is_checked(*v)) {
                continue;
            }
            match &inst.op {
                // A phi only selects one of its operands.
                SsaOp::Phi(_) => {}
                // A property of the parsed URL (`u.href`) stays on its host.
                SsaOp::FieldProj { receiver, .. } if *receiver == url_value => {}
                SsaOp::Call {
                    callee,
                    args,
                    receiver,
                    ..
                } => {
                    if *receiver == Some(url_value) {
                        // A method on the parsed URL (`u.searchParams.get(k)`)
                        // yields data read from it; that data must not end up
                        // as a redirect or request target.
                        if value_reaches_sink(inst.value, ssa, cfg, caps) {
                            return false;
                        }
                        continue;
                    }
                    if receiver.is_some_and(&is_checked) {
                        return false;
                    }
                    let info = &cfg[inst.cfg_node];
                    // Each checked value must be passed as a bare name that is
                    // the checked variable itself.  A copy-propagated
                    // `const x = raw + '@evil.com'` shows up as the value of
                    // `raw` but is spelled `x` at the call.
                    for (i, group) in args.iter().enumerate() {
                        if !group.iter().any(|v| is_checked(*v)) {
                            continue;
                        }
                        let is_bare = i < 64
                            && info.call.arg_bare_names & (1u64 << i) != 0
                            && node_describes_call(info, callee);
                        let spelled_checked = info.call.arg_uses.get(i).is_some_and(|u| {
                            u.first().is_some_and(|first| {
                                names.contains(&first.split('.').next().unwrap_or(first))
                            })
                        });
                        if !is_bare || !spelled_checked {
                            return false;
                        }
                    }
                    let is_sink = info
                        .taint
                        .labels
                        .iter()
                        .any(|l| matches!(l, DataLabel::Sink(c) if c.intersects(caps)));
                    if !is_sink
                        && (info.kind == crate::cfg::StmtKind::Return
                            || result_consumed(inst.value))
                    {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    }
    true
}

/// Look up the path-confinement positions of a callee by bare name in the
/// intra-file SSA summary map.
///
/// Returns the callee's [`SsaFuncSummary::confines_path_params`] when a
/// same-language summary whose `FuncKey.name` matches `bare_name` records at
/// least one confined parameter.  Intra-file only: confinement helpers
/// (`isSafePath`, `isOptimizedDepFile`) overwhelmingly live in the same
/// module as their caller, so the per-file `ssa_summaries` map carries them.
/// A cross-file extension would index `GlobalSummaries` by `(lang, name)`.
fn summary_confined_positions<'b>(
    transfer: &'b SsaTaintTransfer,
    bare_name: &str,
) -> Option<&'b [usize]> {
    let map = transfer.ssa_summaries?;
    for (key, sum) in map.iter() {
        if key.lang == transfer.lang
            && key.name == bare_name
            && !sum.confines_path_params.is_empty()
        {
            return Some(sum.confines_path_params.as_slice());
        }
    }
    None
}

/// Confined argument positions for an *assert-guard* path-confinement helper.
///
/// Mirrors [`summary_confined_positions`] but reads
/// [`crate::summary::ssa_summary::SsaFuncSummary::asserts_path_confined_params`]:
/// the callee is a `void` guard (`Assert.isTrue(p.startsWith(base))`) whose
/// *normal completion* proves the argument at each returned position is
/// contained under a fixed prefix.  Intra-file only — a path-check helper lives
/// in the same class as the handler it guards.  Motivated by CVE-2021-21234.
fn summary_asserts_confined_positions<'b>(
    transfer: &'b SsaTaintTransfer,
    bare_name: &str,
) -> Option<&'b [usize]> {
    let map = transfer.ssa_summaries?;
    for (key, sum) in map.iter() {
        if key.lang == transfer.lang
            && key.name == bare_name
            && !sum.asserts_path_confined_params.is_empty()
        {
            return Some(sum.asserts_path_confined_params.as_slice());
        }
    }
    None
}

/// Which of the three per-call *path-confinement* post-conditions can possibly
/// fire for the body under analysis.
///
/// Each of [`apply_call_post_confinement`] (assert-guard, CVE-2021-21234),
/// [`apply_path_validator_confinement`] (`?`-rejection guard, CVE-2026-53956),
/// and [`apply_call_return_confinement`] (`strncmp`-return confiner,
/// CVE-2020-5221) is a *no-op* unless the file's SSA summary map contains a
/// summary that records the corresponding flag: only a callee whose summary was
/// proved a confiner can strip `Cap::FILE_IO`.  But each pass was invoked
/// unconditionally on **every** `Call` instruction in both the dataflow
/// (`transfer_block`) and event (`collect_block_events`) replays, ~5 passes per
/// body — and `apply_path_validator_confinement` in particular runs the
/// `is_path_safety_validator_name` grammar (a `to_snake_lower` allocation plus
/// ~20 substring `contains` scans) on the callee name of every call before it
/// even consults the summary map.  On a body whose file has no path-confiner
/// summary (the overwhelming majority — the whole of Go/most code) that is pure
/// wasted string work; profiling mm/channels/app attributed ≈1000
/// `StrSearcher::new` / `is_contained_in` samples to it alone.
///
/// This gate hoists the loop-invariant "does any summary confine?" existence
/// check out of the per-call loops: it is computed **once per body analysis**
/// by [`compute_confinement_gates`] (a single cheap scan of `ssa_summaries`,
/// no string work) and each pass is skipped entirely when its flag is `false`.
/// Bit-identical: when a flag is `false` the pass could only ever have found
/// nothing (its summary scan returns `None`), so skipping it is output-identical;
/// when `true` the pass runs exactly as before and the per-call name filter
/// still selects which calls actually confine.
#[derive(Clone, Copy, Default)]
pub(super) struct ConfinementGates {
    /// A summary records non-empty `asserts_path_confined_params`.
    assert: bool,
    /// A summary records non-empty `result_reject_guard_params`.
    path_validator: bool,
    /// A summary records `confines_path_return`.
    return_confiner: bool,
}

/// Scan `transfer.ssa_summaries` once for path-confiner summaries, producing the
/// per-body [`ConfinementGates`].  O(number of file summaries) cheap flag reads
/// (no string classification — the per-call name grammar stays inside the
/// individual passes and only runs when the gate is open).  All-`false` when
/// `ssa_summaries` is `None`.
pub(super) fn compute_confinement_gates(transfer: &SsaTaintTransfer) -> ConfinementGates {
    // Escape hatch: `NYX_DISABLE_CONFINEMENT_GATE=1` forces all three gates open,
    // restoring the pre-hoist behaviour where every per-call confinement pass
    // ran unconditionally.  Used to A/B the gated vs ungated path from a single
    // binary (criterion baseline, differential-correctness check) and as a
    // safety toggle.  Bit-identical to the gated path — an open gate only makes
    // a pass run a scan that finds nothing when no confiner exists.
    if confinement_gate_disabled() {
        return ConfinementGates {
            assert: true,
            path_validator: true,
            return_confiner: true,
        };
    }
    let Some(map) = transfer.ssa_summaries else {
        return ConfinementGates::default();
    };
    if let Some((addr, lang, gates)) = CONFINEMENT_GATES_TLS.get()
        && addr == std::ptr::from_ref(map) as usize
        && lang == transfer.lang
    {
        return gates;
    }
    scan_confinement_gates(map, transfer.lang)
}

/// The scan behind [`compute_confinement_gates`]: one pass over the summary map.
fn scan_confinement_gates(
    map: &HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>,
    lang: Lang,
) -> ConfinementGates {
    let mut g = ConfinementGates::default();
    for (key, sum) in map.iter() {
        if key.lang != lang {
            continue;
        }
        g.assert |= !sum.asserts_path_confined_params.is_empty();
        g.path_validator |= !sum.result_reject_guard_params.is_empty();
        g.return_confiner |= sum.confines_path_return;
        if g.assert && g.path_validator && g.return_confiner {
            break;
        }
    }
    g
}

thread_local! {
    /// Gates of the summary map held fixed by the innermost
    /// [`ConfinementGatesScope`]: `(address of the map, language, gates)`.
    static CONFINEMENT_GATES_TLS: Cell<Option<(usize, Lang, ConfinementGates)>> =
        const { Cell::new(None) };
}

/// Computes the [`ConfinementGates`] of a summary map once and hands them to
/// every taint run on this thread until the guard drops.
///
/// Without it each run scans the whole map, and a file with F functions makes
/// O(F) runs per extraction (one baseline probe plus one per parameter) over F
/// extractions, so the scans alone grow with F squared. The scope trades the
/// scans for one.
///
/// The map is matched by address, so for as long as the guard lives the map
/// must not change in any field the gates read (`confines_path_return`,
/// `asserts_path_confined_params`, `result_reject_guard_params`) and no key may
/// be added whose summary sets one of them. Most entry points open a scope
/// while holding the map as a shared reference, which rules out any change;
/// the child-sink augment pass grows only sink lists on existing entries.
pub(crate) struct ConfinementGatesScope {
    prev: Option<(usize, Lang, ConfinementGates)>,
}

impl ConfinementGatesScope {
    pub(crate) fn enter(
        summaries: Option<&HashMap<FuncKey, crate::summary::ssa_summary::SsaFuncSummary>>,
        lang: Lang,
    ) -> Self {
        let prev = CONFINEMENT_GATES_TLS.get();
        if let Some(map) = summaries {
            let addr = std::ptr::from_ref(map) as usize;
            // An enclosing scope for the same map already holds the answer.
            if !prev.is_some_and(|(a, l, _)| a == addr && l == lang) {
                CONFINEMENT_GATES_TLS.set(Some((addr, lang, scan_confinement_gates(map, lang))));
            }
        }
        ConfinementGatesScope { prev }
    }
}

impl Drop for ConfinementGatesScope {
    fn drop(&mut self) {
        CONFINEMENT_GATES_TLS.set(self.prev);
    }
}

/// Whether `NYX_DISABLE_CONFINEMENT_GATE=1` is set (forces all confinement
/// gates open — the pre-hoist unconditional behaviour).  Cached so the env read
/// is paid once per process.
fn confinement_gate_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var("NYX_DISABLE_CONFINEMENT_GATE")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    })
}

/// Apply an assert-guard path confinement as a call post-condition.
///
/// When `inst` is a call to a helper whose SSA summary records
/// `asserts_path_confined_params` (a `void` guard that
/// `Assert.isTrue(p.startsWith(base))`-style throws unless its path arg is
/// contained under a fixed prefix — CVE-2021-21234), strip [`Cap::FILE_IO`]
/// from the SSA values passed at each confined argument position.
/// **Unconditional**: any normal completion of the callee proves the assertion
/// held, so no caller branch is needed (unlike
/// [`apply_summary_confinement_narrowing`], which gates a return-value confiner
/// on the surviving branch).  A no-op when `transfer.ssa_summaries` is `None`
/// or the callee is not a recognised assert-guard.
fn apply_call_post_confinement(
    inst: &SsaInst,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    let SsaOp::Call {
        callee,
        callee_text,
        args,
        ..
    } = &inst.op
    else {
        return;
    };
    let bare = crate::labels::bare_method_name(callee_text.as_deref().unwrap_or(callee.as_str()));
    let Some(positions) = summary_asserts_confined_positions(transfer, bare) else {
        return;
    };
    // Copy the positions out so the immutable borrow of `transfer` is released
    // before `clear_cap_alias_aware` takes `&mut state` (which also reads
    // `transfer.base_aliases`).
    let positions: SmallVec<[usize; 2]> = positions.iter().copied().collect();
    for pos in positions {
        let Some(group) = args.get(pos) else {
            continue;
        };
        for &v in group {
            if let Some(name) = ssa
                .value_defs
                .get(v.0 as usize)
                .and_then(|vd| vd.var_name.as_deref())
            {
                clear_cap_alias_aware(state, name, Cap::FILE_IO, ssa, transfer.base_aliases);
            }
        }
    }
}

/// Confined argument positions for a *path-safety-validator* rejection guard.
///
/// Reads [`crate::summary::ssa_summary::SsaFuncSummary::result_reject_guard_params`]
/// — the params the callee rejects via a `Result` `Err` — but **only** for a
/// callee whose bare name matches the path-safety-validator grammar
/// (`ensure_safe_path_component`, `validate_safe_path`, …).  The structural
/// summary gate proves the callee is a rejection guard; the call-site name gate
/// proves it is a *path* rejection guard: the path-traversal sentinels the
/// guard rejects (`".."`, `'/'`) are collapsed out of the SSA body by
/// boolean-expression lowering, so the callee name is the only surviving
/// path-specificity signal (see `detect_result_reject_guard_params`).  Intra-
/// file only — a path-component validator lives in the same module as the
/// cache-key builder it guards.  Motivated by CVE-2026-53956 (rattler).
fn summary_path_validator_confined_positions<'b>(
    transfer: &'b SsaTaintTransfer,
    bare_name: &str,
) -> Option<&'b [usize]> {
    if !summary_extract::is_path_safety_validator_name(bare_name) {
        return None;
    }
    let map = transfer.ssa_summaries?;
    for (key, sum) in map.iter() {
        if key.lang == transfer.lang
            && key.name == bare_name
            && !sum.result_reject_guard_params.is_empty()
        {
            return Some(sum.result_reject_guard_params.as_slice());
        }
    }
    None
}

/// Apply a path-safety-validator rejection confinement as a call post-condition.
///
/// When `inst` calls a path-safety-named validator whose SSA summary records
/// `result_reject_guard_params`, strip [`Cap::FILE_IO`] from the SSA values
/// passed at each rejected position — a normal completion of
/// `ensure_safe_path_component(&segment)?` proves `segment` is a single safe
/// path component that cannot escape its parent directory.  The mirror of
/// [`apply_call_post_confinement`] for the `Result`-guard (`?`-propagated)
/// shape, which is *not* a branch condition and so bypasses the
/// `classify_condition` `ValidationCall` narrowing.  Runs in both the dataflow
/// (`transfer_block`) and event-emission (`collect_block_events`) replays.
/// Motivated by CVE-2026-53956 (rattler package-cache path traversal).
fn apply_path_validator_confinement(
    inst: &SsaInst,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    let SsaOp::Call {
        callee,
        callee_text,
        args,
        ..
    } = &inst.op
    else {
        return;
    };
    let bare = crate::labels::bare_method_name(callee_text.as_deref().unwrap_or(callee.as_str()));
    let Some(positions) = summary_path_validator_confined_positions(transfer, bare) else {
        return;
    };
    let positions: SmallVec<[usize; 2]> = positions.iter().copied().collect();
    for pos in positions {
        let Some(group) = args.get(pos) else {
            continue;
        };
        for &v in group {
            if let Some(name) = ssa
                .value_defs
                .get(v.0 as usize)
                .and_then(|vd| vd.var_name.as_deref())
            {
                clear_cap_alias_aware(state, name, Cap::FILE_IO, ssa, transfer.base_aliases);
            }
        }
    }
}

/// Whether the callee (by bare name) is a recognised *return-value path-prefix
/// confiner* whose return value clears [`Cap::FILE_IO`].
///
/// Mirrors [`summary_confines_open_redirect`]: looks the callee up in the
/// intra-file SSA summary map by same-language `FuncKey.name` and returns its
/// [`SsaFuncSummary::confines_path_return`] flag.  Intra-file only — a
/// path-composition helper (`compose_path`) lives in the same module as the
/// handler that consumes its result.  Motivated by CVE-2020-5221 (uftpd).
fn summary_confines_path_return(transfer: &SsaTaintTransfer, bare_name: &str) -> bool {
    let Some(map) = transfer.ssa_summaries else {
        return false;
    };
    map.iter().any(|(key, sum)| {
        key.lang == transfer.lang && key.name == bare_name && sum.confines_path_return
    })
}

/// Apply a return-value path confinement as a call post-condition.
///
/// When `inst` is a call to a helper whose SSA summary records
/// `confines_path_return` (its every non-null return is `strncmp`-confined
/// under a fixed directory prefix — CVE-2020-5221), strip [`Cap::FILE_IO`]
/// from the call *result*.  This is the interprocedural analogue of the
/// intra-function `PathPrefixConfined` narrowing: the confinement proven inside
/// the callee (on a `static` buffer disconnected from the tainted-parameter SSA
/// chain) is carried across the return that otherwise defeats it.  A no-op when
/// `transfer.ssa_summaries` is `None` or the callee is not a recognised
/// return-value confiner.  Runs in both the dataflow (`transfer_block`) and the
/// event-emission (`collect_block_events`) replays so it affects both the
/// computed exit state and the emitted sink findings.
fn apply_call_return_confinement(
    inst: &SsaInst,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    let SsaOp::Call {
        callee,
        callee_text,
        ..
    } = &inst.op
    else {
        return;
    };
    let bare = crate::labels::bare_method_name(callee_text.as_deref().unwrap_or(callee.as_str()));
    if !summary_confines_path_return(transfer, bare) {
        return;
    }
    if let Some(taint) = state.get(inst.value).cloned() {
        let new_caps = taint.caps & !Cap::FILE_IO;
        if new_caps.is_empty() {
            state.remove(inst.value);
        } else {
            state.set(
                inst.value,
                VarTaint {
                    caps: new_caps,
                    origins: taint.origins,
                    uses_summary: taint.uses_summary,
                },
            );
        }
    }
}

/// Whether a callee (by bare name) is a recognised relative-URL confiner
/// whose return value clears [`Cap::OPEN_REDIRECT`].
///
/// Mirrors [`summary_confined_positions`]: looks the callee up in the
/// intra-file SSA summary map by same-language `FuncKey.name` and returns
/// its [`SsaFuncSummary::sanitizes_open_redirect_return`] flag.  Intra-file
/// only — relative-URL confiners (`normalize_relative_url`) live in the same
/// module as the redirect handler.  Motivated by CVE-2026-42259.
fn summary_confines_open_redirect(transfer: &SsaTaintTransfer, bare_name: &str) -> bool {
    let Some(map) = transfer.ssa_summaries else {
        return false;
    };
    map.iter().any(|(key, sum)| {
        key.lang == transfer.lang && key.name == bare_name && sum.sanitizes_open_redirect_return
    })
}

/// Whether an OPEN_REDIRECT sink's argument expression is wrapped by an
/// open-redirect confiner whose call the SSA collapsed away.
///
/// `sink(confiner(source))` in one nested expression (Flask-AppBuilder
/// CVE-2022-24776 `redirect(get_safe_redirect(next_url))`) lowers to
/// `redirect(next_url)` — the SSA drops the unlabeled wrapper `get_safe_redirect`
/// (it carries no source/sink/sanitizer label, so `find_classifiable_inner_call`
/// never preserves it), and the tainted `next_url` flows straight into the sink
/// as a direct arg.  The confiner-return strip in the Call handler therefore has
/// nothing to latch onto.  The wrapper name does survive in the sink node's
/// [`CallMeta::arg_uses`] though, so recover it here: if any argument-expression
/// identifier resolves to a summary that [`SsaFuncSummary::
/// sanitizes_open_redirect_return`], the URL was validated inside that wrapper
/// before reaching the redirect — same-origin, so OPEN_REDIRECT does not apply.
/// Intra-file (mirrors [`summary_confines_open_redirect`]); a no-op when
/// `ssa_summaries` is `None` or no arg identifier names a confiner.
fn sink_arg_wrapped_by_open_redirect_confiner(
    info: &crate::cfg::NodeInfo,
    transfer: &SsaTaintTransfer,
) -> bool {
    info.call
        .arg_uses
        .iter()
        .flatten()
        .chain(info.call.outer_callee.as_ref())
        .any(|ident| {
            summary_confines_open_redirect(transfer, crate::labels::bare_method_name(ident))
        })
}

/// Source-level identifiers whose value flows through an open-redirect confiner
/// wrapper somewhere in this body's call arguments.
///
/// The nested `redirect(get_safe_redirect(next_url))` (CVE-2022-24776) lowers to
/// two `redirect(next_url)` SSA calls — the standalone call node and the
/// `return`-expression duplicate.  Only the standalone node carries the wrapper
/// in [`CallMeta::arg_uses`]; the return node's `arg_uses` is empty, so the
/// per-node [`sink_arg_wrapped_by_open_redirect_confiner`] check misses it.  This
/// harvests every argument identifier that co-occurs with a confiner across the
/// whole body (here `next_url`), so both redirect sinks — matched by their SSA
/// argument's `var_name` — can be recognised as confined.  Empty (fast) for the
/// common case where no call argument names a confiner.
fn open_redirect_confined_arg_names(
    ssa: &SsaBody,
    cfg: &Cfg,
    transfer: &SsaTaintTransfer,
) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut seen_nodes = HashSet::new();
    for block in &ssa.blocks {
        for inst in &block.body {
            if !seen_nodes.insert(inst.cfg_node) {
                continue;
            }
            for group in &cfg[inst.cfg_node].call.arg_uses {
                let has_confiner = group.iter().any(|id| {
                    summary_confines_open_redirect(transfer, crate::labels::bare_method_name(id))
                });
                if has_confiner {
                    for id in group {
                        if !summary_confines_open_redirect(
                            transfer,
                            crate::labels::bare_method_name(id),
                        ) {
                            out.insert(id.clone());
                        }
                    }
                }
            }
        }
    }
    out
}

/// Extract the bare callee name of an inline call condition.
///
/// Strips leading `!` / `(` / whitespace and a Python `not ` keyword, then
/// returns the identifier token before the first `(` (last segment after a
/// `.`/`::` receiver path).  Returns `None` when the condition is not a call
/// (no `(`) or no identifier precedes it.  Mirrors the callee-token peel in
/// [`crate::taint::path_state::classify_condition`].
fn parse_inline_call_callee(text: &str) -> Option<String> {
    if !text.contains('(') {
        return None;
    }
    let trimmed = text.trim_start_matches(['(', '!', ' ', '\t']);
    let trimmed = trimmed.strip_prefix("not ").unwrap_or(trimmed).trim();
    let callee_part = trimmed.split('(').next().unwrap_or("");
    let bare = callee_part
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(callee_part)
        .trim();
    if bare.is_empty()
        || !bare
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    {
        return None;
    }
    Some(bare.to_string())
}

/// Behaviour-based path-confinement branch narrowing.
///
/// Recognises a downstream truthiness gate on a helper whose
/// [`SsaFuncSummary::confines_path_params`] records that its boolean return
/// value confines an argument to a fixed path prefix, and strips
/// `Cap::FILE_IO` from that argument on the surviving (confined) branch.
///
/// Two condition shapes are handled:
///
/// ```text
/// // inline (Vite CVE-2026-39365)
/// if (!isOptimizedDepFile(sourcemapPath)) return next();
/// fsp.readFile(sourcemapPath);   // confined: FILE_IO stripped on this edge
///
/// // two-statement
/// const ok = isOptimizedDepFile(p);
/// if (!ok) return;
/// fsp.readFile(p);
/// ```
///
/// The predicate is `BooleanTrueIsValid` — a `true` result proves
/// confinement — so the validated edge is where the helper returned `true`:
/// the FALSE edge under a leading `!` (captured by `condition_negated`), the
/// TRUE edge otherwise.  Cap-aware (clears only `Cap::FILE_IO`, mirroring the
/// inline `RelativeUrlValidated`/`ShellMetaValidated` handlers), so a
/// confined value that *also* flows to a SQL/command sink still fires.
///
/// Strict-additive: a no-op when the condition is not a call to a
/// confinement helper, no summary records confinement, or no argument
/// var_name is recoverable.
fn apply_summary_confinement_narrowing(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    cond_text: &str,
    condition_vars: &[String],
    condition_negated: bool,
    ssa: &SsaBody,
    block: BlockId,
    transfer: &SsaTaintTransfer,
) {
    if condition_vars.is_empty() {
        return;
    }

    let mut confined_names: SmallVec<[String; 2]> = SmallVec::new();

    // Two-statement shape: `const ok = helper(p); if (!ok)`.  The single
    // condition var resolves to the helper's Call result; the confined arg
    // var_names are read off the recorded confined positions.
    if condition_vars.len() == 1
        && let Some(rv) = resolve_var_to_ssa_value(condition_vars[0].as_str(), ssa, block)
        && let Some(def) = ssa
            .blocks
            .iter()
            .flat_map(|b| b.body.iter())
            .find(|i| i.value == rv)
        && let SsaOp::Call { callee, args, .. } = &def.op
    {
        let bare = crate::labels::bare_method_name(callee);
        if let Some(positions) = summary_confined_positions(transfer, bare) {
            for &pos in positions {
                if let Some(group) = args.get(pos) {
                    for &v in group {
                        if let Some(name) = ssa
                            .value_defs
                            .get(v.0 as usize)
                            .and_then(|vd| vd.var_name.as_deref())
                            && !confined_names.iter().any(|s: &String| s == name)
                        {
                            confined_names.push(name.to_string());
                        }
                    }
                }
            }
        }
    }

    // Inline shape: `if (!helper(p))`.  The callee is parsed from the
    // condition text; the confined args are the condition's own variable
    // uses (the call arguments).  Clearing FILE_IO on the condition vars is
    // sound because the gate only confines a path arg, and the value is the
    // one the helper inspected.  Compound conditions (`&&` / `||`) are
    // skipped: the parsed callee is only the first call, so clearing every
    // condition var could over-suppress a sibling clause's taint.
    if confined_names.is_empty()
        && !cond_text.contains("&&")
        && !cond_text.contains("||")
        && let Some(bare) = parse_inline_call_callee(cond_text)
        && summary_confined_positions(transfer, &bare).is_some()
    {
        for name in condition_vars {
            if !confined_names.iter().any(|s: &String| s == name) {
                confined_names.push(name.clone());
            }
        }
    }

    if confined_names.is_empty() {
        return;
    }

    // BooleanTrueIsValid polarity: the confined branch is where the helper
    // returned `true`.  `condition_negated` captures a leading `!`, so a
    // `!helper(x)` condition puts the confined edge on the FALSE branch.
    let confined_state = if condition_negated {
        false_state
    } else {
        true_state
    };
    for name in &confined_names {
        clear_cap_alias_aware(
            confined_state,
            name,
            Cap::FILE_IO,
            ssa,
            transfer.base_aliases,
        );
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

/// The SSA value of `var_name` that is live at the end of `block`: the last
/// definition in the block (body, then phis), else the first one found
/// walking predecessors breadth-first.  SSA places a phi wherever two
/// definitions meet, so every backward path from `block` hits the same
/// reaching definition first and the walk order does not matter.
/// Returns `None` when no definition is reachable (an orphan catch block,
/// a free variable), in which case callers narrow nothing.
fn reaching_def_at_block_end(var_name: &str, ssa: &SsaBody, block: BlockId) -> Option<SsaValue> {
    let mut queue: VecDeque<BlockId> = VecDeque::new();
    let mut seen: HashSet<BlockId> = HashSet::new();
    queue.push_back(block);
    while let Some(b) = queue.pop_front() {
        if !seen.insert(b) {
            continue;
        }
        let Some(blk) = ssa.blocks.get(b.0 as usize) else {
            continue;
        };
        let defines = |inst: &&SsaInst| inst.var_name.as_deref() == Some(var_name);
        if let Some(inst) = blk.body.iter().rev().find(defines) {
            return Some(inst.value);
        }
        if let Some(inst) = blk.phis.iter().rev().find(defines) {
            return Some(inst.value);
        }
        queue.extend(blk.preds.iter().copied());
    }
    None
}

/// True when the root a path-view guard compares against derives from a
/// source: one of the condition's other variables reaches a source, a tainted
/// parameter or a field of one through copies, phis, constructors and path
/// methods.  A call that is none of those (`servlet.getModule(name).getPath()`)
/// is a lookup whose result the caller does not choose, so it ends the walk.
fn path_view_root_from_source(
    class: &PathBranchClass,
    effective_vars: &[String],
    ssa: &SsaBody,
    block: BlockId,
    cfg: &Cfg,
    state: &SsaTaintState,
) -> bool {
    let Some(view) = class.view.as_ref() else {
        return false;
    };
    let mut seen: Vec<SsaValue> = Vec::new();
    effective_vars
        .iter()
        .filter(|name| **name != view.root)
        .filter_map(|name| reaching_def_at_block_end(name, ssa, block))
        .any(|v| value_derives_from_source(v, ssa, cfg, state, &mut seen))
}

fn value_derives_from_source(
    v: SsaValue,
    ssa: &SsaBody,
    cfg: &Cfg,
    state: &SsaTaintState,
    seen: &mut Vec<SsaValue>,
) -> bool {
    if seen.contains(&v) || seen.len() > 64 {
        return false;
    }
    seen.push(v);
    if state.get(v).is_none_or(|t| t.caps.is_empty()) {
        return false;
    }
    let Some(inst) = find_inst_for_value(v, ssa) else {
        return false;
    };
    match &inst.op {
        SsaOp::Source | SsaOp::Param { .. } => true,
        SsaOp::Phi(_) | SsaOp::Assign(_) | SsaOp::FieldProj { .. } => inst
            .uses_iter()
            .into_iter()
            .any(|u| value_derives_from_source(u, ssa, cfg, state, seen)),
        SsaOp::Call { callee, .. } => {
            let info = &cfg[inst.cfg_node];
            if has_source_label_on_node(info) {
                return true;
            }
            let passes_path = info.call.is_constructor
                || matches!(
                    crate::labels::bare_method_name(callee),
                    "get"
                        | "of"
                        | "toPath"
                        | "toFile"
                        | "normalize"
                        | "toAbsolutePath"
                        | "toRealPath"
                        | "getAbsoluteFile"
                        | "getAbsolutePath"
                        | "getCanonicalFile"
                        | "getCanonicalPath"
                        | "resolve"
                        | "getParent"
                        | "toString"
                        | "valueOf"
                        | "trim"
                        | "concat"
                );
            passes_path
                && inst
                    .uses_iter()
                    .into_iter()
                    .any(|u| value_derives_from_source(u, ssa, cfg, state, seen))
        }
        _ => false,
    }
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
    apply_path_fact_branch_narrowing_with_aliases(
        true_state,
        false_state,
        &classify_path_branch(cond_text),
        effective_vars,
        ssa,
        BlockId(0),
        None,
        false,
    );
}

fn apply_path_fact_branch_narrowing_with_aliases(
    true_state: &mut SsaTaintState,
    false_state: &mut SsaTaintState,
    class: &PathBranchClass,
    effective_vars: &[String],
    ssa: &SsaBody,
    block: BlockId,
    base_aliases: Option<&crate::ssa::alias::BaseAliasResult>,
    negated: bool,
) {
    use crate::abstract_interp::PathFact;
    use crate::abstract_interp::path_domain::{PathAssertion, PathRejection};

    // The (state-independent) text classification is precomputed in `class`
    // and memoized per condition node by the caller — see [`classify_path_branch`]
    // / [`BranchCondClass`].
    let rejection_axes = &class.rejection_axes;
    let assertion = &class.assertion;

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
    let rejection_pre_negated = class.rejection_pre_negated;
    let rejection_safe_is_true = negated && !rejection_pre_negated;

    // A path-shape rejection says nothing about SQL, shell, HTML or any
    // other sink class, so it never marks the variable validated.  When
    // the condition rejects both `..` segments and absolute paths, the
    // surviving value is a relative, `..`-free path, which is the same
    // two-axis test `PathFact::is_path_traversal_safe` applies at the
    // sink.  Clear `Cap::FILE_IO` from the taint in that case so the
    // proof survives shapes the abstract state cannot follow (C
    // out-param copies such as `strncpy(buf, path, n)`).  A single axis
    // (`..` only, or `/` only) leaves taint untouched and FILE_IO is
    // decided by the PathFact narrowing below.  Restricted to a single
    // condition variable: with `a.includes("..") || b.startsWith("/")`
    // neither variable is proven safe on both axes.
    //
    // `startswith("..")` rejects the `..` axis only for a lexically
    // normalized value, whose `..` components are all leading; the reaching
    // definition's PathFact says whether that holds.
    let rejects_absolute = rejection_axes
        .iter()
        .any(|a| matches!(a, PathRejection::AbsoluteSlash | PathRejection::IsAbsolute));
    let rejects_dotdot = rejection_axes.contains(&PathRejection::DotDot)
        || (rejection_axes.contains(&PathRejection::LeadingDotDot)
            && effective_vars.len() == 1
            && reaching_def_at_block_end(&effective_vars[0], ssa, block).is_some_and(|v| {
                let safe_state: &SsaTaintState = if rejection_safe_is_true {
                    true_state
                } else {
                    false_state
                };
                safe_state.abstract_state.as_ref().is_some_and(|abs| {
                    abs.get(v).path.normalized == crate::abstract_interp::Tri::Yes
                })
            }));
    if rejects_dotdot && rejects_absolute && effective_vars.len() == 1 {
        let safe_state: &mut SsaTaintState = if rejection_safe_is_true {
            &mut *true_state
        } else {
            &mut *false_state
        };
        clear_cap_alias_aware(
            safe_state,
            &effective_vars[0],
            Cap::FILE_IO,
            ssa,
            base_aliases,
        );
    }

    // Narrow the SSA value of each condition variable that reaches the
    // branch.  A later redefinition (`p = req.query.b` after the check) is
    // a different value and must not inherit the narrowed fact.
    let mut targets: smallvec::SmallVec<[SsaValue; 2]> = smallvec::SmallVec::new();
    for var_name in effective_vars {
        if let Some(v) = reaching_def_at_block_end(var_name, ssa, block) {
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
                // Lexical normalisation leaves `..` only at the start of a
                // relative path, so a normalized value that does not start
                // with `..` has none.  Any other value may still hold one
                // in the middle.
                PathRejection::LeadingDotDot => {
                    if fact.normalized == crate::abstract_interp::Tri::Yes {
                        fact.dotdot = crate::abstract_interp::Tri::No;
                    }
                }
                PathRejection::None => {}
            }
        }
    };

    // The confinement of a path-view receiver binds to the chain's root
    // variable alone; the other variables of the condition (the root being
    // compared against) are not narrowed.
    //
    // Confinement under a root proves nothing when the root itself is
    // attacker controlled: `f.toPath().normalize().startsWith(r)` passes for
    // any `f` when the attacker also picks `r`.  The caller sets
    // `view_root_untrusted` when the root derives from a source.
    let view_root_def = class
        .view
        .as_ref()
        .and_then(|view| reaching_def_at_block_end(&view.root, ssa, block));
    let view_clears_dotdot = !class.view_root_untrusted
        && class
            .view
            .as_ref()
            .is_some_and(|v| v.normalizes && v.path_valued);
    let assertion_targets: smallvec::SmallVec<[SsaValue; 2]> = match class.view.as_ref() {
        Some(view) if effective_vars.contains(&view.root) => view_root_def.into_iter().collect(),
        _ => targets.clone(),
    };

    // Apply assertion (positive): the branch where it holds narrows
    // prefix_lock.
    let narrow_assertion = |fact: &mut PathFact| {
        if let PathAssertion::PrefixLock(root) | PathAssertion::PrefixLockUnless(root) = assertion {
            let mut updated = fact.clone().with_prefix_lock(root);
            // A lexically normalized path holds `..` only as leading
            // components, and a path that starts with a root that is not
            // itself `..` has none.
            if updated.normalized == crate::abstract_interp::Tri::Yes && !root.starts_with("..") {
                updated.dotdot = crate::abstract_interp::Tri::No;
            }
            // `f.toPath().normalize().startsWith(root)`: the guard tested the
            // normalized view of this variable, whose `..` components are
            // all leading, so passing it proves the location stays under the
            // root.  Only a `Path` view qualifies (component-wise compare).
            if view_clears_dotdot && !root.starts_with("..") {
                updated.dotdot = crate::abstract_interp::Tri::No;
            }
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
    // FILE_IO clear above so soundness is consistent.
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
                Arc::make_mut(abs).set(*v, av);
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
    // `PrefixLockUnless` (`strpos($p, $root) !== 0`) holds on the opposite
    // edge.
    let holds_on_true = !negated ^ matches!(assertion, PathAssertion::PrefixLockUnless(_));
    let assertion_state = if holds_on_true {
        &mut *true_state
    } else {
        &mut *false_state
    };
    for v in &assertion_targets {
        if let Some(ref mut abs) = assertion_state.abstract_state {
            let mut av = abs.get(*v);
            narrow_assertion(&mut av.path);
            if !av.is_top() {
                Arc::make_mut(abs).set(*v, av);
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
        callee,
        args,
        receiver,
        state,
        transfer,
        cfg,
        caller_ssa,
        call_inst,
        &[],
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

/// Resolve callback arguments: when a call argument refers to a known
/// function name (resolvable to a `FuncKey` in `local_summaries` and present
/// in `callee_bodies`), record the mapping `callee param name → target
/// FuncKey` so the callee's analysis can resolve calls through the
/// parameter.
///
/// This is consulted by `resolve_callee` step -1.  Because the resolved
/// bindings shape the callee's return taint but are NOT reflected in the
/// `(FuncKey, ArgTaintSig)` inline-cache key (function references are
/// typically untainted, so different callbacks produce identical sigs),
/// callers MUST skip the inline cache (both lookup and insert) whenever the
/// returned map is non-empty, otherwise a call site passing `safeCb` could
/// reuse / poison the cached shape of a call site passing `sourceCb`.
fn compute_callback_bindings(
    callee_ssa: &SsaBody,
    args: &[SmallVec<[SsaValue; 2]>],
    transfer: &SsaTaintTransfer,
    caller_ssa: &SsaBody,
) -> HashMap<String, FuncKey> {
    let mut callback_bindings: HashMap<String, FuncKey> = HashMap::new();
    for block in &callee_ssa.blocks {
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
    callback_bindings
}

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

    // Set when the body came from another file.  Inline analysis reads
    // such a body by its rebased shape; see `note_inline_positions`.
    let mut xfile_source: Option<&crate::summary::GlobalSummaries> = None;
    let (callee_key, callee_body) = if let (Some(k), Some(b)) = (intra_key, intra_body) {
        (k, b)
    } else {
        let gs = transfer.global_summaries?;
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
        let key = gs.resolve_callee_unique(&query)?;
        let xfile_bodies = transfer.cross_file_bodies?;
        let body = xfile_bodies.get_body_shape(&key)?;
        xfile_source = Some(xfile_bodies);
        // Indexed-scan bodies deserialized from SQLite
        // arrive with `body_graph: None`, but decoding
        // ([`rebuild_body_graph`] in `EncodedBody::decode`)
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

    // Resolve callback bindings BEFORE consulting the cache.  The cache key
    // `(FuncKey, ArgTaintSig)` does not capture WHICH function was passed as
    // a callback argument (function refs are typically untainted, so
    // `wrap(safeCb)` and `wrap(sourceCb)` produce identical sigs).  Since
    // the bound function's summary shapes the callee's return taint via
    // `resolve_callee` step -1, a cached shape is only sound to reuse / store
    // when there are no callback bindings.  When bindings exist we bypass the
    // cache entirely (both lookup below and insert later) to avoid poisoning.
    let callback_bindings = compute_callback_bindings(&callee_body.ssa, args, transfer, caller_ssa);
    let cacheable = callback_bindings.is_empty();

    // Check cache (keyed by FuncKey + arg signature).  The cached value
    // is a structural shape, re-attribute origins to the current call
    // site before returning so two callers with matching caps but
    // different origins see their own source chains.
    if cacheable {
        let cache = cache_ref.borrow();
        if let Some(cached) = cache.get(&(callee_key.clone(), sig.clone())) {
            record_engine_note(crate::engine_notes::EngineNote::InlineCacheReused);
            note_inline_positions(xfile_source, &callee_key, cached);
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

    // Callback argument bindings were resolved before the cache lookup
    // (see `compute_callback_bindings`) so a non-empty map could bypass the
    // inline cache.  Reuse the same map here to drive the child transfer's
    // `resolve_callee` step -1.

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
        // A callee being inlined has a caller by definition, and its
        // `param_seed` says what that caller passes: an empty slot is an
        // untainted argument, which the JS/TS name-based seed would turn
        // into a phantom source.  Turning the seed off here also keeps the
        // shared inline cache independent of which body inlined first.
        auto_seed_handler_params: transfer.auto_seed_handler_params
            && !matches!(transfer.lang, Lang::JavaScript | Lang::TypeScript),
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
        param_route_capture: None,
        recording_summary: transfer.recording_summary,
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
    //
    // Only cache shapes that do not depend on callback identity.  When
    // `callback_bindings` is non-empty the resolved return taint is shaped by
    // step -1 callback resolution, which is invisible to the
    // `(FuncKey, ArgTaintSig)` key, so caching would poison sibling call
    // sites that pass a different callback.
    note_inline_positions(xfile_source, &callee_key, &shape);
    if cacheable {
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

/// Record that this analysis depends on where a cross-file callee body sits
/// in its file, when its inline result carries positions from that body.
///
/// The body itself was read by its rebased shape.  The only absolute
/// positions an inline result hands back are the `source_span`s of origins
/// that arose inside the callee; with none, the result is the same wherever
/// the callee's function sits in its file.
fn note_inline_positions(
    xfile_source: Option<&crate::summary::GlobalSummaries>,
    callee_key: &FuncKey,
    shape: &CachedInlineShape,
) {
    if let Some(gs) = xfile_source
        && shape
            .0
            .as_ref()
            .is_some_and(|s| !s.internal_origins.is_empty())
    {
        gs.note_body_positions(callee_key);
    }
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
    let confinement = compute_confinement_gates(transfer);
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

    // Explicit-return param passthrough: return paths whose return value IS
    // a formal parameter (`return x;`).  This channel is JOINED with the
    // derived channel below so a mixed-return helper
    // (`if (c) return src(); return x;`) propagates BOTH the derived source
    // taint and the parameter passthrough provenance.
    let mut param_caps = Cap::empty();
    let mut param_internal: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut param_params: u64 = 0;
    let mut param_receiver: bool = false;

    // Return(None) fallback param passthrough: caps swept from ALL live
    // param-derived values on implicit-return paths.  Kept separate because
    // it is noisy (it re-adds caps the callee may have sanitized), so it
    // only acts as a last-resort fallback, never joined into the derived
    // channel.
    let mut param_fallback_caps = Cap::empty();
    let mut param_fallback_internal: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    let mut param_fallback_params: u64 = 0;
    let mut param_fallback_receiver: bool = false;

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
                confinement,
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
                                confinement,
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
                        param_fallback_caps |= taint.caps;
                        for orig in &taint.origins {
                            classify_and_push(
                                orig,
                                &mut param_fallback_internal,
                                &mut param_fallback_params,
                                &mut param_fallback_receiver,
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

    // Join the derived channel (taint produced inside the callee) with the
    // explicit-return param-passthrough channel (return paths whose return
    // value IS a formal parameter).  A mixed-return helper
    // (`if (c) return src(); return x;`) has a non-empty derived channel on
    // one path AND a param passthrough on another; the correct return-value
    // abstraction across paths is the union of both, not a choose-one.
    // The noisy Return(None) fallback (`param_fallback_*`) is used only when
    // BOTH structured channels are empty, so it never re-adds caps the
    // callee sanitized on an explicit-return path.
    let (final_caps, final_internal, final_params, final_receiver) =
        if !derived_caps.is_empty() || !param_caps.is_empty() {
            let mut internal = derived_internal;
            for orig in &param_internal {
                push_internal(&mut internal, orig);
            }
            (
                derived_caps | param_caps,
                internal,
                derived_params | param_params,
                derived_receiver || param_receiver,
            )
        } else {
            (
                param_fallback_caps,
                param_fallback_internal,
                param_fallback_params,
                param_fallback_receiver,
            )
        };

    let return_path_fact =
        return_path_fact_acc.unwrap_or_else(crate::abstract_interp::PathFact::top);

    // Surface per-return-path signal in the gate below: at least two
    // distinct entries with non-Top path_fact or a variant_inner_fact.
    // Single-entry lists are no finer than the joined `return_path_fact`.
    let has_per_return_path_signal = per_return_path_entries.len() >= 2
        && per_return_path_entries
            .iter()
            .any(|e| !e.path_fact.is_top() || e.variant_inner_fact.is_some());

    // Even when the callee produces no return taint and no param/receiver
    // provenance, a non-Top PathFact on the return is still meaningful
    // (it tells callers "this helper's return is sanitised along a path
    // axis").  Keep the shape when *any* of the four signals is present.
    if final_caps.is_empty()
        && final_params == 0
        && !final_receiver
        && final_internal.is_empty()
        && return_path_fact.is_top()
        && !has_per_return_path_signal
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

/// Validated-reconstruction support (read side): when reading an
/// element of a container whose BASE symbol was validated by a
/// branch guard on this path (e.g. the true branch of
/// `if (is_numeric($octet[0]) && is_numeric($octet[1]) && …)` marks
/// the `octet` symbol validated), propagate that validation to the
/// element-read result so a value later rebuilt from the elements
/// (`$target = $octet[0] . '.' . $octet[1]`) is recognised as
/// validated by the Assign-arm reconstruction propagation.
///
/// This is the symbol-level counterpart to `apply_container_elem_read_w4`,
/// which lifts validation off `(loc, ELEM)` field cells; the branch
/// guard marks the symbol, not the cells, so the cell path alone misses
/// the "validate each element then rebuild" idiom.  Consistent with the
/// engine's existing policy of validating the whole base symbol on a
/// single element type-check — it extends the reach of that decision to
/// element reads, it does not introduce a new validation criterion.
fn apply_container_read_receiver_validation(
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
    if !crate::pointer::is_container_read_callee_pub(callee) {
        return;
    }
    let Some(rcv) = *receiver else {
        return;
    };
    let (rcv_must, rcv_may) = ssa_value_validated_bits(rcv, ssa, transfer.interner, state);
    if !rcv_must && !rcv_may {
        return;
    }
    if let Some(name) = ssa
        .value_defs
        .get(inst.value.0 as usize)
        .and_then(|vd| vd.var_name.as_deref())
        && let Some(sym) = transfer.interner.get(name)
    {
        if rcv_must {
            state.validated_must.insert(sym);
        }
        if rcv_may {
            state.validated_may.insert(sym);
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

/// Drop the name-keyed facts a new definition makes stale.
///
/// `validated_must` / `validated_may` and `predicates` are keyed by variable
/// name, so they describe whichever SSA value of that name is current.  A
/// definition that does not read the old value (`x = req.query.other`, a Go
/// `:=` shadow, a foreach binder that reuses the name) starts with none of
/// them.  A self-update keeps the old value's validation only when nothing
/// unvalidated is mixed in: `x = x.trim()` stays validated, while
/// `x = x + req.query.extra` or `x = x + y` with an unvalidated `y` does not.
/// `validated_may` survives a mixed self-update because part of the new
/// value is still the validated one.  Predicate bits (null, empty and error
/// checks) describe one value and go on every redefinition.
///
/// Runs before the op arm, so the arms that validate a definition on their
/// own terms (every tainted operand validated, a validating wrapper, a
/// validated-param summary) insert into a state that no longer holds the
/// stale bit.  Field projections read a location rather than redefine a
/// name, and the synthetic base update behind `obj.f = rhs` updates `obj`
/// in place, so neither drops anything.
fn kill_redefined_symbol_facts(
    inst: &SsaInst,
    info: &NodeInfo,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    if state.validated_must.is_empty()
        && state.validated_may.is_empty()
        && state.predicates.is_empty()
    {
        return;
    }
    if matches!(
        inst.op,
        SsaOp::Phi(_)
            | SsaOp::Param { .. }
            | SsaOp::SelfParam
            | SsaOp::Nop
            | SsaOp::Undef
            | SsaOp::FieldProj { .. }
    ) || ssa.field_writes.contains_key(&inst.value)
    {
        return;
    }
    let value_name =
        |v: SsaValue| -> Option<&str> { ssa.value_defs.get(v.0 as usize)?.var_name.as_deref() };
    let Some(name) = value_name(inst.value) else {
        return;
    };
    let Some(sym) = transfer.interner.get(name) else {
        return;
    };
    if let Ok(idx) = state.predicates.binary_search_by_key(&sym, |(id, _)| *id) {
        state.predicates.remove(idx);
    }
    let must = state.validated_must.contains(sym);
    if !must && !state.validated_may.contains(sym) {
        return;
    }
    let operands = inst_use_values(inst);
    let self_update = operands.iter().any(|&v| value_name(v) == Some(name));
    let introduces_source = (info
        .taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Source(_)))
        && !ssa.slot_scoped_assigns.contains(&inst.value))
        || operands::may_hold_nested_sources(info);
    if !self_update || introduces_source {
        state.validated_must.remove(sym);
        state.validated_may.remove(sym);
        return;
    }
    let mixes_unvalidated = must
        && operands.iter().any(|&v| {
            value_name(v) != Some(name)
                && state.get(v).is_some_and(|t| !t.caps.is_empty())
                && !ssa_value_validated_bits(v, ssa, transfer.interner, state).0
        });
    if mixes_unvalidated {
        state.validated_must.remove(sym);
    }
}

/// Forget every validated constant-index element (`parts[0]`) when a
/// statement stores into an indexed location.  The store may reach the
/// element through another name for the same backing array (`q := parts;
/// q[0] = x`), which the element's own base name does not show, so no
/// element stays validated across any indexed store.
fn kill_elem_facts_on_index_store(
    info: &NodeInfo,
    transfer: &SsaTaintTransfer,
    state: &mut SsaTaintState,
) {
    if info.map_stores.is_empty()
        || (state.validated_must.is_empty() && state.validated_may.is_empty())
    {
        return;
    }
    for i in 0..transfer.interner.len() {
        let id = crate::state::symbol::SymbolId(i as u32);
        let name = transfer.interner.resolve(id);
        if name.ends_with(']') && name.contains('[') {
            state.validated_must.remove(id);
            state.validated_may.remove(id);
        }
    }
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

    kill_redefined_symbol_facts(inst, info, ssa, transfer, state);
    kill_elem_facts_on_index_store(info, transfer, state);

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
            // `$n = (int) $_GET['n']`: the value is a number, not the source.
            if !source_caps.is_empty() && !info.yields_number {
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
                    caps: Cap::CAUGHT_EXCEPTION,
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
            let text_facts = call_text_facts(
                Some(transfer.lang),
                callee,
                info.call.outer_callee.as_deref(),
                info.call.is_constructor,
            );
            if text_facts.noreturn {
                *state = SsaTaintState::bot();
                return;
            }

            // Excluded callees (e.g. router.get, app.post) should not propagate
            // taint through their return value, they are framework scaffolding,
            // not data-flow operations.
            if text_facts.excluded {
                return;
            }

            // Phase 03 Promise plumbing: handle `.then(cb)`/`.catch(cb)`/
            // `.finally(cb)` and `Promise.resolve|all|allSettled|race(...)`
            // before the rest of the Call arm.  Returning early avoids
            // re-classifying these as ordinary calls (no summary, no sink),
            // which would otherwise drop the receiver/element taint flow.
            if try_apply_promise_callback(
                inst, info, callee, args, receiver, state, transfer, cfg, ssa,
            ) {
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
                    if matches!(receiver_kind, Some(crate::ssa::type_facts::TypeKind::Url)) {
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
                        // A query parameter cannot change the scheme, host or
                        // path of the URL, so it cannot steer a redirect.
                        arg_caps &= !Cap::OPEN_REDIRECT;
                        if !arg_caps.is_empty() {
                            // Walk the FieldProj receiver chain (and any
                            // Rust-style nested call receivers) so every
                            // SSA value that aliases the URL — `u`,
                            // `u.searchParams`, etc. — picks up the new
                            // taint, not just the immediate set receiver.
                            let chain =
                                receiver_candidates_for_type_lookup(rv, Some(ssa), transfer.lang);
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

            // Sibling operands.  When this op stands for a larger expression
            // (`"<p>" + escapeHtml(name) + bio`, `siteHeader() + bio`), the
            // operands outside the anchor call are not the callee's
            // arguments: the callee semantics below (label sanitizer,
            // summary, inline analysis) see only the operands inside it, and
            // the siblings are added to the result afterwards through the
            // calls that wrap them.  Their taint and validation are read
            // here, before the callee path touches any argument value.
            // Source calls nested in the expression (`siteHeader() +
            // getCmd()`, `foo(getenv("X"))`) have no SSA value of their own,
            // so they join the siblings here.
            let mut operand_split = operands::split_call_operands(info, ssa, args, *receiver);
            let nested_ops = (operand_split.is_some() || operands::may_hold_nested_sources(info))
                .then(|| operands::NestedOperands::new(info, transfer))
                .flatten();
            if !nested_ops
                .as_ref()
                .is_some_and(|ops| ops.anchor_separable(info, transfer.lang))
            {
                operand_split = None;
            }
            let sibling = nested_ops.and_then(|ops| {
                let mut sib = match &operand_split {
                    Some(split) => {
                        operands::sibling_taint(&ops, &split.siblings, ssa, transfer, state)
                    }
                    None => operands::SiblingTaint::default(),
                };
                let (src_caps, src_origins) =
                    ops.expression_sources(info, inst.cfg_node, state, transfer.lang);
                if !src_caps.is_empty() {
                    sib.caps |= src_caps;
                    for o in src_origins {
                        push_origin_bounded(&mut sib.origins, o);
                    }
                    sib.all_validated = false;
                }
                (!sib.caps.is_empty()).then_some(sib)
            });
            let result_sym = sibling.as_ref().and_then(|_| {
                ssa.value_defs
                    .get(inst.value.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                    .and_then(|n| transfer.interner.get(n))
            });
            let result_was_validated =
                result_sym.is_some_and(|sym| state.validated_must.contains(sym));
            let split_receiver: Option<SsaValue>;
            let (args, receiver) = match &operand_split {
                Some(split) => {
                    split_receiver = split.callee_receiver;
                    (&split.callee_args, &split_receiver)
                }
                None => (args, receiver),
            };

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
            //
            // Only two readers use the set: the Source-label outer-callee
            // suppression further down, and the Go `append` element-write
            // hook below.  Resolving every wrapper's summary is the costly
            // part, and a callback-heavy call resolves one per closure
            // argument, so the walk runs only when a reader can consume it.
            let has_source_label = has_source_label_on_node(info);
            let go_append_chain = transfer.lang == Lang::Go
                && receiver.is_none()
                && (callee == "append" || info.call.outer_callee.as_deref() == Some("append"));
            let caller_func_for_chain = info.ast.enclosing_func.as_deref().unwrap_or("");
            let mut chain_wrapper_sanitizer_caps = Cap::empty();
            if !info.arg_callees.is_empty() && (has_source_label || go_append_chain) {
                let source_arg_pos = info
                    .arg_callees
                    .iter()
                    .position(|c| c.as_deref() == Some(callee.as_str()));
                let mut per_arg_sanitizer_caps: SmallVec<[Cap; 4]> = SmallVec::new();
                // With the source as an argument callee nothing is credited,
                // so there is no wrapper to look at.
                let wrappers: &[Option<String>] = if source_arg_pos.is_none() {
                    &info.arg_callees
                } else {
                    &[]
                };
                for maybe_callee in wrappers {
                    if per_arg_sanitizer_caps.len() >= 2 {
                        // A second sanitising wrapper makes the credit
                        // ambiguous, so the result is already empty.
                        break;
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
            if let Some((path_idx, _base_idx)) = crate::ssa::type_facts::url_builder_arg_indices(
                transfer.lang,
                callee,
                info.call.outer_callee.as_deref(),
                info.call.is_constructor,
            ) {
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
            // Detect a hardcoded URL via three channels:
            //   1. `info.string_prefix`, populated by the JS/TS template-
            //      literal extractor and inline call shapes.
            //   2. AbstractState `StringFact` on the first positional arg,
            //      populated by const propagation for plain string literals.
            //   3. As a last resort when `info.call.first_arg_text` is
            //      populated with a hardcoded literal, extracted at CFG
            //      construction time for network-fetch primitive callees.
            // Channels 1 and 3 read only the CFG node, so they live in
            // `node_is_hardcoded_network_fetch_source` where the structural
            // `cfg-unguarded-sink` pass (which has no abstract state) shares
            // them.  Channel 2 needs this block's `AbstractState` and stays
            // here.
            let url_prefix_safe_via_abs = is_network_fetch_source(info)
                && state.abstract_state.as_ref().is_some_and(|abs| {
                    args.first().is_some_and(|first_arg| {
                        !first_arg.is_empty()
                            && first_arg.iter().all(|v| {
                                is_string_safe_for_ssrf(
                                    &abs.get(*v).string,
                                    info.call.callee.as_deref(),
                                )
                            })
                    })
                });
            let url_is_hardcoded_safe =
                node_is_hardcoded_network_fetch_source(info) || url_prefix_safe_via_abs;

            // Set when this node's own Source label put fresh taint on the
            // result.  Such a result does not inherit its operands'
            // validation below: `'... ' + sort + ' LIMIT ' + req.query.limit`
            // is not validated just because `sort` passed an allowlist.
            let mut fresh_source_applied = false;
            for lbl in &info.taint.labels {
                if let DataLabel::Source(bits) = lbl {
                    if url_is_hardcoded_safe {
                        // Skip Source propagation, see network-fetch
                        // source suppression rationale above.
                        continue;
                    }
                    fresh_source_applied |= !bits.is_empty();
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

            // Output-parameter source tainting: for known APIs that write
            // input into an argument (C `fgets` / `recv` buffers, Go request
            // binders such as `c.ShouldBindJSON(&in)`), taint the argument
            // SSA values at the registered output positions.
            //
            // A Go binder's only return value is the `error`, which carries
            // no request data; `binder_error_return` keeps it clean even
            // though the default arg-to-return propagation below would copy
            // the now-tainted destination pointer into it.
            let mut binder_error_return = false;
            // A Rust read that fills its argument is a method on an open
            // reader (`file.read_to_end(&mut buf)`); the path call
            // `fs::read(path)` is a source that returns its bytes and writes
            // nothing into `path`.
            let out_param_call = transfer.lang != Lang::Rust || receiver.is_some();
            if !return_bits.is_empty() && out_param_call {
                if let Some(positions) =
                    crate::labels::output_param_source_positions(transfer.lang.as_str(), callee)
                {
                    if transfer.lang == Lang::Go {
                        // A Go binder decodes into a struct pointer, so the
                        // taint has to reach `in.Field` reads through the
                        // heap and field-cell channels as well.
                        let bound = VarTaint {
                            caps: return_bits,
                            origins: return_origins.clone(),
                            uses_summary: false,
                        };
                        for &pos in positions {
                            if let Some(arg_group) = args.get(pos) {
                                taint_writeback_dest(state, transfer, arg_group, &bound);
                            }
                        }
                        return_bits = Cap::empty();
                        return_origins.clear();
                        binder_error_return = true;
                    } else {
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
                                    forget_abstract_value(state, arg_v);
                                }
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
                                Arc::make_mut(abs).set(inst.value, av);
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
            // A hoisted member read (`useEffect(cb, [location.search])`) names
            // no call of this node, so its text must not bind to a same-leaf
            // project function (`MailPit.search`); the wrapping call is
            // resolved through `outer_callee` below.
            let callee_summary = if info.call.callee_nesting == CalleeNesting::Hoisted {
                None
            } else {
                resolve_callee_typed(
                    transfer,
                    callee,
                    caller_func,
                    info.call.call_ordinal,
                    arity_hint,
                    *receiver,
                )
            };

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
                    if let Some(env) = state.path_env.as_mut() {
                        use crate::constraint::domain::{TypeSet, ValueFact};
                        let mut fact = ValueFact::top();
                        fact.types = TypeSet::singleton(rtype);
                        Arc::make_mut(env).refine(inst.value, &fact);
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

                    if !effective_params.is_empty() {
                        // Per-parameter application: each propagating param
                        // contributes taint narrowed by ITS OWN sanitizer
                        // (`effective_param_sanitizer`, which prefers the
                        // param's per-return-path strip bits and otherwise
                        // falls back to its own `param_to_return_strip` —
                        // never the cross-param aggregate).  This avoids the
                        // cross-parameter sanitizer bleed of unioning all
                        // args then stripping the aggregate: for
                        // `f(a,b){ return a + escape(b) }`, param 1's
                        // HTML_ESCAPE strip must not clear param 0's taint.
                        // Origins are still aggregated across params, they
                        // name source anchors, not transforms.
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
                        // No positional argument info (`arg_uses` empty), so
                        // per-param attribution is impossible.  Union all
                        // propagating-arg taint; the aggregate sanitizer is
                        // applied below.  This is the only path that may
                        // over-strip, and only when positions are unknown.
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

                // Behaviour-based open-redirect confiner (CVE-2026-42259):
                // when the callee normalises its input and rejects
                // protocol-relative (`//`) and `scheme:` URLs before
                // returning the confined value, its return is provably
                // same-origin — strip OPEN_REDIRECT so redirecting to the
                // result no longer fires.  Sound because the recogniser
                // requires backslash normalisation + `//`-prefix rejection +
                // scheme rejection (see `detect_open_redirect_normalizer`);
                // the weak `!url.includes("//")` form is not recognised.
                // (Applied at the universal result-commit point below so it
                // runs regardless of which resolution path handled the call.)

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
                let declared = info.call.receiver_decl_type.as_ref();
                if (receiver.is_some()
                    && (transfer.type_facts.is_some() || state.path_env.is_some()))
                    || declared.is_some()
                {
                    let tq_labels = resolve_type_qualified_labels(
                        callee,
                        *receiver,
                        transfer.type_facts,
                        state.path_env.as_deref(),
                        declared,
                        transfer.lang,
                        transfer.extra_labels,
                        Some(ssa),
                    );
                    // A callee whose own text already matches a Source rule but
                    // reached here without the label had it withdrawn at CFG
                    // construction (a process-output `readLine`, an excluded
                    // callee).  The qualified form (`FileHandle.readLine`)
                    // matches the same bare rule and would bring it back.
                    let plain_text_is_source =
                        tq_labels.iter().any(|l| matches!(l, DataLabel::Source(_)))
                            && crate::labels::classify_all(
                                transfer.lang.as_str(),
                                callee,
                                transfer.extra_labels,
                            )
                            .iter()
                            .any(|l| matches!(l, DataLabel::Source(_)));
                    for lbl in &tq_labels {
                        match lbl {
                            DataLabel::Source(bits)
                                if !has_source_label && !plain_text_is_source =>
                            {
                                return_bits |= *bits;
                                let source_kind = crate::labels::infer_source_kind(*bits, callee);
                                let origin = TaintOrigin {
                                    node: inst.cfg_node,
                                    source_kind,
                                    source_span: None,
                                };
                                if !return_origins.iter().any(|o| o.node == inst.cfg_node) {
                                    return_origins.push(origin);
                                }
                                // A typed read that fills a buffer argument
                                // (`file.read_to_end(&mut buf)`): the buffer
                                // carries the bytes, as for a direct Source.
                                // The call may end in `.unwrap()` / `?`, so the
                                // read's own name is found past those.
                                if transfer.lang == Lang::Rust
                                    && let Some(positions) =
                                        method_candidates_from_chain(callee, transfer.lang)
                                            .iter()
                                            .find_map(|m| {
                                                crate::labels::output_param_source_positions(
                                                    transfer.lang.as_str(),
                                                    m,
                                                )
                                            })
                                {
                                    for &pos in positions {
                                        for &arg_v in args.get(pos).into_iter().flatten() {
                                            state.set(
                                                arg_v,
                                                VarTaint {
                                                    caps: *bits,
                                                    origins: return_origins.clone(),
                                                    uses_summary: false,
                                                },
                                            );
                                            forget_abstract_value(state, arg_v);
                                        }
                                    }
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

                // A builder chain that holds an escaper
                // (`sb.append(n).append(escapeHtml4(x))`) is one node whose
                // callee label is the sanitizer.  The escaper clears the
                // node's return value, not the other operands appended to
                // the builder, so the append is still stored, each operand
                // narrowed by the calls that wrap it.
                if transfer.lang == Lang::Java {
                    for c in [Some(callee.as_str()), info.call.outer_callee.as_deref()]
                        .into_iter()
                        .flatten()
                    {
                        if java_builder_store_op(info, args, receiver, transfer, c, state).is_some()
                        {
                            try_container_propagation(
                                inst, info, args, receiver, state, transfer, c, ssa,
                            );
                            break;
                        }
                    }
                }

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
                        apply_container_read_receiver_validation(inst, ssa, transfer, state);
                        if let Some(sib) = &sibling
                            && !sib.caps.is_empty()
                        {
                            merge_taint_into(state, inst.value, sib.caps, &sib.origins);
                        }
                        return;
                    }
                } else {
                    // Curl special case: propagate URL taint to handle
                    if try_curl_url_propagation(inst, info, args, state) {
                        if let Some(sib) = &sibling
                            && !sib.caps.is_empty()
                        {
                            merge_taint_into(state, inst.value, sib.caps, &sib.origins);
                        }
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

                    // No labels and no summary, default propagation (gen/kill).
                    // A SQL query call that declares its payload positions
                    // (the query text) returns rows, not the text: values
                    // bound through the other positions do not flow into the
                    // result, only the receiver and the query text do.
                    let (use_caps, use_origins) = match sql_query_payload_positions(info) {
                        Some(payload) => {
                            let (mut caps, mut origins) = match sql_query_text_field_names(info) {
                                // Config-object form
                                // (`pool.query({ text, values })`): only the
                                // SQL text fields of the object are the
                                // query, `values` is bound.
                                Some(names) => {
                                    collect_named_args_taint(args, state, ssa, &payload, &names)
                                }
                                None => collect_args_taint(args, &None, state, &payload),
                            };
                            if let Some(taint) = receiver.as_ref().and_then(|rv| state.get(*rv)) {
                                caps |= taint.caps;
                                for orig in &taint.origins {
                                    push_origin_bounded(&mut origins, *orig);
                                }
                            }
                            (caps, origins)
                        }
                        None => collect_args_taint(args, receiver, state, &[]),
                    };
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
                    if !return_bits.is_empty() && !fresh_source_applied {
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
                            transfer.lang,
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
                            transfer.lang,
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
                            // The aggregate strip would let a wrapper that
                            // escapes one parameter clean a source passed in
                            // another (`card(req.query.t, req.query.b)`).
                            // When the inline sources are bound to argument
                            // positions, each keeps what its own parameter
                            // lets through.
                            let src_positions: SmallVec<[usize; 2]> = info
                                .call
                                .arg_uses
                                .iter()
                                .enumerate()
                                .filter(|(_, g)| g.iter().any(|u| u.starts_with("__nyx_src_")))
                                .map(|(i, _)| i)
                                .collect();
                            if src_positions.is_empty() {
                                return_bits &= !oc_sum.sanitizer_caps;
                            } else {
                                let bits = return_bits;
                                return_bits = Cap::empty();
                                for p in src_positions {
                                    if oc_sum.propagating_params.is_empty()
                                        || oc_sum.propagating_params.contains(&p)
                                    {
                                        return_bits |=
                                            bits & !effective_param_sanitizer(oc_sum, p, state);
                                    }
                                }
                            }
                            if return_bits.is_empty() {
                                return_origins.clear();
                            }
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
            //
            // Classes whose instance IS the path or string value (Java
            // `File`, `String`, `StringBuilder`; see
            // `constructor_is_value_wrapper`) keep every cap.  When the CFG
            // moved an inline source argument into the callee
            // (`new File(req.getParameter("f"))`), the class name is in
            // `outer_callee`.
            let ctor_is_value =
                crate::ssa::type_facts::constructor_is_value_wrapper(transfer.lang, callee)
                    || info.call.outer_callee.as_deref().is_some_and(|oc| {
                        crate::ssa::type_facts::constructor_is_value_wrapper(transfer.lang, oc)
                    });
            if info.call.is_constructor && !ctor_is_value && !return_bits.is_empty() {
                let strip = Cap::FILE_IO | Cap::FMT_STRING | Cap::URL_ENCODE | Cap::JSON_PARSE;
                return_bits &= !strip;
                if return_bits.is_empty() {
                    return_origins.clear();
                }
            }

            // Behaviour-based open-redirect confiner (CVE-2026-42259): when
            // the callee normalises its input and rejects protocol-relative
            // (`//`) and `scheme:` URLs before returning the confined value,
            // its return is provably same-origin — strip OPEN_REDIRECT so
            // redirecting to the result no longer fires.  Applied at this
            // universal commit point so it holds regardless of which
            // resolution path (inline / summary / label) produced
            // `return_bits`.  Sound: the recogniser requires backslash
            // normalisation + `//`-prefix rejection + scheme rejection (see
            // `detect_open_redirect_normalizer`); the weak
            // `!url.includes("//")` form is not recognised.
            // The confining call is often the *outer* wrapper of a nested
            // source expression — `const dest = normalize_relative_url(
            // decodeURIComponent(req.body.dest))` lowers to the `req.body.dest`
            // source flowing straight into `dest`, with the wrapper recorded
            // only in `info.call.outer_callee`.  Consult both the primary
            // callee and the outer wrapper.
            if return_bits.contains(Cap::OPEN_REDIRECT) {
                let primary_confines = summary_confines_open_redirect(
                    transfer,
                    crate::labels::bare_method_name(callee),
                );
                let outer_confines = info.call.outer_callee.as_deref().is_some_and(|oc| {
                    summary_confines_open_redirect(transfer, crate::labels::bare_method_name(oc))
                });
                if primary_confines || outer_confines {
                    return_bits &= !Cap::OPEN_REDIRECT;
                    if return_bits.is_empty() {
                        return_origins.clear();
                    }
                }
            }

            // Sibling operands flow into the expression value directly; none
            // of the callee handling above applies to them.  Validation
            // follows the operands: siblings alone keep the unresolved-call
            // rule (validated when every tainted one is), and an unvalidated
            // sibling withdraws a validation this call just granted.
            if let Some(sib) = &sibling
                && !sib.caps.is_empty()
            {
                let callee_contributed = !return_bits.is_empty();
                return_bits |= sib.caps;
                for o in &sib.origins {
                    push_origin_bounded(&mut return_origins, *o);
                }
                if let Some(sym) = result_sym {
                    if !sib.all_validated {
                        if !result_was_validated {
                            state.validated_must.remove(sym);
                        }
                    } else if !callee_contributed {
                        state.validated_must.insert(sym);
                        state.validated_may.insert(sym);
                    }
                }
                if let Some(aliases) = transfer.base_aliases
                    && !aliases.is_empty()
                {
                    propagate_taint_to_aliases(
                        inst,
                        state,
                        sib.caps,
                        &sib.origins,
                        aliases,
                        ssa,
                        transfer.lang,
                    );
                }
            }

            // Write result
            if return_bits.is_empty() || binder_error_return {
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
                    // `container[key]`: the key selects an element, the value
                    // comes from the container.
                    if let Some(key) = info.index_read_key.as_deref()
                        && ssa
                            .value_defs
                            .get(use_val.0 as usize)
                            .and_then(|vd| vd.var_name.as_deref())
                            == Some(key)
                    {
                        continue;
                    }
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
                            transfer.lang,
                        );
                    }
                }
            }

            // Check for source labels.  Skip outer-node Source pickup when
            // this Assign was emitted by the bare-array slot-scoped kill arm
            // in `src/ssa/lower.rs` (per-slot Source classification puts the
            // SsaValue into `ssa.slot_scoped_assigns`).  Operand union still
            // ran above, so transitive taint via inner uses propagates.
            let suppress_node_source = ssa.slot_scoped_assigns.contains(&inst.value);
            let mut node_source_applied = false;
            if !suppress_node_source {
                for lbl in &info.taint.labels {
                    if let DataLabel::Source(bits) = lbl {
                        node_source_applied |= !bits.is_empty();
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
            }

            // A numeric conversion or arithmetic result carries no payload,
            // whatever its operands (or a source on this node) contributed.
            if info.yields_number {
                combined_caps = Cap::empty();
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
                            transfer.lang,
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

                // Validated-reconstruction propagation: when a tainted value is
                // rebuilt from operands that are themselves all validated (e.g.
                // `$target = $octet[0] . '.' . $octet[1] . '.' . $octet[2]`
                // where each `$octet[i]` inherited an `is_numeric` branch-guard
                // validation), the result is validated too.  We AND `must` /
                // OR `may` over the TAINTED operands only — string literals and
                // other untainted operands carry no taint into the sink, so
                // they neither contribute to nor block validation.  This is the
                // scalar counterpart to the field-cell `must_all`/`may_any`
                // lift below and closes the "validate-each-part then rebuild"
                // idiom (DVWA exec/source/impossible.php).
                // A Source label on this node is fresh taint that no
                // operand vouches for, so it counts as an unvalidated part.
                let mut tainted_must_all = !node_source_applied;
                let mut tainted_may_any = false;
                let mut saw_tainted = node_source_applied;
                for &u in uses {
                    if state.get(u).is_some() {
                        saw_tainted = true;
                        let (am, av) = ssa_value_validated_bits(u, ssa, transfer.interner, state);
                        tainted_must_all &= am;
                        tainted_may_any |= av;
                    }
                }
                if saw_tainted
                    && (tainted_must_all || tainted_may_any)
                    && let Some(name) = ssa
                        .value_defs
                        .get(inst.value.0 as usize)
                        .and_then(|vd| vd.var_name.as_deref())
                    && let Some(sym) = transfer.interner.get(name)
                {
                    if tainted_must_all {
                        state.validated_must.insert(sym);
                    }
                    if tainted_may_any {
                        state.validated_may.insert(sym);
                    }
                }
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
            // intrinsic-source contract. Gate is set by the caller: for
            // JS/TS only bodies with no known caller in the file or the
            // call graph (and never inlined callees), for Java only
            // AnonymousFunction bodies.
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
                    // Destructured Express request param (`({ query }, res) =>
                    // …`): `query` lowers as a bare `Param`, so the textual
                    // `req.query` source label never matches. Seed it only when
                    // a sibling response param is present (the route-handler
                    // signal), so a plain `paginate(query)` stays un-seeded.
                    let is_destructured_request_field =
                        crate::labels::is_express_request_field_name(var_name) && {
                            let eb = &ssa.blocks[ssa.entry.0 as usize];
                            eb.phis.iter().chain(eb.body.iter()).any(|i| {
                                matches!(i.op, SsaOp::Param { .. })
                                    && ssa
                                        .value_defs
                                        .get(i.value.0 as usize)
                                        .and_then(|vd| vd.var_name.as_deref())
                                        .map(crate::labels::is_handler_response_param_name)
                                        .unwrap_or(false)
                            })
                        };
                    // Request-bound formal (`@Query('q') q`, `@Body() dto`) or
                    // a field path rooted at one (`dto.cmd`): the framework
                    // fills it from the request whatever its name.
                    let root = var_name.split('.').next().unwrap_or(var_name);
                    // Only TypeScript decorators set the flag for this seed;
                    // other languages fill it for their own routing and the
                    // seeding passes for those read it elsewhere.
                    let is_request_bound = matches!(transfer.lang, Lang::TypeScript)
                        && transfer
                            .param_route_capture
                            .is_some_and(|flags| flags.iter().any(|f| *f))
                        && request_bound_formal(ssa, transfer, root);
                    if crate::labels::is_js_ts_handler_param_name(var_name)
                        || root_is_handler
                        || is_destructured_request_field
                        || is_request_bound
                    {
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
        apply_container_read_receiver_validation(inst, ssa, transfer, state);
    }

    // Constraint propagation through instructions.
    //
    // `path_env` is `Arc`-shared (copy-on-write). Reads (`env.get`) borrow
    // through the `Arc` without cloning; `Arc::make_mut` is taken lazily,
    // only once a mutation is actually about to happen. Instructions that
    // fall through to the `_ =>` arm (the common case: calls, phis, sources,
    // multi-use assigns) never deep-copy the env, so a block performing no
    // constraint refinement shares its predecessor's `PathEnv` for free.
    if let Some(env_arc) = state.path_env.as_mut() {
        match &inst.op {
            SsaOp::Assign(uses) if uses.len() == 1 => {
                // Copy: propagate facts from source to destination.
                // Read first (immutable, no clone), decide whether any
                // mutation is needed, then `make_mut` once.
                let src_fact = env_arc.get(uses[0]);
                let do_copy = !src_fact.is_top();
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
                let cast_kind = node_info
                    .cast_target_type
                    .as_ref()
                    .and_then(|cast_type| crate::constraint::solver::parse_type_name(cast_type));
                if do_copy || cast_kind.is_some() {
                    let env = Arc::make_mut(env_arc);
                    if do_copy {
                        env.refine(inst.value, &src_fact);
                        env.assert_equal(inst.value, uses[0]);
                    }
                    if let Some(kind) = cast_kind {
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
                    let env = Arc::make_mut(env_arc);
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

    // Forward abstract value transfer. `Arc::make_mut` forks the shared
    // AbstractState lazily, the first mutating instruction in a block pays
    // the single deep copy; all later instructions mutate the now-unique Arc
    // in place. Stored snapshots (exit-state, pred_states) keep sharing the
    // pre-fork Arc as refcount bumps.
    if let Some(ref mut abs) = state.abstract_state {
        transfer_abstract(inst, cfg, Arc::make_mut(abs), Some(transfer.lang));
    }

    // Cross-file abstract return injection.
    // Applied after transfer_abstract so summary-provided facts override the
    // default Top that transfer_abstract assigns to unknown callees.
    if let Some(ref abs_val) = callee_return_abstract {
        if let Some(ref mut abs) = state.abstract_state {
            Arc::make_mut(abs).set(inst.value, abs_val.clone());
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
    // A base built by a call can be anything the callee returns, and a group
    // with several values is an expression over several names: neither is
    // the single constant the domain below describes.
    if info.arg_callees.get(base_idx).is_some_and(Option::is_some) {
        return None;
    }
    let bv = match args.get(base_idx) {
        Some(group) if group.len() == 1 => group[0],
        _ => return None,
    };
    let dom = abs.get(bv).string.domain?;
    if dom.len() == 1 {
        Some(dom.into_iter().next().expect("len==1 guards index"))
    } else {
        None
    }
}

/// String knowledge for the path (reference) argument of a URL builder call:
/// the inline literal, the literal head of an inline `"/v1/" + p` /
/// template / f-string argument, or, for a plain variable argument, the
/// variable's abstract fact.  An argument that is itself a call result has no
/// usable fact, since the callee may rewrite the text.
fn url_builder_path_fact(
    info: &NodeInfo,
    callee: &str,
    args: &[SmallVec<[SsaValue; 2]>],
    abs: &AbstractState,
    path_idx: usize,
) -> crate::abstract_interp::StringFact {
    use crate::abstract_interp::StringFact;
    if let Some(Some(lit)) = info.call.arg_string_literals.get(path_idx) {
        return StringFact::exact(lit);
    }
    if let Some(Some(prefix)) = info.call.arg_string_prefixes.get(path_idx) {
        return StringFact::from_prefix(prefix);
    }
    // Only an argument that is exactly a name has the name's fact: a slice
    // or a call over it can drop the head that keeps the host.
    bare_name_arg(info, callee, args, path_idx)
        .map(|v| abs.get(v).string)
        .unwrap_or_else(StringFact::top)
}

/// Abstract value of an integer constant.
fn int_const_value(n: i64) -> crate::abstract_interp::AbstractValue {
    use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, PathFact, StringFact};
    AbstractValue {
        interval: IntervalFact::exact(n),
        string: StringFact::top(),
        bits: BitFact::from_const(n),
        path: PathFact::top(),
    }
}

/// Abstract value of a string constant.
///
/// The PathFact axes come from the *literal* content.  An empty string has no
/// `..` segment and no absolute root, both axes proven safe, so a Const `""`
/// (Python / JS / TS / Java rejection-arm sentinel) carries a path-safe fact
/// even without a per-language allocator recogniser like Rust's
/// `String::new()`.  Non-empty literals also surface their own
/// dotdot/absolute axes when the literal text proves them.
///
/// The `Const` transfer and the body's constant table both build their facts
/// here, so the table entry equals what the transfer would store and the
/// state does not keep a copy of it.
fn string_const_value(s: &str) -> crate::abstract_interp::AbstractValue {
    use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, PathFact, StringFact};
    let mut pf = PathFact::top();
    if !s.contains("..") {
        pf = pf.with_dotdot_cleared();
    }
    if !(s.starts_with('/') || s.starts_with('\\')) {
        pf = pf.with_absolute_cleared();
    }
    AbstractValue {
        interval: IntervalFact::top(),
        string: StringFact::exact(s),
        bits: BitFact::top(),
        path: pf,
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
    transfer_abstract_inner(inst, cfg, abs, lang);
    // A variable that can change behind the SSA form's back (`&p`, a closure
    // write) keeps no excluded-character claim.
    if cfg[inst.cfg_node].aliased_def {
        let mut value = abs.get(inst.value);
        if value.string.has_exclusions() {
            value.string = value.string.without_exclusions();
            abs.set(inst.value, value);
        }
    }
}

fn transfer_abstract_inner(inst: &SsaInst, cfg: &Cfg, abs: &mut AbstractState, lang: Option<Lang>) {
    use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, PathFact, StringFact};
    use crate::cfg::BinOp;

    let info = &cfg[inst.cfg_node];
    // Text-only questions about the callee, answered once per distinct callee.
    let facts = match &inst.op {
        SsaOp::Call { callee, .. } => call_text_facts(
            lang,
            callee,
            info.call.outer_callee.as_deref(),
            info.call.is_constructor,
        ),
        _ => CallTextFacts::default(),
    };
    match &inst.op {
        SsaOp::Const(Some(text)) => {
            let trimmed = text.trim();
            if let Ok(n) = trimmed.parse::<i64>() {
                abs.set(inst.value, int_const_value(n));
            } else if is_string_const(trimmed) {
                abs.set(
                    inst.value,
                    string_const_value(&strip_string_quotes(trimmed)),
                );
            }
            // Bool/Null/other: leave as Top
        }

        // Phase 08 / Phase 14: `(base, path)` URL builder origin-lock.
        // When the base arg is a literal (read off
        // `info.call.arg_string_literals[base_idx]`) or a const-bound
        // identifier whose abstract `StringFact.domain` is a singleton
        // (e.g. `const BASE = "https://api.cal.com"; new URL(path, BASE)`),
        // seed the result's [`StringFact`] so `is_string_safe_for_ssrf` can
        // suppress the SSRF sink at the downstream HTTP call.  The arg
        // position table lives in [`crate::ssa::type_facts::url_builder_arg_indices`]:
        // JS/TS `new URL(path, base)`, Python `urljoin(base, path)`, Go
        // `url.JoinPath(base, ...)`, Java `new URL(URL, spec)`, Ruby
        // `URI.join(base, path)`.
        //
        // Reference resolution is not concatenation: an absolute or
        // protocol-relative path replaces the base's host, so the origin
        // stays pinned only when the path is provably a relative reference
        // (`StringFact::from_url_with_base`).  Go `JoinPath` appends path
        // segments and pins the origin whatever they hold.
        //
        // This arm owns every two-argument builder call.  The generic
        // string-prefix arms below read the *first* argument, which for
        // `urljoin(base, path)` is the base and for `new URL(path, base)`
        // the attacker's path, and would lock the origin of a builder whose
        // base is unknown.  A builder without a concrete base leaves its
        // result Top.
        SsaOp::Call { callee, args, .. } if args.len() >= 2 && facts.url_builder.is_some() => {
            let lang_u = lang.expect("a URL builder fact implies a language");
            let (path_idx, base_idx) = facts.url_builder.expect("guard ensures Some");
            if let Some(base) = url_builder_concrete_base(info, args, abs, base_idx) {
                let path_fact = url_builder_path_fact(info, callee, args, abs, path_idx);
                let string = if crate::ssa::type_facts::url_builder_appends_path(lang_u) {
                    StringFact::from_url_joined_path(&base, &path_fact)
                } else {
                    StringFact::from_url_with_base(&base, &path_fact)
                };
                abs.set(
                    inst.value,
                    AbstractValue {
                        interval: IntervalFact::top(),
                        string,
                        bits: BitFact::top(),
                        path: PathFact::top(),
                    },
                );
            }
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
            // `"/" + name`: the literal followed by whatever the name holds.
            let string = match &inst.op {
                SsaOp::Assign(uses) if info.string_concat_tail && uses.len() == 1 => {
                    StringFact::exact(prefix).concat(&abs.get(uses[0]).string)
                }
                _ => StringFact::from_prefix(prefix),
            };
            abs.set(
                inst.value,
                AbstractValue {
                    interval: IntervalFact::top(),
                    string,
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
        // fires when that arm doesn't.  A two-argument `(path, base)` call is
        // the builder arm's; only the single-argument form passes its
        // argument through.
        SsaOp::Call { callee, args, .. } if facts.url_single_arg && args.len() < 2 => {
            // A literal argument has no SSA use, so it is read off the node:
            // `URL base = new URL("https://api.example.com/")` is what a later
            // `new URL(base, spec)` resolves against.
            let literal_arg = node_describes_call(info, callee)
                .then(|| info.call.arg_string_literals.first())
                .flatten()
                .and_then(|l| l.as_deref());
            let arg_string = match (args.first().and_then(|g| g.first().copied()), literal_arg) {
                (Some(pv), _) => abs.get(pv).string,
                (None, Some(lit)) => StringFact::exact(lit),
                (None, None) => StringFact::top(),
            };
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
        SsaOp::Call { .. } if facts.int_producing => {
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

        // Go string functions whose result keeps part of what the input
        // proves: `strings.Trim*` leaves a first character outside the
        // cutset, `strings.ReplaceAll` removes a character, `fmt.Sprintf`
        // concatenates its format with its arguments.
        SsaOp::Call { callee, args, .. }
            if lang == Some(Lang::Go) && go_string_fn(callee).is_some() =>
        {
            if let Some(string) = go_string_call_fact(callee, info, args, abs) {
                abs.set(
                    inst.value,
                    AbstractValue {
                        interval: IntervalFact::top(),
                        string,
                        bits: BitFact::top(),
                        path: PathFact::top(),
                    },
                );
            }
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
            let mut input_fact = input_val
                .map(|v| abs.get(v).path)
                .unwrap_or_else(PathFact::top);
            // A value that starts with `/` is rooted, whether the text is a
            // tracked variable (`"/" + name`) or the call's own first argument
            // (`filepath.Clean("/" + name)`).  The node describes the call
            // only when the SSA call is the node's own call, not one nested in
            // an argument of the statement's outer call.
            if input_fact.absolute == crate::abstract_interp::Tri::Maybe {
                let rooted = |p: &str| p.starts_with('/') || p.starts_with('\\');
                // The value read is the call's own first argument, and only
                // when that argument is exactly a name: `p[1:]` or a call on
                // `p` drops the leading `/` that `p`'s prefix shows.
                let by_value = receiver.is_none()
                    && bare_name_arg(info, callee, args, 0)
                        .is_some_and(|v| abs.get(v).string.prefix.as_deref().is_some_and(rooted));
                let by_arg = node_describes_call(info, callee)
                    && info
                        .call
                        .arg_string_prefixes
                        .first()
                        .and_then(|p| p.as_deref())
                        .is_some_and(rooted);
                if by_value || by_arg {
                    input_fact.absolute = crate::abstract_interp::Tri::Yes;
                }
            }

            // Primary path-producing primitives, per-language dispatch.
            let lang_unwrapped = lang.expect("guard ensures lang.is_some()");
            if let Some(pf) =
                segment_join_under_rooted_base(lang_unwrapped, callee, info, args, abs)
            {
                abs.set(inst.value, AbstractValue::with_path_fact(pf));
            } else if let Some(pf) =
                crate::abstract_interp::path_domain::classify_path_primitive_for_lang(
                    lang_unwrapped,
                    callee,
                    &input_fact,
                )
            {
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
                            let mut new_fact = input_fact;
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

    // Prefix-from-CFG for Call instructions whose result is the variable
    // binding (e.g. `url = wrapper('lit' + userPath)`).  The CFG node carries
    // `string_prefix` extracted from the call's URL argument; without it the
    // Call result's StringFact is Top and downstream SSRF suppression
    // (`is_call_abstract_safe` looking at `axios.get(url)`'s own first arg)
    // cannot read the lock.  It only fills in the string component, after the
    // arms above, so a path primitive (`Clean("/data/" + f)`) keeps its
    // PathFact.  A `(base, path)` URL builder never takes it: the prefix
    // belongs to an argument, not to the URL the builder resolves.
    if let (SsaOp::Call { args, .. }, Some(prefix)) = (&inst.op, info.string_prefix.as_deref()) {
        let is_url_builder = args.len() >= 2 && facts.url_builder.is_some();
        if !is_url_builder {
            let mut value = abs.get(inst.value);
            // `"/" + f(x)`: the literal followed by the call's own result,
            // when this is the call the node's right-hand side ends in.
            if info.string_concat_tail
                && info.call.callee.as_deref() == callee_of(&inst.op)
                && !value.string.is_bottom()
            {
                value.string = StringFact::exact(prefix).concat(&value.string);
                abs.set(inst.value, value);
            } else if value.string.is_top() {
                value.string = StringFact::from_prefix(prefix);
                abs.set(inst.value, value);
            }
        }
    }
}

/// Drop what the abstract domains know about `v`: a call has written into the
/// buffer it names (`file.read_to_end(&mut buf)`), so the facts of the
/// allocation that came before (an empty `Vec::new()`) no longer describe it.
fn forget_abstract_value(state: &mut SsaTaintState, v: SsaValue) {
    if let Some(abs) = state.abstract_state.as_mut() {
        Arc::make_mut(abs).set(v, crate::abstract_interp::AbstractValue::top());
    }
}

/// The SSA value of positional argument `i` of the call `callee` when the
/// argument is exactly a name (see `CallMeta::arg_bare_names`), so the
/// value's abstract facts are the argument's.  `None` for any other argument
/// shape, for a call the node does not describe, and when the use group does
/// not hold exactly one value.
fn bare_name_arg(
    info: &NodeInfo,
    callee: &str,
    args: &[SmallVec<[SsaValue; 2]>],
    i: usize,
) -> Option<SsaValue> {
    if i >= 64 || info.call.arg_bare_names & (1u64 << i) == 0 {
        return None;
    }
    if !node_describes_call(info, callee) {
        return None;
    }
    match args.get(i) {
        Some(group) if group.len() == 1 => Some(group[0]),
        _ => None,
    }
}

fn callee_of(op: &SsaOp) -> Option<&str> {
    match op {
        SsaOp::Call { callee, .. } => Some(callee.as_str()),
        _ => None,
    }
}

/// Go standard-library string functions with a string-fact transfer.
fn go_string_fn(callee: &str) -> Option<()> {
    matches!(
        callee,
        "strings.Trim"
            | "strings.TrimLeft"
            | "strings.TrimRight"
            | "strings.TrimSpace"
            | "strings.ReplaceAll"
            | "fmt.Sprintf"
    )
    .then_some(())
}

/// String fact of a call to one of [`go_string_fn`], from the literal
/// arguments the node records and the facts of arguments that are bare names.
/// `None` when the call has no usable shape (a cutset that is not a literal,
/// a format with `%[n]d` or `%*d`).
fn go_string_call_fact(
    callee: &str,
    info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    abs: &AbstractState,
) -> Option<crate::abstract_interp::StringFact> {
    use crate::abstract_interp::StringFact;
    use crate::abstract_interp::string_domain::{AsciiSet, go_literal_value};
    if !node_describes_call(info, callee) {
        return None;
    }
    // The value of string-literal argument `i`, escapes read.
    let literal = |i: usize| -> Option<String> {
        let text = info.call.arg_string_literals.get(i)?.as_deref()?;
        let is_raw = i < 64 && info.call.arg_raw_string_mask & (1u64 << i) != 0;
        go_literal_value(text, is_raw)
    };
    let arg_fact = |i: usize| {
        bare_name_arg(info, callee, args, i)
            .map(|v| abs.get(v).string)
            .unwrap_or_else(StringFact::top)
    };
    match callee {
        "strings.Trim" | "strings.TrimLeft" | "strings.TrimRight" => {
            let cutset = AsciiSet::of_str(&literal(1)?);
            Some(arg_fact(0).trimmed(
                cutset,
                callee != "strings.TrimRight",
                callee != "strings.TrimLeft",
            ))
        }
        "strings.TrimSpace" => {
            Some(arg_fact(0).trimmed(AsciiSet::of_str(" \t\n\x0b\x0c\r"), true, true))
        }
        "strings.ReplaceAll" => {
            // A single character `old` and a literal `new` that lacks it.
            let old_text = literal(1)?;
            let mut chars = old_text.chars();
            let old = chars.next().filter(|c| c.is_ascii())?;
            if chars.next().is_some() {
                return None;
            }
            let new_chars = AsciiSet::of_str(&literal(2)?);
            Some(arg_fact(0).with_char_replaced(old, new_chars))
        }
        "fmt.Sprintf" => go_sprintf_fact(&literal(0)?, arg_fact),
        _ => None,
    }
}

/// `fmt.Sprintf(format, args...)` as a concatenation of the format's literal
/// runs and, for each plain `%s` / `%v` directive, the fact of its argument.
/// Any other directive contributes an unknown string.  `None` for a format
/// with an escape, an explicit argument index or a `*` width, which this does
/// not follow.
fn go_sprintf_fact(
    format: &str,
    arg_fact: impl Fn(usize) -> crate::abstract_interp::StringFact,
) -> Option<crate::abstract_interp::StringFact> {
    use crate::abstract_interp::StringFact;
    if format.contains('\\') {
        return None;
    }
    let mut acc = StringFact::exact("");
    let mut literal_run = String::new();
    let mut next_arg = 1usize;
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            literal_run.push(c);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            literal_run.push('%');
            continue;
        }
        if !literal_run.is_empty() {
            acc = acc.concat(&StringFact::exact(&literal_run));
            literal_run.clear();
        }
        let mut plain = true;
        let verb = loop {
            match chars.next()? {
                '[' | '*' => return None,
                v if v.is_ascii_alphabetic() => break v,
                _ => plain = false,
            }
        };
        let segment = if plain && matches!(verb, 's' | 'v') {
            arg_fact(next_arg)
        } else {
            StringFact::top()
        };
        next_arg += 1;
        acc = acc.concat(&segment);
    }
    if !literal_run.is_empty() {
        acc = acc.concat(&StringFact::exact(&literal_run));
    }
    Some(acc)
}

/// True when `info` is the CFG node of the call `callee`, not of an outer
/// call whose argument list the SSA call sits in (`os.ReadFile(filepath.Clean(x))`
/// shares one node between both calls).  Per-argument literals and prefixes on
/// the node belong to the node's own call only.
fn node_describes_call(info: &NodeInfo, callee: &str) -> bool {
    let leaf = |c: &str| c.rsplit(['.', ':']).next().unwrap_or(c).to_string();
    info.call
        .callee
        .as_deref()
        .is_some_and(|node_callee| leaf(node_callee) == leaf(callee))
}

/// PathFact of `filepath.Join(base, elems...)` / `path.join(base, elems...)`
/// when `base` is a rooted literal and no later element can carry a `..`.
///
/// These joins treat every later argument as a path segment and clean the
/// result, so the result stays under `base`: an absolute element does not
/// replace it (unlike Python's `os.path.join`), and `..` is the only way out.
/// `filepath.Join("/var/data", filepath.Clean("/" + name))` and
/// `filepath.Join("/var/data", filepath.Base(name))` qualify; a bare request
/// value does not, and keeps the classifier's `normalized`-only fact.
fn segment_join_under_rooted_base(
    lang: Lang,
    callee: &str,
    info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    abs: &AbstractState,
) -> Option<crate::abstract_interp::PathFact> {
    use crate::abstract_interp::{PathFact, Tri};
    let is_segment_join = match lang {
        Lang::Go => matches!(callee, "filepath.Join" | "path.Join"),
        Lang::JavaScript | Lang::TypeScript => {
            matches!(callee, "path.join" | "path.posix.join")
        }
        _ => false,
    };
    if !is_segment_join || !node_describes_call(info, callee) {
        return None;
    }
    let base = info.call.arg_string_literals.first()?.as_deref()?;
    if !base.starts_with('/') || base.split('/').any(|seg| seg == "." || seg == "..") {
        return None;
    }
    let positional = info.call.arg_uses.len();
    if positional < 2 {
        return None;
    }
    // Each element is its own path segment run, so a `..` can only come from
    // inside one element.  A non-literal element must be exactly a name whose
    // fact rules `..` out: `clean + "/.."` has the same single SSA use as
    // `clean` but not its fact.
    for i in 1..positional {
        let literal = info
            .call
            .arg_string_literals
            .get(i)
            .and_then(|l| l.as_deref());
        let ok = match literal {
            Some(l) => !l.contains(".."),
            None => bare_name_arg(info, callee, args, i)
                .is_some_and(|v| abs.get(v).path.dotdot == Tri::No),
        };
        if !ok {
            return None;
        }
    }
    let mut fact = PathFact::top().with_dotdot_cleared().with_prefix_lock(base);
    fact.normalized = Tri::Yes;
    fact.absolute = Tri::Yes;
    Some(fact)
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
    // See [`transfer_block`]; skips the per-call confinement string work when no
    // confiner summary exists for this body.
    confinement: ConfinementGates,
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
                        Arc::make_mut(abs).set(phi.value, joined);
                    }
                }
            }
        }
    }

    // Lazily-computed set of argument names wrapped by an open-redirect
    // confiner across the whole body (CVE-2022-24776); only built when the
    // block actually reaches an OPEN_REDIRECT sink whose own `arg_uses` did not
    // already reveal the wrapper.
    let mut or_confined_names: Option<HashSet<String>> = None;

    // Process body with sink detection
    for inst in &block.body {
        transfer_inst(inst, cfg, ssa, transfer, &mut state);
        // Assert-guard path confinement (CVE-2021-21234).  Mirror the clearing
        // done in `transfer_block`: this event-collection replay is a distinct
        // pass over the block body, so the FILE_IO strip on an
        // `Assert.isTrue(p.startsWith(base))`-style guard's confined args must
        // be applied here too — otherwise the later sink call in the same block
        // (`streamContent(path, …)`) is scanned against un-narrowed taint and
        // re-fires the finding the confinement was meant to suppress.
        if confinement.assert {
            apply_call_post_confinement(inst, ssa, transfer, &mut state);
        }
        // Path-safety-validator rejection confinement (CVE-2026-53956): mirror
        // the `apply_path_validator_confinement` FILE_IO strip so the emitted
        // `fs::write(path.join(segment), …)` finding is suppressed in the
        // event-collection replay, not just in the dataflow replay.
        if confinement.path_validator {
            apply_path_validator_confinement(inst, ssa, transfer, &mut state);
        }
        // Return-value path confinement (CVE-2020-5221): mirror the call-result
        // FILE_IO strip so the emitted `fopen(compose_abspath(...))` finding is
        // suppressed here, not just in the dataflow replay.
        if confinement.return_confiner {
            apply_call_return_confinement(inst, transfer, &mut state);
        }

        // Check for sink
        let info = &cfg[inst.cfg_node];
        if info.all_args_literal
            && !literal_arg_call_has_tainted_subject_receiver(inst, &state, transfer, ssa)
        {
            continue;
        }

        // Parameterized SQL queries are safe, skip sink detection.
        if info.parameterized_query {
            continue;
        }

        let sink_info = resolve_sink_info(info, transfer);
        let mut sink_caps = sink_info.caps;

        // Nested-expression open-redirect confiner (CVE-2022-24776).  When the
        // redirect target is wrapped by a same-origin confiner in one nested
        // expression (`redirect(get_safe_redirect(next_url))`), the SSA dropped
        // the unlabeled wrapper and the tainted URL reaches the sink directly.
        // Recover the confinement from the sink node's `arg_uses`, falling back
        // to the whole-body confined-argument-name set for the `return`-node
        // duplicate whose `arg_uses` is empty.  The same-origin host check
        // neutralises both OPEN_REDIRECT and the SSRF bit the redirect sink also
        // carries, so a validated redirect no longer fires either finding.
        if sink_caps.intersects(Cap::OPEN_REDIRECT) {
            let mut wrapped = sink_arg_wrapped_by_open_redirect_confiner(info, transfer);
            if !wrapped {
                let set = or_confined_names
                    .get_or_insert_with(|| open_redirect_confined_arg_names(ssa, cfg, transfer));
                if !set.is_empty() {
                    if let SsaOp::Call { args, .. } = &inst.op {
                        wrapped = args.iter().flatten().any(|v| {
                            ssa.def_of(*v)
                                .var_name
                                .as_deref()
                                .is_some_and(|n| set.contains(n))
                        });
                    }
                }
            }
            if wrapped {
                sink_caps &= !(Cap::OPEN_REDIRECT | Cap::SSRF);
            }
        }

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
        strip_receiver_incompatible_sink_caps(&mut sink_caps, inst, info, transfer, &state);

        // Type-qualified sink resolution: when normal sink resolution found nothing,
        // try using the receiver's inferred type to construct a qualified callee name.
        // For known type-qualified ORM raw-SQL methods (`TypeOrmRepo.query` et al.),
        // also capture the restricted payload-arg list so bind-array taint at arg 1+
        // does not fire.
        let mut tq_filters: SmallVec<[TqSinkFilter; 2]> = SmallVec::new();
        if sink_caps.is_empty() {
            if let SsaOp::Call {
                callee, receiver, ..
            } = &inst.op
            {
                // A declared receiver type needs no SSA receiver: a Java
                // field read in a body lowered without its class scope has
                // no value, but its declaration still names the type.
                let declared = info.call.receiver_decl_type.as_ref();
                if (receiver.is_some()
                    && (transfer.type_facts.is_some() || state.path_env.is_some()))
                    || declared.is_some()
                {
                    let (tq_labels, tq_args) = resolve_type_qualified_labels_with_args(
                        callee,
                        info.call.outer_callee.as_deref(),
                        *receiver,
                        transfer.type_facts,
                        state.path_env.as_deref(),
                        declared,
                        transfer.lang,
                        transfer.extra_labels,
                        Some(ssa),
                    );
                    for lbl in &tq_labels {
                        if let DataLabel::Sink(bits) = lbl {
                            sink_caps |= *bits;
                        }
                    }
                    tq_filters = tq_args;
                    // The qualified name (`FileHandle.println`) also matches
                    // the bare suffix rules the receiver type just ruled out.
                    strip_receiver_incompatible_sink_caps(
                        &mut sink_caps,
                        inst,
                        info,
                        transfer,
                        &state,
                    );
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
                        let arg_callees_name: Option<String> =
                            info.arg_callees.get(cb_idx).and_then(|ac| ac.clone());
                        let ssa_var_name: Option<String> =
                            if let SsaOp::Call { args, .. } = &inst.op {
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
                            // Mark every callback-resolved sink site as
                            // `from_chain=true`: the callback callee is a
                            // logically-deeper frame than the outer
                            // `.then(cb)` / `setImmediate(cb)` / etc. call
                            // site. Without this, `should_promote_sink_site`
                            // filters same-file callback sinks out (the file
                            // matches `caller_namespace`), and the trace
                            // finding falls back to the outer dispatch line
                            // instead of attributing to the actual sink.
                            let cb_param_to_sink_sites: Vec<(usize, SmallVec<[SinkSite; 1]>)> =
                                if let Some(ref r) = cb_resolved {
                                    matching_sink_caps = r
                                        .param_to_sink
                                        .iter()
                                        .filter(|(_, caps)| !(src_caps & *caps).is_empty())
                                        .fold(Cap::empty(), |acc, (_, c)| acc | *c);
                                    r.param_to_sink_sites
                                        .iter()
                                        .map(|(idx, sites)| {
                                            let chain_sites: SmallVec<[SinkSite; 1]> = sites
                                                .iter()
                                                .map(|s| {
                                                    let mut sc = s.clone();
                                                    sc.from_chain = true;
                                                    sc
                                                })
                                                .collect();
                                            (*idx, chain_sites)
                                        })
                                        .collect()
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
                                    transfer.namespace,
                                    transfer.recording_summary,
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
                                    false,
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
        // Go `fmt.Fprint*` reflected-XSS gate: the HTML_ESCAPE label only
        // applies when the writer (positional arg 0) can be an
        // `http.ResponseWriter`.  When the writer is provably a non-response
        // byte sink (`*bytes.Buffer`, `*os.File`, `bufio.Writer`, `io.Writer`
        // param, …) the call is a stream/buffer write, not response
        // rendering.  Prefer the flow-insensitive static [`TypeFactResult`]:
        // the flow-sensitive abstract env widens the writer's type to
        // `Unknown` inside loops (gitea `mock_http.go` writes to an
        // `os.Create` handle inside a nested `for`), so consulting only
        // `path_env` misses the suppression and re-opens the FP.  The env is
        // a fallback for values the static pass could not type.
        if transfer.lang == Lang::Go && sink_caps.intersects(Cap::HTML_ESCAPE) {
            if let SsaOp::Call { args, callee, .. } = &inst.op {
                // Restricted to the `fmt.Fprint*` family: only there is arg 0
                // the WRITER whose type decides response-vs-buffer.  For a
                // `template.HTML(x)` sink arg 0 is the payload, so a
                // non-response arg type (e.g. a tainted `String`) must NOT
                // strip the XSS label.
                if crate::ssa::type_facts::is_go_writer_sink_callee(callee) {
                    if let Some(&first_val) = args.first().and_then(|g| g.first()) {
                        let writer_kind = transfer
                            .type_facts
                            .and_then(|tf| tf.get_type(first_val).cloned())
                            .or_else(|| {
                                state
                                    .path_env
                                    .as_ref()
                                    .and_then(|env| env.get(first_val).types.as_singleton())
                            });
                        if writer_kind
                            .as_ref()
                            .is_some_and(crate::ssa::type_facts::go_writer_is_non_response)
                        {
                            sink_caps &= !Cap::HTML_ESCAPE;
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
        let mut arg_callee_strip = Cap::empty();
        for maybe_callee in &info.arg_callees {
            if let Some(inner_callee) = maybe_callee {
                let caller_func = info.ast.enclosing_func.as_deref().unwrap_or("");
                if let Some(resolved) = resolve_callee(transfer, inner_callee, caller_func, 0) {
                    arg_callee_strip |= resolved.sanitizer_caps;
                } else {
                    // Fallback: check label classification (built-in + custom rules).
                    // This handles sanitizers that have no function summary (e.g.
                    // external libraries like `escapeHtml`, `DOMPurify.sanitize`).
                    let lang_str = transfer.lang.as_str();
                    let labels =
                        crate::labels::classify_all(lang_str, inner_callee, transfer.extra_labels);
                    for lbl in &labels {
                        if let DataLabel::Sanitizer(bits) = lbl {
                            arg_callee_strip |= *bits;
                        }
                    }
                }
            }
        }
        // That strip is node-wide: one sanitizing wrapper anywhere in the
        // arguments clears its caps for every argument, including operands it
        // does not wrap (`res.send(escapeHtml(t) + bio)`,
        // `Fprintf(w, f, html.EscapeString(a), b)`).  When the node records
        // its call nesting, defer to a per-value pass after the tainted values
        // are collected: each value then keeps the caps that survive the calls
        // actually wrapping it, sanitizers and callee summaries alike.
        let nested_operands = operands::NestedOperands::for_sink(info, transfer);
        if nested_operands.is_none() {
            sink_caps &= !arg_callee_strip;
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
                transfer.lang,
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
                    transfer.lang,
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
        // Multi-sink-per-param de-masking.  When a *summary-resolved* sink's
        // `param_to_sink_sites` records consumptions in DISTINCT capability
        // classes (e.g. a helper param flows to SSRF at `new HttpGet(url)`
        // co-located with HEADER_INJECTION at `req.addHeader("X", url)`), the
        // legacy single-union pass collapses every site's cap into one
        // `sink_caps` mask and emits a single event.  The cap→rule routing in
        // `ast.rs` then resolves the union to the single most-specific rule id
        // (`taint-header-injection`), MASKING the generic-routed flow
        // (`SSRF` → `taint-unsanitised-flow`).  Split into one filter pass per
        // distinct site cap so each event carries exactly the cap consumed at
        // its attributed location.  `collect_tainted_sink_values` (Priority 2,
        // keyed on `param_to_sink` ∩ `sink_caps`) and `pick_primary_sink_sites`
        // both re-filter per pass, so a cap with no actual tainted flow yields
        // an empty `tainted` set and is skipped — no spurious zero-cap events.
        //
        // Naturally scoped to summary-resolved sinks: `resolve_sink_info`
        // returns an empty `param_to_sink_sites` for direct label / gated
        // sinks (the early `label_sink_caps` return) and for the type-qualified
        // ORM raw-SQL path, so those single-pass behaviors are byte-identical.
        // The explicit `tq_filters.is_empty()` guard keeps the type-qualified
        // payload-restriction path on its own filters even if it ever
        // co-occurs.
        let multi_sink_caps: smallvec::SmallVec<[Cap; 4]> =
            if !multi_gate && !summary_per_position && tq_filters.is_empty() {
                distinct_summary_sink_caps(&sink_info.param_to_sink_sites, sink_caps)
            } else {
                smallvec::SmallVec::new()
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
        } else if multi_sink_caps.len() > 1 {
            multi_sink_caps.iter().map(|&c| (c, None, None)).collect()
        } else if tq_filters.len() > 1 {
            // A typed receiver whose qualified callee carries one gate per
            // cap (`HttpClient.Post`: SSRF on the URL, DATA_EXFIL on the
            // body).  One pass per gate, as for `info.call.gate_filters`.
            tq_filters
                .iter()
                .map(|&(caps, payload)| (sink_caps & caps, payload, None))
                .collect()
        } else {
            let payload = tq_filters.first().and_then(|&(_, p)| p);
            smallvec::smallvec![(sink_caps, payload, None)]
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
            let mut tainted = collect_tainted_sink_values(
                inst,
                info,
                &state,
                filter_caps,
                ssa,
                cfg,
                transfer,
                &sink_info.param_to_sink,
                positions_override,
                destination_override,
            );
            refine_exec_argv_array_shell_taint(inst, transfer.lang, &state, ssa, &mut tainted);
            if let Some(ops) = &nested_operands {
                operands::refine_sink_values(
                    ops,
                    info,
                    transfer,
                    &mut tainted,
                    ssa,
                    &state,
                    arg_callee_strip,
                    filter_caps,
                );
                // Source calls nested in the payload (`exec(getCmd(r))`) are
                // reported as their own event: they carry no SSA value, so
                // they must not join (or break) the validation verdict of
                // the values above.
                if destination_override
                    .or(info.call.destination_uses.as_deref())
                    .is_none()
                {
                    let lang = transfer.lang;
                    let mut inline_tainted = Vec::new();
                    let via_summary = operands::add_nested_source_values(
                        ops,
                        inst.value,
                        inst.cfg_node,
                        info,
                        ssa,
                        &state,
                        filter_caps,
                        positions_override.or(info.call.sink_payload_args.as_deref()),
                        &sink_info.param_to_sink,
                        sink_fully_type_suppressible(filter_caps),
                        |c: &str| {
                            crate::ssa::type_facts::is_safe_string_producing_callee(c)
                                || crate::ssa::type_facts::is_int_producing_callee(Some(lang), c)
                        },
                        &tainted,
                        &mut inline_tainted,
                    );
                    if !inline_tainted.is_empty() {
                        emit_ssa_taint_events(
                            events,
                            inst.cfg_node,
                            inline_tainted,
                            filter_caps,
                            false,
                            None,
                            via_summary,
                            Vec::new(),
                            true,
                        );
                    }
                }
            }
            if tainted.is_empty() {
                continue;
            }
            // A summary-resolved call reports the caps of the parameters the
            // tainted arguments reach, not the union over every parameter of
            // the callee.  Without this a helper such as
            // `writeResponse(w, code, body, mime)` (body → HTML_ESCAPE,
            // mime → HEADER_INJECTION) turns a tainted `body` into a
            // header-injection finding, and that wrong cap is recorded in the
            // caller's own summary and repeated at each of its call sites.
            if positions_override.is_none()
                && let Some(reached) =
                    summary_caps_reached(inst, &tainted, &sink_info.param_to_sink)
            {
                filter_caps &= reached;
                if filter_caps.is_empty() {
                    continue;
                }
            }
            // Compute all_validated: check if all tainted vars are validated
            let all_validated = tainted.iter().all(|(val, _, _)| {
                let var_name = ssa
                    .value_defs
                    .get(val.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref());
                if let Some(name) = var_name {
                    // Require validation on EVERY reaching path
                    // (intersection-on-join) before suppressing the
                    // sink.  `validated_may` is the union over
                    // predecessors (validated on SOME path), so a value
                    // validated on one branch but bypassable on another
                    // would be wrongly silenced (`if (valid(x)) {...}
                    // else {} sink(x)`).  `validated_must` is the sound
                    // "all paths validated" gate.
                    if let Some(sym) = transfer.interner.get(name) {
                        if state.validated_must.contains(sym) {
                            return true;
                        }
                    }
                    // Copy-alias-aware validation: the branch guard records
                    // `validated_must` keyed by the condition's variable name
                    // (e.g. `uri` in `if !in_array(uri, allow)`), but the
                    // value reaching the sink can be reported under the name
                    // it was copied from after copy propagation / an elided
                    // container index (`uri := parts[1]` lowers to
                    // `uri = assign(parts)`, so the sink taint may surface as
                    // `parts`).  Treat the value as validated when one of its
                    // own copies is validated under the copy's name.  The bit
                    // is keyed by name, so it only speaks for the copy when
                    // that name has no other definition: after
                    // `host = extra` a stale bit from an earlier `host` must
                    // not vouch for `extra`.  Motivated by CVE-2026-21859
                    // (Mailpit `InArray(uri, links)` SSRF allowlist reached
                    // through a base64/split-derived uri).
                    if let Some(aliases) = transfer.base_aliases {
                        if aliases.copies_of(*val).any(|copy| {
                            ssa.value_defs
                                .get(copy.0 as usize)
                                .and_then(|vd| vd.var_name.as_deref())
                                .is_some_and(|copy_name| {
                                    copy_name != name
                                        && name_has_single_definition(ssa, copy_name)
                                        && transfer
                                            .interner
                                            .get(copy_name)
                                            .is_some_and(|sym| state.validated_must.contains(sym))
                                })
                        }) {
                            return true;
                        }
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
                transfer.namespace,
                transfer.recording_summary,
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
                false,
            );
        }
    }
}

/// Union of the summary sink caps of the parameters whose argument carries
/// one of the `tainted` values, or `None` when the call has no per-parameter
/// summary detail or a tainted value is not a positional argument of a
/// summarised parameter (the event's caps are then left alone).
fn summary_caps_reached(
    inst: &SsaInst,
    tainted: &[(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)],
    param_to_sink: &[(usize, Cap)],
) -> Option<Cap> {
    if param_to_sink.is_empty() {
        return None;
    }
    let SsaOp::Call { args, .. } = &inst.op else {
        return None;
    };
    let mut reached = Cap::empty();
    for (value, _, _) in tainted {
        let mut found = false;
        for &(idx, caps) in param_to_sink {
            if args.get(idx).is_some_and(|group| group.contains(value)) {
                reached |= caps;
                found = true;
            }
        }
        if !found {
            return None;
        }
    }
    Some(reached)
}

fn refine_exec_argv_array_shell_taint(
    inst: &SsaInst,
    lang: Lang,
    state: &SsaTaintState,
    ssa: &SsaBody,
    tainted: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
) {
    if !matches!(lang, Lang::C | Lang::Cpp) {
        return;
    }
    let SsaOp::Call { callee, args, .. } = &inst.op else {
        return;
    };
    let method = crate::labels::bare_method_name(callee);
    if !matches!(method, "execv" | "execve" | "execvp" | "execvpe") {
        return;
    }
    let Some(argv_values) = args.get(1) else {
        return;
    };
    if argv_values.is_empty() {
        return;
    }

    for (value, caps, origins) in tainted.iter_mut() {
        let Some(vector) = exec_argv_vector_for(*value, argv_values, ssa) else {
            continue;
        };
        let Some((argv_caps, argv_origins)) =
            exec_argv_non_executable_shell_taint(vector, inst.value, state, ssa)
        else {
            continue;
        };
        *caps = (*caps & !Cap::SHELL_ESCAPE) | argv_caps;
        if argv_caps.contains(Cap::SHELL_ESCAPE) {
            *origins = argv_origins;
        }
    }

    tainted.retain(|(_, caps, _)| caps.contains(Cap::SHELL_ESCAPE));
}

/// Resolve the argv vector that a tainted `execv*` operand speaks for.
///
/// Returns the vector itself when `value` IS the argv argument, and the
/// container it was read out of when `value` is the synthetic `__index_get__`
/// result the CFG pre-emits for a subscript argument.  The alias matters
/// because the executable path is idiomatically read back out of the vector
/// (`execvp(args[0], (char *const *)args)`): with pointer analysis on, arg 0
/// binds to a `__nyx_idxget_*` element read, a value distinct from `args`, so
/// a plain membership test sees the two operands as unrelated.
///
/// Both operands are governed by the same rule.  Taint that only reaches the
/// executable slot of the vector chooses *which* binary the vector runs — the
/// `GIT_SSH` shape behind CVE-2017-1000117 — which
/// [`exec_argv_non_executable_shell_taint`] already separates from argv
/// injection.  Resolving arg 0 back to the vector keeps that separation now
/// that the executable path is a payload position of the `execv*` gates.
///
/// `None` for an operand unrelated to the vector, so a program path that does
/// NOT come out of argv (`execvp(getenv("PROG_PATH"), NULL)`) keeps its
/// SHELL_ESCAPE taint: nothing about the argv vector says anything about it.
fn exec_argv_vector_for(
    value: SsaValue,
    argv_values: &[SsaValue],
    ssa: &SsaBody,
) -> Option<SsaValue> {
    if argv_values.contains(&value) {
        return Some(value);
    }
    for block in &ssa.blocks {
        for candidate in block.phis.iter().chain(block.body.iter()) {
            if candidate.value != value {
                continue;
            }
            let SsaOp::Call {
                callee,
                receiver: Some(receiver),
                ..
            } = &candidate.op
            else {
                return None;
            };
            if callee == "__index_get__" && argv_values.contains(receiver) {
                return Some(*receiver);
            }
            return None;
        }
    }
    None
}

fn exec_argv_non_executable_shell_taint(
    argv: SsaValue,
    sink_value: SsaValue,
    state: &SsaTaintState,
    ssa: &SsaBody,
) -> Option<(Cap, SmallVec<[TaintOrigin; 2]>)> {
    let mut stores: Vec<(u32, SmallVec<[SsaValue; 2]>)> = Vec::new();
    for block in &ssa.blocks {
        for candidate in block.phis.iter().chain(block.body.iter()) {
            if candidate.value.0 >= sink_value.0 {
                continue;
            }
            let SsaOp::Call {
                callee,
                args,
                receiver: Some(receiver),
                ..
            } = &candidate.op
            else {
                continue;
            };
            if callee != "__index_set__" || *receiver != argv {
                continue;
            }
            stores.push((candidate.value.0, args.get(1).cloned().unwrap_or_default()));
        }
    }
    if stores.is_empty() {
        return None;
    }
    stores.sort_by_key(|(value, _)| *value);

    let mut caps = Cap::empty();
    let mut origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    for (_, values) in stores.into_iter().skip(1) {
        for value in values {
            let Some(taint) = state.get(value) else {
                continue;
            };
            if !taint.caps.contains(Cap::SHELL_ESCAPE) {
                continue;
            }
            let non_env_origins: SmallVec<[TaintOrigin; 2]> = taint
                .origins
                .iter()
                .copied()
                .filter(|origin| origin.source_kind != SourceKind::EnvironmentConfig)
                .collect();
            if non_env_origins.is_empty() {
                continue;
            }
            caps |= Cap::SHELL_ESCAPE;
            for origin in non_env_origins {
                push_origin_bounded(&mut origins, origin);
            }
        }
    }

    Some((caps, origins))
}

fn is_noreturn_call(lang: Lang, callee: &str) -> bool {
    if !matches!(lang, Lang::C | Lang::Cpp) {
        return false;
    }
    // Only free-function calls terminate the process.  A receiver-qualified
    // method whose trailing segment happens to be `exit`/`abort`/etc.
    // (e.g. `transaction.abort()`, `app.exit()`) is an ordinary call and
    // must NOT wipe the taint state.  Reject any callee carrying a receiver
    // (`.` member access or `->` pointer access) and match the full text.
    if callee.contains('.') || callee.contains("->") {
        return false;
    }
    matches!(callee, "exit" | "_Exit" | "quick_exit" | "abort")
}

// ── Primary sink-site attribution ───────────────────────────────────────

/// Decide whether a [`SinkSite`] should be promoted into a caller-side
/// `Finding.primary_location`.
///
/// Same-file single-hop helpers keep call-site emission, the existing
/// intra-procedural finding already lights up the deep sink line and the
/// flow finding then fires at the call site to give reviewers two
/// coordinates (deep + call-site).  Promoting the deep coordinate onto
/// the flow finding would collapse the pair via `deduplicate_taint_flows`
/// and matches benchmark fixtures that expect the call-site shape.
///
/// Multi-hop chains and cross-file callees promote: a chain hop has no
/// per-frame intermediate finding to dedup with, and a cross-file callee's
/// body is not visible to the caller's intra-file taint pass.
///
/// Returns `true` when the site is `from_chain` (chain-hop marker) or its
/// `file_rel` differs from the caller's namespace (cross-file).
fn should_promote_sink_site(site: &SinkSite, caller_namespace: &str) -> bool {
    site.from_chain || (!site.file_rel.is_empty() && site.file_rel != caller_namespace)
}

/// Pick primary [`SinkSite`]s for a summary-based sink event in the main
/// sink-detection path.
///
/// Filters `param_to_sink_sites` to entries whose:
/// 1. `param_idx` appears in the call's positional `args` and contains one
///    of the `tainted` SSA values (proves this site's parameter actually
///    carried the tainted flow), AND
/// 2. [`SinkSite`] carries resolved coordinates (`line != 0`, cap-only
///    sites are ignored), AND
/// 3. [`SinkSite::cap`] intersects `sink_caps` (the propagated cap mask),
///    AND
/// 4. [`should_promote_sink_site`] returns `true` (chain-hop marker or
///    cross-file callee), so same-file single-hop helpers keep their
///    call-site emission.
///
/// Returns the deduped list of matching sites (`dedup_key` identity).
/// Empty ⇒ no primary attribution, caller emits a single event with
/// `primary_sink_site = None`.
fn pick_primary_sink_sites(
    inst: &SsaInst,
    tainted: &[(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)],
    sink_caps: Cap,
    param_to_sink_sites: &[(usize, SmallVec<[SinkSite; 1]>)],
    caller_namespace: &str,
    recording_summary: bool,
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
            if !recording_summary && !should_promote_sink_site(site, caller_namespace) {
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

/// Distinct per-site capability masks for the multi-sink-per-param
/// de-masking split in [`collect_block_events`].
///
/// A summary-resolved sink records one [`SinkSite`] per distinct
/// consumption capability of a helper parameter (e.g. SSRF at
/// `new HttpGet(url)` co-located with HEADER_INJECTION at
/// `req.addHeader(name, url)`).  Without splitting, the caller-side
/// emission unions every site's cap into a single mask and the cap->rule
/// routing in `ast.rs` collapses the union to the single most-specific
/// rule id, masking the generically-routed flow (e.g. SSRF, which surfaces
/// as `taint-unsanitised-flow`).
///
/// Returns the deduped list of `site.cap & sink_caps` masks across all
/// resolved sites (cap-only sites with `line == 0` are skipped, since they
/// carry no attribution and would split off a phantom event).  A result of
/// length > 1 drives one per-cap filter pass; length 0 or 1 keeps the
/// single-pass union behavior byte-identical.  Order follows
/// `param_to_sink_sites` iteration (deterministic for a fixed summary).
fn distinct_summary_sink_caps(
    param_to_sink_sites: &[(usize, SmallVec<[SinkSite; 1]>)],
    sink_caps: Cap,
) -> smallvec::SmallVec<[Cap; 4]> {
    let mut distinct: smallvec::SmallVec<[Cap; 4]> = smallvec::SmallVec::new();
    for (_, sites) in param_to_sink_sites {
        for site in sites {
            if site.line == 0 {
                continue;
            }
            let c = site.cap & sink_caps;
            if c.is_empty() {
                continue;
            }
            if !distinct.contains(&c) {
                distinct.push(c);
            }
        }
    }
    distinct
}

/// Pick primary [`SinkSite`]s for the callback-pattern path, where the
/// tainted-arg positional mapping is not directly available (the callback
/// callee is resolved separately from the outer call's `args`).  Matches
/// on cap intersection, coordinate resolution, and the same chain-hop /
/// cross-file gate used by [`pick_primary_sink_sites`].
fn pick_primary_sink_sites_from_resolved(
    sink_caps: Cap,
    param_to_sink_sites: &[(usize, SmallVec<[SinkSite; 1]>)],
    caller_namespace: &str,
    recording_summary: bool,
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
            if !recording_summary && !should_promote_sink_site(site, caller_namespace) {
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
#[allow(clippy::too_many_arguments)]
fn emit_ssa_taint_events(
    events: &mut Vec<SsaTaintEvent>,
    sink_node: NodeIndex,
    tainted_values: Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    sink_caps: Cap,
    all_validated: bool,
    guard_kind: Option<PredicateKind>,
    uses_summary: bool,
    primary_sites: Vec<SinkSite>,
    inline_source: bool,
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
            inline_source,
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
            inline_source,
        });
    }
}

/// Argument positions holding the SQL text of a SQL query sink call.
///
/// `Some` only when the call is classified as a `SQL_QUERY` sink and its gate
/// declares explicit payload positions (`pool.query(text, binds)`,
/// `cursor.execute(text, params)`); the remaining positions are bind
/// parameters, which the driver sends apart from the text.  `None` for every
/// other call, including SQL sinks that treat all arguments as the query.
fn sql_query_payload_positions(info: &NodeInfo) -> Option<Vec<usize>> {
    let sql = Cap::SQL_QUERY;
    let mut positions: Vec<usize> = Vec::new();
    if !info.call.gate_filters.is_empty() {
        for gate in info
            .call
            .gate_filters
            .iter()
            .filter(|g| g.label_caps.intersects(sql))
        {
            positions.extend(gate.payload_args.iter().copied());
        }
        // A callee carrying other gates (a non-SQL one) is not a plain query
        // call; only an all-SQL gate set describes the return value.
        if info
            .call
            .gate_filters
            .iter()
            .any(|g| !g.label_caps.intersects(sql))
        {
            return None;
        }
    } else if info
        .taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Sink(c) if c.intersects(sql)))
    {
        positions.extend(info.call.sink_payload_args.as_deref()?.iter().copied());
    }
    positions.sort_unstable();
    positions.dedup();
    (!positions.is_empty()).then_some(positions)
}

/// Identifiers read by the SQL text fields of an object-literal query
/// argument (`pool.query({ text: sql, values })` gives `["sql"]`), when every
/// SQL gate of the call narrows its destination to such fields.  `None` for a
/// call whose SQL argument is not an object-literal config.
fn sql_query_text_field_names(info: &NodeInfo) -> Option<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    let mut any = false;
    for gate in info
        .call
        .gate_filters
        .iter()
        .filter(|g| g.label_caps.intersects(Cap::SQL_QUERY))
    {
        names.extend(gate.destination_uses.as_ref()?.iter().cloned());
        any = true;
    }
    any.then_some(names)
}

/// Taint of the arguments at `positions` restricted to values whose variable
/// name is in `names`, the same narrowing the sink check applies for a
/// destination-filtered gate.
fn collect_named_args_taint(
    args: &[SmallVec<[SsaValue; 2]>],
    state: &SsaTaintState,
    ssa: &SsaBody,
    positions: &[usize],
    names: &[String],
) -> (Cap, SmallVec<[TaintOrigin; 2]>) {
    let mut caps = Cap::empty();
    let mut origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
    for &pos in positions {
        for &v in args.get(pos).into_iter().flatten() {
            let named = ssa
                .def_of(v)
                .var_name
                .as_deref()
                .is_some_and(|vn| names.iter().any(|n| n == vn));
            if !named {
                continue;
            }
            if let Some(taint) = state.get(v) {
                caps |= taint.caps;
                for orig in &taint.origins {
                    push_origin_bounded(&mut origins, *orig);
                }
            }
        }
    }
    (caps, origins)
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
///
/// Map a proven constant index/key to its precise `HeapSlot`, or `None`
/// (caller falls back to `HeapSlot::Elements`).
///
/// * Non-negative integer within `MAX_TRACKED_INDICES` → `Index(n)`.
/// * Any other string constant → `Key(hash)` — a keyed read sees only its own
///   key's cell (plus dynamic-key taint in `Elements`); a read of a *different*
///   constant key cannot inherit it.  Unknown/dynamic keys keep the coarse
///   `Elements` merge, so no precision is lost and no false negative arises.
///
/// Both the SSA-value path (`resolve_container_index`) and the
/// literal-argument path (`resolve_op_slot`) funnel through here so a
/// `put("k", …)` written with a literal and a `get(kVar)` whose `kVar`
/// const-props to `"k"` resolve to the *same* slot.
fn slot_from_const(c: &crate::ssa::const_prop::ConstLattice) -> Option<HeapSlot> {
    use crate::ssa::const_prop::ConstLattice;
    use crate::ssa::heap::{MAX_TRACKED_INDICES, hash_const_key};
    match c {
        ConstLattice::Int(n) if *n >= 0 && (*n as u64) < MAX_TRACKED_INDICES as u64 => {
            Some(HeapSlot::Index(*n as u64))
        }
        ConstLattice::Str(s) => Some(HeapSlot::Key(hash_const_key(s))),
        _ => None,
    }
}

/// Look up the SSA op that defines value `v`, searching `v`'s defining block.
pub(super) fn op_for_value(ssa: &SsaBody, v: SsaValue) -> Option<&SsaOp> {
    let vd = ssa.value_defs.get(v.0 as usize)?;
    let blk = ssa.blocks.iter().find(|b| b.id == vd.block)?;
    blk.phis
        .iter()
        .chain(blk.body.iter())
        .find(|i| i.value == v)
        .map(|i| &i.op)
}

/// Resolve a container index/key SSA value to a `HeapSlot` by tracing its
/// definition to an underlying constant.  Handles the case where a literal
/// key (`map.get("k")`) surfaces as a *copy* of a `Const` (e.g.
/// `v = Assign([const])` from a cast/temporary) that the optimised
/// `const_values` map records as `Varying` rather than the literal.  Bounded
/// depth; follows single-use `Assign` copies only (no phi merge, to stay
/// precise — a key joined across paths is genuinely dynamic).
fn slot_from_ssa_value(v: SsaValue, ssa: &SsaBody, depth: u32) -> Option<HeapSlot> {
    if depth > 8 {
        return None;
    }
    match op_for_value(ssa, v)? {
        SsaOp::Const(Some(text)) => {
            slot_from_const(&crate::ssa::const_prop::ConstLattice::parse(text))
        }
        SsaOp::Assign(uses) if uses.len() == 1 => slot_from_ssa_value(uses[0], ssa, depth + 1),
        _ => None,
    }
}

fn resolve_container_index(index_val: SsaValue, transfer: &SsaTaintTransfer) -> HeapSlot {
    transfer
        .const_values
        .and_then(|cv| cv.get(&index_val))
        .and_then(slot_from_const)
        .unwrap_or(HeapSlot::Elements)
}

/// Resolve the `HeapSlot` for a container operation given its `index_arg`.
///
/// When `index_arg` is `Some(idx_pos)`, applies `arg_offset` and resolves
/// the index/key.  Two channels, checked in order:
///   1. the SSA value at that argument position (a *variable* index/key that
///      const-props to an int/string);
///   2. the parallel `arg_string_literals` slot (a *literal* index/key, e.g.
///      `map.get("keyB")`, which carries no SSA value because it is not a
///      variable — the dominant OWASP shape).
///
/// Otherwise returns `HeapSlot::Elements`.
fn resolve_op_slot(
    index_arg: Option<usize>,
    arg_offset: usize,
    args: &[SmallVec<[SsaValue; 2]>],
    arg_string_literals: &[Option<String>],
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
) -> HeapSlot {
    if let Some(idx_pos) = index_arg {
        let effective = idx_pos + arg_offset;
        // 1. Variable index/key channel: an SSA value that const-props to an
        //    int/string.  Only claim resolution when it yields a *precise*
        //    slot — a literal key/index often surfaces here as an SSA value
        //    that const-prop could not pin down (so `resolve_container_index`
        //    returns `Elements`); in that case fall through to the next
        //    channel rather than collapsing to the coarse merge.
        if let Some(&v) = args.get(effective).and_then(|g| g.first()) {
            let slot = resolve_container_index(v, transfer);
            if slot != HeapSlot::Elements {
                return slot;
            }
            // 1b. SSA-trace channel: the value is a literal that surfaced as a
            //     copy of a `Const` (e.g. `(String) map.get("k")` lowers the
            //     key to `v = Assign([const])`, which optimised `const_values`
            //     records as `Varying`).  Follow the def to the underlying
            //     constant so the keyed slot is recovered.
            if let Some(slot) = slot_from_ssa_value(v, ssa, 0) {
                return slot;
            }
        }
        // 2. Literal index/key channel: the constant (string/int) literal
        //    captured at CFG build, parsed through the same `slot_from_const`
        //    mapping the variable path uses.  This is the dominant OWASP
        //    shape (`map.get("keyB")`), where the key is a bare literal.
        if let Some(Some(lit)) = arg_string_literals.get(effective) {
            let parsed = crate::ssa::const_prop::ConstLattice::parse(lit);
            if let Some(slot) = slot_from_const(&parsed) {
                return slot;
            }
        }
    }
    HeapSlot::Elements
}

/// True when `v` is the synthetic Param scoped lowering made for a free
/// Java name that is a class (`Paths`, `java.nio.file.Files`): a free name
/// whose last segment is UpperCamelCase.  Free fields are lowerCamelCase and
/// constants UPPER_SNAKE_CASE, so neither matches.
fn is_java_class_receiver(ssa: &SsaBody, v: SsaValue) -> bool {
    if !ssa.synthetic_externals.contains(&v) {
        return false;
    }
    let Some(name) = ssa
        .value_defs
        .get(v.0 as usize)
        .and_then(|d| d.var_name.as_deref())
    else {
        return false;
    };
    let leaf = name.rsplit('.').next().unwrap_or(name);
    leaf.starts_with(|c: char| c.is_ascii_uppercase())
        && leaf.chars().any(|c| c.is_ascii_lowercase())
}

/// Java `sb.append(x)` / `sb.insert(i, x)` on a receiver known to be a
/// `StringBuilder` / `StringBuffer`: the argument is written into the
/// builder.  The receiver type comes from the SSA type facts, the path
/// environment, or the declared type of the receiver, so an unrelated user
/// class with an `append` method keeps the default call propagation.
///
/// A chained statement `sb.append(a).append(b);` is one call node on the
/// root builder; the inner calls' arguments sit in a trailing implicit
/// argument group.  Every argument group is therefore written into the
/// builder, not only the first.
fn java_builder_store_op(
    info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    transfer: &SsaTaintTransfer,
    callee: &str,
    state: &SsaTaintState,
) -> Option<crate::ssa::pointsto::ContainerOp> {
    use crate::ssa::pointsto::ContainerOp;
    use crate::ssa::type_facts::TypeKind;
    if transfer.lang != Lang::Java {
        return None;
    }
    crate::ssa::pointsto::classify_java_builder_op(crate::labels::bare_method_name(callee))?;
    let rv = (*receiver)?;
    let kind = transfer
        .type_facts
        .and_then(|tf| tf.get_type(rv))
        .cloned()
        .or_else(|| {
            state
                .path_env
                .as_ref()
                .and_then(|env| env.get(rv).types.as_singleton())
        })
        .filter(|k| !matches!(k, TypeKind::Unknown))
        .or_else(|| info.call.receiver_decl_type.clone());
    if !matches!(kind, Some(TypeKind::StringBuilder)) {
        return None;
    }
    Some(ContainerOp::Store {
        value_args: (0..args.len()).collect(),
        index_arg: None,
    })
}

/// Taint a value brings into a builder append, after the calls wrapping its
/// occurrences in the node (`sb.append(escapeHtml4(x))` keeps nothing of
/// `x`).  A value with no recorded occurrence keeps its full taint, and a
/// value an earlier check validated (an allowlist guard) brings none.
fn builder_operand_caps(
    nested: Option<&operands::NestedOperands>,
    v: SsaValue,
    caps: Cap,
    ssa: &SsaBody,
    transfer: &SsaTaintTransfer,
    state: &SsaTaintState,
) -> Cap {
    let validated = ssa
        .value_defs
        .get(v.0 as usize)
        .and_then(|d| d.var_name.as_deref())
        .and_then(|n| transfer.interner.get(n))
        .is_some_and(|sym| state.validated_must.contains(sym));
    if validated {
        return Cap::empty();
    }
    nested
        .and_then(|ops| ops.builder_value_caps(v, caps, ssa, state))
        .unwrap_or(caps)
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
    info: &NodeInfo,
    args: &[SmallVec<[SsaValue; 2]>],
    receiver: &Option<SsaValue>,
    state: &mut SsaTaintState,
    transfer: &SsaTaintTransfer,
    callee: &str,
    ssa: &SsaBody,
) -> bool {
    let lang = transfer.lang;
    use crate::ssa::pointsto::{ContainerOp, classify_container_op};

    let mut is_builder_store = false;
    let op = match classify_container_op(callee, lang) {
        Some(op) => op,
        None => match java_builder_store_op(info, args, receiver, transfer, callee, state) {
            Some(op) => {
                is_builder_store = true;
                op
            }
            None => return false,
        },
    };

    // A static call on a Java class (`Paths.get(p)`) is not a container
    // operation.  Scoped lowering gives the free class name a synthetic
    // Param, so it would read as a load from a container named `Paths` and
    // drop the argument taint.  Plain lowering leaves that receiver unset;
    // treat the class receiver the same way.
    let receiver = &receiver.filter(|&r| !(lang == Lang::Java && is_java_class_receiver(ssa, r)));

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
            let slot = resolve_op_slot(
                index_arg,
                arg_offset,
                args,
                &info.call.arg_string_literals,
                ssa,
                transfer,
            );

            // Collect taint from value argument(s).  A builder append is one
            // node for the whole chain, so each value is narrowed by the
            // calls that wrap it there.
            let builder_nested = is_builder_store
                .then(|| operands::NestedOperands::for_call_chain(info, transfer))
                .flatten();
            let mut val_caps = Cap::empty();
            let mut val_origins: SmallVec<[TaintOrigin; 2]> = SmallVec::new();
            for &arg_idx in &value_args {
                let effective_idx = arg_idx + arg_offset;
                if let Some(arg_vals) = args.get(effective_idx) {
                    for &v in arg_vals {
                        if let Some(taint) = state.get(v) {
                            let caps = if is_builder_store {
                                builder_operand_caps(
                                    builder_nested.as_ref(),
                                    v,
                                    taint.caps,
                                    ssa,
                                    transfer,
                                    state,
                                )
                            } else {
                                taint.caps
                            };
                            if caps.is_empty() {
                                continue;
                            }
                            val_caps |= caps;
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
            let slot = resolve_op_slot(
                index_arg,
                arg_offset,
                args,
                &info.call.arg_string_literals,
                ssa,
                transfer,
            );

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
            // string and `args` holds positional args starting at 0.
            if let Some(arg_vals) = args.get(dest_arg) {
                taint_writeback_dest(state, transfer, arg_vals, &recv_taint);
            }
            true
        }
    }
}

/// Taint the destination pointer of a decode-into call
/// (`dec.Decode(&dest)`, `c.ShouldBindJSON(&dest)`) at three layers:
/// (1) the SSA-value level so downstream uses of the pointer itself see
/// taint; (2) the heap-Elements slot via the simpler-tier `lookup_pts`
/// channel; and (3) the field-cell channel via `pointer_facts.pt(v)` with
/// [`FieldId::ANY_FIELD`] as a tainted-at-all-fields wildcard so subsequent
/// `dest.Field` projections (which read through the higher-tier
/// `pointer_facts.pt(receiver)` channel, see the `SsaOp::FieldProj` arm)
/// inherit the taint.  Without (3), CVE shapes like
/// `json.NewDecoder(r.Body).Decode(&dest)` followed by
/// `os.Remove(filepath.Join(_, dest.Name))` left the dest field channel empty
/// even though the heap was tainted; the wildcard bridges the two channels
/// and is read back by the `FieldProj` arm's fallback.
fn taint_writeback_dest(
    state: &mut SsaTaintState,
    transfer: &SsaTaintTransfer,
    dest_vals: &[SsaValue],
    taint: &VarTaint,
) {
    for &v in dest_vals {
        merge_taint_into(state, v, taint.caps, &taint.origins);
        if let Some(pts) = lookup_pts(transfer, v) {
            state.heap.store_set(
                &pts,
                crate::ssa::heap::HeapSlot::Elements,
                taint.caps,
                &taint.origins,
            );
        }
        if let Some(pf) = transfer.pointer_facts {
            let pt_arg = pf.pt(v);
            if !pt_arg.is_empty() && !pt_arg.is_top() {
                for loc in pt_arg.iter() {
                    let key = crate::taint::ssa_transfer::state::FieldTaintKey {
                        loc,
                        field: crate::ssa::ir::FieldId::ANY_FIELD,
                    };
                    state.add_field(key, taint.clone(), false, false);
                }
            }
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
    let primary = info
        .call
        .callee
        .as_ref()
        .filter(|_| info.call.callee_nesting != CalleeNesting::Hoisted)
        .and_then(|c| {
            resolve_callee_hinted(transfer, c, caller_func, info.call.call_ordinal, arity_hint)
        });
    if let Some(r) = primary.filter(|r| !r.sink_caps.is_empty()) {
        return SinkInfo {
            caps: r.sink_caps,
            param_to_sink: r.param_to_sink.clone(),
            param_to_sink_sites: r.param_to_sink_sites.clone(),
            param_to_gate_filters: r.param_to_gate_filters.clone(),
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
                param_to_sink: r.param_to_sink.clone(),
                param_to_sink_sites: r.param_to_sink_sites.clone(),
                param_to_gate_filters: r.param_to_gate_filters.clone(),
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

/// True when `value` is a dotted free name (`item.name`) whose root is a real
/// formal typed as a request-body model (a Pydantic class or a `dict`), the
/// shape SSA lowering gives an attribute read on that formal.
fn is_body_model_field(ssa: &SsaBody, transfer: &SsaTaintTransfer, value: SsaValue) -> bool {
    let var_name = |v: SsaValue| {
        ssa.value_defs
            .get(v.0 as usize)
            .and_then(|vd| vd.var_name.as_deref())
    };
    let Some((root, _)) = var_name(value).and_then(|n| n.split_once('.')) else {
        return false;
    };
    let eb = &ssa.blocks[ssa.entry.0 as usize];
    eb.phis.iter().chain(eb.body.iter()).any(|i| {
        matches!(i.op, SsaOp::Param { .. })
            && !ssa.synthetic_externals.contains(&i.value)
            && var_name(i.value) == Some(root)
            && transfer
                .type_facts
                .and_then(|tf| tf.get_type(i.value))
                .is_some_and(|t| {
                    matches!(
                        t,
                        crate::ssa::type_facts::TypeKind::Dto(_)
                            | crate::ssa::type_facts::TypeKind::Object
                    )
                })
    })
}

/// True when `name` is a real formal of the body (not a synthetic external)
/// whose `param_route_capture` flag marks it as filled from the request.
fn request_bound_formal(ssa: &SsaBody, transfer: &SsaTaintTransfer, name: &str) -> bool {
    let Some(flags) = transfer.param_route_capture else {
        return false;
    };
    let eb = &ssa.blocks[ssa.entry.0 as usize];
    eb.phis.iter().chain(eb.body.iter()).any(|i| match i.op {
        SsaOp::Param { index } => {
            flags.get(index).copied().unwrap_or(false)
                && !ssa.synthetic_externals.contains(&i.value)
                && ssa
                    .value_defs
                    .get(i.value.0 as usize)
                    .and_then(|vd| vd.var_name.as_deref())
                    == Some(name)
        }
        _ => false,
    })
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
    cfg: &Cfg,
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
            retain_inner_sink_reaching_uses(&mut result, info, ssa);
            apply_field_aware_suppression(&mut result, inst, info, state, sink_caps, ssa, cfg);
            apply_arg_type_safe_suppression(
                &mut result,
                sink_caps,
                transfer.type_facts,
                inst,
                info,
                ssa,
                transfer.lang,
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
            retain_inner_sink_reaching_uses(&mut result, info, ssa);
            apply_field_aware_suppression(&mut result, inst, info, state, sink_caps, ssa, cfg);
            apply_arg_type_safe_suppression(
                &mut result,
                sink_caps,
                transfer.type_facts,
                inst,
                info,
                ssa,
                transfer.lang,
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

    retain_inner_sink_reaching_uses(&mut result, info, ssa);

    apply_field_aware_suppression(&mut result, inst, info, state, sink_caps, ssa, cfg);
    apply_arg_type_safe_suppression(
        &mut result,
        sink_caps,
        transfer.type_facts,
        inst,
        info,
        ssa,
        transfer.lang,
    );
    result
}

/// Inner-nested-sink argument attribution.  When this node's `Sink` label was
/// contributed by a call nested inside a larger non-sink outer expression
/// (`Ok(Reader { meta: <tainted>, h: File::open(const) })`, `str(eval(x))`),
/// only values that syntactically appear inside that inner sink call are its
/// payload.  A tainted value occupying a DIFFERENT sub-position of the
/// enclosing aggregate is a sibling that reaches the aggregate's returned
/// value, not the sink's argument, so drop it.  Named values outside the set
/// are dropped; unnamed temporaries are kept (conservative — the inner sink's
/// payload may be an unnamed sub-call).
///
/// This runs on EVERY priority tier of [`collect_tainted_sink_values`], not
/// just the Priority-3 aggregate fallback.  A gated file-IO sink
/// (`sink_payload_args = [0]`, e.g. the Rust `File::open` path-confinement
/// gate) whose call is ALSO nested inside an `Ok(Struct { … })` aggregate hits
/// Priority 1, whose `positions` restriction lands on the flattened
/// aggregate's single `args[0]` — which lumps the path idents together with
/// every sibling struct field.  Without applying this retain there, the
/// FileSystem-tainted siblings survive the early return and re-introduce the
/// self-referential `file_system -> FILE_IO` flow the gate was meant to close
/// (meilisearch `crates/dump/src/reader/v6/mod.rs:140`).  It is a no-op when
/// `sink_reaching_uses` is `None` (the common non-nested sink), so the added
/// call on the Priority-1/2 fast paths never changes their result there.
fn retain_inner_sink_reaching_uses(
    result: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    info: &NodeInfo,
    ssa: &SsaBody,
) {
    if let Some(reaching) = info.call.sink_reaching_uses.as_deref() {
        result.retain(|(v, _, _)| {
            match ssa
                .value_defs
                .get(v.0 as usize)
                .and_then(|vd| vd.var_name.as_deref())
            {
                Some(name) => reaching.iter().any(|n| n == name),
                None => true,
            }
        });
    }
}

/// Whether every cap of `sink_caps` is one a numeric or safe-string value
/// cannot carry.  An arg whose enclosing call is a "safe string" producer
/// (numeric/boolean to-string conversion or a class-name accessor) emits a
/// string provably free of the metacharacters that drive these injection
/// classes.  The same mask the shared
/// [`crate::ssa::type_facts::is_type_safe_for_sink`] gate uses for `Int` /
/// `Bool` values, applied at Call sinks against the arg-level callee text
/// instead of the value-level type kind.
fn sink_fully_type_suppressible(sink_caps: Cap) -> bool {
    let type_suppressible = Cap::SQL_QUERY
        | Cap::FILE_IO
        | Cap::SHELL_ESCAPE
        | Cap::HTML_ESCAPE
        | Cap::SSRF
        | Cap::DATA_EXFIL
        | Cap::HEADER_INJECTION
        | Cap::OPEN_REDIRECT;
    !sink_caps.is_empty() && (sink_caps & !type_suppressible).is_empty()
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
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    inst: &SsaInst,
    info: &NodeInfo,
    ssa: &SsaBody,
    lang: Lang,
) {
    use crate::ssa::type_facts::{
        TypeKind, is_int_producing_callee, is_safe_string_producing_callee,
    };
    if result.is_empty() {
        return;
    }
    // Value-level drop for header and redirect sinks: a tainted operand
    // whose SSA type fact is `Int` / `Bool` (`n := len(q)`,
    // `s := strconv.Itoa(n)`) cannot carry CRLF, a header-meaningful token
    // or a redirect target.  Limited to these two classes; SQL / FILE_IO /
    // shell sinks keep their stricter rules (a bounded integer alone does
    // not clear them).
    if let Some(tf) = type_facts
        && !sink_caps.is_empty()
        && (sink_caps & !(Cap::HEADER_INJECTION | Cap::OPEN_REDIRECT)).is_empty()
    {
        result.retain(|(v, _, _)| !matches!(tf.get_type(*v), Some(TypeKind::Int | TypeKind::Bool)));
        if result.is_empty() {
            return;
        }
    }
    if !sink_fully_type_suppressible(sink_caps) {
        return;
    }
    // Numeric-confinement drop: an inline numeric call-chain argument
    // (`sink(s.parse::<u16>().unwrap().to_string())`) never lowers to its own
    // SSA value, so the tainted source leaf `s` is flattened directly into the
    // sink's use set with its original (string) taint.  `NodeInfo.numeric_
    // confined_uses` records, from an AST walk at CFG construction, the
    // value-use identifiers whose *every* occurrence in this node is consumed
    // by a numeric / safe-string producer — i.e. the leaf reaches the sink
    // only as a number.  Drop those tainted leaves here, the arg-level
    // analogue of the value-level `TypeKind::Int` suppression.  Confinement is
    // soundness-gated at extraction time (a single raw occurrence blocks it),
    // so this never masks an injection through the same variable.
    if !info.numeric_confined_uses.is_empty() {
        result.retain(|(v, _, _)| match ssa.def_of(*v).var_name.as_deref() {
            Some(name) => !info.numeric_confined_uses.iter().any(|n| n == name),
            None => true,
        });
        if result.is_empty() {
            return;
        }
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
        let arg_callee = info.arg_callees.get(pos).and_then(|c| c.as_deref());
        // Two arg shapes are provably non-payload-bearing:
        //   1. A "safe-string" producer — numeric/boolean to-string conversion
        //      or a class-name accessor (`Integer.toString`, `Class.getName`).
        //   2. A numeric-producing call chain — `Atoi(s)` / `parseInt(s)` /
        //      `int(s)` / `s.parse::<u16>().unwrap().to_string()`.  When the
        //      ENTIRE arg expression is such a chain its value is numeric (or a
        //      numeric stringified by an identity/to-string tail), which cannot
        //      encode CRLF, `..`, quote, or shell metacharacters.  This is the
        //      arg-level analogue of the value-level `TypeKind::Int` suppression
        //      in `is_type_safe_for_sink`: the inline shape
        //      `sink(s.parse::<u16>().unwrap().to_string())` never lowers the
        //      inner chain to its own SSA value (the outer call's arg list
        //      captures the tainted source leaf `s` directly), so there is no
        //      intermediate value to carry the `Int` fact — the only place to
        //      recover "this arg is a numeric producer" is the `arg_callees`
        //      text.  The let-bound form `let n = s.parse()…; sink(n)` is
        //      already suppressed because `n` materialises as an `Int`-typed
        //      SSA value.
        let safe = arg_callee
            .map(|c| is_safe_string_producing_callee(c) || is_int_producing_callee(Some(lang), c))
            .unwrap_or(false);
        if safe {
            for &v in arg_vals {
                safe_string_values.insert(v);
            }
        }
    }
    // `arg_callees` names the first call of a composite argument, so for
    // `"... " + Integer.toString(n) + name` it would vouch for `name` too.
    // When the node records its call nesting, decide per value instead: a
    // value is dropped only when every occurrence of it sits in an argument
    // that IS a producer call.
    let producer =
        |c: &str| is_safe_string_producing_callee(c) || is_int_producing_callee(Some(lang), c);
    result.retain(
        |(v, _, _)| match operands::value_confined_by(info, *v, ssa, producer) {
            Some(confined) => !confined,
            None => !safe_string_values.contains(v),
        },
    );
}

/// Suppress plain-ident taint when a dotted-path field value used by the same
/// instruction is untainted. Prevents false positives from base-ident bleed
/// (e.g. `obj.safe = "const"; sink(obj.safe)` where `obj` is tainted).
///
/// A field value only counts as clean evidence when it is backed by
/// something.  A real def (`obj.safe = "const"`) carries its own taint.  A
/// read of a property the body never writes (`body.dir` after `const body =
/// req.body`) lowers to an unbacked phantom `Param` with no taint at all, so
/// on its own it says nothing about the field: it is clean only when the
/// object's defining literal proves it (see
/// [`phantom_field_provably_clean`]).
fn apply_field_aware_suppression(
    result: &mut Vec<(SsaValue, Cap, SmallVec<[TaintOrigin; 2]>)>,
    inst: &SsaInst,
    info: &NodeInfo,
    state: &SsaTaintState,
    sink_caps: Cap,
    ssa: &SsaBody,
    cfg: &Cfg,
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
        // the SSRF.  The CFG distinguishes method refs from field reads via
        // `arg_callees`: when an argument expression is itself a call, its
        // callee text is recorded; pure member-access args leave the slot
        // `None`.  Skip phantoms whose var_name appears as an arg_callee.
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
        // are clean for the relevant sink caps.
        let all_fields_clean = !field_values.is_empty()
            && field_values.iter().all(|&u| {
                let untainted = match state.get(u) {
                    None => true,
                    Some(t) => (t.caps & sink_caps).is_empty(),
                };
                if !untainted {
                    return false;
                }
                if !is_phantom_param_value(u, ssa) {
                    return true;
                }
                let path = ssa
                    .def_of(u)
                    .var_name
                    .as_deref()
                    .and_then(|n| n.strip_prefix(&prefix))
                    .unwrap_or("");
                phantom_field_provably_clean(*v, path, sink_caps, state, ssa, cfg)
            });
        !all_fields_clean
    });
}

/// True when reading the dotted property `path` (e.g. `auth.template`) off
/// the object held by `base` provably yields no taint for `sink_caps`.
///
/// The read is a phantom: the body never writes that property, so the only
/// evidence is how the object was built.  Walks synthetic `obj.f = rhs`
/// updates back to the object's root def, which must be a single-binding
/// object literal ([`crate::cfg::TaintMeta::rhs_object_literal`]).  Any other
/// root (a source, a call result, a parameter, a copy, a phi) is opaque and
/// the read is treated as carrying the object's own taint.
fn phantom_field_provably_clean(
    base: SsaValue,
    path: &str,
    sink_caps: Cap,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> bool {
    let segments: SmallVec<[&str; 4]> = path.split('.').collect();
    let Some(&first) = segments.first() else {
        return false;
    };
    if first.is_empty() {
        return false;
    }
    let mut root = base;
    let mut hops = 0usize;
    while let Some(&(recv, field)) = ssa.field_writes.get(&root) {
        // A write to the read property would have given it a real def.
        if ssa.field_name(field) == first || hops >= 64 {
            return false;
        }
        root = recv;
        hops += 1;
    }
    let def = ssa.def_of(root);
    let Some(def_inst) = ssa.blocks[def.block.0 as usize]
        .body
        .iter()
        .find(|i| i.value == root)
    else {
        return false;
    };
    let Some(info) = cfg.node_weight(def.cfg_node) else {
        return false;
    };
    if def.var_name.is_none() || info.taint.defines != def.var_name {
        return false;
    }
    let Some(lit) = info.taint.rhs_object_literal.as_deref() else {
        return false;
    };
    let ident_clean = |name: &str| -> bool {
        let Some(u) = object_literal_ident_value(name, def_inst, ssa) else {
            return false;
        };
        match state.get(u) {
            None => true,
            Some(t) => (t.caps & sink_caps).is_empty(),
        }
    };
    object_literal_path_clean(lit, &segments, &ident_clean)
}

/// The SSA value an identifier inside an object literal reads.  Prefers the
/// operand of the literal's own `Assign`; otherwise accepts the name only
/// when the body defines it exactly once.
fn object_literal_ident_value(name: &str, def_inst: &SsaInst, ssa: &SsaBody) -> Option<SsaValue> {
    if let SsaOp::Assign(uses) = &def_inst.op {
        if let Some(&u) = uses
            .iter()
            .find(|&&u| ssa.def_of(u).var_name.as_deref() == Some(name))
        {
            return Some(u);
        }
    }
    let mut defs = ssa
        .value_defs
        .iter()
        .enumerate()
        .filter(|(_, vd)| vd.var_name.as_deref() == Some(name));
    let (idx, _) = defs.next()?;
    if defs.next().is_some() {
        return None;
    }
    Some(SsaValue(idx as u32))
}

fn object_literal_path_clean(
    lit: &crate::cfg::RhsObjectLiteral,
    path: &[&str],
    ident_clean: &dyn Fn(&str) -> bool,
) -> bool {
    let Some((&seg, rest)) = path.split_first() else {
        return object_literal_all_clean(lit, ident_clean);
    };
    if lit.open {
        return false;
    }
    match lit.fields.iter().rev().find(|(k, _)| k == seg) {
        // Absent from a closed literal: the read is `undefined`.
        None => true,
        Some((_, slot)) => object_slot_clean(slot, rest, ident_clean),
    }
}

fn object_slot_clean(
    slot: &crate::cfg::RhsObjectSlot,
    rest: &[&str],
    ident_clean: &dyn Fn(&str) -> bool,
) -> bool {
    use crate::cfg::RhsObjectSlot;
    match slot {
        // A literal, or a property of one (`"abc".length`).
        RhsObjectSlot::Literal => true,
        RhsObjectSlot::Ident(name) => ident_clean(name),
        RhsObjectSlot::Object(inner) => object_literal_path_clean(inner, rest, ident_clean),
        RhsObjectSlot::Complex => false,
    }
}

fn object_literal_all_clean(
    lit: &crate::cfg::RhsObjectLiteral,
    ident_clean: &dyn Fn(&str) -> bool,
) -> bool {
    !lit.open
        && lit
            .fields
            .iter()
            .all(|(_, slot)| object_slot_clean(slot, &[], ident_clean))
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

/// Whether exactly one SSA value in `ssa` is named `name`, so a name-keyed
/// fact about `name` can only describe that value.
fn name_has_single_definition(ssa: &SsaBody, name: &str) -> bool {
    ssa.value_defs
        .iter()
        .filter(|vd| vd.var_name.as_deref() == Some(name))
        .take(2)
        .count()
        == 1
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

/// Whether defining a plain identifier can write through to a copy of it.
///
/// CFG lowering drops `&x` / `&mut x` and C++ reference binders, so
/// `p := &cmd` (Go), `let b = &mut a` (Rust) and `T& b = a` (C++) reach SSA
/// as the plain copy `p = cmd`, and the later `*p = v` / `b = v` defines the
/// pointer's own name.  In those languages the name-level alias groups are
/// what carries the write back to the pointee.  Everywhere else rebinding a
/// local never changes its copies: `b = a; b = req.query.c` leaves `a` alone
/// and `b = escape(b)` does not sanitize `a`.  Writes through a shared object
/// (`b.f = v`, `b.push(v)`) go through the dotted-path branch, the receiver
/// value and the points-to cells instead.
fn plain_ident_rebind_may_write_through(lang: Lang) -> bool {
    matches!(lang, Lang::Go | Lang::Rust | Lang::C | Lang::Cpp)
}

/// The values a plain-identifier definition at `inst` must update besides
/// itself, in a language where rebinding cannot write through: the copies
/// copy propagation eliminated in favour of `inst.value`.  A stale reference
/// to such a copy (a `Return` terminator or a FieldProj receiver, which copy
/// propagation does not rewrite) still reads the value defined here.
fn plain_ident_copy_targets(
    inst: &SsaInst,
    aliases: &crate::ssa::alias::BaseAliasResult,
) -> SmallVec<[SsaValue; 8]> {
    aliases.copies_of(inst.value).collect()
}

/// True when the definition of `def` can execute before the definition of
/// `at`: it sits earlier in the same block, or its block reaches `at`'s block.
/// A definition on a sibling branch never precedes the other arm.
fn def_precedes(ssa: &SsaBody, def: SsaValue, at: SsaValue) -> bool {
    let (Some(d), Some(a)) = (
        ssa.value_defs.get(def.0 as usize),
        ssa.value_defs.get(at.0 as usize),
    ) else {
        return false;
    };
    if d.block == a.block {
        return def.0 < at.0;
    }
    let mut seen = vec![false; ssa.blocks.len()];
    let mut stack = vec![d.block];
    while let Some(b) = stack.pop() {
        let Some(blk) = ssa.blocks.get(b.0 as usize) else {
            continue;
        };
        for &succ in &blk.succs {
            if succ == a.block {
                return true;
            }
            if let Some(slot) = seen.get_mut(succ.0 as usize)
                && !*slot
            {
                *slot = true;
                stack.push(succ);
            }
        }
    }
    false
}

/// After sanitizing `inst`, propagate the sanitization to must-aliased field paths.
///
/// When `alias.data` is sanitized and `alias` and `obj` are base aliases (from
/// copy propagation), this function also sanitizes `obj.data` in the taint state.
/// For plain idents (no dot), sanitizing `alias` also sanitizes `obj` in the
/// languages where rebinding can write through (see
/// [`plain_ident_rebind_may_write_through`]); elsewhere only the eliminated
/// copies of `inst.value` itself follow it.
fn propagate_sanitization_to_aliases(
    inst: &SsaInst,
    state: &mut SsaTaintState,
    sanitizer_bits: Cap,
    aliases: &crate::ssa::alias::BaseAliasResult,
    ssa: &SsaBody,
    lang: Lang,
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

    let to_sanitize: SmallVec<[SsaValue; 8]> =
        if suffix.is_empty() && !plain_ident_rebind_may_write_through(lang) {
            plain_ident_copy_targets(inst, aliases)
        } else {
            let alias_bases = match aliases.aliases_of(base) {
                Some(bases) => bases,
                None => return,
            };
            // Collect SsaValues to sanitize (avoid borrowing state while iterating).
            state
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
                        if suffix.is_empty() {
                            // Plain ident: look for exact match on alias base
                            if vdef_name == alias_base.as_str() {
                                return Some(v);
                            }
                        } else if vdef_name.len() == alias_base.len() + suffix.len()
                            && vdef_name.starts_with(alias_base.as_str())
                            && vdef_name.ends_with(suffix)
                        {
                            // Dotted path: vdef_name == "{alias_base}{suffix}"
                            return Some(v);
                        }
                    }
                    None
                })
                .collect()
        };

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
/// For plain idents (no dot), tainting `obj` also taints `alias` in the
/// languages where rebinding can write through (see
/// [`plain_ident_rebind_may_write_through`]); elsewhere only the eliminated
/// copies of `inst.value` itself pick the taint up.
///
/// Uses only the existing `BaseAliasResult` alias groups, no new alias inference.
fn propagate_taint_to_aliases(
    inst: &SsaInst,
    state: &mut SsaTaintState,
    taint_caps: Cap,
    taint_origins: &SmallVec<[TaintOrigin; 2]>,
    aliases: &crate::ssa::alias::BaseAliasResult,
    ssa: &SsaBody,
    lang: Lang,
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

    let to_taint: SmallVec<[SsaValue; 8]> =
        if suffix.is_empty() && !plain_ident_rebind_may_write_through(lang) {
            plain_ident_copy_targets(inst, aliases)
        } else {
            let alias_bases = match aliases.aliases_of(base) {
                Some(bases) => bases,
                None => return,
            };
            // Collect SsaValues to taint. Iterate value_defs (not state.values)
            // because target alias values may not yet be in the taint state.
            ssa.value_defs
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
                        } else if vdef_name.len() == alias_base.len() + suffix.len()
                            && vdef_name.starts_with(alias_base.as_str())
                            && vdef_name.ends_with(suffix)
                        {
                            // Dotted path: vdef_name == "{alias_base}{suffix}"
                            return Some(SsaValue(idx as u32));
                        }
                    }
                    None
                })
                // A literal or declaration-only definition of an alias name (the
                // `'name'` arm of `order = ok ? s : 'name'`) holds no data from the
                // tainted value, so it is never a copy target.  The exception is
                // a pointee written through a pointer (`cmd := "ls"; p := &cmd;
                // *p = src`): its initial literal is the definition the write
                // replaces, so it is a target when it comes before the write.
                .filter(|v| {
                    !matches!(op_for_value(ssa, *v), Some(SsaOp::Const(_) | SsaOp::Nop))
                        || (suffix.is_empty()
                            && plain_ident_rebind_may_write_through(lang)
                            && def_precedes(ssa, *v, inst.value))
                })
                .collect()
        };

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
fn all_args_const(inst: &SsaInst, const_values: &crate::ssa::const_prop::ConstValues) -> bool {
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
/// 3. The receiver's declared type recorded at CFG construction
///    ([`crate::cfg::CallMeta::receiver_decl_type`])
#[allow(clippy::too_many_arguments)]
fn resolve_type_qualified_labels(
    callee: &str,
    receiver: Option<SsaValue>,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    path_env: Option<&constraint::PathEnv>,
    declared: Option<&crate::ssa::type_facts::TypeKind>,
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
    let receiver_candidates = receiver
        .map(|rv| receiver_candidates_for_type_lookup(rv, ssa, lang))
        .unwrap_or_default();

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

    // 3. Declared receiver type
    if let Some(prefix) = declared.and_then(|t| t.label_prefix()) {
        for method in &method_candidates {
            let qualified = format!("{}.{}", prefix, method);
            let labels = crate::labels::classify_all(lang.as_str(), &qualified, extra_labels);
            if !labels.is_empty() {
                return labels;
            }
        }
    }

    SmallVec::new()
}

/// Per-cap payload restriction for a sink found by type-qualified
/// resolution: `(caps, payload arg positions)`, `None` scanning every
/// argument.
type TqSinkFilter = (Cap, Option<&'static [usize]>);

/// Labels for a type-qualified callee plus its per-cap payload filters.
type TqResolution = (SmallVec<[DataLabel; 2]>, SmallVec<[TqSinkFilter; 2]>);

/// Sibling of [`resolve_type_qualified_labels`] used at sink-firing time.
///
/// Returns the resolved labels plus the payload restriction for the sink
/// caps.  Restrictions come from the language's gated sinks keyed on the
/// qualified name (`HttpClient.Post` is SSRF on arg 0 and DATA_EXFIL on
/// arg 2), or, for flat type-qualified rules with no gate, from
/// [`crate::labels::type_qualified_sink_payload_args`] (Phase 07 ORM raw-SQL
/// receiver methods such as `TypeOrmRepo.query`).  The caller scans each
/// filter separately so taint in the body of a typed client call does not
/// fire SSRF, and bind-array taint at arg 1+ of `TypeOrmRepo.query` does not
/// fire SQL.  An empty list means the whole call is scanned.
///
/// `outer_callee` is the call's own text when CFG construction relabelled
/// the node with a source nested in its arguments
/// (`c.Get(r.FormValue("u"))` becomes callee `r.FormValue`); the SSA
/// receiver still belongs to the outer call, so its method is tried too.
#[allow(clippy::too_many_arguments)]
fn resolve_type_qualified_labels_with_args(
    callee: &str,
    outer_callee: Option<&str>,
    receiver: Option<SsaValue>,
    type_facts: Option<&crate::ssa::type_facts::TypeFactResult>,
    path_env: Option<&constraint::PathEnv>,
    declared: Option<&crate::ssa::type_facts::TypeKind>,
    lang: Lang,
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
    ssa: Option<&SsaBody>,
) -> TqResolution {
    let mut method_candidates = method_candidates_from_chain(callee, lang);
    if let Some(outer) = outer_callee {
        for m in method_candidates_from_chain(outer, lang) {
            if !method_candidates.contains(&m) {
                method_candidates.push(m);
            }
        }
    }
    let receiver_candidates = receiver
        .map(|rv| receiver_candidates_for_type_lookup(rv, ssa, lang))
        .unwrap_or_default();

    let mut prefixes: SmallVec<[&'static str; 4]> = SmallVec::new();
    if let Some(tf) = type_facts {
        for rv in &receiver_candidates {
            if let Some(prefix) = tf.get_type(*rv).and_then(|t| t.label_prefix()) {
                prefixes.push(prefix);
            }
        }
    }
    if let Some(env) = path_env {
        for rv in &receiver_candidates {
            if let Some(prefix) = env
                .get(*rv)
                .types
                .as_singleton()
                .and_then(|t| t.label_prefix())
            {
                prefixes.push(prefix);
            }
        }
    }
    if let Some(prefix) = declared.and_then(|t| t.label_prefix()) {
        prefixes.push(prefix);
    }

    for prefix in prefixes {
        for method in &method_candidates {
            let qualified = format!("{}.{}", prefix, method);
            if let Some(found) = classify_type_qualified_sink(lang, &qualified, extra_labels) {
                return found;
            }
        }
    }

    (SmallVec::new(), SmallVec::new())
}

/// Labels and payload filters for one qualified callee
/// (`HttpClient.Post`), or `None` when nothing matches.  Flat rules and
/// destination gates are merged: the gates give per-cap payload positions,
/// and any flat sink cap no gate covers is scanned over every argument.
/// Gates that narrow by object-literal field are left out, since the field
/// bindings are only lifted for the call's own callee at CFG construction.
fn classify_type_qualified_sink(
    lang: Lang,
    qualified: &str,
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<TqResolution> {
    let mut labels = crate::labels::classify_all(lang.as_str(), qualified, extra_labels);
    let mut filters: SmallVec<[TqSinkFilter; 2]> = SmallVec::new();
    for gate in
        crate::labels::classify_gated_sink(lang.as_str(), qualified, |_| None, |_| None, |_| false)
    {
        let DataLabel::Sink(caps) = gate.label else {
            continue;
        };
        if !gate.object_destination_fields.is_empty() {
            continue;
        }
        let payload = (!gate.payload_args.is_empty()
            && gate.payload_args != crate::labels::ALL_ARGS_PAYLOAD)
            .then_some(gate.payload_args);
        filters.push((caps, payload));
        if !labels.contains(&gate.label) {
            labels.push(gate.label);
        }
    }
    if labels.is_empty() {
        return None;
    }
    if filters.is_empty() {
        if let Some(payload) = crate::labels::type_qualified_sink_payload_args(qualified) {
            let caps = labels.iter().fold(Cap::empty(), |acc, l| match l {
                DataLabel::Sink(c) => acc | *c,
                _ => acc,
            });
            filters.push((caps, Some(payload)));
        }
    } else {
        let gated = filters.iter().fold(Cap::empty(), |acc, (c, _)| acc | *c);
        let flat = labels.iter().fold(Cap::empty(), |acc, l| match l {
            DataLabel::Sink(c) => acc | *c,
            _ => acc,
        });
        let ungated = flat & !gated;
        if !ungated.is_empty() {
            filters.push((ungated, None));
        }
    }
    Some((labels, filters))
}

/// The instruction that defines `v`. The value table names the defining block,
/// so only that block is searched; a hand-built body whose table disagrees with
/// its block layout falls back to scanning every block.
fn defining_inst(body: &SsaBody, v: SsaValue) -> Option<&SsaInst> {
    fn in_block(b: &SsaBlock, v: SsaValue) -> Option<&SsaInst> {
        b.phis
            .iter()
            .chain(b.body.iter())
            .find(|inst| inst.value == v)
    }
    if let Some(vd) = body.value_defs.get(v.0 as usize)
        && let Some(block) = body.blocks.get(vd.block.0 as usize)
        && let Some(inst) = in_block(block, v)
    {
        return Some(inst);
    }
    body.blocks.iter().find_map(|b| in_block(b, v))
}

/// A call whose positional arguments are all literals normally carries no
/// payload, so sink detection skips it.  That is wrong for the handle types
/// whose receiver IS the sink subject: `p = Path(user); p.write_text("x")`
/// writes to the attacker's path and `Net::HTTP.new(host).get("/")` requests
/// the attacker's host, with nothing tainted in the argument list.
///
/// True when the receiver is tainted, typed as one of those handles, and the
/// method is a sink through the type-qualified route (`FileHandle.write_text`).
/// A literal-argument call that only matches a flat sink rule stays skipped, so
/// receiver-only matches such as `re.exec("abc")` on a `RegExp` built from
/// user input do not start firing.
fn literal_arg_call_has_tainted_subject_receiver(
    inst: &SsaInst,
    state: &SsaTaintState,
    transfer: &SsaTaintTransfer,
    ssa: &SsaBody,
) -> bool {
    use crate::ssa::type_facts::TypeKind;
    let SsaOp::Call {
        callee,
        receiver: Some(rv),
        ..
    } = &inst.op
    else {
        return false;
    };
    if state.get(*rv).is_none() {
        return false;
    }
    if transfer.type_facts.is_none() && state.path_env.is_none() {
        return false;
    }
    let is_subject = |k: &TypeKind| matches!(k, TypeKind::FileHandle | TypeKind::HttpClient);
    let typed = receiver_candidates_for_type_lookup(*rv, Some(ssa), transfer.lang)
        .iter()
        .find_map(|cand| {
            transfer
                .type_facts
                .and_then(|tf| tf.get_type(*cand))
                .cloned()
                .filter(is_subject)
                .or_else(|| {
                    state
                        .path_env
                        .as_deref()
                        .and_then(|env| env.get(*cand).types.as_singleton())
                        .filter(is_subject)
                })
        });
    let Some(kind) = typed else {
        return false;
    };
    let (labels, _) = resolve_type_qualified_labels_with_args(
        callee,
        None,
        Some(*rv),
        transfer.type_facts,
        state.path_env.as_deref(),
        None,
        transfer.lang,
        transfer.extra_labels,
        Some(ssa),
    );
    // The qualified lookup (`FileHandle.write`) also matches bare suffix
    // rules (`write`).  Caps the receiver type rules out (the servlet
    // response `write` rule on a `FileWriter`) do not make it the subject.
    labels.iter().any(|l| {
        matches!(l, DataLabel::Sink(bits)
            if !(*bits & !receiver_incompatible_sink_caps(&kind, *bits)).is_empty())
    })
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
        if let Some(inst) = defining_inst(body, current) {
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
                } if matches!(lang, Lang::Rust | Lang::JavaScript | Lang::TypeScript) => {
                    next_receiver = Some(*rv);
                }
                _ => {}
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
        // A chain split over lines (`)\n    .unwrap()`) leaves whitespace around
        // the segment.
        let seg = segments[i - 1].trim();
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

/// Suppress sinks from known non-sink callees (e.g., Go `fmt.Fprintf(os.Stderr, ..)`).
///
/// These are callees whose suffix matches a broad sink rule but whose
/// receiver is known to be safe (console output, not HTTP response).
fn suppress_known_safe_callees(sink_caps: Cap, callee: &str, lang: Lang, info: &NodeInfo) -> Cap {
    match lang {
        // Java `System.out` / `System.err` prints never carry the sink: they
        // are in `labels::java::EXCLUDES`, so the CFG node has no label.
        // Go `fmt.Fprint*` / `io.WriteString` carry an HTML_ESCAPE
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
            if !crate::ssa::type_facts::is_go_writer_sink_callee(callee) {
                return sink_caps;
            }
            let Some(first_arg) = info.call.arg_uses.first() else {
                return sink_caps;
            };
            if first_arg
                .iter()
                .any(|s| crate::ssa::type_facts::is_go_non_response_writer(s.as_str()))
            {
                sink_caps & !Cap::HTML_ESCAPE
            } else {
                sink_caps
            }
        }
        _ => sink_caps,
    }
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

/// Drop sink caps the receiver's type rules out, from every type source: the
/// flow-sensitive `path_env` type, the static `type_facts` type, and (Java) the
/// type the receiver's declaration names.
fn strip_receiver_incompatible_sink_caps(
    sink_caps: &mut Cap,
    inst: &SsaInst,
    info: &NodeInfo,
    transfer: &SsaTaintTransfer,
    state: &SsaTaintState,
) {
    if let SsaOp::Call {
        receiver: Some(rv), ..
    } = &inst.op
    {
        if let Some(ref env) = state.path_env {
            if let Some(kind) = env.get(*rv).types.as_singleton() {
                *sink_caps &= !receiver_incompatible_sink_caps(&kind, *sink_caps);
            }
        }
        if let Some(tf) = transfer.type_facts {
            if let Some(kind) = tf.get_type(*rv) {
                *sink_caps &= !receiver_incompatible_sink_caps(kind, *sink_caps);
            }
        }
    }
    // A Java receiver typed only by its declaration (an injected field, a
    // formal) has no SSA type fact; its declared type still proves a
    // response-write sink does not apply (`PrintStream err; err.println`).
    if let Some(kind) = info.call.receiver_decl_type.as_ref() {
        *sink_caps &= !receiver_incompatible_sink_caps(kind, *sink_caps);
    }
}

/// Check if a receiver type is incompatible with a sink label's requirements.
///
/// Returns the Cap bits that should be REMOVED because the receiver type
/// proves the sink doesn't apply. For example, `HTML_ESCAPE` sinks require
/// an HTTP-response-like receiver, if the receiver is known to be
/// Int/Bool/String, `HTML_ESCAPE` doesn't apply.
pub(crate) fn receiver_incompatible_sink_caps(
    kind: &crate::ssa::type_facts::TypeKind,
    sink_caps: Cap,
) -> Cap {
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
    lang: Lang,
) -> bool {
    let used = inst_use_values(inst);
    if used.is_empty() {
        return false;
    }

    // SSRF / open redirect, string prefix with locked origin
    if sink_caps.intersects(Cap::SSRF | Cap::OPEN_REDIRECT) {
        // Inline template-literal prefix attached to the CFG node directly
        // (covers sinks whose URL is a template literal argument without an
        // intermediate Assign to seed the abstract domain).
        let node_info = &cfg[inst.cfg_node];
        let callee = node_info.call.callee.as_deref();
        if let Some(prefix) = node_info.string_prefix.as_deref() {
            let synthetic = crate::abstract_interp::StringFact::from_prefix(prefix);
            if is_string_safe_for_ssrf(&synthetic, callee) {
                return true;
            }
        }
        if used
            .iter()
            .all(|v| is_string_safe_for_ssrf(&abs.get(*v).string, callee))
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
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg, lang);
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
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg, lang);
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
    sink_caps.intersects(Cap::FILE_IO) && is_path_safe_for_sink(inst, state, ssa, cfg, abs, lang)
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
    lang: Lang,
) -> bool {
    let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg, lang);
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
    lang: Lang,
) -> bool {
    // SSRF / open redirect, check if the URL argument (first arg) has a
    // prefix that locks the origin.
    if sink_caps.intersects(Cap::SSRF | Cap::OPEN_REDIRECT) {
        // Inline template-literal prefix from the call AST itself
        // (e.g. `axios.get(\`https://host/…${x}\`)` has no intermediate Assign
        // to seed a StringFact, check the node-attached prefix directly).
        let node_info = &cfg[inst.cfg_node];
        let callee = node_info.call.callee.as_deref();
        if let Some(prefix) = node_info.string_prefix.as_deref() {
            let synthetic = crate::abstract_interp::StringFact::from_prefix(prefix);
            if is_string_safe_for_ssrf(&synthetic, callee) {
                return true;
            }
        }
        if let Some(first_arg) = args.first() {
            if !first_arg.is_empty()
                && first_arg
                    .iter()
                    .all(|v| is_string_safe_for_ssrf(&abs.get(*v).string, callee))
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
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg, lang);
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
            let leaves = trace_tainted_leaf_values(inst, state, ssa, cfg, lang);
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
    sink_caps.intersects(Cap::FILE_IO) && is_path_safe_for_sink(inst, state, ssa, cfg, abs, lang)
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
    lang: Lang,
) -> SmallVec<[SsaValue; 4]> {
    let mut leaves = SmallVec::new();
    let used = inst_use_values(inst);
    for &v in &used {
        if state.get(v).is_some() {
            trace_single_leaf(v, state, ssa, cfg, lang, &mut leaves, 0);
        }
    }
    leaves
}

fn trace_single_leaf(
    v: SsaValue,
    state: &SsaTaintState,
    ssa: &SsaBody,
    cfg: &Cfg,
    lang: Lang,
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
                    trace_single_leaf(u, state, ssa, cfg, lang, leaves, depth + 1);
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
                        trace_single_leaf(u, state, ssa, cfg, lang, leaves, depth + 1);
                        found = true;
                    }
                }
            }
            if !found {
                leaves.push(v);
            }
        }
        SsaOp::Call { callee, .. }
            if crate::ssa::type_facts::is_int_producing_callee(Some(lang), callee) =>
        {
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
                            trace_single_leaf(u, state, ssa, cfg, lang, leaves, depth + 1);
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
                trace_single_leaf(u, state, ssa, cfg, lang, leaves, depth + 1);
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

/// True when this call node is a network-fetch primitive: it carries BOTH a
/// `Source` label and a `Sink(SSRF)` label (PHP `file_get_contents` /
/// `curl_exec`, Python `requests.get`, JS `axios.get`, …).  Such a call is a
/// source only because it reaches out over the network, so what it returns is
/// exactly as trustworthy as the URL it was handed.
fn is_network_fetch_source(info: &crate::cfg::NodeInfo) -> bool {
    info.taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Source(_)))
        && info
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SSRF)))
}

/// Node-only half of the network-fetch source suppression applied in the
/// `SsaOp::Call` transfer: a network-fetch primitive invoked with a hardcoded
/// URL whose prefix passes [`is_string_safe_for_ssrf`] (a fully-formed
/// `scheme://host/path`) has its endpoint bound at compile time, so the
/// response body is developer-chosen, not attacker-chosen, and the `Source`
/// label does not apply.
///
/// Lives here, on the node rather than on the dataflow state, so the
/// structural `cfg-unguarded-sink` pass in `cfg_analysis::guards` can consult
/// the same predicate.  Both engines must agree on which nodes introduce
/// untrusted data: when only the taint engine honours the suppression, the
/// structural rule keeps treating the fetch result as a source and fires on
/// whatever consumes it, re-creating the finding the suppression removed.
pub(crate) fn node_is_hardcoded_network_fetch_source(info: &crate::cfg::NodeInfo) -> bool {
    if !is_network_fetch_source(info) {
        return false;
    }
    let safe_prefix = |p: &str| {
        is_string_safe_for_ssrf(
            &crate::abstract_interp::StringFact::from_prefix(p),
            info.call.callee.as_deref(),
        )
    };
    info.string_prefix.as_deref().is_some_and(safe_prefix)
        || info
            .call
            .arg_string_literals
            .first()
            .and_then(|v| v.as_deref())
            .is_some_and(safe_prefix)
}

/// URL-sink safety (SSRF and open redirect): the known prefix pins the
/// origin, either `scheme://host/` or a same-origin `/path` that cannot be
/// widened into `//host` (see
/// [`crate::abstract_interp::string_domain::prefix_locks_origin_for`], which
/// also takes the sink `callee`: a callee that reads local paths, such as PHP
/// `file_get_contents`, is not pinned by a `/path` prefix).
fn is_string_safe_for_ssrf(sf: &crate::abstract_interp::StringFact, callee: Option<&str>) -> bool {
    crate::abstract_interp::string_domain::fact_locks_origin_for(callee, sf)
}

/// Whether the abstract string facts of `ssa` prove that every value that
/// reaches the URL sink at `sink` from an untrusted source cannot leave the
/// current origin or a fixed host ([`is_string_safe_for_ssrf`]).  The
/// structural unguarded-sink pass asks it so that it keeps in step with the
/// taint engine, which suppresses such a sink from the same facts.
/// `introduces_untrusted_data` says which CFG nodes are sources.  `false`
/// when no value reaching the sink comes from one.
///
/// The facts are rebuilt here on demand for just the values the sink depends
/// on: each value's operands first, then its own transfer, a phi as the join
/// of its operands.  A value reached again while it is being evaluated (a
/// loop-carried phi) is left unknown.
pub(crate) fn url_sink_origin_locked_by_facts(
    ssa: &SsaBody,
    cfg: &Cfg,
    lang: Lang,
    sink: NodeIndex,
    introduces_untrusted_data: impl Fn(&NodeInfo) -> bool,
) -> bool {
    use crate::abstract_interp::AbstractValue;
    type Defs<'a> = rustc_hash::FxHashMap<SsaValue, &'a SsaInst>;
    let mut defs: Defs = rustc_hash::FxHashMap::default();
    let mut sink_call: Option<&SsaInst> = None;
    for block in &ssa.blocks {
        for inst in block.phis.iter().chain(&block.body) {
            defs.insert(inst.value, inst);
            if inst.cfg_node == sink && matches!(inst.op, SsaOp::Call { .. }) {
                sink_call = Some(inst);
            }
        }
    }
    let Some(sink_call) = sink_call else {
        return false;
    };

    fn eval(
        v: SsaValue,
        defs: &Defs,
        cfg: &Cfg,
        lang: Lang,
        abs: &mut AbstractState,
        seen: &mut rustc_hash::FxHashSet<SsaValue>,
        depth: usize,
    ) {
        if depth > 64 || !seen.insert(v) {
            return;
        }
        let Some(inst) = defs.get(&v) else {
            return;
        };
        for u in inst_use_values(inst) {
            eval(u, defs, cfg, lang, abs, seen, depth + 1);
        }
        match &inst.op {
            SsaOp::Phi(operands) => {
                let mut joined = AbstractValue::bottom();
                for (_, operand) in operands {
                    joined = joined.join(&abs.get(*operand));
                }
                abs.set(inst.value, joined);
            }
            _ => transfer_abstract(inst, cfg, abs, Some(lang)),
        }
    }

    // Whether `v` is computed from a value an untrusted source defines.  A
    // formal parameter is not one: the taint engine seeds none of them.
    fn from_source(
        v: SsaValue,
        defs: &Defs,
        cfg: &Cfg,
        is_source: &dyn Fn(&NodeInfo) -> bool,
        seen: &mut rustc_hash::FxHashSet<SsaValue>,
        depth: usize,
    ) -> bool {
        if depth > 64 || !seen.insert(v) {
            return false;
        }
        let Some(inst) = defs.get(&v) else {
            return false;
        };
        let formal = matches!(inst.op, SsaOp::Param { .. } | SsaOp::SelfParam);
        (!formal && is_source(&cfg[inst.cfg_node]))
            || inst_use_values(inst)
                .into_iter()
                .any(|u| from_source(u, defs, cfg, is_source, seen, depth + 1))
    }

    let callee = cfg[sink].call.callee.as_deref();
    let mut abs = AbstractState::empty();
    let mut eval_seen = rustc_hash::FxHashSet::default();
    let mut any_source = false;
    for v in inst_use_values(sink_call) {
        let mut seen = rustc_hash::FxHashSet::default();
        if !from_source(v, &defs, cfg, &introduces_untrusted_data, &mut seen, 0) {
            continue;
        }
        any_source = true;
        eval(v, &defs, cfg, lang, &mut abs, &mut eval_seen, 0);
        if !is_string_safe_for_ssrf(&abs.get(v).string, callee) {
            return false;
        }
    }
    any_source
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
pub(crate) fn split_qualifier(raw: &str) -> (Option<&str>, Option<&str>) {
    let raw = crate::callgraph::trim_trailing_turbofish(raw);
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

/// Per-file index of `local_summaries` keyed by function leaf name.
///
/// `resolve_callee_full` resolves the callee string of *every* `Call`
/// instruction against `local_summaries` (the file's
/// [`FuncSummaries`]).  The historical resolvers
/// ([`caller_container_for`], [`resolve_local_func_key_query`],
/// [`resolve_local_func_key`], and the ambiguity probe in
/// [`resolve_callee_full`]) each did a *full linear scan* over
/// `local_summaries.keys()` filtering by `(name, lang)`.  With `C`
/// call-sites and `F` functions per file that is `O(C·F)` ≈ `O(F²)`
/// per file, and it runs once for *every* taint pass (summary
/// extraction, the main analysis, child-sink augmentation — ~5×/body).
/// On large source files (hundreds of methods per class) the quadratic
/// dominates callee resolution.
///
/// This index is built once per file from the same `local_summaries`
/// and turns each lookup into an `O(1)` hash probe returning the
/// handful of same-leaf-name candidates.  The single biggest payoff is
/// the *no-match* case (the common one — most callees are external /
/// stdlib functions with no local definition): the linear scan visited
/// all `F` keys to discover "no candidate", whereas the index answers
/// in `O(1)`.
///
/// Keyed by owned name `String` (not a borrow) so the index is a plain
/// owned value with no lifetime, published for the duration of a file's
/// taint passes via the [`with_local_name_index`] scoped guard (mirrors
/// the [`crate::ssa::type_facts::with_file_imports`] /
/// [`crate::cfg::safe_fields::with_safe_lookup_fields`] idiom).  When no
/// index is published the resolvers fall back to the original linear
/// scan, so behaviour is identical for unit tests / probes that analyse
/// a synthetic body without a published index.
pub(crate) struct FuncNameIndex {
    by_name: rustc_hash::FxHashMap<String, SmallVec<[FuncKey; 2]>>,
}

impl FuncNameIndex {
    /// Build the index from a file's `local_summaries`.  `O(F)` clones of
    /// `FuncKey` (3 `String`s each), paid once per file in exchange for
    /// removing the per-call-site `O(F)` scan.
    pub(crate) fn build(local_summaries: &FuncSummaries) -> Self {
        let mut by_name: rustc_hash::FxHashMap<String, SmallVec<[FuncKey; 2]>> =
            rustc_hash::FxHashMap::default();
        for k in local_summaries.keys() {
            by_name.entry(k.name.clone()).or_default().push(k.clone());
        }
        FuncNameIndex { by_name }
    }
}

thread_local! {
    /// Per-file `local_summaries` name index published by
    /// [`with_local_name_index`] around the taint passes that drive
    /// callee resolution.  `None` outside a published scope, in which
    /// case the resolvers use their linear-scan fallback.
    static LOCAL_NAME_INDEX_TLS: RefCell<Option<FuncNameIndex>> = const { RefCell::new(None) };
}

/// RAII guard that publishes a [`FuncNameIndex`] as the per-thread
/// callee-resolution view for the lifetime of the guard, restoring the
/// prior value on drop so nested publications compose (e.g.
/// `lower_all_functions_from_bodies` then `analyse_file_with_lowered`
/// both publish their own index over the same file).
///
/// Use at the top of a file-scoped taint entry point:
/// `let _idx = LocalNameIndexGuard::publish(FuncNameIndex::build(local_summaries));`
pub(crate) struct LocalNameIndexGuard(Option<FuncNameIndex>);

impl LocalNameIndexGuard {
    pub(crate) fn publish(index: FuncNameIndex) -> Self {
        // Escape hatch: `NYX_DISABLE_NAME_INDEX=1` suppresses publication so
        // the resolvers fall back to the linear `local_summaries.keys()`
        // scan.  Used to A/B the indexed vs linear path from a single binary
        // (criterion baseline, differential-correctness check) and as a
        // safety toggle.  Cached so the env read is paid once per process.
        static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let disabled = *DISABLED.get_or_init(|| {
            std::env::var("NYX_DISABLE_NAME_INDEX")
                .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false)
        });
        if disabled {
            return LocalNameIndexGuard(None);
        }
        let prev = LOCAL_NAME_INDEX_TLS.with(|cell| cell.borrow_mut().replace(index));
        LocalNameIndexGuard(prev)
    }
}

impl Drop for LocalNameIndexGuard {
    fn drop(&mut self) {
        LOCAL_NAME_INDEX_TLS.with(|cell| *cell.borrow_mut() = self.0.take());
    }
}

/// Runs `f` over the file-local candidates for `name` (lang-filtered) held by
/// the per-file `FuncNameIndex`, without deep-cloning them out of the
/// thread-local index. `f` receives borrowed `&FuncKey`s that live only for
/// the duration of its call, so it extracts what it needs (typically cloning
/// at most the single winning key) before returning.
///
/// Returns `None` when no index is published, so the caller falls back to a
/// linear `local_summaries` scan (unit-test / probe paths). Returns
/// `Some(f(&[]))` when an index is published but holds no same-lang candidate
/// for `name`.
///
/// Replaces the former `indexed_local_candidates`, which materialised an owned
/// `SmallVec<[FuncKey; 2]>` (a full `FuncKey` clone, three `String` allocations
/// each, per candidate) on every callee resolution, only for the caller to
/// borrow the copies, filter them, and clone at most one winner. Handing the
/// borrowed refs through a closure drops that per-resolution candidate-list
/// clone entirely; the sole remaining `FuncKey` clone is the one winning key
/// each resolver returns by value.
fn with_indexed_local_candidates<R>(
    name: &str,
    lang: Lang,
    f: impl FnOnce(&[&FuncKey]) -> R,
) -> Option<R> {
    LOCAL_NAME_INDEX_TLS.with(|cell| {
        let borrowed = cell.borrow();
        let index = borrowed.as_ref()?;
        let refs: SmallVec<[&FuncKey; 2]> = match index.by_name.get(name) {
            Some(keys) => keys.iter().filter(|k| k.lang == lang).collect(),
            None => SmallVec::new(),
        };
        Some(f(&refs))
    })
}

/// Look up the caller's own container by matching its name in
/// `local_summaries`.  Used so bare self-calls (`foo()` inside a class
/// method) prefer same-class candidates over free functions.
fn caller_container_for(transfer: &SsaTaintTransfer, caller_func: &str) -> Option<String> {
    if caller_func.is_empty() {
        return None;
    }
    // Pick the sole non-empty container shared by every same-name candidate,
    // or `None` if zero or ambiguous.  Operates on borrowed refs so the
    // indexed path never clones the candidate list.
    fn pick(keys: &[&FuncKey]) -> Option<String> {
        let mut containers: Vec<&str> = keys
            .iter()
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
    if let Some(res) = with_indexed_local_candidates(caller_func, transfer.lang, pick) {
        return res;
    }
    let keys: Vec<&FuncKey> = transfer
        .local_summaries
        .keys()
        .filter(|k| k.lang == transfer.lang && k.name == caller_func)
        .collect();
    pick(&keys)
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
    // Prefer the per-file name index (O(1) probe, borrowed candidates → no
    // clone); fall back to the linear scan when no index is published
    // (unit-test / probe paths).
    if let Some(res) =
        with_indexed_local_candidates(q.name, q.caller_lang, |all| resolve_lfk_query_from(all, q))
    {
        return res;
    }
    let all: Vec<&FuncKey> = local_summaries
        .keys()
        .filter(|k| k.name == q.name && k.lang == q.caller_lang)
        .collect();
    resolve_lfk_query_from(&all, q)
}

/// Qualified-first resolution over an already-collected candidate slice.
/// Shared by the indexed (borrowed refs) and linear-scan fallback paths of
/// [`resolve_local_func_key_query`] so neither clones the candidate list.
fn resolve_lfk_query_from(all: &[&FuncKey], q: &CalleeQuery<'_>) -> Option<FuncKey> {
    if all.is_empty() {
        return None;
    }

    // Exact arity first.  When no candidate has the call's arity, tolerate
    // under-application (`param_count >= call_arity`): the surplus parameters
    // are default-valued or optional, a routine call shape in Python, JS/TS,
    // PHP and Ruby.  Mirrors the global resolver's widening so a same-file
    // callee with optional parameters resolves like a cross-file one.
    let widened = q.caller_lang.allows_under_application()
        && q.arity
            .is_some_and(|a| !all.iter().any(|k| k.arity == Some(a)));
    let arity_matches = |k: &FuncKey| match q.arity {
        Some(a) if widened => matches!(k.arity, Some(p) if p >= a),
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
        // A `::`-qualified callee (`Type::method` / `module::func`) names a
        // concrete type or module.  When no local definition has
        // `container == <qualifier>`, the call is an external associated
        // function (stdlib / third-party crate) or a module-path free
        // function — never a same-leaf METHOD living in a different,
        // unrelated container.  Refuse to fall through to the
        // caller-container / arity-only / receiver-var heuristics below,
        // which would otherwise bind the stdlib `File::open` to
        // `impl V5Reader { fn open }` (caller-container self-collision) or
        // `BufReader::new` to a unique-arity `UpdateFile::new` (arity-only
        // leaf collision).  The one legitimate fall-through is a unique
        // same-leaf FREE function (empty container, e.g.
        // `crate::util::sanitize` → top-level `fn sanitize`).  `Self::` /
        // `self::` is a genuine self-call and defers to caller_container.
        if !matches!(nq, "Self" | "self") {
            let free: Vec<&FuncKey> = all
                .iter()
                .copied()
                .filter(|k| k.container.is_empty() && arity_matches(k))
                .collect();
            return if free.len() == 1 {
                Some(free[0].clone())
            } else {
                None
            };
        }
    }

    // Mirrors `GlobalSummaries::resolve_callee` step 3: only a call on the
    // caller's own instance resolves through the caller's container.  A
    // `super` / `parent` call targets a supertype, which this file-local
    // index cannot see, so it is left to the global resolver.
    match q.receiver() {
        CallReceiver::Own => {
            if let Some(cc) = q.caller_container
                && let Some(k) = pick_with_container(cc)
            {
                return Some(k);
            }
        }
        CallReceiver::Super => return None,
        CallReceiver::Other => {}
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

/// Free functions of one name (and call arity, when known) defined in a C
/// file.  More than one means preprocessor alternatives, since C has no
/// overloading and a plain redefinition does not compile.
fn c_preproc_alternatives(
    local_summaries: &FuncSummaries,
    name: &str,
    arity: Option<usize>,
) -> Vec<FuncKey> {
    let pick = |k: &FuncKey| {
        k.container.is_empty()
            && k.lang == Lang::C
            && match arity {
                Some(a) => k.arity == Some(a),
                None => true,
            }
    };
    if let Some(res) = with_indexed_local_candidates(name, Lang::C, |keys| {
        keys.iter()
            .copied()
            .filter(|k| pick(k))
            .cloned()
            .collect::<Vec<_>>()
    }) {
        return res;
    }
    local_summaries
        .keys()
        .filter(|k| k.name == name && pick(k))
        .cloned()
        .collect()
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
    //
    // Prefer the per-file name index (borrowed candidates → no clone); fall
    // back to the linear scan when no index is published.
    if let Some(res) = with_indexed_local_candidates(leaf_name, lang, |keys| {
        resolve_lfk_from(keys, container_hint)
    }) {
        return res;
    }
    let candidates: Vec<&FuncKey> = local_summaries
        .keys()
        .filter(|k| k.name == leaf_name && k.lang == lang)
        .collect();
    resolve_lfk_from(&candidates, container_hint)
}

/// Container-hint narrowing over an already-collected candidate slice.  Shared
/// by the indexed and fallback paths of [`resolve_local_func_key`]; clones
/// only the single winning key (`&FuncKey` refs are pointer copies).
fn resolve_lfk_from(all: &[&FuncKey], container_hint: Option<&str>) -> Option<FuncKey> {
    if all.is_empty() {
        return None;
    }
    let mut candidates: Vec<&FuncKey> = all.to_vec();
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
    /// Per-parameter sanitizer strip-bits lifted from
    /// `SsaFuncSummary::param_to_return`.  Each `(param_idx, bits)` entry
    /// means "taint flowing through THIS parameter to the return value has
    /// `bits` stripped" (a `StripBits` transform on that param).  Params with
    /// an `Identity` transform contribute no entry.
    ///
    /// Kept per-parameter so the call site can strip a param's sanitizer
    /// only from that param's own taint contribution, instead of unioning
    /// every param's StripBits into one aggregate (`sanitizer_caps`) and
    /// applying it to the union of all propagating args — which bleeds one
    /// param's sanitizer onto an unsanitized sibling arg
    /// (`f(a,b){ return a + escape(b) }` would otherwise strip `a`'s caps).
    param_to_return_strip: Vec<(usize, Cap)>,
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
) -> Option<Rc<ResolvedSummary>> {
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
) -> Option<Rc<ResolvedSummary>> {
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
) -> Option<Rc<ResolvedSummary>> {
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

// ── Per-run callee resolution memo ──────────────────────────────────────

/// One answer of [`resolve_callee_full`] together with the inputs that
/// selected it.
struct ResolveMemoEntry {
    callee: String,
    caller_func: String,
    call_ordinal: u32,
    arity_hint: Option<usize>,
    receiver_type: Option<String>,
    result: Option<Rc<ResolvedSummary>>,
}

impl ResolveMemoEntry {
    fn matches(
        &self,
        callee: &str,
        caller_func: &str,
        call_ordinal: u32,
        arity_hint: Option<usize>,
        receiver_type: Option<&str>,
    ) -> bool {
        self.call_ordinal == call_ordinal
            && self.arity_hint == arity_hint
            && self.receiver_type.as_deref() == receiver_type
            && self.callee == callee
            && self.caller_func == caller_func
    }
}

struct ResolveMemoFrame {
    /// Address of the [`SsaTaintTransfer`] the entries were computed for.
    owner: usize,
    entries: rustc_hash::FxHashMap<u64, SmallVec<[ResolveMemoEntry; 1]>>,
}

thread_local! {
    /// Stack of memo frames, one per taint run in progress on this thread. An
    /// inline analysis nests a run for the callee body inside the caller's run.
    static RESOLVE_MEMO: RefCell<Vec<ResolveMemoFrame>> = const { RefCell::new(Vec::new()) };
}

/// Keeps what [`resolve_callee_full`] has answered during one taint run.
///
/// A run visits each block of the body again whenever a predecessor's state
/// changes, then replays every block once more to collect events, and every
/// visit resolves the same calls. During a run the inputs of a resolution do
/// not change: the transfer is borrowed immutably, and it holds shared
/// references to the summaries it consults. So the answer for a call site is
/// worked out once and shared.
///
/// A frame answers only for the transfer that opened it, matched by address.
/// An inline analysis builds its own transfer for the callee body and opens its
/// own frame; lookups made with any other transfer bypass the memo.
pub(super) struct ResolveMemoScope {
    pushed: bool,
}

impl ResolveMemoScope {
    pub(super) fn enter(transfer: &SsaTaintTransfer) -> Self {
        if resolve_memo_disabled() {
            return ResolveMemoScope { pushed: false };
        }
        RESOLVE_MEMO.with(|m| {
            m.borrow_mut().push(ResolveMemoFrame {
                owner: std::ptr::from_ref(transfer) as usize,
                entries: Default::default(),
            });
        });
        ResolveMemoScope { pushed: true }
    }
}

impl Drop for ResolveMemoScope {
    fn drop(&mut self) {
        if self.pushed {
            RESOLVE_MEMO.with(|m| {
                m.borrow_mut().pop();
            });
        }
    }
}

/// `NYX_DISABLE_RESOLVE_MEMO=1` resolves every call from scratch, to compare
/// the memoised and plain paths from one binary. Read once per process.
fn resolve_memo_disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var("NYX_DISABLE_RESOLVE_MEMO")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    })
}

fn resolve_memo_key(
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
    receiver_type: Option<&str>,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = rustc_hash::FxHasher::default();
    callee.hash(&mut h);
    caller_func.hash(&mut h);
    call_ordinal.hash(&mut h);
    arity_hint.hash(&mut h);
    receiver_type.hash(&mut h);
    h.finish()
}

fn resolve_callee_full(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
    receiver_type: Option<&str>,
) -> Option<Rc<ResolvedSummary>> {
    // A callee the language lists in its label EXCLUDES is a library API
    // (Java `System.out.println`, Express `app.get`), never project code,
    // so its leaf name must not bind to a same-named project function such
    // as a `println(PrintWriter, String)` helper in another class.
    let head = callee.split(['(', '<']).next().unwrap_or(callee).trim();
    if crate::labels::is_excluded(transfer.lang.as_str(), head.as_bytes()) {
        return None;
    }
    let owner = std::ptr::from_ref(transfer) as usize;
    let key = resolve_memo_key(callee, caller_func, call_ordinal, arity_hint, receiver_type);
    let hit = RESOLVE_MEMO.with(|m| {
        let frames = m.borrow();
        let frame = frames.last().filter(|f| f.owner == owner)?;
        let entry =
            frame.entries.get(&key)?.iter().find(|e| {
                e.matches(callee, caller_func, call_ordinal, arity_hint, receiver_type)
            })?;
        Some(entry.result.clone())
    });
    if let Some(result) = hit {
        return result;
    }

    let result = resolve_callee_uncached(
        transfer,
        callee,
        caller_func,
        call_ordinal,
        arity_hint,
        receiver_type,
    );

    RESOLVE_MEMO.with(|m| {
        let mut frames = m.borrow_mut();
        if let Some(frame) = frames.last_mut().filter(|f| f.owner == owner) {
            frame
                .entries
                .entry(key)
                .or_default()
                .push(ResolveMemoEntry {
                    callee: callee.to_string(),
                    caller_func: caller_func.to_string(),
                    call_ordinal,
                    arity_hint,
                    receiver_type: receiver_type.map(str::to_string),
                    result: result.clone(),
                });
        }
    });
    result
}

fn resolve_callee_uncached(
    transfer: &SsaTaintTransfer,
    callee: &str,
    caller_func: &str,
    call_ordinal: u32,
    arity_hint: Option<usize>,
    receiver_type: Option<&str>,
) -> Option<Rc<ResolvedSummary>> {
    // -2) Import alias resolution: if the callee matches an aliased import
    // (e.g. `fetchUserCmd` → `getInput` from `./source`), resolve using the
    // original exported name instead.  This fires before all other resolution
    // so that downstream steps see the canonical symbol name.
    if let Some(bindings) = transfer.import_bindings {
        if let Some(binding) = bindings.get(callee_leaf_name(callee)) {
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
    resolve_callee_steps(
        transfer,
        callee,
        caller_func,
        call_ordinal,
        arity_hint,
        receiver_type,
    )
    .map(Rc::new)
}

fn resolve_callee_steps(
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
                    param_to_return_strip: vec![],
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
                    param_to_return_strip: vec![],
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

    // 0a) C `#if` / `#else` alternatives: two free functions of one name and
    // arity in a file are the arms of a preprocessor group, and either arm can
    // be the one compiled.  Union their summaries (any-impl) so a flow into
    // the vulnerable arm is kept whichever arm comes first.
    if let Some(ssa_sums) = transfer.ssa_summaries
        && transfer.lang == Lang::C
        && namespace_qualifier.is_none()
        && receiver_var.is_none()
        && receiver_type.is_none()
    {
        let alts = c_preproc_alternatives(transfer.local_summaries, normalized, arity_hint);
        if alts.len() > 1 {
            let mut accum: Option<ResolvedSummary> = None;
            let mut covered = 0usize;
            for key in &alts {
                let found = ssa_sums.get(key).or_else(|| {
                    ssa_sums
                        .iter()
                        .find(|(k, _)| {
                            k.lang == key.lang
                                && k.container == key.container
                                && k.name == key.name
                                && k.arity == key.arity
                                && k.disambig == key.disambig
                                && k.kind == key.kind
                        })
                        .map(|(_, v)| v)
                });
                if let Some(ssa_sum) = found {
                    let r = convert_ssa_to_resolved(ssa_sum);
                    accum = Some(match accum {
                        None => r,
                        Some(a) => merge_resolved_summaries_fanout(a, r),
                    });
                    covered += 1;
                }
            }
            if covered == alts.len() {
                return accum;
            }
        }
    }

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
            let candidates = gs.ssa_keys_by_qualified(target.lang, &target.namespace, &target.name);
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
                param_to_return_strip: vec![],
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
        let ambiguous_local =
            with_indexed_local_candidates(normalized, transfer.lang, |keys| keys.len() > 1)
                .unwrap_or_else(|| {
                    transfer
                        .local_summaries
                        .keys()
                        .filter(|k| k.name == normalized && k.lang == transfer.lang)
                        .count()
                        > 1
                });
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
            param_to_return_strip: vec![],
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
                param_to_return_strip: vec![],
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

/// Strip bits recorded for a single parameter (`param_to_return_strip`),
/// or `Cap::empty()` when this parameter has no `StripBits` transform.
///
/// This is the per-parameter sanitizer.  When per-parameter decomposition
/// EXISTS (`param_to_return_strip` non-empty) it deliberately does NOT
/// consult the cross-param aggregate (`resolved.sanitizer_caps`), so one
/// parameter's sanitizer cannot bleed onto a sibling argument's taint
/// (`f(a,b){ return a + escape(b) }`).
///
/// When `param_to_return_strip` is ENTIRELY empty, the summary carries no
/// per-param decomposition at all — this is the coarse cross-file tier
/// (`ResolvedSummary` built from a `FuncSummary`/`LocalFuncSummary` where
/// only the aggregate `sanitizer_caps` is known, e.g. cross-file resolution
/// in [`resolve_callee_full`]).  There is no sibling param to bleed from, so
/// fall back to the aggregate — matching the pre-#37 behaviour and keeping
/// cross-file sanitizers (`clean(input)` in another file) effective.
fn param_strip_bits(resolved: &ResolvedSummary, param_idx: usize) -> Cap {
    if resolved.param_to_return_strip.is_empty() {
        return resolved.sanitizer_caps;
    }
    resolved
        .param_to_return_strip
        .iter()
        .find(|(i, _)| *i == param_idx)
        .map(|(_, caps)| *caps)
        .unwrap_or_else(Cap::empty)
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
/// Falls back to the parameter's own `param_to_return_strip` bits (see
/// [`param_strip_bits`], NOT the cross-param aggregate) when:
///   * the summary has no per-path data for this parameter;
///   * every path is predicate-compatible (the narrowing adds no information);
///   * no path is predicate-compatible (conservative: keep the per-param bits).
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
        None => {
            // No per-return-path decomposition for this param: fall back to
            // THIS parameter's own strip bits, NOT the cross-param aggregate
            // (`resolved.sanitizer_caps`).  Using the aggregate here bleeds a
            // sibling param's sanitizer onto this param's taint
            // (`f(a,b){ return a + escape(b) }`).
            return param_strip_bits(resolved, param_idx);
        }
    };

    // Caller-side predicate envelope: union of known_true / known_false bits
    // observed across the caller's tracked variables.  A path is
    // compatible if its required bits (known_true / known_false) do not
    // contradict this envelope.
    let mut caller_kt: u8 = 0;
    let mut caller_kf: u8 = 0;
    for (_, pred) in &state.predicates {
        caller_kt |= pred.known_true & crate::taint::domain::INTERPROC_PREDICATE_BITS;
        caller_kf |= pred.known_false & crate::taint::domain::INTERPROC_PREDICATE_BITS;
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
        // recorded return.  Fall back to THIS parameter's own strip bits
        // rather than the cross-param aggregate (which would bleed a sibling
        // param's sanitizer onto this param's taint).
        return param_strip_bits(resolved, param_idx);
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
        param_strip_bits(resolved, param_idx)
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

    // Compute effective sanitizer caps: union of StripBits across all params.
    // Retained for the aggregate fallback / non-positional resolution paths,
    // but the per-parameter `param_to_return_strip` below is what the call
    // site should prefer so one param's sanitizer does not bleed onto a
    // sibling arg's taint.
    let mut sanitizer_caps = Cap::empty();
    let mut param_to_return_strip: Vec<(usize, Cap)> = Vec::new();
    for (idx, transform) in &ssa_sum.param_to_return {
        if let TaintTransform::StripBits(bits) = transform {
            sanitizer_caps |= *bits;
            if !bits.is_empty() {
                param_to_return_strip.push((*idx, *bits));
            }
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
    // Strip same-file, non-chain sites when `caller_namespace` is
    // supplied: a single-hop intra-file helper's own sink coordinates
    // collide with the caller's pass-2 intraprocedural finding under
    // [`crate::commands::scan::deduplicate_taint_flows`], silently
    // dropping the call-site flow finding.  Sites with `from_chain=true`
    // are chain-hop markers from a deeper callee and have no matching
    // intermediate finding to dedup with — keep them so multi-hop
    // chains surface the deepest sink line.  Cross-file sites are
    // preserved (the other file's analysis can't be deduped against
    // this one).  Mirrors the gate in [`should_promote_sink_site`].
    let param_to_sink_sites = if let Some(caller_ns) = caller_namespace {
        ssa_sum
            .param_to_sink
            .iter()
            .map(|(idx, sites)| {
                let filtered: SmallVec<[crate::summary::SinkSite; 1]> = sites
                    .iter()
                    .filter(|s| s.from_chain || s.file_rel.is_empty() || s.file_rel != caller_ns)
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
        param_to_return_strip,
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

    // param_to_return_strip: intersect per-parameter strip bits, mirroring
    // the `sanitizer_caps` AND rule.  Only bits stripped by EVERY
    // implementer for a given parameter can be considered cleared, since the
    // virtual dispatch could land on an implementer that does not sanitize
    // that parameter.  A param present in only one side is dropped (the
    // other implementer strips nothing for it).
    let mut merged_strip: Vec<(usize, Cap)> = Vec::new();
    for (idx, caps) in &acc.param_to_return_strip {
        if let Some((_, other)) = r.param_to_return_strip.iter().find(|(i, _)| i == idx) {
            let inter = *caps & *other;
            if !inter.is_empty() {
                merged_strip.push((*idx, inter));
            }
        }
    }
    acc.param_to_return_strip = merged_strip;

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

#[cfg(test)]
mod engine_audit_fixes_tests {
    use super::*;

    // Finding #9: `!== null` must NOT be read as an equality null-check.
    #[test]
    fn null_check_strict_inequality_is_not_success_branch() {
        // Equality forms: null/none/no-error outcome is the TRUE branch.
        assert!(null_check_true_branch_is_success("err == null"));
        assert!(null_check_true_branch_is_success("err === null"));
        assert!(null_check_true_branch_is_success("err == nil"));
        assert!(null_check_true_branch_is_success("err == none"));
        assert!(null_check_true_branch_is_success("err is none"));
        assert!(null_check_true_branch_is_success("is_ok(err)"));

        // Inequality forms: null outcome is the FALSE branch.  The strict
        // `!==` form previously matched `== null` as a substring.
        assert!(!null_check_true_branch_is_success("err !== null"));
        assert!(!null_check_true_branch_is_success("err != null"));
        assert!(!null_check_true_branch_is_success("err != nil"));
        assert!(!null_check_true_branch_is_success("err != none"));
        assert!(!null_check_true_branch_is_success("is_err(err)"));
    }

    // Finding #6: only free-function exit/abort wipes taint state; a
    // receiver-qualified method with the same trailing segment must not.
    #[test]
    fn noreturn_only_matches_free_functions() {
        // Free functions in C/C++ terminate the process.
        assert!(is_noreturn_call(Lang::C, "exit"));
        assert!(is_noreturn_call(Lang::Cpp, "abort"));
        assert!(is_noreturn_call(Lang::C, "_Exit"));
        assert!(is_noreturn_call(Lang::Cpp, "quick_exit"));

        // Method calls (dot or arrow receiver) are ordinary calls.
        assert!(!is_noreturn_call(Lang::Cpp, "transaction.abort"));
        assert!(!is_noreturn_call(Lang::Cpp, "app.exit"));
        assert!(!is_noreturn_call(Lang::C, "handlers->abort"));
        assert!(!is_noreturn_call(Lang::Cpp, "state_machine.abort"));

        // Other languages never treat these as noreturn.
        assert!(!is_noreturn_call(Lang::JavaScript, "exit"));
    }

    // Finding #7: protocol-relative `//host` bypass of the leading-slash
    // SSRF origin lock.
    #[test]
    fn ssrf_safe_rejects_protocol_relative_prefix() {
        use crate::abstract_interp::StringFact;

        // A real same-origin path lock is safe.
        assert!(is_string_safe_for_ssrf(
            &StringFact::from_prefix("/api/"),
            None
        ));
        assert!(is_string_safe_for_ssrf(
            &StringFact::from_prefix("/projects"),
            None
        ));

        // A bare "/" lock is NOT safe: a tainted "/evil.com" suffix yields
        // a protocol-relative "//evil.com" URL.
        assert!(!is_string_safe_for_ssrf(
            &StringFact::from_prefix("/"),
            None
        ));

        // An already protocol-relative prefix is not safe either.
        assert!(!is_string_safe_for_ssrf(
            &StringFact::from_prefix("//"),
            None
        ));
        assert!(!is_string_safe_for_ssrf(
            &StringFact::from_prefix("//evil.com"),
            None
        ));

        // Scheme-locked absolute URL with a path separator stays safe.
        assert!(is_string_safe_for_ssrf(
            &StringFact::from_prefix("https://api.internal/"),
            None
        ));
    }
}

#[cfg(test)]
mod namespace_qualifier_authority_tests {
    //! Regression pins for the `::`-qualified callee authority rule in
    //! [`resolve_local_func_key_query`].  Distilled from meilisearch
    //! `crates/dump/src/reader/v5/mod.rs`, where the stdlib `File::open`
    //! (leaf `open`) and `BufReader::new` (leaf `new`) share their leaf
    //! names with the user methods `Reader::open` / `IndexReader::new`.  A
    //! qualified callee whose qualifier matches no local container must not
    //! bind a same-leaf method from an unrelated container.
    use super::*;
    use crate::cfg::{FuncSummaries, LocalFuncSummary};
    use crate::summary::CalleeQuery;
    use crate::symbol::{FuncKey, FuncKind};
    use petgraph::graph::NodeIndex;

    fn method_key(container: &str, name: &str, arity: usize) -> FuncKey {
        FuncKey::from_parts(
            Lang::Rust,
            "mod.rs",
            container,
            name,
            Some(arity),
            None,
            FuncKind::Method,
        )
    }

    fn stub_summary(arity: usize) -> LocalFuncSummary {
        // The query only reads `local_summaries` keys; the value is inert.
        LocalFuncSummary {
            entry: NodeIndex::new(0),
            source_caps: Cap::empty(),
            sanitizer_caps: Cap::empty(),
            sink_caps: Cap::empty(),
            param_count: arity,
            param_names: Vec::new(),
            propagating_params: Vec::new(),
            tainted_sink_params: Vec::new(),
            callees: Vec::new(),
            container: String::new(),
            disambig: None,
            kind: FuncKind::Method,
        }
    }

    fn summaries() -> FuncSummaries {
        // `Reader::open(dump)` and `IndexReader::new(path)` — both non-empty
        // containers, both arity 1, plus a free `sanitize(s)` helper.
        let mut m = FuncSummaries::default();
        m.insert(method_key("Reader", "open", 1), stub_summary(1));
        m.insert(method_key("IndexReader", "new", 1), stub_summary(1));
        m.insert(
            FuncKey::new_function(Lang::Rust, "mod.rs", "sanitize", Some(1)),
            stub_summary(1),
        );
        m
    }

    fn q<'a>(
        name: &'a str,
        qualifier: Option<&'a str>,
        caller_container: Option<&'a str>,
    ) -> CalleeQuery<'a> {
        CalleeQuery {
            name,
            caller_lang: Lang::Rust,
            caller_namespace: "mod.rs",
            caller_container,
            receiver_type: None,
            namespace_qualifier: qualifier,
            receiver_var: None,
            arity: Some(1),
        }
    }

    #[test]
    fn file_open_does_not_bind_caller_container_open_method() {
        // `File::open(...)` inside `impl Reader { fn open }`: qualifier
        // `File` has no local container, and the caller-container fallback
        // must NOT bind the enclosing `Reader::open`.
        let s = summaries();
        let r = resolve_local_func_key_query(&s, &q("open", Some("File"), Some("Reader")));
        assert!(
            r.is_none(),
            "File::open must not resolve to caller-container Reader::open, got {r:?}"
        );
    }

    #[test]
    fn bufreader_new_does_not_bind_unique_arity_new_method() {
        // `BufReader::new(x)` with a unique arity-1 `IndexReader::new`: the
        // arity-only leaf fallback must not bind it.
        let s = summaries();
        let r = resolve_local_func_key_query(&s, &q("new", Some("BufReader"), Some("Reader")));
        assert!(
            r.is_none(),
            "BufReader::new must not resolve to IndexReader::new, got {r:?}"
        );
    }

    #[test]
    fn qualifier_matching_container_still_resolves() {
        // A genuine `Reader::open(...)` (qualifier == container) resolves.
        let s = summaries();
        let r = resolve_local_func_key_query(&s, &q("open", Some("Reader"), None));
        assert_eq!(r, Some(method_key("Reader", "open", 1)));
    }

    #[test]
    fn self_qualifier_defers_to_caller_container() {
        // `Self::open(...)` inside `impl Reader` is a real self-call and must
        // still resolve to `Reader::open`.
        let s = summaries();
        let r = resolve_local_func_key_query(&s, &q("open", Some("Self"), Some("Reader")));
        assert_eq!(r, Some(method_key("Reader", "open", 1)));
    }

    #[test]
    fn module_path_free_function_still_resolves() {
        // `crate::util::sanitize(x)` (qualifier `util`) must still bind the
        // unique same-leaf FREE function.
        let s = summaries();
        let r = resolve_local_func_key_query(&s, &q("sanitize", Some("util"), Some("Reader")));
        assert_eq!(
            r,
            Some(FuncKey::new_function(
                Lang::Rust,
                "mod.rs",
                "sanitize",
                Some(1)
            ))
        );
    }
}
