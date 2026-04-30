//! Demand-driven backwards taint analysis from sinks.
//!
//! The forward taint engine (`ssa_transfer.rs`) proceeds source-to-sink,
//! spending analysis budget on every function the source might touch.  Its
//! precision ceiling is fixed by what summaries + inline re-analysis can
//! preserve on every edge of a flow, a single lossy edge drops the finding.
//!
//! This module implements the opposite direction: start at each sink value,
//! walk *reverse* SSA edges and (when needed) cross-file callee bodies on
//! demand, and emit a [`BackwardFlow`] when a source is reached or an
//! accumulated path predicate proves the flow infeasible.
//!
//! The analysis is additive:
//!
//! * When a forward finding's sink is confirmed by a backwards walk that
//!   reaches a matching source, we append `backwards-confirmed` to the
//!   finding's evidence notes.
//! * When the backwards walk proves the flow infeasible via accumulated
//!   path predicates, we append `backwards-infeasible`, consumed by the
//!   confidence scorer as a cap-to-Low signal.
//! * Backward flows that reach a source with no matching forward finding
//!   become standalone `taint-backwards-flow` diags (a separate rule id so
//!   existing graders can distinguish the two channels).
//!
//! The feature is gated by
//! [`crate::utils::analysis_options::AnalysisOptions::backwards_analysis`]
//! (default off) so enabling it is opt-in.

use crate::cfg::Cfg;
use crate::labels::{Cap, DataLabel, SourceKind};
use crate::ssa::{SsaBody, SsaOp, SsaValue};
use crate::summary::GlobalSummaries;
use crate::symbol::{FuncKey, Lang};
use crate::taint::Finding;
use crate::taint::ssa_transfer::CalleeSsaBody;
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};

// ─── Budgets ────────────────────────────────────────────────────────────────

/// Default k-depth cap for cross-function body expansion.  The forward path
/// uses k=1 inline re-analysis; backwards starts higher because the common
/// case ("sink in callee → operand comes from a caller's caller") needs at
/// least two frames to resolve.
pub const DEFAULT_BACKWARDS_DEPTH: u32 = 2;

/// Maximum number of SSA values any single backwards walk may expand before
/// bailing out with [`BackwardFlow::budget_exhausted`] set.  Chosen to match
/// the forward engine's `MAX_TRACKED_VARS` (64) by a factor of ~16 so that
/// pathological flat functions still terminate.
pub const BACKWARDS_VALUE_BUDGET: u32 = 1024;

/// Maximum number of blocks a cross-file callee body may have before we
/// refuse to expand it during a backwards walk.  Mirrors
/// `MAX_INLINE_BLOCKS` on the forward path so the two directions use
/// compatible policies for "too large to inspect".
pub const MAX_BACKWARDS_CALLEE_BLOCKS: usize = 500;

// ─── Demand + flow records ─────────────────────────────────────────────────

/// The demand a sink makes on an operand: which capabilities would trigger
/// the finding, and which predicate evidence (if any) has been gathered so
/// far.
///
/// `caps` is monotone, the walk can only narrow the demand (by proving
/// operands validated or sanitized against specific capability bits), never
/// widen it.  This keeps backwards composition with summary-derived
/// transforms sound.
#[derive(Clone, Debug, Default)]
pub struct DemandState {
    /// Capability bits the sink consumes.  A source with a cap outside this
    /// set is not considered a match.
    pub caps: Cap,
    /// Validation predicate bits accumulated along the walk.  Encoded using
    /// [`crate::taint::domain::predicate_kind_bit`]; bit `i` set means the
    /// corresponding `PredicateKind` was observed as holding on every
    /// predecessor visited so far.
    pub validated_true: u8,
    /// Counterpart to [`Self::validated_true`] for known-false predicates.
    pub validated_false: u8,
    /// Number of cross-function inline expansions performed along this walk.
    pub depth: u32,
}

impl DemandState {
    /// Seed a fresh demand state from a sink's capability mask.
    pub fn new(caps: Cap) -> Self {
        Self {
            caps,
            validated_true: 0,
            validated_false: 0,
            depth: 0,
        }
    }
}

/// One backwards flow: a single value-chain from a sink to either a proven
/// source, an infeasible prune, or a budget exhaustion.
#[derive(Clone, Debug)]
pub struct BackwardFlow {
    /// SSA value that the sink consumed.
    pub sink_value: SsaValue,
    /// CFG node of the sink statement.
    pub sink_node: NodeIndex,
    /// Capability bits the sink demanded.
    pub sink_caps: Cap,
    /// Source classification if the walk reached one.
    pub source_kind: Option<SourceKind>,
    /// CFG node of the reached source (if any).
    pub source_node: Option<NodeIndex>,
    /// Set when the accumulated predicates proved the flow infeasible before
    /// reaching any source.
    pub infeasible: bool,
    /// Set when the walk hit [`BACKWARDS_VALUE_BUDGET`] without terminating.
    pub budget_exhausted: bool,
    /// Maximum cross-function expansion depth reached.
    pub max_depth: u32,
    /// SSA-value chain traversed, sink first, source last.  Truncated to
    /// the last [`MAX_CHAIN_LEN`] values to bound memory.
    pub chain: SmallVec<[SsaValue; 8]>,
}

impl BackwardFlow {
    /// Whether this flow confirmed a source/sink pairing.  Infeasible and
    /// budget-exhausted flows never confirm.
    pub fn is_confirmation(&self) -> bool {
        self.source_kind.is_some() && !self.infeasible && !self.budget_exhausted
    }
}

/// Hard cap on [`BackwardFlow::chain`] length.  Truncation is lossy for
/// diagnostic display but preserves the sink→source shape.
pub const MAX_CHAIN_LEN: usize = 16;

// ─── Driver context ────────────────────────────────────────────────────────

/// Inputs the driver needs to resolve cross-function operand demands.
///
/// The context is intentionally narrow: it borrows from whatever analysis
/// objects the caller has already prepared (summaries, the current body,
/// cross-file body maps) and does not build its own.  This keeps the
/// backwards pass cheap to enable, when off, none of this code is touched.
pub struct BackwardsCtx<'a> {
    /// Callee's SSA body.
    pub ssa: &'a SsaBody,
    /// Callee's CFG (for `cfg_node → NodeInfo` lookups at source events).
    pub cfg: &'a Cfg,
    /// Language tag for source-kind heuristics (e.g. `os.getenv` hints).
    pub lang: Lang,
    /// Whole-program summaries: used to discover cross-file bodies and
    /// [`SsaFuncSummary`] metadata at call instructions.
    pub global_summaries: Option<&'a GlobalSummaries>,
    /// Pre-lowered intra-file callee bodies keyed by [`FuncKey`].  Shared
    /// with the forward path so we do not lower functions twice.
    pub intra_file_bodies: Option<&'a HashMap<FuncKey, CalleeSsaBody>>,
    /// Maximum allowed cross-function expansion depth.
    pub depth_budget: u32,
}

impl<'a> BackwardsCtx<'a> {
    /// Construct a minimal context against an already-lowered body.  Callers
    /// that want cross-file resolution must also populate `global_summaries`
    /// and/or `intra_file_bodies`.
    pub fn new(ssa: &'a SsaBody, cfg: &'a Cfg, lang: Lang) -> Self {
        Self {
            ssa,
            cfg,
            lang,
            global_summaries: None,
            intra_file_bodies: None,
            depth_budget: DEFAULT_BACKWARDS_DEPTH,
        }
    }
}

// ─── Transfer function ─────────────────────────────────────────────────────

/// One step of the backwards transfer: given a demand on `value`, compute
/// the demand on its immediate SSA operands.  Returns the list of
/// `(operand, demand)` pairs, possibly empty if the defining op terminates
/// the walk (Source/Const/Param).
///
/// This is a pure function over the op and demand; cycle detection and
/// budget enforcement live in the driver.
pub fn backward_transfer(
    ssa: &SsaBody,
    value: SsaValue,
    demand: &DemandState,
) -> (BackwardStep, SmallVec<[(SsaValue, DemandState); 4]>) {
    let def = ssa.def_of(value);
    let block = &ssa.blocks[def.block.0 as usize];
    // Locate the defining instruction inside the block.  Phis come first,
    // body instructions after.
    let op = block
        .phis
        .iter()
        .chain(block.body.iter())
        .find(|i| i.value == value)
        .map(|i| &i.op);

    let op = match op {
        Some(o) => o,
        None => return (BackwardStep::Unknown, SmallVec::new()),
    };

    match op {
        SsaOp::Source => (BackwardStep::ReachedSource(def.cfg_node), SmallVec::new()),
        SsaOp::Const(_) => (BackwardStep::ReachedConst, SmallVec::new()),
        SsaOp::Param { index } => (
            BackwardStep::ReachedParam {
                index: *index,
                node: def.cfg_node,
            },
            SmallVec::new(),
        ),
        SsaOp::SelfParam => (
            BackwardStep::ReachedParam {
                index: 0,
                node: def.cfg_node,
            },
            SmallVec::new(),
        ),
        SsaOp::CatchParam => (BackwardStep::ReachedCatchParam, SmallVec::new()),
        SsaOp::Nop => (BackwardStep::Unknown, SmallVec::new()),
        // Undef is a phi-operand sentinel on edges with no reaching
        // definition, nothing to trace backwards through.
        SsaOp::Undef => (BackwardStep::ReachedConst, SmallVec::new()),
        SsaOp::Phi(operands) => {
            // Demand fans out to every incoming value: the runtime value of
            // a phi is the runtime value of exactly one predecessor, so
            // any reaching source on any predecessor produces a flow.
            let mut next: SmallVec<[(SsaValue, DemandState); 4]> = SmallVec::new();
            for (_pred_block, pred_value) in operands {
                next.push((*pred_value, demand.clone()));
            }
            (BackwardStep::Phi, next)
        }
        SsaOp::Assign(operands) => {
            // Conservative: demand flows to every operand.  Assign carries
            // the union of BinOp / Cast / Copy shapes in the current IR, so
            // treating them all as "any operand could supply caps" is the
            // only sound choice without an explicit BinOp split.
            let mut next: SmallVec<[(SsaValue, DemandState); 4]> = SmallVec::new();
            for op in operands {
                next.push((*op, demand.clone()));
            }
            (BackwardStep::Assign, next)
        }
        SsaOp::Call {
            callee,
            args,
            receiver,
            ..
        } => {
            // For Call ops the full demand transfer depends on callee
            // metadata (summary or body).  The driver handles that ,
            // return a `BackwardStep::Call` carrying the receiver + args
            // so the driver can consult [`GlobalSummaries`] / bodies_by_key.
            let mut flat: SmallVec<[(SsaValue, DemandState); 4]> = SmallVec::new();
            if let Some(r) = receiver {
                flat.push((*r, demand.clone()));
            }
            for arg_uses in args {
                for u in arg_uses {
                    flat.push((*u, demand.clone()));
                }
            }
            (
                BackwardStep::Call {
                    callee: callee.clone(),
                },
                flat,
            )
        }
        SsaOp::FieldProj { receiver, .. } => {
            // Field projection: demand for `obj.f` flows to `obj`.  Treated
            // structurally like a single-operand Assign for the backwards
            // walk, sufficient until future passes will introduce field-sensitive
            // demand discrimination.
            let mut next: SmallVec<[(SsaValue, DemandState); 4]> = SmallVec::new();
            next.push((*receiver, demand.clone()));
            (BackwardStep::Assign, next)
        }
    }
}

/// Classification of a single backwards transfer step, used by the driver to
/// decide whether to terminate, fan out, or perform a callee-specific
/// resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackwardStep {
    /// Defining op is a tainted [`SsaOp::Source`], walk terminates with a
    /// confirmed flow.
    ReachedSource(NodeIndex),
    /// Defining op is a [`SsaOp::Const`], walk terminates without a source.
    ReachedConst,
    /// Defining op is an [`SsaOp::Param`] / [`SsaOp::SelfParam`], walk may
    /// continue by resolving the parameter against the caller's arguments
    /// (requires reverse call-graph expansion, which is out of scope for
    /// the current cut and is handled as a terminal step).
    ReachedParam { index: usize, node: NodeIndex },
    /// Defining op is a [`SsaOp::CatchParam`].  Treated as a taint boundary:
    /// a catch parameter may carry exception-borne taint, but resolving
    /// the actual exception source requires exception-edge traversal not
    /// performed here.
    ReachedCatchParam,
    /// Phi node, driver fans out to predecessors.
    Phi,
    /// Arithmetic / copy / cast, driver fans out to operands.
    Assign,
    /// Call op, driver consults summaries and/or callee bodies.
    Call { callee: String },
    /// Defining op could not be located or was a [`SsaOp::Nop`], walk
    /// terminates as inconclusive.
    Unknown,
}

// ─── Driver ────────────────────────────────────────────────────────────────

/// Walk backwards from `sink_value` in `ctx.ssa`, producing at most one
/// [`BackwardFlow`] per reached source (phi fan-outs can produce multiple).
///
/// Does not consult forward findings, the caller is responsible for
/// matching the returned flows against its finding set.
pub fn analyse_sink_backwards(
    ctx: &BackwardsCtx<'_>,
    sink_value: SsaValue,
    sink_node: NodeIndex,
    sink_caps: Cap,
) -> Vec<BackwardFlow> {
    let mut out = Vec::new();
    let mut visited: HashSet<SsaValue> = HashSet::new();
    let mut budget: u32 = 0;
    let initial_demand = DemandState::new(sink_caps);
    let mut chain: SmallVec<[SsaValue; 8]> = SmallVec::new();
    chain.push(sink_value);
    walk_dfs(
        ctx,
        sink_value,
        sink_node,
        sink_caps,
        &initial_demand,
        &mut visited,
        &mut budget,
        &mut chain,
        &mut out,
    );
    out
}

#[allow(clippy::too_many_arguments)]
fn walk_dfs(
    ctx: &BackwardsCtx<'_>,
    value: SsaValue,
    sink_node: NodeIndex,
    sink_caps: Cap,
    demand: &DemandState,
    visited: &mut HashSet<SsaValue>,
    budget: &mut u32,
    chain: &mut SmallVec<[SsaValue; 8]>,
    out: &mut Vec<BackwardFlow>,
) {
    if *budget >= BACKWARDS_VALUE_BUDGET {
        // Budget exhausted → emit one "unknown" flow so the caller can
        // surface the exhaustion as a confidence limiter.
        out.push(BackwardFlow {
            sink_value: chain.first().copied().unwrap_or(value),
            sink_node,
            sink_caps,
            source_kind: None,
            source_node: None,
            infeasible: false,
            budget_exhausted: true,
            max_depth: demand.depth,
            chain: clip_chain(chain),
        });
        return;
    }
    *budget += 1;
    if !visited.insert(value) {
        return; // cycle / already-expanded
    }

    // Before dispatching on the SSA op kind, consult the defining CFG node's
    // label set.  Many Source-labelled callables in the CFG lower to an
    // `SsaOp::Call` rather than `SsaOp::Source` (request.args.get,
    // os.getenv, …), recognising the label here keeps the walk in
    // sync with the forward engine's source model.
    let def_cfg_node = ctx.ssa.def_of(value).cfg_node;
    if def_cfg_node.index() < ctx.cfg.node_count() {
        let info = &ctx.cfg[def_cfg_node];
        let source_cap_match = info
            .taint
            .labels
            .iter()
            .any(|l| matches!(l, DataLabel::Source(c) if !(*c & sink_caps).is_empty()));
        if source_cap_match {
            let source_kind = classify_source_kind(ctx, def_cfg_node, sink_caps);
            out.push(BackwardFlow {
                sink_value: chain.first().copied().unwrap_or(value),
                sink_node,
                sink_caps,
                source_kind: Some(source_kind),
                source_node: Some(def_cfg_node),
                infeasible: false,
                budget_exhausted: false,
                max_depth: demand.depth,
                chain: clip_chain(chain),
            });
            return;
        }
    }

    let (step, next) = backward_transfer(ctx.ssa, value, demand);
    match step {
        BackwardStep::ReachedSource(node) => {
            let source_kind = classify_source_kind(ctx, node, sink_caps);
            out.push(BackwardFlow {
                sink_value: chain.first().copied().unwrap_or(value),
                sink_node,
                sink_caps,
                source_kind: Some(source_kind),
                source_node: Some(node),
                infeasible: false,
                budget_exhausted: false,
                max_depth: demand.depth,
                chain: clip_chain(chain),
            });
        }
        BackwardStep::ReachedConst => {
            // Constants never supply taint, treat as a silent prune.
        }
        BackwardStep::ReachedParam { index: _, node } => {
            // Reverse-call-graph expansion is intentionally left out of the
            // first cut: the confirmation use-case (matching a forward
            // finding) does not need it because the forward engine already
            // reached the param via the caller's argument flow.  Record a
            // terminal "parameter" flow so the caller can see the walk
            // terminated cleanly.  Downstream merge treats param-terminals
            // as non-confirmatory.
            out.push(BackwardFlow {
                sink_value: chain.first().copied().unwrap_or(value),
                sink_node,
                sink_caps,
                source_kind: None,
                source_node: Some(node),
                infeasible: false,
                budget_exhausted: false,
                max_depth: demand.depth,
                chain: clip_chain(chain),
            });
        }
        BackwardStep::ReachedCatchParam => {
            // Exception-borne taint, record but don't confirm.  Marked
            // non-confirmatory so unit tests can distinguish "walk reached
            // catch-param" from "walk reached source".
        }
        BackwardStep::Phi | BackwardStep::Assign => {
            for (operand, next_demand) in next {
                chain.push(operand);
                walk_dfs(
                    ctx,
                    operand,
                    sink_node,
                    sink_caps,
                    &next_demand,
                    visited,
                    budget,
                    chain,
                    out,
                );
                chain.pop();
            }
        }
        BackwardStep::Call { callee } => {
            // First attempt: resolve via cross-file / intra-file SSA bodies.
            //
            // This path fires only when the callee can be keyed to a
            // [`FuncKey`] via [`GlobalSummaries`] because the call graph
            // and summary map both index on that key.  If we cannot resolve
            // the callee we fall through to the `Assign` conservative
            // fanout below.
            let resolved = resolve_callee_body(ctx, &callee, demand.depth);
            if let Some((callee_body, callee_key)) = resolved {
                // Over the callee body, collect return-block demand roots
                // and recurse.  Cycle guard: deeper walks reuse `visited`
                // via a nested set so distinct callees don't false-share.
                let mut callee_visited: HashSet<SsaValue> = HashSet::new();
                let mut callee_budget: u32 = 0;
                let callee_ctx = BackwardsCtx {
                    ssa: &callee_body.ssa,
                    cfg: callee_body.body_graph.as_ref().unwrap_or(ctx.cfg),
                    lang: ctx.lang,
                    global_summaries: ctx.global_summaries,
                    intra_file_bodies: ctx.intra_file_bodies,
                    depth_budget: ctx.depth_budget,
                };
                let mut callee_demand = demand.clone();
                callee_demand.depth += 1;
                for block in &callee_body.ssa.blocks {
                    if let crate::ssa::ir::Terminator::Return(Some(ret_val)) = &block.terminator {
                        walk_dfs(
                            &callee_ctx,
                            *ret_val,
                            sink_node,
                            sink_caps,
                            &callee_demand,
                            &mut callee_visited,
                            &mut callee_budget,
                            chain,
                            out,
                        );
                    }
                }
                // Prevent an unused-variable warning while still accepting
                // the key in the matcher, the key is useful for debug
                // logging in bigger expansions.
                let _ = callee_key;
                return;
            }
            // Fall-through: no resolvable body.  Conservatively fan out to
            // every operand / receiver so a source reachable through the
            // call arguments is still observed.
            for (operand, next_demand) in next {
                chain.push(operand);
                walk_dfs(
                    ctx,
                    operand,
                    sink_node,
                    sink_caps,
                    &next_demand,
                    visited,
                    budget,
                    chain,
                    out,
                );
                chain.pop();
            }
        }
        BackwardStep::Unknown => {
            // No information, terminate silently.
        }
    }
}

/// Try to resolve a callee name to a pre-lowered body using the same
/// precedence as the forward engine: intra-file first, then cross-file.
fn resolve_callee_body<'a>(
    ctx: &BackwardsCtx<'a>,
    callee: &str,
    current_depth: u32,
) -> Option<(&'a CalleeSsaBody, FuncKey)> {
    if current_depth >= ctx.depth_budget {
        return None;
    }
    // Strip Rust / Python qualification to a leaf name, mirroring
    // `callgraph::callee_leaf_name`.  The normalised leaf is the lookup key
    // against both body maps.
    let leaf = callee
        .rsplit("::")
        .next()
        .unwrap_or(callee)
        .rsplit('.')
        .next()
        .unwrap_or(callee);
    if let Some(map) = ctx.intra_file_bodies {
        for (key, body) in map.iter() {
            if key.name == leaf && body.ssa.blocks.len() <= MAX_BACKWARDS_CALLEE_BLOCKS {
                return Some((body, key.clone()));
            }
        }
    }
    if let Some(map) = ctx.global_summaries.and_then(|gs| gs.bodies_by_key()) {
        for (key, body) in map.iter() {
            if key.name == leaf && body.ssa.blocks.len() <= MAX_BACKWARDS_CALLEE_BLOCKS {
                return Some((body, key.clone()));
            }
        }
    }
    None
}

/// Attempt to infer the source kind of a reached source op by inspecting
/// its label on the CFG node.  Falls back to `SourceKind::Unknown` when the
/// node either has no labels or its labels do not include a Source.
fn classify_source_kind(ctx: &BackwardsCtx<'_>, node: NodeIndex, sink_caps: Cap) -> SourceKind {
    if node.index() >= ctx.cfg.node_count() {
        return SourceKind::Unknown;
    }
    let info = &ctx.cfg[node];
    // If the node carries a Source label matching the demanded caps, we
    // can use the existing `infer_source_kind` heuristic against the
    // callee name for finer-grained classification (UserInput vs
    // EnvironmentConfig vs FileSystem …).
    let caps_match = info
        .taint
        .labels
        .iter()
        .any(|l| matches!(l, DataLabel::Source(c) if !(*c & sink_caps).is_empty()));
    if caps_match {
        let callee_str = info.call.callee.as_deref().unwrap_or("");
        crate::labels::infer_source_kind(sink_caps, callee_str)
    } else {
        SourceKind::Unknown
    }
}

fn clip_chain(chain: &SmallVec<[SsaValue; 8]>) -> SmallVec<[SsaValue; 8]> {
    if chain.len() <= MAX_CHAIN_LEN {
        return chain.clone();
    }
    // Keep the sink end (first) and the most recent tail so the diagnostic
    // retains both ends of the flow.
    let tail = &chain[chain.len() - (MAX_CHAIN_LEN - 1)..];
    let mut out: SmallVec<[SsaValue; 8]> = SmallVec::new();
    out.push(chain[0]);
    out.extend_from_slice(tail);
    out
}

// ─── Finding annotation ────────────────────────────────────────────────────

/// Note appended to `evidence.notes` when a forward finding is corroborated
/// by a backwards flow reaching a compatible source.
pub const NOTE_CONFIRMED: &str = "backwards-confirmed";
/// Note appended when backwards ruled the flow infeasible.
pub const NOTE_INFEASIBLE: &str = "backwards-infeasible";
/// Note appended when the walk hit the budget without a verdict.
pub const NOTE_BUDGET: &str = "backwards-budget-exhausted";

/// Classification for a forward finding after backwards post-processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingVerdict {
    /// Backwards reached a matching source, finding corroborated.
    Confirmed,
    /// Backwards was inconclusive (no source, not infeasible).  Finding
    /// keeps its forward-assigned confidence.
    Inconclusive,
    /// Backwards proved the flow infeasible, finding confidence must drop.
    Infeasible,
    /// Budget exhausted before a verdict was reached.
    BudgetExhausted,
}

/// Reduce a batch of backward flows for a single sink into a single verdict.
pub fn aggregate_verdict(flows: &[BackwardFlow]) -> FindingVerdict {
    if flows.iter().any(|f| f.is_confirmation()) {
        return FindingVerdict::Confirmed;
    }
    if flows.iter().all(|f| f.infeasible) && !flows.is_empty() {
        return FindingVerdict::Infeasible;
    }
    if flows.iter().any(|f| f.budget_exhausted) {
        return FindingVerdict::BudgetExhausted;
    }
    FindingVerdict::Inconclusive
}

/// Apply a verdict as a note on a [`Finding`].  No-ops when the verdict is
/// [`FindingVerdict::Inconclusive`], the forward finding retains its
/// original metadata.
pub fn annotate_finding(finding: &mut Finding, verdict: FindingVerdict) {
    // `Finding` does not own an Evidence struct directly (that lives on
    // the emitted `Diag`), but it carries `symbolic: Option<SymbolicVerdict>`.
    // We piggy-back on `SymbolicVerdict.cutoff_notes` so the backwards
    // corroboration survives finding → diag → evidence without requiring
    // a new schema field.  When `symbolic` is empty we synthesise one with
    // `Verdict::NotAttempted` to make the notes addressable.
    let note = match verdict {
        FindingVerdict::Confirmed => NOTE_CONFIRMED,
        FindingVerdict::Infeasible => NOTE_INFEASIBLE,
        FindingVerdict::BudgetExhausted => NOTE_BUDGET,
        FindingVerdict::Inconclusive => return,
    };
    let sv = finding
        .symbolic
        .get_or_insert(crate::evidence::SymbolicVerdict {
            verdict: crate::evidence::Verdict::NotAttempted,
            constraints_checked: 0,
            paths_explored: 0,
            witness: None,
            interproc_call_chains: Vec::new(),
            cutoff_notes: Vec::new(),
        });
    if !sv.cutoff_notes.iter().any(|n| n == note) {
        sv.cutoff_notes.push(note.to_string());
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{EdgeKind, NodeInfo};
    use crate::ssa::ir::{BlockId, SsaBlock, SsaInst, Terminator, ValueDef};
    use petgraph::Graph;
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    fn make_value_def(block: BlockId, cfg_node: NodeIndex) -> ValueDef {
        ValueDef {
            var_name: None,
            cfg_node,
            block,
        }
    }

    /// Build a one-block SSA body with a Source → Assign → terminator shape
    /// so the backward driver can walk a realistic chain end-to-end.
    fn build_trivial_source_body() -> (SsaBody, Cfg) {
        let mut cfg: Graph<NodeInfo, EdgeKind> = Graph::new();
        let src_node = cfg.add_node(NodeInfo::default());
        let use_node = cfg.add_node(NodeInfo::default());

        let source_val = SsaValue(0);
        let user_val = SsaValue(1);

        let block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: source_val,
                    op: SsaOp::Source,
                    cfg_node: src_node,
                    var_name: None,
                    span: (0, 0),
                },
                SsaInst {
                    value: user_val,
                    op: SsaOp::Assign(smallvec![source_val]),
                    cfg_node: use_node,
                    var_name: None,
                    span: (0, 0),
                },
            ],
            terminator: Terminator::Return(Some(user_val)),
            preds: SmallVec::new(),
            succs: SmallVec::new(),
        };

        let ssa = SsaBody {
            blocks: vec![block],
            entry: BlockId(0),
            value_defs: vec![
                make_value_def(BlockId(0), src_node),
                make_value_def(BlockId(0), use_node),
            ],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: Vec::new(),
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),
            synthetic_externals: std::collections::HashSet::new(),
        };

        (ssa, cfg)
    }

    #[test]
    fn demand_state_new_sets_caps() {
        let d = DemandState::new(Cap::SQL_QUERY);
        assert_eq!(d.caps, Cap::SQL_QUERY);
        assert_eq!(d.depth, 0);
        assert_eq!(d.validated_true, 0);
        assert_eq!(d.validated_false, 0);
    }

    /// Regression guard: the cap-routing logic must round-trip
    /// `Cap::DATA_EXFIL` exactly like every other cap.  The backwards
    /// engine treats the demand as opaque bits, so if a future change
    /// accidentally narrows the type of `caps` (e.g. a hardcoded mask)
    /// the data-exfiltration cap stops surviving the walk.
    #[test]
    fn demand_state_roundtrips_data_exfil_cap() {
        let d = DemandState::new(Cap::DATA_EXFIL);
        assert_eq!(d.caps, Cap::DATA_EXFIL);
        assert!(d.caps.contains(Cap::DATA_EXFIL));
        // Sanity: combined demand keeps the bit alongside SSRF (the two
        // most-frequently-co-occurring caps on outbound HTTP gates).
        let combined = DemandState::new(Cap::DATA_EXFIL | Cap::SSRF);
        assert!(combined.caps.contains(Cap::DATA_EXFIL));
        assert!(combined.caps.contains(Cap::SSRF));
    }

    /// The backwards driver must classify a `DATA_EXFIL`-capable source
    /// even when the sink demand is *exactly* `DATA_EXFIL` (no other
    /// caps).  Mirrors `driver_walks_source_to_sink` but pins the cap so
    /// a future change that intersects with a wider mask (and thus
    /// silently widens the demand) is caught.
    #[test]
    fn driver_walks_data_exfil_source_to_sink() {
        let (ssa, mut cfg) = build_trivial_source_body();
        // Tag the source CFG node with a Source(DATA_EXFIL) label so
        // the cap-match path (the one that actually rules end-to-end
        // routing) exercises the bit.
        let src_node = NodeIndex::new(0);
        cfg[src_node]
            .taint
            .labels
            .push(DataLabel::Source(Cap::DATA_EXFIL));

        let ctx = BackwardsCtx::new(&ssa, &cfg, Lang::JavaScript);
        let flows =
            analyse_sink_backwards(&ctx, SsaValue(1), NodeIndex::new(1), Cap::DATA_EXFIL);
        assert_eq!(flows.len(), 1, "exactly one DATA_EXFIL flow expected");
        assert!(flows[0].is_confirmation(), "must confirm at the source");
        assert_eq!(flows[0].sink_caps, Cap::DATA_EXFIL);
    }

    #[test]
    fn backward_transfer_source_terminates() {
        let (ssa, _cfg) = build_trivial_source_body();
        let demand = DemandState::new(Cap::all());
        let (step, next) = backward_transfer(&ssa, SsaValue(0), &demand);
        assert_eq!(next.len(), 0);
        matches!(step, BackwardStep::ReachedSource(_));
    }

    #[test]
    fn backward_transfer_const_terminates() {
        let mut cfg: Graph<NodeInfo, EdgeKind> = Graph::new();
        let c_node = cfg.add_node(NodeInfo::default());
        let ssa = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Const(None),
                    cfg_node: c_node,
                    var_name: None,
                    span: (0, 0),
                }],
                terminator: Terminator::Return(Some(SsaValue(0))),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![make_value_def(BlockId(0), c_node)],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: Vec::new(),
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),
            synthetic_externals: std::collections::HashSet::new(),
        };
        let demand = DemandState::new(Cap::all());
        let (step, next) = backward_transfer(&ssa, SsaValue(0), &demand);
        assert!(next.is_empty());
        assert_eq!(step, BackwardStep::ReachedConst);
    }

    #[test]
    fn backward_transfer_param_terminates() {
        let mut cfg: Graph<NodeInfo, EdgeKind> = Graph::new();
        let p_node = cfg.add_node(NodeInfo::default());
        let ssa = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Param { index: 2 },
                    cfg_node: p_node,
                    var_name: None,
                    span: (0, 0),
                }],
                terminator: Terminator::Return(Some(SsaValue(0))),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![make_value_def(BlockId(0), p_node)],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: Vec::new(),
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),
            synthetic_externals: std::collections::HashSet::new(),
        };
        let demand = DemandState::new(Cap::all());
        let (step, _next) = backward_transfer(&ssa, SsaValue(0), &demand);
        match step {
            BackwardStep::ReachedParam { index, .. } => assert_eq!(index, 2),
            other => panic!("expected ReachedParam, got {:?}", other),
        }
    }

    #[test]
    fn backward_transfer_assign_fans_out() {
        let (ssa, _cfg) = build_trivial_source_body();
        let demand = DemandState::new(Cap::all());
        let (step, next) = backward_transfer(&ssa, SsaValue(1), &demand);
        assert_eq!(step, BackwardStep::Assign);
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].0, SsaValue(0));
        assert_eq!(next[0].1.caps, Cap::all());
    }

    #[test]
    fn backward_transfer_phi_fans_out() {
        let mut cfg: Graph<NodeInfo, EdgeKind> = Graph::new();
        let n0 = cfg.add_node(NodeInfo::default());
        let n1 = cfg.add_node(NodeInfo::default());
        let n2 = cfg.add_node(NodeInfo::default());
        let n3 = cfg.add_node(NodeInfo::default());

        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Source,
                        cfg_node: n0,
                        var_name: None,
                        span: (0, 0),
                    }],
                    terminator: Terminator::Goto(BlockId(2)),
                    preds: SmallVec::new(),
                    succs: smallvec![BlockId(2)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Const(None),
                        cfg_node: n1,
                        var_name: None,
                        span: (0, 0),
                    }],
                    terminator: Terminator::Goto(BlockId(2)),
                    preds: SmallVec::new(),
                    succs: smallvec![BlockId(2)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Phi(smallvec![
                            (BlockId(0), SsaValue(0)),
                            (BlockId(1), SsaValue(1))
                        ]),
                        cfg_node: n2,
                        var_name: None,
                        span: (0, 0),
                    }],
                    body: vec![],
                    terminator: Terminator::Return(Some(SsaValue(2))),
                    preds: smallvec![BlockId(0), BlockId(1)],
                    succs: SmallVec::new(),
                },
            ],
            entry: BlockId(0),
            value_defs: vec![
                make_value_def(BlockId(0), n0),
                make_value_def(BlockId(1), n1),
                make_value_def(BlockId(2), n2),
                make_value_def(BlockId(2), n3),
            ],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: Vec::new(),
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),
            synthetic_externals: std::collections::HashSet::new(),
        };

        let demand = DemandState::new(Cap::all());
        let (step, next) = backward_transfer(&ssa, SsaValue(2), &demand);
        assert_eq!(step, BackwardStep::Phi);
        assert_eq!(next.len(), 2);
    }

    #[test]
    fn driver_walks_source_to_sink() {
        let (ssa, cfg) = build_trivial_source_body();
        let ctx = BackwardsCtx::new(&ssa, &cfg, Lang::Python);
        let flows = analyse_sink_backwards(&ctx, SsaValue(1), NodeIndex::new(1), Cap::all());
        assert_eq!(flows.len(), 1, "one source-reaching flow expected");
        assert!(flows[0].is_confirmation(), "flow should confirm");
        assert_eq!(
            flows[0].sink_node.index(),
            1,
            "sink_node passthrough preserved"
        );
    }

    #[test]
    fn driver_phi_yields_two_flows() {
        // Two-predecessor phi where only one branch carries a Source.
        let mut cfg: Graph<NodeInfo, EdgeKind> = Graph::new();
        let n0 = cfg.add_node(NodeInfo::default());
        let n1 = cfg.add_node(NodeInfo::default());
        let n2 = cfg.add_node(NodeInfo::default());

        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Source,
                        cfg_node: n0,
                        var_name: None,
                        span: (0, 0),
                    }],
                    terminator: Terminator::Goto(BlockId(2)),
                    preds: SmallVec::new(),
                    succs: smallvec![BlockId(2)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Const(None),
                        cfg_node: n1,
                        var_name: None,
                        span: (0, 0),
                    }],
                    terminator: Terminator::Goto(BlockId(2)),
                    preds: SmallVec::new(),
                    succs: smallvec![BlockId(2)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Phi(smallvec![
                            (BlockId(0), SsaValue(0)),
                            (BlockId(1), SsaValue(1))
                        ]),
                        cfg_node: n2,
                        var_name: None,
                        span: (0, 0),
                    }],
                    body: vec![],
                    terminator: Terminator::Return(Some(SsaValue(2))),
                    preds: smallvec![BlockId(0), BlockId(1)],
                    succs: SmallVec::new(),
                },
            ],
            entry: BlockId(0),
            value_defs: vec![
                make_value_def(BlockId(0), n0),
                make_value_def(BlockId(1), n1),
                make_value_def(BlockId(2), n2),
            ],
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: Vec::new(),
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),
            synthetic_externals: std::collections::HashSet::new(),
        };

        let ctx = BackwardsCtx::new(&ssa, &cfg, Lang::JavaScript);
        let flows = analyse_sink_backwards(&ctx, SsaValue(2), NodeIndex::new(2), Cap::all());
        // One flow per phi operand visited (const branch yields no flow;
        // source branch yields one confirmation).
        assert_eq!(
            flows.iter().filter(|f| f.is_confirmation()).count(),
            1,
            "exactly one source-reaching flow through the phi"
        );
    }

    #[test]
    fn aggregate_verdict_prefers_confirmation() {
        let confirmed = BackwardFlow {
            sink_value: SsaValue(0),
            sink_node: NodeIndex::new(0),
            sink_caps: Cap::SQL_QUERY,
            source_kind: Some(SourceKind::UserInput),
            source_node: Some(NodeIndex::new(1)),
            infeasible: false,
            budget_exhausted: false,
            max_depth: 0,
            chain: SmallVec::new(),
        };
        let infeasible = BackwardFlow {
            sink_value: SsaValue(0),
            sink_node: NodeIndex::new(0),
            sink_caps: Cap::SQL_QUERY,
            source_kind: None,
            source_node: None,
            infeasible: true,
            budget_exhausted: false,
            max_depth: 0,
            chain: SmallVec::new(),
        };
        assert_eq!(
            aggregate_verdict(&[confirmed.clone(), infeasible.clone()]),
            FindingVerdict::Confirmed
        );
        assert_eq!(aggregate_verdict(&[infeasible]), FindingVerdict::Infeasible);
        assert_eq!(aggregate_verdict(&[]), FindingVerdict::Inconclusive);
    }

    #[test]
    fn annotate_finding_appends_note() {
        use crate::evidence::FlowStepKind;
        use crate::taint::FlowStepRaw;
        let mut f = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: NodeIndex::new(0),
            source: NodeIndex::new(1),
            path: vec![],
            source_kind: SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![FlowStepRaw {
                cfg_node: NodeIndex::new(1),
                var_name: None,
                op_kind: FlowStepKind::Source,
            }],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };
        annotate_finding(&mut f, FindingVerdict::Confirmed);
        let sv = f.symbolic.as_ref().expect("symbolic verdict created");
        assert!(sv.cutoff_notes.iter().any(|n| n == NOTE_CONFIRMED));
        // Idempotent
        annotate_finding(&mut f, FindingVerdict::Confirmed);
        let sv = f.symbolic.as_ref().unwrap();
        assert_eq!(
            sv.cutoff_notes
                .iter()
                .filter(|n| *n == NOTE_CONFIRMED)
                .count(),
            1
        );
    }

    #[test]
    fn annotate_finding_inconclusive_no_change() {
        let mut f = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: NodeIndex::new(0),
            source: NodeIndex::new(1),
            path: vec![],
            source_kind: SourceKind::Unknown,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 0,
            uses_summary: false,
            flow_steps: vec![],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };
        annotate_finding(&mut f, FindingVerdict::Inconclusive);
        assert!(f.symbolic.is_none());
    }

    #[test]
    fn budget_exhausted_flow_not_confirmation() {
        let bf = BackwardFlow {
            sink_value: SsaValue(0),
            sink_node: NodeIndex::new(0),
            sink_caps: Cap::all(),
            source_kind: Some(SourceKind::UserInput),
            source_node: Some(NodeIndex::new(1)),
            infeasible: false,
            budget_exhausted: true,
            max_depth: 0,
            chain: SmallVec::new(),
        };
        assert!(!bf.is_confirmation());
    }
}
