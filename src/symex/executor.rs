//! Multi-path symbolic exploration with bounded forking and loop awareness.
//!
//! Extends single-path symbolic execution to explore multiple paths through
//! the CFG from source to sink. At branch points where both successors lie on
//! some source-to-sink CFG path, the executor forks the symbolic state and
//! explores both branches independently.
//!
//! Loop-aware execution: back edges are detected via dominator analysis,
//! loops are unrolled up to `MAX_LOOP_UNROLL` iterations, then phi-defined
//! values are widened to `Unknown` (preserving taint) and the executor jumps
//! to the loop exit successor.
//!
//! Hard budgets on forks, paths, and total symbolic transfer steps guarantee
//! termination. Verdict aggregation is sound: `Infeasible` is only returned
//! when the entire relevant search space was explored without budget exhaustion.

#![allow(clippy::collapsible_if, clippy::unnecessary_map_or)]

use std::collections::{HashMap, HashSet, VecDeque};

use smallvec::SmallVec;

use crate::cfg::Cfg;
use crate::constraint;
use crate::evidence::{SymbolicVerdict, Verdict};
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::ir::{BlockId, SsaBody, SsaValue, Terminator};
use crate::taint::Finding;

use super::SymexContext;
use super::loops::LoopInfo;
use super::state::{PathConstraint, SymbolicState};
use super::transfer::{self, SymexHeapCtx, SymexSummaryCtx};
use super::value::SymbolicValue;

// ─────────────────────────────────────────────────────────────────────────────
//  Budget constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum branch forks per finding before falling back to single-path.
const MAX_FORKS_PER_FINDING: usize = 3;

/// Maximum total paths explored per finding.
const MAX_PATHS_PER_FINDING: usize = 8;

/// Maximum symbolic transfer steps (phi + body instructions) summed across
/// ALL paths for one finding. Global, not per-path.
const MAX_TOTAL_STEPS: usize = 500;

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

/// A single exploration path in flight.
///
/// The executor advances this one block at a time via successor transitions.
/// No pre-computed block sequence, successor choice happens at each terminator.
struct ExplorationState {
    /// Current symbolic state (cloned at fork points).
    sym_state: SymbolicState,
    /// Constraint environment (cloned at fork points).
    env: constraint::PathEnv,
    /// Block to process next.
    current_block: BlockId,
    /// Last block visited (for path-sensitive phi resolution).
    predecessor: Option<BlockId>,
    /// Forks consumed by this path and its ancestors.
    forks_used: usize,
    /// Symbolic transfer steps on THIS path.
    steps_taken: usize,
    /// Constraints checked on this path.
    constraints_checked: u32,
    /// Per-block visit count for bounded loop unrolling.
    /// Inherited at fork points, both branches share the visit history.
    visit_counts: HashMap<BlockId, u8>,
    /// When `Some`, this path entered via an exception edge.
    /// Moved into `sym_state.exception_context` immediately before block
    /// transfer so that `CatchParam` can consume it. This is a taint carrier
    /// (`SymbolicValue::Unknown`), not a faithful thrown-value model.
    exception_context: Option<SymbolicValue>,
}

/// Outcome of a single completed exploration path.
pub(super) struct PathOutcome {
    verdict: Verdict,
    constraints_checked: u32,
    witness: Option<String>,
}

/// Result of multi-path exploration across all paths for one finding.
pub(super) struct ExplorationResult {
    pub paths_completed: Vec<PathOutcome>,
    #[allow(dead_code)]
    pub paths_pruned: usize,
    #[allow(dead_code)]
    pub total_steps: usize,
    /// True IFF the relevant search space was fully explored under budget.
    /// False if any fork/path/step budget prevented exploring a relevant path.
    pub search_exhausted: bool,
    /// Interprocedural internal sink findings collected across all paths.
    pub interproc_findings: Vec<super::interproc::InternalSinkFinding>,
    /// Interprocedural cutoff reasons collected across all paths.
    pub interproc_cutoffs: Vec<super::interproc::CutoffReason>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Reachability
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the set of blocks on some CFG path from source to sink.
///
/// This is **CFG source-to-sink reachability pruning**, NOT a taint slice.
/// It does not prove that tainted data flows through these blocks, only that
/// control flow can reach the sink from the source through them. Used to
/// prevent exploring branches structurally disconnected from the
/// source-to-sink span.
///
/// Algorithm: BFS forward from source ∩ BFS backward from sink. O(|blocks|).
fn compute_source_sink_reachable(
    ssa: &SsaBody,
    source_block: BlockId,
    sink_block: BlockId,
    exception_succs: &HashMap<BlockId, SmallVec<[BlockId; 2]>>,
    exception_preds: &HashMap<BlockId, SmallVec<[BlockId; 2]>>,
) -> HashSet<BlockId> {
    // Forward BFS from source
    let mut forward = HashSet::new();
    let mut queue = VecDeque::new();
    forward.insert(source_block);
    queue.push_back(source_block);
    while let Some(bid) = queue.pop_front() {
        if let Some(block) = ssa.blocks.get(bid.0 as usize) {
            for &succ in &block.succs {
                if forward.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        // Follow exception edges from this block
        if let Some(catches) = exception_succs.get(&bid) {
            for &catch in catches {
                if forward.insert(catch) {
                    queue.push_back(catch);
                }
            }
        }
    }

    // Backward BFS from sink
    let mut backward = HashSet::new();
    backward.insert(sink_block);
    queue.push_back(sink_block);
    while let Some(bid) = queue.pop_front() {
        if let Some(block) = ssa.blocks.get(bid.0 as usize) {
            for &pred in &block.preds {
                if backward.insert(pred) {
                    queue.push_back(pred);
                }
            }
        }
        // Follow exception edges TO this block (reverse)
        if let Some(srcs) = exception_preds.get(&bid) {
            for &src in srcs {
                if backward.insert(src) {
                    queue.push_back(src);
                }
            }
        }
    }

    // Intersection
    forward.intersection(&backward).copied().collect()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Exploration engine
// ─────────────────────────────────────────────────────────────────────────────

/// Run multi-path symbolic exploration for a single finding.
///
/// Walks the CFG from the source block to the sink block, forking at branch
/// points where both successors are on some source-to-sink CFG path.
/// Budget-bounded: at most [`MAX_FORKS_PER_FINDING`] forks,
/// [`MAX_PATHS_PER_FINDING`] total paths, and [`MAX_TOTAL_STEPS`] symbolic
/// transfer steps across all paths.
pub(super) fn explore_finding(finding: &Finding, ctx: &SymexContext) -> ExplorationResult {
    let ssa = ctx.ssa;
    let cfg = ctx.cfg;
    let const_values = ctx.const_values;
    let type_facts = ctx.type_facts;
    let path_blocks = super::extract_path_blocks(finding, ssa);
    if path_blocks.len() < 2 {
        return ExplorationResult {
            paths_completed: vec![PathOutcome {
                verdict: Verdict::Inconclusive,
                constraints_checked: 0,
                witness: None,
            }],
            paths_pruned: 0,
            total_steps: 0,
            search_exhausted: true,
            interproc_findings: Vec::new(),
            interproc_cutoffs: Vec::new(),
        };
    }

    let source_block = path_blocks[0];
    let sink_block = path_blocks[path_blocks.len() - 1];

    // Precompute exception edge maps (O(n) once, reused everywhere)
    let exception_succs: HashMap<BlockId, SmallVec<[BlockId; 2]>> = {
        let mut map: HashMap<BlockId, SmallVec<[BlockId; 2]>> = HashMap::new();
        for &(src, catch) in &ssa.exception_edges {
            let entry = map.entry(src).or_default();
            if !entry.contains(&catch) {
                entry.push(catch);
            }
        }
        map
    };
    let exception_preds: HashMap<BlockId, SmallVec<[BlockId; 2]>> = {
        let mut map: HashMap<BlockId, SmallVec<[BlockId; 2]>> = HashMap::new();
        for &(src, catch) in &ssa.exception_edges {
            let entry = map.entry(catch).or_default();
            if !entry.contains(&src) {
                entry.push(src);
            }
        }
        map
    };

    let reachable = compute_source_sink_reachable(
        ssa,
        source_block,
        sink_block,
        &exception_succs,
        &exception_preds,
    );
    let on_path: HashSet<BlockId> = path_blocks.iter().copied().collect();

    // Compute loop information
    let loop_info = super::loops::analyse_loops(ssa);

    // Seed symbolic state (same as single-path analyse_finding_path)
    let mut sym_state = SymbolicState::new();
    sym_state.seed_from_const_values(const_values);
    for step in &finding.flow_steps {
        if matches!(step.op_kind, crate::evidence::FlowStepKind::Source)
            && let Some(&ssa_val) = ssa.cfg_node_map.get(&step.cfg_node)
        {
            sym_state.mark_tainted(ssa_val);
            sym_state.set(ssa_val, SymbolicValue::Symbol(ssa_val));
        }
    }

    // Seed constraint environment
    let mut env = constraint::PathEnv::empty();
    env.seed_from_optimization(const_values, type_facts);

    // Initialize work queue
    let initial = ExplorationState {
        sym_state,
        env,
        current_block: source_block,
        predecessor: None,
        forks_used: 0,
        steps_taken: 0,
        constraints_checked: 0,
        visit_counts: HashMap::new(),
        exception_context: None,
    };

    let mut work_queue: VecDeque<ExplorationState> = VecDeque::new();
    work_queue.push_back(initial);

    let mut outcomes: Vec<PathOutcome> = Vec::new();
    let mut paths_pruned: usize = 0;
    let mut total_steps: usize = 0;
    let mut search_exhausted = true;

    // Build summary context for cross-file symbolic modeling
    let summary_ctx = ctx.global_summaries.map(|gs| SymexSummaryCtx {
        global_summaries: gs,
        lang: ctx.lang,
        namespace: ctx.namespace,
        type_facts: Some(ctx.type_facts),
    });
    let summary_ctx_ref = summary_ctx.as_ref();

    // Build heap context for field-sensitive symbolic heap.
    let heap_ctx = ctx.points_to.map(|pts| SymexHeapCtx {
        points_to: pts,
        ssa,
        lang: ctx.lang,
        const_values: ctx.const_values,
    });
    let heap_ctx_ref = heap_ctx.as_ref();

    // Build interprocedural context for callee body execution.
    let interproc_budget = std::cell::Cell::new(super::interproc::InterprocBudget::new());
    let interproc_cache = std::cell::RefCell::new(std::collections::HashMap::new());
    let interproc_reentry = std::cell::RefCell::new(std::collections::HashMap::new());
    let interproc_stats = std::cell::Cell::new(super::interproc::InterprocStats::default());
    let interproc_ctx = ctx
        .callee_bodies
        .map(|bodies| super::interproc::InterprocCtx {
            callee_bodies: bodies,
            cfg,
            lang: ctx.lang,
            max_depth: super::interproc::DEFAULT_MAX_DEPTH,
            budget: &interproc_budget,
            cache: &interproc_cache,
            reentry_counts: &interproc_reentry,
            max_reentry_per_func: super::interproc::DEFAULT_MAX_REENTRY_PER_FUNC,
            scc_membership: ctx.scc_membership,
            max_scc_reentry: super::interproc::DEFAULT_MAX_SCC_REENTRY,
            stats: &interproc_stats,
            cross_file_bodies: ctx.cross_file_bodies,
            cross_file_depth: 0,
            caller_namespace: ctx.namespace,
        });
    let interproc_ctx_ref = interproc_ctx.as_ref();

    // Create SMT context for cross-variable constraint solving.
    #[cfg(feature = "smt")]
    let mut smt_ctx = if super::smt_enabled() {
        Some(super::smt::SmtContext::new())
    } else {
        None
    };

    while let Some(mut state) = work_queue.pop_front() {
        // Global budget check: path count
        if outcomes.len() >= MAX_PATHS_PER_FINDING {
            paths_pruned += 1;
            search_exhausted = false;
            continue;
        }

        // Global budget check: total steps
        if total_steps >= MAX_TOTAL_STEPS {
            paths_pruned += 1;
            search_exhausted = false;
            continue;
        }

        // Process blocks along this path until termination or fork
        let outcome = run_path(
            &mut state,
            ssa,
            cfg,
            const_values,
            &reachable,
            &on_path,
            &loop_info,
            &exception_succs,
            &mut work_queue,
            &mut outcomes,
            &mut total_steps,
            &mut search_exhausted,
            finding,
            summary_ctx_ref,
            heap_ctx_ref,
            interproc_ctx_ref,
            #[cfg(feature = "smt")]
            &mut smt_ctx,
        );

        if let Some(outcome) = outcome {
            outcomes.push(outcome);
        }
    }

    ExplorationResult {
        paths_completed: outcomes,
        paths_pruned,
        total_steps,
        search_exhausted,
        interproc_findings: Vec::new(),
        interproc_cutoffs: Vec::new(),
    }
}

/// Process blocks along a single path until it terminates, forks, or exhausts budget.
///
/// Returns `Some(PathOutcome)` when the path reaches a terminal state.
/// Returns `None` when the path was consumed by a fork (both branches enqueued).
#[allow(clippy::too_many_arguments)]
fn run_path(
    state: &mut ExplorationState,
    ssa: &SsaBody,
    cfg: &Cfg,
    const_values: &HashMap<SsaValue, ConstLattice>,
    reachable: &HashSet<BlockId>,
    on_path: &HashSet<BlockId>,
    loop_info: &LoopInfo,
    exception_succs: &HashMap<BlockId, SmallVec<[BlockId; 2]>>,
    work_queue: &mut VecDeque<ExplorationState>,
    outcomes: &mut Vec<PathOutcome>,
    total_steps: &mut usize,
    search_exhausted: &mut bool,
    finding: &Finding,
    summary_ctx: Option<&SymexSummaryCtx>,
    heap_ctx: Option<&SymexHeapCtx>,
    interproc_ctx: Option<&super::interproc::InterprocCtx>,
    #[cfg(feature = "smt")] smt_ctx: &mut Option<super::smt::SmtContext>,
) -> Option<PathOutcome> {
    loop {
        // Global step budget
        if *total_steps >= MAX_TOTAL_STEPS {
            *search_exhausted = false;
            return Some(record_outcome(state, finding, ssa, cfg));
        }

        let block_id = state.current_block;
        let block = match ssa.blocks.get(block_id.0 as usize) {
            Some(b) => b,
            None => {
                let witness = try_extract_witness(state, finding, ssa, cfg);
                return Some(PathOutcome {
                    verdict: Verdict::Inconclusive,
                    constraints_checked: state.constraints_checked,
                    witness,
                });
            }
        };

        // Increment visit count and check bounded unrolling
        let visit_count = {
            let count = state.visit_counts.entry(block_id).or_insert(0);
            *count = count.saturating_add(1);
            *count
        };

        if loop_info.loop_heads.contains(&block_id) && visit_count > super::loops::MAX_LOOP_UNROLL {
            // Widen symbolic precision but PRESERVE taint
            state.sym_state.widen_at_loop_head(block_id, ssa);

            // Skip to exit successor (natural-body-based)
            if let Some(exit_blk) = loop_info.loop_exit_successor(ssa, block_id) {
                if reachable.contains(&exit_blk) {
                    state.predecessor = Some(block_id);
                    state.current_block = exit_blk;
                    continue;
                }
            }
            // Fallback: try on_path successor not in loop body
            if let Terminator::Branch {
                true_blk,
                false_blk,
                ..
            } = &block.terminator
            {
                let body = loop_info.loop_bodies.get(&block_id);
                let candidates = [*true_blk, *false_blk];
                let exit = candidates
                    .iter()
                    .find(|blk| on_path.contains(blk) && body.map_or(true, |b| !b.contains(blk)));
                if let Some(&exit_blk) = exit {
                    state.predecessor = Some(block_id);
                    state.current_block = exit_blk;
                    continue;
                }
            }
            // Stuck (infinite loop / nested loops with no exit)
            return Some(record_outcome(state, finding, ssa, cfg));
        }

        // Move exception context into sym_state before block transfer
        // so CatchParam can consume it during instruction transfer
        if let Some(exc_val) = state.exception_context.take() {
            state.sym_state.set_exception_context(exc_val);
        }

        // Transfer this block's instructions
        let lang = summary_ctx.map(|c| c.lang).or(heap_ctx.map(|c| c.lang));
        transfer::transfer_block_with_predecessor(
            &mut state.sym_state,
            block,
            cfg,
            ssa,
            state.predecessor,
            summary_ctx,
            heap_ctx,
            interproc_ctx,
            lang,
            None, // Caller-level: always uses real CFG
        );

        // Collapse induction variables after re-visit to prevent
        // expression tree growth like ((i+1)+1)+1. Only applied after the
        // first re-visit (count > 1), not on the initial iteration.
        if loop_info.loop_heads.contains(&block_id) && visit_count > 1 {
            for phi in &block.phis {
                if loop_info.induction_vars.contains(&phi.value) {
                    state.sym_state.set(phi.value, SymbolicValue::Unknown);
                }
            }
        }

        let step_count = block.phis.len() + block.body.len();
        state.steps_taken += step_count;
        *total_steps += step_count;

        // Fork into exception paths from this block
        if let Some(catch_blocks) = exception_succs.get(&block_id) {
            for &catch_blk in catch_blocks {
                if !reachable.contains(&catch_blk) {
                    continue;
                }
                let can_fork = state.forks_used < MAX_FORKS_PER_FINDING
                    && outcomes.len() + work_queue.len() + 1 < MAX_PATHS_PER_FINDING
                    && *total_steps < MAX_TOTAL_STEPS;
                if can_fork {
                    let exc_state = ExplorationState {
                        sym_state: state.sym_state.clone(),
                        env: constraint::PathEnv::empty(),
                        current_block: catch_blk,
                        predecessor: Some(block_id),
                        forks_used: state.forks_used + 1,
                        steps_taken: state.steps_taken,
                        constraints_checked: state.constraints_checked,
                        visit_counts: state.visit_counts.clone(),
                        // Taint carrier, not a faithful thrown-value model.
                        // CatchParam transfer will mark the catch parameter tainted.
                        exception_context: Some(SymbolicValue::Unknown),
                    };
                    work_queue.push_back(exc_state);
                } else {
                    *search_exhausted = false;
                }
            }
        }

        // Examine terminator
        match &block.terminator {
            Terminator::Branch {
                cond,
                true_blk,
                false_blk,
                condition,
            } => {
                let true_reachable = reachable.contains(true_blk);
                let false_reachable = reachable.contains(false_blk);

                match (true_reachable, false_reachable) {
                    (false, false) => {
                        // Dead end, neither successor reaches sink.
                        // Still try to extract a witness: the path may have
                        // already walked past the sink node.
                        let witness = try_extract_witness(state, finding, ssa, cfg);
                        return Some(PathOutcome {
                            verdict: Verdict::Inconclusive,
                            constraints_checked: state.constraints_checked,
                            witness,
                        });
                    }
                    (true, false) => {
                        // Only true branch reaches sink
                        if let Some(outcome) = apply_branch_constraint(
                            state,
                            cfg,
                            ssa,
                            const_values,
                            block_id,
                            *cond,
                            condition,
                            true,
                            #[cfg(feature = "smt")]
                            smt_ctx,
                        ) {
                            return Some(outcome);
                        }
                        state.predecessor = Some(block_id);
                        state.current_block = *true_blk;
                    }
                    (false, true) => {
                        // Only false branch reaches sink
                        if let Some(outcome) = apply_branch_constraint(
                            state,
                            cfg,
                            ssa,
                            const_values,
                            block_id,
                            *cond,
                            condition,
                            false,
                            #[cfg(feature = "smt")]
                            smt_ctx,
                        ) {
                            return Some(outcome);
                        }
                        state.predecessor = Some(block_id);
                        state.current_block = *false_blk;
                    }
                    (true, true) => {
                        // Both successors reachable, fork candidate
                        let can_fork = state.forks_used < MAX_FORKS_PER_FINDING
                            && outcomes.len() + work_queue.len() + 1 < MAX_PATHS_PER_FINDING
                            && *total_steps < MAX_TOTAL_STEPS;

                        if can_fork {
                            // Fork: clone state for true branch, reuse state for false
                            return fork_at_branch(
                                state,
                                cfg,
                                ssa,
                                const_values,
                                block_id,
                                *cond,
                                condition,
                                *true_blk,
                                *false_blk,
                                work_queue,
                                outcomes,
                                #[cfg(feature = "smt")]
                                smt_ctx,
                            );
                        } else {
                            // Budget exhausted, follow original path
                            *search_exhausted = false;
                            let preferred_polarity = if on_path.contains(true_blk) {
                                true
                            } else if on_path.contains(false_blk) {
                                false
                            } else {
                                true // deterministic fallback: prefer true_blk
                            };
                            let target = if preferred_polarity {
                                *true_blk
                            } else {
                                *false_blk
                            };
                            if let Some(outcome) = apply_branch_constraint(
                                state,
                                cfg,
                                ssa,
                                const_values,
                                block_id,
                                *cond,
                                condition,
                                preferred_polarity,
                                #[cfg(feature = "smt")]
                                smt_ctx,
                            ) {
                                return Some(outcome);
                            }
                            state.predecessor = Some(block_id);
                            state.current_block = target;
                        }
                    }
                }
            }
            Terminator::Goto(target) => {
                // Single-path explorer: follows the terminator's single logical
                // successor. For collapsed ≥3-way fanouts (src/ssa/lower.rs
                // `three_successor_collapse`) the explorer only walks the first
                // successor; the other CFG succs may carry additional witnesses
                // but are intentionally skipped here to preserve the budget
                // model. Finding emission itself is not affected: the taint
                // engine propagates across `block.succs` authoritatively.
                if !reachable.contains(target) {
                    // Successor not on any source-to-sink path.
                    // Still try to extract a witness from accumulated state.
                    let witness = try_extract_witness(state, finding, ssa, cfg);
                    return Some(PathOutcome {
                        verdict: Verdict::Inconclusive,
                        constraints_checked: state.constraints_checked,
                        witness,
                    });
                }
                state.predecessor = Some(block_id);
                state.current_block = *target;
            }
            Terminator::Switch {
                scrutinee,
                targets,
                default,
                case_values,
            } => {
                // Switch is emitted for guaranteed-exclusive dispatch
                // (Go switch, Java arrow-switch, Rust match). For each
                // reachable (case_literal, target) pair, fork the state
                // and add `scrutinee == case_value` as a path constraint.
                // The default arm gets a `scrutinee ∉ {case_values}`
                // constraint when at least one case literal is known.
                if let Some(outcome) = step_switch(
                    state,
                    *scrutinee,
                    targets,
                    *default,
                    case_values,
                    block_id,
                    reachable,
                    work_queue,
                    outcomes,
                    search_exhausted,
                    finding,
                    ssa,
                    cfg,
                ) {
                    return Some(outcome);
                }
            }
            Terminator::Return(_) | Terminator::Unreachable => {
                return Some(record_outcome(state, finding, ssa, cfg));
            }
        }
    }
}

/// Step over a `Terminator::Switch`, forking the state per-case where case
/// literals are known.
///
/// Forks one path per (case_literal, target) pair when `case_values[i]` is
/// `Some(lit)`. The default arm is explored with a chain of `scrutinee !=
/// known_lit_i` refinements. When no case literals are known (synthetic ≥3-way
/// fanouts), falls back to the legacy first-reachable behavior so the
/// exploration stays deterministic.
///
/// Returns `Some(PathOutcome)` only on dead-ends (no reachable successor). On
/// success, the original state is consumed (forked into work_queue) and `None`
/// is returned so the caller stops the current path.
#[allow(clippy::too_many_arguments)]
fn step_switch(
    state: &mut ExplorationState,
    scrutinee: SsaValue,
    targets: &smallvec::SmallVec<[BlockId; 4]>,
    default: BlockId,
    case_values: &smallvec::SmallVec<[Option<crate::constraint::domain::ConstValue>; 4]>,
    block_id: BlockId,
    reachable: &HashSet<BlockId>,
    work_queue: &mut VecDeque<ExplorationState>,
    outcomes: &mut Vec<PathOutcome>,
    search_exhausted: &mut bool,
    finding: &Finding,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> Option<PathOutcome> {
    use crate::constraint::lower::{CompOp, ConditionExpr, Operand};

    // Collect known (case_literal, target) pairs that are reachable.
    let known_cases: Vec<(crate::constraint::domain::ConstValue, BlockId)> = targets
        .iter()
        .enumerate()
        .filter_map(|(i, &tgt)| {
            if !reachable.contains(&tgt) {
                return None;
            }
            case_values
                .get(i)
                .and_then(|cv| cv.clone())
                .map(|lit| (lit, tgt))
        })
        .collect();

    let default_reachable = reachable.contains(&default);

    // Fallback: no case literals known → preserve legacy first-reachable
    // behavior to keep exploration deterministic and budget-bounded.
    if known_cases.is_empty() {
        let next = std::iter::once(&default)
            .chain(targets.iter())
            .find(|s| reachable.contains(s))
            .copied();
        match next {
            Some(target) => {
                state.predecessor = Some(block_id);
                state.current_block = target;
                return None;
            }
            None => {
                let witness = try_extract_witness(state, finding, ssa, cfg);
                return Some(PathOutcome {
                    verdict: Verdict::Inconclusive,
                    constraints_checked: state.constraints_checked,
                    witness,
                });
            }
        }
    }

    // Helper: build `scrutinee == lit` as a structured ConditionExpr.
    let mk_eq = |lit: &crate::constraint::domain::ConstValue| ConditionExpr::Comparison {
        lhs: Operand::Value(scrutinee),
        op: CompOp::Eq,
        rhs: Operand::Const(lit.clone()),
    };

    let total_paths_planned = known_cases.len() + if default_reachable { 1 } else { 0 };
    let can_fork_per_path = |outcomes_len: usize, queue_len: usize, planned: usize| -> bool {
        state.forks_used < MAX_FORKS_PER_FINDING
            && outcomes_len + queue_len + planned + 1 < MAX_PATHS_PER_FINDING
    };

    let mut planned_remaining = total_paths_planned;
    let mut any_enqueued = false;

    // Fork one state per known case.
    for (lit, target) in &known_cases {
        if !can_fork_per_path(outcomes.len(), work_queue.len(), planned_remaining) {
            *search_exhausted = false;
            break;
        }
        planned_remaining = planned_remaining.saturating_sub(1);

        let mut case_state = ExplorationState {
            sym_state: state.sym_state.clone(),
            env: state.env.clone(),
            current_block: *target,
            predecessor: Some(block_id),
            forks_used: state.forks_used + 1,
            steps_taken: state.steps_taken,
            constraints_checked: state.constraints_checked,
            visit_counts: state.visit_counts.clone(),
            exception_context: None,
        };

        let cond = mk_eq(lit);
        case_state.sym_state.add_constraint(PathConstraint {
            block: block_id,
            condition: cond.clone(),
            polarity: true,
        });
        case_state.env = constraint::refine_env(&case_state.env, &cond, true);
        case_state.constraints_checked += 1;

        if case_state.env.is_unsat() {
            outcomes.push(PathOutcome {
                verdict: Verdict::Infeasible,
                constraints_checked: case_state.constraints_checked,
                witness: None,
            });
        } else {
            work_queue.push_back(case_state);
            any_enqueued = true;
        }
    }

    // Fork a state for the default arm with `scrutinee != lit` for each
    // known case (negate-eq refinement). When all cases are known and the
    // refinement makes the environment unsatisfiable, the default path is
    // recorded as Infeasible.
    if default_reachable && can_fork_per_path(outcomes.len(), work_queue.len(), planned_remaining) {
        planned_remaining = planned_remaining.saturating_sub(1);
        let mut default_state = ExplorationState {
            sym_state: state.sym_state.clone(),
            env: state.env.clone(),
            current_block: default,
            predecessor: Some(block_id),
            forks_used: state.forks_used + 1,
            steps_taken: state.steps_taken,
            constraints_checked: state.constraints_checked,
            visit_counts: state.visit_counts.clone(),
            exception_context: None,
        };

        for (lit, _) in &known_cases {
            let cond = mk_eq(lit);
            default_state.sym_state.add_constraint(PathConstraint {
                block: block_id,
                condition: cond.clone(),
                polarity: false,
            });
            default_state.env = constraint::refine_env(&default_state.env, &cond, false);
            default_state.constraints_checked += 1;
        }

        if default_state.env.is_unsat() {
            outcomes.push(PathOutcome {
                verdict: Verdict::Infeasible,
                constraints_checked: default_state.constraints_checked,
                witness: None,
            });
        } else {
            work_queue.push_back(default_state);
            any_enqueued = true;
        }
    } else if default_reachable {
        *search_exhausted = false;
    }
    let _ = planned_remaining;

    if !any_enqueued {
        // All paths were pruned by infeasibility, record the current
        // state's witness so the caller can decide.
        let witness = try_extract_witness(state, finding, ssa, cfg);
        return Some(PathOutcome {
            verdict: Verdict::Infeasible,
            constraints_checked: state.constraints_checked,
            witness,
        });
    }
    None
}

/// Apply a branch constraint and check for UNSAT.
///
/// Returns `Some(PathOutcome)` with `Infeasible` if the constraint makes the
/// environment unsatisfiable. Returns `None` if the path should continue.
#[allow(clippy::too_many_arguments)]
fn apply_branch_constraint(
    state: &mut ExplorationState,
    cfg: &Cfg,
    ssa: &SsaBody,
    const_values: &HashMap<SsaValue, ConstLattice>,
    block_id: BlockId,
    cond: petgraph::graph::NodeIndex,
    pre_lowered: &Option<Box<constraint::ConditionExpr>>,
    polarity: bool,
    #[cfg(feature = "smt")] smt_ctx: &mut Option<super::smt::SmtContext>,
) -> Option<PathOutcome> {
    let cond_expr = if let Some(pre) = pre_lowered {
        (**pre).clone()
    } else {
        constraint::lower_condition(&cfg[cond], ssa, block_id, Some(const_values))
    };

    if matches!(cond_expr, constraint::ConditionExpr::Unknown) {
        // No useful constraint, continue without recording
        return None;
    }

    state.sym_state.add_constraint(PathConstraint {
        block: block_id,
        condition: cond_expr.clone(),
        polarity,
    });

    state.env = constraint::refine_env(&state.env, &cond_expr, polarity);
    state.constraints_checked += 1;

    if state.env.is_unsat() {
        return Some(PathOutcome {
            verdict: Verdict::Infeasible,
            constraints_checked: state.constraints_checked,
            witness: None,
        });
    }

    // SMT escalation, check with Z3 when PathEnv says SAT but
    // accumulated constraints have cross-variable shape.
    #[cfg(feature = "smt")]
    if let Some(smt) = smt_ctx {
        if super::smt::should_escalate(state.sym_state.path_constraints()) && smt.has_budget() {
            if let super::smt::SmtResult::Unsat = smt.check_path_feasibility(
                state.sym_state.path_constraints(),
                &state.sym_state,
                &state.env,
            ) {
                return Some(PathOutcome {
                    verdict: Verdict::Infeasible,
                    constraints_checked: state.constraints_checked,
                    witness: None,
                });
            }
        }
    }

    None
}

/// Fork at a branch point: create two exploration states (one per successor).
///
/// Immediately checks each forked state for UNSAT and records `Infeasible`
/// outcomes without enqueuing. Returns `None` (path consumed by fork).
#[allow(clippy::too_many_arguments)]
fn fork_at_branch(
    state: &mut ExplorationState,
    cfg: &Cfg,
    ssa: &SsaBody,
    const_values: &HashMap<SsaValue, ConstLattice>,
    block_id: BlockId,
    cond: petgraph::graph::NodeIndex,
    pre_lowered: &Option<Box<constraint::ConditionExpr>>,
    true_blk: BlockId,
    false_blk: BlockId,
    work_queue: &mut VecDeque<ExplorationState>,
    outcomes: &mut Vec<PathOutcome>,
    #[cfg(feature = "smt")] smt_ctx: &mut Option<super::smt::SmtContext>,
) -> Option<PathOutcome> {
    let cond_expr = if let Some(pre) = pre_lowered {
        (**pre).clone()
    } else {
        constraint::lower_condition(&cfg[cond], ssa, block_id, Some(const_values))
    };

    let is_unknown = matches!(cond_expr, constraint::ConditionExpr::Unknown);

    // True branch
    let mut true_state = ExplorationState {
        sym_state: state.sym_state.clone(),
        env: state.env.clone(),
        current_block: true_blk,
        predecessor: Some(block_id),
        forks_used: state.forks_used + 1,
        steps_taken: state.steps_taken,
        constraints_checked: state.constraints_checked,
        visit_counts: state.visit_counts.clone(),
        exception_context: None,
    };

    if !is_unknown {
        true_state.sym_state.add_constraint(PathConstraint {
            block: block_id,
            condition: cond_expr.clone(),
            polarity: true,
        });
        true_state.env = constraint::refine_env(&true_state.env, &cond_expr, true);
        true_state.constraints_checked += 1;
    }

    // False branch (reuse original state's data to avoid extra clone)
    let mut false_state = ExplorationState {
        sym_state: state.sym_state.clone(),
        env: state.env.clone(),
        current_block: false_blk,
        predecessor: Some(block_id),
        forks_used: state.forks_used + 1,
        steps_taken: state.steps_taken,
        constraints_checked: state.constraints_checked,
        visit_counts: state.visit_counts.clone(),
        exception_context: None,
    };

    if !is_unknown {
        false_state.sym_state.add_constraint(PathConstraint {
            block: block_id,
            condition: cond_expr.clone(),
            polarity: false,
        });
        false_state.env = constraint::refine_env(&false_state.env, &cond_expr, false);
        false_state.constraints_checked += 1;
    }

    // Enqueue feasible branches; record infeasible immediately.
    // Also check SMT for cross-variable infeasibility.
    let true_infeasible = true_state.env.is_unsat() || {
        #[cfg(feature = "smt")]
        {
            smt_check_infeasible(smt_ctx, &true_state)
        }
        #[cfg(not(feature = "smt"))]
        false
    };

    if true_infeasible {
        outcomes.push(PathOutcome {
            verdict: Verdict::Infeasible,
            constraints_checked: true_state.constraints_checked,
            witness: None,
        });
    } else {
        work_queue.push_back(true_state);
    }

    let false_infeasible = false_state.env.is_unsat() || {
        #[cfg(feature = "smt")]
        {
            smt_check_infeasible(smt_ctx, &false_state)
        }
        #[cfg(not(feature = "smt"))]
        false
    };

    if false_infeasible {
        outcomes.push(PathOutcome {
            verdict: Verdict::Infeasible,
            constraints_checked: false_state.constraints_checked,
            witness: None,
        });
    } else {
        work_queue.push_back(false_state);
    }

    // Original state consumed by fork, no outcome from this path
    None
}

/// Check if a forked state is infeasible via SMT.
///
/// Only invoked when the `smt` feature is enabled and the escalation
/// predicate fires (cross-variable constraints detected).
#[cfg(feature = "smt")]
fn smt_check_infeasible(
    smt_ctx: &mut Option<super::smt::SmtContext>,
    state: &ExplorationState,
) -> bool {
    if let Some(smt) = smt_ctx {
        if super::smt::should_escalate(state.sym_state.path_constraints()) && smt.has_budget() {
            return matches!(
                smt.check_path_feasibility(
                    state.sym_state.path_constraints(),
                    &state.sym_state,
                    &state.env,
                ),
                super::smt::SmtResult::Unsat
            );
        }
    }
    false
}

/// Record the final outcome for a path that has reached its terminal state.
///
/// Tries cap-aware `extract_witness` first (produces concrete exploit payloads
/// for string-renderable sinks). Falls back to raw expression-tree Display via
/// `get_sink_witness` when no cap-aware witness is available.
fn record_outcome(
    state: &ExplorationState,
    finding: &Finding,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> PathOutcome {
    let witness = try_extract_witness(state, finding, ssa, cfg);
    // All constraints passed (or none on path) → feasible
    let verdict = Verdict::Confirmed;
    PathOutcome {
        verdict,
        constraints_checked: state.constraints_checked,
        witness,
    }
}

/// Best-effort witness extraction from the current symbolic state.
///
/// Used by both `record_outcome` (Confirmed paths) and inconclusive exits
/// where the path has already walked past the sink node and built up
/// symbolic expressions. Returns `None` if the sink's expression is
/// `Unknown` or not useful.
fn try_extract_witness(
    state: &ExplorationState,
    finding: &Finding,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> Option<String> {
    super::witness::extract_witness(&state.sym_state, finding, ssa, cfg)
        .or_else(|| state.sym_state.get_sink_witness(finding, ssa))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Verdict aggregation
// ─────────────────────────────────────────────────────────────────────────────

impl ExplorationResult {
    /// Aggregate per-path outcomes into a single [`SymbolicVerdict`].
    ///
    /// Sound aggregation:
    /// - ANY path `Confirmed` → `Confirmed`
    /// - ALL paths `Infeasible` AND `search_exhausted` → `Infeasible`
    /// - Otherwise → `Inconclusive`
    ///
    /// `Infeasible` is only returned when the entire relevant search space
    /// was explored without budget exhaustion.
    pub fn aggregate_verdict(&self) -> SymbolicVerdict {
        let paths_explored = self.paths_completed.len() as u32;
        let constraints_checked: u32 = self
            .paths_completed
            .iter()
            .map(|p| p.constraints_checked)
            .sum();

        let has_confirmed = self
            .paths_completed
            .iter()
            .any(|p| p.verdict == Verdict::Confirmed);
        let all_infeasible = !self.paths_completed.is_empty()
            && self
                .paths_completed
                .iter()
                .all(|p| p.verdict == Verdict::Infeasible);

        let verdict = if has_confirmed {
            Verdict::Confirmed
        } else if all_infeasible && self.search_exhausted {
            Verdict::Infeasible
        } else {
            Verdict::Inconclusive
        };

        // Prefer witness from a Confirmed path; fall back to any path's witness
        let witness = self
            .paths_completed
            .iter()
            .filter(|p| p.verdict == Verdict::Confirmed)
            .find_map(|p| p.witness.clone())
            .or_else(|| self.paths_completed.iter().find_map(|p| p.witness.clone()));

        // Collect unique interprocedural call chains
        let mut interproc_call_chains: Vec<Vec<String>> = Vec::new();
        let mut seen_chains: std::collections::HashSet<String> = std::collections::HashSet::new();
        for finding in &self.interproc_findings {
            let key = finding.call_chain.join(" → ");
            if seen_chains.insert(key) {
                interproc_call_chains.push(finding.call_chain.clone());
            }
        }

        // Deduplicated cutoff notes
        let mut cutoff_notes: Vec<String> = Vec::new();
        let mut seen_notes: std::collections::HashSet<String> = std::collections::HashSet::new();
        for reason in &self.interproc_cutoffs {
            let note = format!("{}", reason);
            if seen_notes.insert(note.clone()) {
                cutoff_notes.push(note);
            }
        }

        // Enrich witness with interprocedural context
        let enriched_witness =
            append_interproc_context(witness, &interproc_call_chains, &cutoff_notes);

        SymbolicVerdict {
            verdict,
            constraints_checked,
            paths_explored,
            witness: enriched_witness,
            interproc_call_chains,
            cutoff_notes,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Witness enrichment
// ─────────────────────────────────────────────────────────────────────────────

/// Append interprocedural context to a witness string.
///
/// Adds call chain info (e.g., " [via helper → inner_query]") and cutoff
/// notes for transparency about analysis limitations.
fn append_interproc_context(
    witness: Option<String>,
    call_chains: &[Vec<String>],
    cutoff_notes: &[String],
) -> Option<String> {
    if call_chains.is_empty() && cutoff_notes.is_empty() {
        return witness;
    }

    let mut result = witness.unwrap_or_default();

    if !call_chains.is_empty() {
        for chain in call_chains {
            if !chain.is_empty() {
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push_str("[via ");
                result.push_str(&chain.join(" → "));
                result.push(']');
            }
        }
    }

    if !cutoff_notes.is_empty() {
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str("[cutoff: ");
        result.push_str(&cutoff_notes.join("; "));
        result.push(']');
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::ir::{SsaBlock, SsaInst, SsaOp, SsaValue, Terminator, ValueDef};
    use crate::ssa::type_facts::TypeFactResult;
    use crate::taint::FlowStepRaw;
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    fn empty_type_facts() -> TypeFactResult {
        TypeFactResult {
            facts: HashMap::new(),
        }
    }

    fn make_value_def(block: BlockId, cfg_node: NodeIndex) -> ValueDef {
        ValueDef {
            var_name: None,
            cfg_node,
            block,
        }
    }

    /// Build a minimal Finding with source at n0 and sink at n1.
    fn make_finding(n0: NodeIndex, n1: NodeIndex) -> Finding {
        Finding {
            body_id: crate::cfg::BodyId(0),
            sink: n1,
            source: n0,
            path: vec![n0, n1],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 1,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![
                FlowStepRaw {
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Source,
                },
                FlowStepRaw {
                    cfg_node: n1,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Sink,
                },
            ],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        }
    }

    // ─── Test: compute_source_sink_reachable ────────────────────────────

    #[test]
    fn reachable_diamond_excludes_dead_end() {
        // B0 → B1, B0 → B2 (dead-end), B1 → B3 (sink)
        let b0 = BlockId(0);
        let b1 = BlockId(1);
        let b2 = BlockId(2);
        let b3 = BlockId(3);
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b1),
                    preds: smallvec![],
                    succs: smallvec![b1, b2],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![b0],
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b2,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b0],
                    succs: smallvec![],
                },
                SsaBlock {
                    id: b3,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b1],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let empty_succs = HashMap::new();
        let empty_preds = HashMap::new();
        let reachable = compute_source_sink_reachable(&ssa, b0, b3, &empty_succs, &empty_preds);
        assert!(reachable.contains(&b0));
        assert!(reachable.contains(&b1));
        assert!(reachable.contains(&b3));
        assert!(!reachable.contains(&b2), "dead-end B2 should be excluded");
    }

    #[test]
    fn reachable_diamond_includes_both_branches() {
        // B0 → {B1, B2} → B3 (sink)
        let b0 = BlockId(0);
        let b1 = BlockId(1);
        let b2 = BlockId(2);
        let b3 = BlockId(3);
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b1),
                    preds: smallvec![],
                    succs: smallvec![b1, b2],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![b0],
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b2,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![b0],
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b3,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b1, b2],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let empty_succs = HashMap::new();
        let empty_preds = HashMap::new();
        let reachable = compute_source_sink_reachable(&ssa, b0, b3, &empty_succs, &empty_preds);
        assert_eq!(reachable.len(), 4);
        assert!(reachable.contains(&b1));
        assert!(reachable.contains(&b2));
    }

    // ─── Test: aggregate_verdict ────────────────────────────────────────

    #[test]
    fn aggregate_any_confirmed_wins() {
        let result = ExplorationResult {
            paths_completed: vec![
                PathOutcome {
                    verdict: Verdict::Infeasible,
                    constraints_checked: 1,
                    witness: None,
                },
                PathOutcome {
                    verdict: Verdict::Confirmed,
                    constraints_checked: 1,
                    witness: Some("sym(v0)".into()),
                },
            ],
            paths_pruned: 0,
            total_steps: 10,
            search_exhausted: true,
            interproc_findings: Vec::new(),
            interproc_cutoffs: Vec::new(),
        };
        let v = result.aggregate_verdict();
        assert_eq!(v.verdict, Verdict::Confirmed);
        assert_eq!(v.paths_explored, 2);
        assert_eq!(v.witness, Some("sym(v0)".into()));
    }

    #[test]
    fn aggregate_all_infeasible_exhausted() {
        let result = ExplorationResult {
            paths_completed: vec![
                PathOutcome {
                    verdict: Verdict::Infeasible,
                    constraints_checked: 1,
                    witness: None,
                },
                PathOutcome {
                    verdict: Verdict::Infeasible,
                    constraints_checked: 2,
                    witness: None,
                },
            ],
            paths_pruned: 0,
            total_steps: 10,
            search_exhausted: true,
            interproc_findings: Vec::new(),
            interproc_cutoffs: Vec::new(),
        };
        let v = result.aggregate_verdict();
        assert_eq!(v.verdict, Verdict::Infeasible);
        assert_eq!(v.constraints_checked, 3);
    }

    #[test]
    fn aggregate_all_infeasible_but_budget_hit_is_inconclusive() {
        let result = ExplorationResult {
            paths_completed: vec![PathOutcome {
                verdict: Verdict::Infeasible,
                constraints_checked: 1,
                witness: None,
            }],
            paths_pruned: 2,
            total_steps: 500,
            search_exhausted: false, // budget prevented full exploration
            interproc_findings: Vec::new(),
            interproc_cutoffs: Vec::new(),
        };
        let v = result.aggregate_verdict();
        assert_eq!(v.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn aggregate_empty_is_inconclusive() {
        let result = ExplorationResult {
            paths_completed: vec![],
            paths_pruned: 0,
            total_steps: 0,
            search_exhausted: true,
            interproc_findings: Vec::new(),
            interproc_cutoffs: Vec::new(),
        };
        let v = result.aggregate_verdict();
        assert_eq!(v.verdict, Verdict::Inconclusive);
    }

    // ─── Test: explore_finding with linear CFG (no fork) ────────────────

    #[test]
    fn explore_linear_no_fork() {
        // B0(source) → Goto → B1(sink) → Return
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let b0 = BlockId(0);
        let b1 = BlockId(1);

        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b1),
                    preds: smallvec![],
                    succs: smallvec![b1],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b0],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![make_value_def(b0, n0), make_value_def(b1, n1)],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let finding = make_finding(n0, n1);
        let ctx = super::SymexContext {
            ssa: &ssa,
            cfg: &Cfg::new(),
            const_values: &HashMap::new(),
            type_facts: &empty_type_facts(),
            global_summaries: None,
            lang: crate::symbol::Lang::JavaScript,
            namespace: "test.js",
            points_to: None,
            callee_bodies: None,
            scc_membership: None,
            cross_file_bodies: None,
        };
        let result = explore_finding(&finding, &ctx);

        assert_eq!(result.paths_completed.len(), 1);
        assert_eq!(result.paths_completed[0].verdict, Verdict::Confirmed);
        assert!(result.search_exhausted);

        let v = result.aggregate_verdict();
        assert_eq!(v.verdict, Verdict::Confirmed);
        assert_eq!(v.paths_explored, 1);
    }

    // ─── Test: diamond CFG, both paths feasible ─────────────────────────

    #[test]
    fn explore_diamond_both_feasible() {
        // B0(source) → Branch → {B1, B2} → B3(sink)
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let n2 = NodeIndex::new(2);
        let n3 = NodeIndex::new(3);
        let n_cond = NodeIndex::new(0);
        let b0 = BlockId(0);
        let b1 = BlockId(1);
        let b2 = BlockId(2);
        let b3 = BlockId(3);

        // Minimal CFG with a condition node
        let mut cfg_graph = Cfg::new();
        let _c = cfg_graph.add_node(crate::cfg::NodeInfo {
            kind: crate::cfg::StmtKind::Seq,
            ..Default::default()
        });

        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: n_cond,
                        true_blk: b1,
                        false_blk: b2,
                        condition: None,
                    },
                    preds: smallvec![],
                    succs: smallvec![b1, b2],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![b0],
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b2,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![b0],
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b3,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b1, b2],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![
                make_value_def(b0, n0),
                make_value_def(b1, n1),
                make_value_def(b2, n2),
                make_value_def(b3, n3),
            ],
            cfg_node_map: [
                (n0, SsaValue(0)),
                (n1, SsaValue(1)),
                (n2, SsaValue(2)),
                (n3, SsaValue(3)),
            ]
            .into_iter()
            .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        // Finding path goes through B0 → B1 → B3
        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: n3,
            source: n0,
            path: vec![n0, n1, n3],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 2,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![
                FlowStepRaw {
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Source,
                },
                FlowStepRaw {
                    cfg_node: n1,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Assignment,
                },
                FlowStepRaw {
                    cfg_node: n3,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Sink,
                },
            ],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };

        let ctx = super::SymexContext {
            ssa: &ssa,
            cfg: &cfg_graph,
            const_values: &HashMap::new(),
            type_facts: &empty_type_facts(),
            global_summaries: None,
            lang: crate::symbol::Lang::JavaScript,
            namespace: "test.js",
            points_to: None,
            callee_bodies: None,
            scc_membership: None,
            cross_file_bodies: None,
        };
        let result = explore_finding(&finding, &ctx);

        // Both branches should be explored (fork at B0)
        assert!(
            result.paths_completed.len() >= 2,
            "expected >= 2 paths, got {}",
            result.paths_completed.len()
        );
        assert!(result.search_exhausted);

        let v = result.aggregate_verdict();
        assert_eq!(v.verdict, Verdict::Confirmed);
        assert!(v.paths_explored >= 2);
    }

    // ─── Test: single-successor branch (no fork) ───────────────────────

    #[test]
    fn explore_branch_single_reachable_no_fork() {
        // B0(source) → Branch → {B1 (→ B3 sink), B2 (→ Return, dead-end)}
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let n3 = NodeIndex::new(3);
        let n_cond = NodeIndex::new(0);
        let b0 = BlockId(0);
        let b1 = BlockId(1);
        let b2 = BlockId(2);
        let b3 = BlockId(3);

        let mut cfg_graph = Cfg::new();
        cfg_graph.add_node(crate::cfg::NodeInfo {
            kind: crate::cfg::StmtKind::Seq,
            ..Default::default()
        });

        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: n_cond,
                        true_blk: b1,
                        false_blk: b2,
                        condition: None,
                    },
                    preds: smallvec![],
                    succs: smallvec![b1, b2],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![b0],
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b2,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None), // dead-end: doesn't reach sink
                    preds: smallvec![b0],
                    succs: smallvec![],
                },
                SsaBlock {
                    id: b3,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b1],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![
                make_value_def(b0, n0),
                make_value_def(b1, n1),
                ValueDef {
                    var_name: None,
                    cfg_node: NodeIndex::new(2),
                    block: b2,
                },
                make_value_def(b3, n3),
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n3, SsaValue(3))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: n3,
            source: n0,
            path: vec![n0, n1, n3],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 2,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![
                FlowStepRaw {
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Source,
                },
                FlowStepRaw {
                    cfg_node: n1,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Assignment,
                },
                FlowStepRaw {
                    cfg_node: n3,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Sink,
                },
            ],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };

        let ctx = super::SymexContext {
            ssa: &ssa,
            cfg: &cfg_graph,
            const_values: &HashMap::new(),
            type_facts: &empty_type_facts(),
            global_summaries: None,
            lang: crate::symbol::Lang::JavaScript,
            namespace: "test.js",
            points_to: None,
            callee_bodies: None,
            scc_membership: None,
            cross_file_bodies: None,
        };
        let result = explore_finding(&finding, &ctx);

        // Only one path (B2 is not reachable from source to sink)
        assert_eq!(result.paths_completed.len(), 1);
        assert_eq!(result.paths_completed[0].verdict, Verdict::Confirmed);
        assert!(result.search_exhausted);
    }

    // ─── Exception-aware reachability and forking ─────────────

    #[test]
    fn reachable_includes_exception_edges() {
        // B0 → B1 (Goto, normal), exception edge B0→B2, B2 → B3 (Goto)
        // Target: B0 to B3. B1 is NOT on any path to B3.
        let b0 = BlockId(0);
        let b1 = BlockId(1);
        let b2 = BlockId(2);
        let b3 = BlockId(3);
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b1),
                    preds: smallvec![],
                    succs: smallvec![b1],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b0],
                    succs: smallvec![],
                },
                SsaBlock {
                    id: b2,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![], // orphan: only reachable via exception edge
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b3,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b2],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![(b0, b2)],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let mut exc_succs: HashMap<BlockId, SmallVec<[BlockId; 2]>> = HashMap::new();
        exc_succs.insert(b0, smallvec![b2]);
        let mut exc_preds: HashMap<BlockId, SmallVec<[BlockId; 2]>> = HashMap::new();
        exc_preds.insert(b2, smallvec![b0]);

        let reachable = compute_source_sink_reachable(&ssa, b0, b3, &exc_succs, &exc_preds);
        assert!(reachable.contains(&b0), "source should be reachable");
        assert!(
            reachable.contains(&b2),
            "catch block should be reachable via exception edge"
        );
        assert!(reachable.contains(&b3), "sink should be reachable");
        assert!(!reachable.contains(&b1), "B1 is NOT on any path to B3");
    }

    #[test]
    fn reachable_exception_backward() {
        // B0 → B1 (normal, dead-end), exception edge B0→B2, B2 → B3 (sink)
        // Sink B3 is only reachable from B0 via the exception path.
        let b0 = BlockId(0);
        let b1 = BlockId(1);
        let b2 = BlockId(2);
        let b3 = BlockId(3);
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b1),
                    preds: smallvec![],
                    succs: smallvec![b1],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b0],
                    succs: smallvec![],
                },
                SsaBlock {
                    id: b2,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![],
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b3,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b2],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![(b0, b2)],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let mut exc_succs: HashMap<BlockId, SmallVec<[BlockId; 2]>> = HashMap::new();
        exc_succs.insert(b0, smallvec![b2]);
        let mut exc_preds: HashMap<BlockId, SmallVec<[BlockId; 2]>> = HashMap::new();
        exc_preds.insert(b2, smallvec![b0]);

        let reachable = compute_source_sink_reachable(&ssa, b0, b3, &exc_succs, &exc_preds);
        assert!(reachable.contains(&b0));
        assert!(reachable.contains(&b2));
        assert!(reachable.contains(&b3));
        // B1 is forward-reachable from B0 but backward-unreachable from B3
        assert!(!reachable.contains(&b1));
    }

    #[test]
    fn exception_fork_catch_param_tainted() {
        // B0: Source (tainted) → Goto B1
        // B1: Call instruction → Goto B3  (exception edge B1→B2)
        // B2: CatchParam → Goto B3        (catch block)
        // B3: Return                       (sink block)
        let b0 = BlockId(0);
        let b1 = BlockId(1);
        let b2 = BlockId(2);
        let b3 = BlockId(3);

        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let n2 = NodeIndex::new(2);
        let n3 = NodeIndex::new(3);

        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: b0,
                    phis: vec![],
                    body: vec![SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Source,
                        cfg_node: n0,
                        var_name: Some("x".into()),
                        span: (0, 0),
                    }],
                    terminator: Terminator::Goto(b1),
                    preds: smallvec![],
                    succs: smallvec![b1],
                },
                SsaBlock {
                    id: b1,
                    phis: vec![],
                    body: vec![SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Call {
                            callee: "JSON.parse".into(),
                            callee_text: None,
                            args: vec![smallvec![SsaValue(0)]],
                            receiver: None,
                        },
                        cfg_node: n1,
                        var_name: None,
                        span: (0, 0),
                    }],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![b0],
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b2,
                    phis: vec![],
                    body: vec![SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::CatchParam,
                        cfg_node: n2,
                        var_name: Some("e".into()),
                        span: (0, 0),
                    }],
                    terminator: Terminator::Goto(b3),
                    preds: smallvec![], // orphan: only via exception edge
                    succs: smallvec![b3],
                },
                SsaBlock {
                    id: b3,
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![b1, b2],
                    succs: smallvec![],
                },
            ],
            entry: b0,
            value_defs: vec![
                make_value_def(b0, n0),
                make_value_def(b1, n1),
                make_value_def(b2, n2),
                make_value_def(b3, n3),
            ],
            cfg_node_map: [
                (n0, SsaValue(0)),
                (n1, SsaValue(1)),
                (n2, SsaValue(2)),
                (n3, SsaValue(3)),
            ]
            .into_iter()
            .collect(),
            exception_edges: vec![(b1, b2)],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: n3,
            source: n0,
            path: vec![n0, n1, n3],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 2,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![
                FlowStepRaw {
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Source,
                },
                FlowStepRaw {
                    cfg_node: n3,
                    var_name: Some("x".into()),
                    op_kind: crate::evidence::FlowStepKind::Sink,
                },
            ],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };

        let cfg_graph = crate::cfg::Cfg::new();
        let ctx = super::SymexContext {
            ssa: &ssa,
            cfg: &cfg_graph,
            const_values: &HashMap::new(),
            type_facts: &empty_type_facts(),
            global_summaries: None,
            lang: crate::symbol::Lang::JavaScript,
            namespace: "test.js",
            points_to: None,
            callee_bodies: None,
            scc_membership: None,
            cross_file_bodies: None,
        };
        let result = explore_finding(&finding, &ctx);

        // Both normal and exception paths should be explored
        assert!(
            result.paths_completed.len() >= 2,
            "Expected at least 2 paths (normal + exception), got {}",
            result.paths_completed.len()
        );
        // At least one path should be Confirmed
        assert!(
            result
                .paths_completed
                .iter()
                .any(|p| p.verdict == Verdict::Confirmed),
            "Expected at least one Confirmed path via exception fork"
        );
    }
}
