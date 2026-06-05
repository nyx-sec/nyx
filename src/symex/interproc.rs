//! Interprocedural symbolic execution.
//!
//! When a callee's `CalleeSsaBody` is available, the symbolic executor walks
//! the callee's SSA blocks as a nested frame instead of treating it as an
//! opaque `mk_call`.  Full symbolic state, return values, heap mutations,
//! taint, and path constraints, is propagated back to the caller.
//!
//! Resolution order in `transfer_inst` Call arm:
//!   container ops → string methods → **interprocedural execution** → summary → opaque mk_call.
//!
//! Transitive descent is supported: callee Call instructions can themselves
//! resolve to bodies, up to `InterprocCtx.max_depth`.
//!
//! Additional capabilities:
//!   - Full budget and cutoff controls (instructions, forks, solver checks, path states)
//!   - Explicit recursion and SCC-aware policy
//!   - Intra-callee forking with merge policies

#![allow(
    clippy::let_and_return,
    clippy::new_without_default,
    clippy::question_mark,
    clippy::too_many_arguments
)]
//!   - Heap-aware cache keys and size limits
//!   - Structured cutoff reasons for diagnostics

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use petgraph::graph::NodeIndex;
use smallvec::SmallVec;

use crate::callgraph::callee_leaf_name;
use crate::cfg::Cfg;
use crate::labels::{Cap, DataLabel};
use crate::ssa::ir::{BlockId, SsaOp, SsaValue, Terminator};
use crate::symbol::Lang;
use crate::taint::ssa_transfer::CalleeSsaBody;

use super::heap::{HeapKey, SymbolicHeap};
use super::state::{PathConstraint, SymbolicState};
use super::transfer::{self, SymexHeapCtx, SymexSummaryCtx};
use super::value::{SymbolicValue, mk_phi};

//  Constants

/// Default max call depth (caller → callee → callee's callee → ...).
pub(crate) const DEFAULT_MAX_DEPTH: usize = 3;

/// Max callee blocks before declining to execute.
const MAX_CALLEE_BLOCKS: usize = 200;

/// Max cross-file nesting depth (one level of cross-file descent).
const MAX_CROSS_FILE_DEPTH: usize = 1;

/// Max transfer steps (phis + body instructions) per single callee frame.
const MAX_CALLEE_STEPS: usize = 200;

/// Max total blocks executed across all interprocedural frames for one finding.
const DEFAULT_MAX_BLOCKS: usize = 500;

/// Max frames (callee invocations) across one finding's exploration.
const DEFAULT_MAX_FRAMES: usize = 15;

/// Max total instructions executed across all interprocedural frames.
const DEFAULT_MAX_INSTRUCTIONS: usize = 2000;

/// Max symbolic forks across all interprocedural callee explorations.
const DEFAULT_MAX_SYMBOLIC_FORKS: usize = 8;

/// Max solver feasibility checks during interprocedural execution.
const DEFAULT_MAX_SOLVER_CHECKS: usize = 20;

/// Max retained callee path states (work-queue size across all callees).
const DEFAULT_MAX_RETAINED_PATH_STATES: usize = 16;

/// Max forks within a single callee's exploration.
const MAX_FORKS_PER_CALLEE: usize = 2;

/// Default max re-entries per individual function (direct recursion).
pub(crate) const DEFAULT_MAX_REENTRY_PER_FUNC: usize = 2;

/// Default max combined re-entries for functions in the same SCC (mutual recursion).
pub(crate) const DEFAULT_MAX_SCC_REENTRY: usize = 3;

/// Max cache entries before eviction (simple clear).
const MAX_CACHE_ENTRIES: usize = 64;

//  Feature gate

/// Check if interprocedural symbolic execution is enabled.
///
/// Controlled by `analysis.engine.symex.interprocedural` in `nyx.conf`
/// (default `true`) or the `--symex-interproc / --no-symex-interproc` CLI
/// flag.
pub fn interproc_enabled() -> bool {
    crate::utils::analysis_options::current()
        .symex
        .interprocedural
}

//  Cutoff reasons

/// Structured record of why interprocedural execution was cut short.
///
/// Carried on `CallOutcome` and surfaced in `SymbolicVerdict` diagnostics.
#[derive(Clone, Debug)]
pub enum CutoffReason {
    DepthExceeded {
        max_depth: usize,
    },
    BudgetBlocks {
        executed: usize,
        max: usize,
    },
    BudgetFrames {
        created: usize,
        max: usize,
    },
    BudgetInstructions {
        executed: usize,
        max: usize,
    },
    BudgetForks {
        used: usize,
        max: usize,
    },
    BudgetSolverChecks {
        used: usize,
        max: usize,
    },
    BudgetPathStates {
        retained: usize,
        max: usize,
    },
    RecursionLimit {
        function: String,
        re_entries: usize,
        max: usize,
    },
    SccRecursionLimit {
        scc_functions: Vec<String>,
        total_entries: usize,
        max: usize,
    },
    CalleeBodyTooLarge {
        callee: String,
        blocks: usize,
        max: usize,
    },
    StepBudgetPerFrame {
        callee: String,
        steps: usize,
        max: usize,
    },
}

impl fmt::Display for CutoffReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CutoffReason::DepthExceeded { max_depth } => {
                write!(f, "call depth exceeded (max {})", max_depth)
            }
            CutoffReason::BudgetBlocks { executed, max } => {
                write!(f, "block budget exhausted ({}/{})", executed, max)
            }
            CutoffReason::BudgetFrames { created, max } => {
                write!(f, "frame budget exhausted ({}/{})", created, max)
            }
            CutoffReason::BudgetInstructions { executed, max } => {
                write!(f, "instruction budget exhausted ({}/{})", executed, max)
            }
            CutoffReason::BudgetForks { used, max } => {
                write!(f, "fork budget exhausted ({}/{})", used, max)
            }
            CutoffReason::BudgetSolverChecks { used, max } => {
                write!(f, "solver check budget exhausted ({}/{})", used, max)
            }
            CutoffReason::BudgetPathStates { retained, max } => {
                write!(f, "path state budget exhausted ({}/{})", retained, max)
            }
            CutoffReason::RecursionLimit {
                function,
                re_entries,
                max,
            } => {
                write!(
                    f,
                    "recursion limit for '{}' ({}/{})",
                    function, re_entries, max
                )
            }
            CutoffReason::SccRecursionLimit {
                scc_functions,
                total_entries,
                max,
            } => {
                write!(
                    f,
                    "SCC recursion limit for [{}] ({}/{})",
                    scc_functions.join(", "),
                    total_entries,
                    max,
                )
            }
            CutoffReason::CalleeBodyTooLarge {
                callee,
                blocks,
                max,
            } => {
                write!(
                    f,
                    "callee '{}' too large ({} blocks, max {})",
                    callee, blocks, max
                )
            }
            CutoffReason::StepBudgetPerFrame { callee, steps, max } => {
                write!(
                    f,
                    "per-frame step budget for '{}' ({}/{})",
                    callee, steps, max
                )
            }
        }
    }
}

//  Context

/// Shared context for interprocedural symbolic execution.
///
/// Created once per `explore_finding()` invocation.  Budget, cache, and
/// reentry counts use interior mutability so the context can be shared by
/// immutable reference across recursive `execute_callee()` calls.
pub struct InterprocCtx<'a> {
    /// Pre-lowered intra-file function bodies, keyed by canonical `FuncKey`.
    pub callee_bodies: &'a HashMap<crate::symbol::FuncKey, CalleeSsaBody>,
    /// The top-level caller's body CFG. Callees have their own per-body graphs
    /// (see `CalleeSsaBody::body_graph`), `execute_callee` must swap this for
    /// the callee's own graph before indexing by `SsaInst::cfg_node`.
    pub cfg: &'a Cfg,
    /// Source language.
    pub lang: Lang,
    /// Maximum call depth.
    pub max_depth: usize,
    /// Shared budget counters.
    pub budget: &'a Cell<InterprocBudget>,
    /// Memoization cache for interprocedural outcomes.
    pub cache: &'a RefCell<InterprocCache>,
    /// Per-function re-entry counts for recursion detection.
    pub reentry_counts: &'a RefCell<HashMap<String, usize>>,
    /// Maximum re-entries per individual function before cutoff.
    pub max_reentry_per_func: usize,
    /// SCC membership: maps normalized function name → SCC index.
    /// Functions in the same SCC are mutually recursive.
    pub scc_membership: Option<&'a HashMap<String, usize>>,
    /// Maximum combined SCC re-entries before cutoff.
    pub max_scc_reentry: usize,
    /// Optional statistics counters.
    pub stats: &'a Cell<InterprocStats>,
    /// Cross-file callee bodies via GlobalSummaries.
    pub cross_file_bodies: Option<&'a crate::summary::GlobalSummaries>,
    /// Current cross-file nesting depth.
    pub cross_file_depth: usize,
    /// Caller namespace (for cross-file resolution disambiguation).
    pub caller_namespace: &'a str,
}

/// Budget counters shared across all interprocedural frames for one finding.
#[derive(Clone, Copy, Debug)]
pub struct InterprocBudget {
    pub blocks_executed: usize,
    pub max_blocks: usize,
    pub frames_created: usize,
    pub max_frames: usize,
    pub instructions_executed: usize,
    pub max_instructions: usize,
    pub symbolic_forks: usize,
    pub max_symbolic_forks: usize,
    pub solver_checks: usize,
    pub max_solver_checks: usize,
    pub retained_path_states: usize,
    pub max_retained_path_states: usize,
}

impl InterprocBudget {
    /// Create a budget with default limits.
    pub fn new() -> Self {
        InterprocBudget {
            blocks_executed: 0,
            max_blocks: DEFAULT_MAX_BLOCKS,
            frames_created: 0,
            max_frames: DEFAULT_MAX_FRAMES,
            instructions_executed: 0,
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            symbolic_forks: 0,
            max_symbolic_forks: DEFAULT_MAX_SYMBOLIC_FORKS,
            solver_checks: 0,
            max_solver_checks: DEFAULT_MAX_SOLVER_CHECKS,
            retained_path_states: 0,
            max_retained_path_states: DEFAULT_MAX_RETAINED_PATH_STATES,
        }
    }

    /// Check if any budget limit is exceeded.
    pub fn exhausted(&self) -> bool {
        self.blocks_executed >= self.max_blocks
            || self.frames_created >= self.max_frames
            || self.instructions_executed >= self.max_instructions
    }

    /// Return the most relevant exhaustion reason, if any.
    fn exhaustion_reason(&self) -> Option<CutoffReason> {
        if self.blocks_executed >= self.max_blocks {
            Some(CutoffReason::BudgetBlocks {
                executed: self.blocks_executed,
                max: self.max_blocks,
            })
        } else if self.frames_created >= self.max_frames {
            Some(CutoffReason::BudgetFrames {
                created: self.frames_created,
                max: self.max_frames,
            })
        } else if self.instructions_executed >= self.max_instructions {
            Some(CutoffReason::BudgetInstructions {
                executed: self.instructions_executed,
                max: self.max_instructions,
            })
        } else {
            None
        }
    }
}

/// Optional statistics counters for interprocedural execution.
#[derive(Clone, Copy, Debug, Default)]
pub struct InterprocStats {
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub total_frames: usize,
    pub total_blocks: usize,
    pub cutoffs: usize,
    pub forks: usize,
}

//  Result types

/// Result of executing a callee to completion.
#[derive(Clone, Debug)]
pub struct CallOutcome {
    /// One exit state per feasible return path in the callee.
    pub exit_states: Vec<CalleeExitState>,
    /// Callee-internal sink findings with full call-chain evidence.
    pub internal_findings: Vec<InternalSinkFinding>,
    /// Reasons execution was cut short (empty if ran to completion).
    pub cutoff_reasons: Vec<CutoffReason>,
}

impl CallOutcome {
    /// Create a cutoff outcome with conservative return.
    ///
    /// Returns `Unknown` with taint preserved if any argument was tainted.
    /// This ensures cutoffs never silently drop taint, conservative soundness.
    fn cutoff(reason: CutoffReason, any_arg_tainted: bool) -> Self {
        CallOutcome {
            exit_states: if any_arg_tainted {
                vec![CalleeExitState {
                    return_value: SymbolicValue::Unknown,
                    return_tainted: true,
                    heap_delta: Vec::new(),
                    taint_delta: HashSet::new(),
                    path_constraints: Vec::new(),
                }]
            } else {
                Vec::new()
            },
            internal_findings: Vec::new(),
            cutoff_reasons: vec![reason],
        }
    }
}

/// Symbolic state at a single callee return point.
#[derive(Clone, Debug)]
pub struct CalleeExitState {
    /// Symbolic value at the return point (from `Terminator::Return(Some(v))`).
    pub return_value: SymbolicValue,
    /// Whether the return value carries taint.
    pub return_tainted: bool,
    /// Heap fields written by the callee (propagated to caller on resume).
    pub heap_delta: Vec<HeapMutation>,
    /// SSA values newly tainted during callee execution.
    pub taint_delta: HashSet<SsaValue>,
    /// Path constraints accumulated inside the callee.
    pub path_constraints: Vec<PathConstraint>,
}

/// A heap field written by the callee.
#[derive(Clone, Debug)]
pub struct HeapMutation {
    pub key: HeapKey,
    pub value: SymbolicValue,
    pub tainted: bool,
}

/// A sink finding detected inside a callee during interprocedural execution.
#[derive(Clone, Debug)]
pub struct InternalSinkFinding {
    /// CFG node of the sink inside the callee.
    pub sink_node: NodeIndex,
    /// Cap bits of the sink.
    pub sink_cap: Cap,
    /// The tainted symbolic value reaching the sink.
    pub tainted_value: SymbolicValue,
    /// Call chain from the outermost caller to the callee containing the sink.
    pub call_chain: Vec<String>,
    /// Path constraints under which this sink is reached.
    pub constraints: Vec<PathConstraint>,
}

/// Accumulator for interprocedural events during transfer.
///
/// Threaded through `transfer_inst` calls to collect callee-internal findings
/// and cutoff reasons without changing the transfer function's return type.
#[derive(Clone, Debug, Default)]
pub struct InterprocEvents {
    pub internal_findings: Vec<InternalSinkFinding>,
    pub cutoff_reasons: Vec<CutoffReason>,
}

//  Merge policy

/// Policy for merging multiple callee exit states into a single caller state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergePolicy {
    /// Conservative phi merge: `mk_phi` of return values, union taint/heap.
    PhiMerge,
    /// Widen to `Unknown`, preserving taint union. Used under budget pressure.
    Widen,
    /// Keep the most-tainted exit state. Used when too many exit states.
    MostTainted,
}

/// Select merge policy based on exit state count and cutoff status.
pub fn select_merge_policy(exit_count: usize, has_cutoffs: bool) -> MergePolicy {
    if has_cutoffs {
        MergePolicy::Widen
    } else if exit_count > 4 {
        MergePolicy::MostTainted
    } else {
        MergePolicy::PhiMerge
    }
}

//  Cache

/// Cache key abstraction of argument symbolic values.
///
/// Encodes per-argument: (position, tag).  The tag captures:
///   - bits 0: is_tainted
///   - bits 1-4: SymbolicValue discriminant
///   - bits 5-15: hash of concrete value (if Concrete/ConcreteStr)
///
/// Richer than taint-only, captures concrete string/int identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArgAbstraction(SmallVec<[(usize, u16); 4]>);

impl ArgAbstraction {
    /// Build an argument abstraction from the call-site's symbolic values.
    pub fn build(arg_values: &[(SsaValue, SymbolicValue, bool)]) -> Self {
        let mut entries: SmallVec<[(usize, u16); 4]> = SmallVec::new();
        for (pos, (_, sym, tainted)) in arg_values.iter().enumerate() {
            let taint_bit: u16 = if *tainted { 1 } else { 0 };
            let discrim: u16 = match sym {
                SymbolicValue::Concrete(_) => 0,
                SymbolicValue::ConcreteStr(_) => 1,
                SymbolicValue::Symbol(_) => 2,
                SymbolicValue::BinOp(..) => 3,
                SymbolicValue::Concat(..) => 4,
                SymbolicValue::Call(..) => 5,
                SymbolicValue::Phi(..) => 6,
                SymbolicValue::Unknown => 7,
                _ => 8, // string ops, etc.
            };
            let concrete_hash: u16 = match sym {
                SymbolicValue::Concrete(n) => (*n as u16).wrapping_mul(31),
                SymbolicValue::ConcreteStr(s) => {
                    let mut h: u16 = 0;
                    for b in s.bytes().take(8) {
                        h = h.wrapping_mul(31).wrapping_add(b as u16);
                    }
                    h
                }
                _ => 0,
            };
            let tag = taint_bit | (discrim << 1) | (concrete_hash << 5);
            entries.push((pos, tag));
        }
        ArgAbstraction(entries)
    }
}

/// Cache type: maps (callee_name, arg_abstraction, heap_fingerprint) → CallOutcome.
pub type InterprocCache = HashMap<(String, ArgAbstraction, u64), CallOutcome>;

//  RAII re-entry guard

/// RAII guard that increments a function's re-entry count on creation and
/// decrements it on drop.  Ensures the count is correct on all exit paths.
struct ReentryGuard<'a> {
    counts: &'a RefCell<HashMap<String, usize>>,
    name: String,
}

impl<'a> ReentryGuard<'a> {
    fn new(counts: &'a RefCell<HashMap<String, usize>>, name: String) -> Self {
        {
            let mut c = counts.borrow_mut();
            *c.entry(name.clone()).or_insert(0) += 1;
        }
        ReentryGuard { counts, name }
    }
}

impl<'a> Drop for ReentryGuard<'a> {
    fn drop(&mut self) {
        let mut c = self.counts.borrow_mut();
        if let Some(count) = c.get_mut(&self.name) {
            *count = count.saturating_sub(1);
        }
    }
}

//  Core execution

/// Execute a callee's SSA body interprocedurally.
///
/// Returns `None` only if the feature is disabled or the callee has no body.
/// Budget/depth/recursion cutoffs return `Some(CallOutcome)` with cutoff
/// reasons and conservative return values (taint preserved).
///
/// # Arguments
/// * `ctx`         , shared interprocedural context
/// * `callee_name` , raw callee name from `SsaOp::Call`
/// * `arg_values`  , per-argument (caller SsaValue, SymbolicValue, tainted)
/// * `caller_heap` , caller's current symbolic heap (for callee reads)
/// * `depth`       , current call depth (0 = top-level caller)
/// * `call_chain`  , function names from outermost caller to current
/// * `summary_ctx` , summary context for nested calls that can't be inlined
/// * `heap_ctx`    , heap context for nested calls
pub fn execute_callee(
    ctx: &InterprocCtx,
    callee_name: &str,
    arg_values: &[(SsaValue, SymbolicValue, bool)],
    caller_heap: &SymbolicHeap,
    depth: usize,
    call_chain: &[String],
    summary_ctx: Option<&SymexSummaryCtx>,
    heap_ctx: Option<&SymexHeapCtx>,
) -> Option<CallOutcome> {
    // Feature gate
    if !interproc_enabled() {
        return None;
    }

    let any_arg_tainted = arg_values.iter().any(|(_, _, t)| *t);

    // Depth check
    if depth >= ctx.max_depth {
        let mut s = ctx.stats.get();
        s.cutoffs += 1;
        ctx.stats.set(s);
        return Some(CallOutcome::cutoff(
            CutoffReason::DepthExceeded {
                max_depth: ctx.max_depth,
            },
            any_arg_tainted,
        ));
    }

    // Global budget check
    {
        let b = ctx.budget.get();
        if b.exhausted() {
            let mut s = ctx.stats.get();
            s.cutoffs += 1;
            ctx.stats.set(s);
            return Some(CallOutcome::cutoff(
                b.exhaustion_reason().unwrap_or(CutoffReason::BudgetBlocks {
                    executed: b.blocks_executed,
                    max: b.max_blocks,
                }),
                any_arg_tainted,
            ));
        }
    }

    // Resolve callee by leaf name, finds first FuncKey with matching name
    // (optionally agreeing on arity). Symex preserves its existing leaf-name
    // semantics; disambiguation happens upstream in the taint engine.
    let normalized = callee_leaf_name(callee_name);
    let arity_hint = arg_values.len();
    let intra_match = ctx
        .callee_bodies
        .iter()
        .find(|(k, _)| k.name == normalized && k.arity == Some(arity_hint))
        .or_else(|| ctx.callee_bodies.iter().find(|(k, _)| k.name == normalized))
        .map(|(_, v)| v);
    let (body, is_cross_file) = match intra_match {
        Some(b) => (b, false),
        None => {
            // Cross-file body resolution (gated + depth-limited)
            if !super::cross_file_symex_enabled() {
                return None;
            }
            if ctx.cross_file_depth >= MAX_CROSS_FILE_DEPTH {
                return None;
            }
            let arity_hint = Some(arg_values.len());
            match ctx.cross_file_bodies.and_then(|gs| {
                gs.resolve_callee_body(ctx.lang, normalized, arity_hint, ctx.caller_namespace)
            }) {
                Some(b) => (b, true),
                None => return None, // No body, fall through to summary
            }
        }
    };

    if body.ssa.blocks.len() > MAX_CALLEE_BLOCKS {
        let mut s = ctx.stats.get();
        s.cutoffs += 1;
        ctx.stats.set(s);
        return Some(CallOutcome::cutoff(
            CutoffReason::CalleeBodyTooLarge {
                callee: normalized.to_string(),
                blocks: body.ssa.blocks.len(),
                max: MAX_CALLEE_BLOCKS,
            },
            any_arg_tainted,
        ));
    }

    // Recursion check: per-function re-entry limit
    {
        let counts = ctx.reentry_counts.borrow();
        let re_entries = counts.get(normalized).copied().unwrap_or(0);
        if re_entries >= ctx.max_reentry_per_func {
            let mut s = ctx.stats.get();
            s.cutoffs += 1;
            ctx.stats.set(s);
            return Some(CallOutcome::cutoff(
                CutoffReason::RecursionLimit {
                    function: normalized.to_string(),
                    re_entries,
                    max: ctx.max_reentry_per_func,
                },
                any_arg_tainted,
            ));
        }
    }

    // SCC-based mutual recursion check
    if let Some(scc_map) = ctx.scc_membership {
        if let Some(&callee_scc) = scc_map.get(normalized) {
            let counts = ctx.reentry_counts.borrow();
            let scc_total: usize = counts
                .iter()
                .filter(|(name, _)| scc_map.get(name.as_str()) == Some(&callee_scc))
                .map(|(_, &count)| count)
                .sum();
            if scc_total >= ctx.max_scc_reentry {
                let scc_funcs: Vec<String> = scc_map
                    .iter()
                    .filter(|(_, idx)| **idx == callee_scc)
                    .map(|(name, _)| name.clone())
                    .collect();
                let mut s = ctx.stats.get();
                s.cutoffs += 1;
                ctx.stats.set(s);
                return Some(CallOutcome::cutoff(
                    CutoffReason::SccRecursionLimit {
                        scc_functions: scc_funcs,
                        total_entries: scc_total,
                        max: ctx.max_scc_reentry,
                    },
                    any_arg_tainted,
                ));
            }
        }
    }

    // Cache check (includes heap fingerprint)
    let sig = ArgAbstraction::build(arg_values);
    let heap_fp = caller_heap.fingerprint();
    {
        let cache = ctx.cache.borrow();
        if let Some(cached) = cache.get(&(normalized.to_string(), sig.clone(), heap_fp)) {
            let mut s = ctx.stats.get();
            s.cache_hits += 1;
            ctx.stats.set(s);
            return Some(cached.clone());
        }
    }
    {
        let mut s = ctx.stats.get();
        s.cache_misses += 1;
        ctx.stats.set(s);
    }

    // Increment re-entry count (RAII guard ensures decrement on all exits)
    let _reentry_guard = ReentryGuard::new(ctx.reentry_counts, normalized.to_string());

    // Increment frames budget
    {
        let mut b = ctx.budget.get();
        b.frames_created += 1;
        ctx.budget.set(b);
    }
    {
        let mut s = ctx.stats.get();
        s.total_frames += 1;
        ctx.stats.set(s);
    }

    // Create callee state
    let mut initial_state = SymbolicState::new();
    initial_state.seed_from_const_values(&body.opt.const_values);

    // Seed parameters: walk callee SSA for Param instructions
    for block in &body.ssa.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            if let SsaOp::Param { index } = &inst.op {
                if let Some((_, sym, tainted)) = arg_values.get(*index) {
                    initial_state.set(inst.value, sym.clone());
                    if *tainted {
                        initial_state.mark_tainted(inst.value);
                    }
                }
            }
        }
    }

    // Snapshot caller heap: callee starts with a clone of the caller's heap.
    let initial_heap = caller_heap.clone();
    *initial_state.heap_mut() = initial_heap.clone();

    // Build call chain for this frame
    let mut frame_chain = call_chain.to_vec();
    frame_chain.push(normalized.to_string());

    // ─── Work-queue exploration (intra-callee forking) ────────

    let mut exit_states: Vec<CalleeExitState> = Vec::new();
    let mut internal_findings: Vec<InternalSinkFinding> = Vec::new();
    let mut cutoff_reasons: Vec<CutoffReason> = Vec::new();

    let mut work_queue: VecDeque<CalleePathState> = VecDeque::new();
    work_queue.push_back(CalleePathState {
        sym_state: initial_state,
        current_block: body.ssa.entry,
        predecessor: None,
        steps: 0,
        forks_used: 0,
    });

    while let Some(mut path) = work_queue.pop_front() {
        loop {
            // Per-frame step budget
            if path.steps >= MAX_CALLEE_STEPS {
                cutoff_reasons.push(CutoffReason::StepBudgetPerFrame {
                    callee: normalized.to_string(),
                    steps: path.steps,
                    max: MAX_CALLEE_STEPS,
                });
                break;
            }
            // Global budget
            {
                let b = ctx.budget.get();
                if b.blocks_executed >= b.max_blocks {
                    cutoff_reasons.push(CutoffReason::BudgetBlocks {
                        executed: b.blocks_executed,
                        max: b.max_blocks,
                    });
                    break;
                }
                if b.instructions_executed >= b.max_instructions {
                    cutoff_reasons.push(CutoffReason::BudgetInstructions {
                        executed: b.instructions_executed,
                        max: b.max_instructions,
                    });
                    break;
                }
            }

            let block = match body.ssa.blocks.get(path.current_block.0 as usize) {
                Some(b) => b,
                None => break,
            };

            // Transfer block instructions
            let xfile_meta = if is_cross_file {
                Some(&body.node_meta)
            } else {
                None
            };
            // `inst.cfg_node` indices are body-local, refer to `body.body_graph`,
            // not `ctx.cfg` (the caller's graph). Fall back to `ctx.cfg` only for
            // cross-file bodies, where `node_meta` is populated and the graph is
            // never indexed directly.
            let body_cfg = body.body_graph.as_ref().unwrap_or(ctx.cfg);
            transfer::transfer_block_with_predecessor(
                &mut path.sym_state,
                block,
                body_cfg,
                &body.ssa,
                path.predecessor,
                summary_ctx,
                heap_ctx,
                // Pass None for interproc_ctx, we handle nested calls directly below.
                None,
                Some(ctx.lang),
                xfile_meta,
            );

            // Count steps and update global budget
            let block_steps = block.phis.len() + block.body.len();
            path.steps += block_steps;
            {
                let mut b = ctx.budget.get();
                b.blocks_executed += 1;
                b.instructions_executed += block_steps;
                ctx.budget.set(b);
            }
            {
                let mut s = ctx.stats.get();
                s.total_blocks += 1;
                ctx.stats.set(s);
            }

            // Detect callee-internal sinks
            detect_internal_sinks(
                block,
                body_cfg,
                &path.sym_state,
                &frame_chain,
                &mut internal_findings,
                xfile_meta,
            );

            // Handle nested calls
            handle_nested_calls(
                block,
                ctx,
                &mut path.sym_state,
                depth,
                &frame_chain,
                summary_ctx,
                heap_ctx,
                &mut internal_findings,
                &mut cutoff_reasons,
            );

            // Examine terminator
            match &block.terminator {
                Terminator::Return(ret_val) => {
                    let (return_value, return_tainted) = if let Some(v) = ret_val {
                        (path.sym_state.get(*v), path.sym_state.is_tainted(*v))
                    } else {
                        (SymbolicValue::Unknown, false)
                    };

                    let heap_delta = compute_heap_delta(&initial_heap, path.sym_state.heap());
                    let taint_delta = path.sym_state.tainted_values().clone();

                    exit_states.push(CalleeExitState {
                        return_value,
                        return_tainted,
                        heap_delta,
                        taint_delta,
                        path_constraints: path.sym_state.path_constraints().to_vec(),
                    });
                    break;
                }
                Terminator::Goto(target) => {
                    // Single-path callee explorer: follows the terminator's
                    // single logical successor. Collapsed ≥3-way fanouts
                    // (src/ssa/lower.rs `three_successor_collapse`) forfeit
                    // the other CFG succs here, which is acceptable because
                    // this walker only refines witnesses for findings already
                    // raised by the taint engine (which uses `block.succs`).
                    path.predecessor = Some(path.current_block);
                    path.current_block = *target;
                }
                Terminator::Branch {
                    true_blk,
                    false_blk,
                    ..
                } => {
                    // Fork both branches when budget allows
                    let can_fork = path.forks_used < MAX_FORKS_PER_CALLEE && {
                        let b = ctx.budget.get();
                        b.symbolic_forks < b.max_symbolic_forks
                            && (work_queue.len() + 1) < b.max_retained_path_states
                    };

                    let true_valid = body.ssa.blocks.get(true_blk.0 as usize).is_some();
                    let false_valid = body.ssa.blocks.get(false_blk.0 as usize).is_some();

                    if can_fork && true_valid && false_valid {
                        // Fork: push false branch to work queue, continue with true
                        let false_state = path.sym_state.clone();
                        // Note: both branches share the visit history
                        let false_path = CalleePathState {
                            sym_state: false_state,
                            current_block: *false_blk,
                            predecessor: Some(path.current_block),
                            steps: path.steps,
                            forks_used: path.forks_used + 1,
                        };
                        work_queue.push_back(false_path);

                        // Update fork budgets
                        {
                            let mut b = ctx.budget.get();
                            b.symbolic_forks += 1;
                            ctx.budget.set(b);
                        }
                        {
                            let mut s = ctx.stats.get();
                            s.forks += 1;
                            ctx.stats.set(s);
                        }

                        path.predecessor = Some(path.current_block);
                        path.current_block = *true_blk;
                        path.forks_used += 1;
                    } else {
                        // Deterministic: prefer true branch, fallback to false
                        path.predecessor = Some(path.current_block);
                        if true_valid {
                            path.current_block = *true_blk;
                        } else if false_valid {
                            path.current_block = *false_blk;
                        } else {
                            break;
                        }
                    }
                }
                Terminator::Switch { .. } => {
                    // Multi-way dispatch: step into the first valid
                    // successor. The callee walker refines witnesses only;
                    // soundness of taint propagation for Switch is handled
                    // by the taint engine which treats all succs uniformly.
                    let next = block
                        .succs
                        .iter()
                        .find(|s| body.ssa.blocks.get(s.0 as usize).is_some())
                        .copied();
                    match next {
                        Some(target) => {
                            path.predecessor = Some(path.current_block);
                            path.current_block = target;
                        }
                        None => break,
                    }
                }
                Terminator::Unreachable => {
                    break;
                }
            }
        }
    }

    let outcome = CallOutcome {
        exit_states,
        internal_findings,
        cutoff_reasons,
    };

    // Cache the result (with size limit)
    {
        let mut cache = ctx.cache.borrow_mut();
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert((normalized.to_string(), sig, heap_fp), outcome.clone());
    }

    Some(outcome)
}

/// A single exploration path within a callee.
struct CalleePathState {
    sym_state: SymbolicState,
    current_block: BlockId,
    predecessor: Option<BlockId>,
    steps: usize,
    forks_used: usize,
}

/// Detect callee-internal sinks in a block.
fn detect_internal_sinks(
    block: &crate::ssa::ir::SsaBlock,
    cfg: &Cfg,
    callee_state: &SymbolicState,
    frame_chain: &[String],
    internal_findings: &mut Vec<InternalSinkFinding>,
    node_meta: Option<
        &std::collections::HashMap<u32, crate::taint::ssa_transfer::CrossFileNodeMeta>,
    >,
) {
    for inst in block.body.iter() {
        let labels: &[DataLabel] = if let Some(meta) = node_meta {
            // cross-file body, use embedded metadata
            meta.get(&(inst.cfg_node.index() as u32))
                .map(|m| m.info.taint.labels.as_slice())
                .unwrap_or(&[])
        } else {
            &cfg[inst.cfg_node].taint.labels
        };
        for label in labels {
            if let DataLabel::Sink(cap) = label {
                let operands = match &inst.op {
                    SsaOp::Call { args, receiver, .. } => {
                        let mut ops: Vec<SsaValue> = Vec::new();
                        if let Some(r) = receiver {
                            ops.push(*r);
                        }
                        for slot in args {
                            if let Some(&v) = slot.first() {
                                ops.push(v);
                            }
                        }
                        ops
                    }
                    SsaOp::Assign(uses) => uses.to_vec(),
                    _ => Vec::new(),
                };
                if operands.iter().any(|v| callee_state.is_tainted(*v)) {
                    let tainted_val = operands
                        .iter()
                        .find(|v| callee_state.is_tainted(**v))
                        .map(|v| callee_state.get(*v))
                        .unwrap_or(SymbolicValue::Unknown);
                    internal_findings.push(InternalSinkFinding {
                        sink_node: inst.cfg_node,
                        sink_cap: *cap,
                        tainted_value: tainted_val,
                        call_chain: frame_chain.to_vec(),
                        constraints: callee_state.path_constraints().to_vec(),
                    });
                }
            }
        }
    }
}

/// Handle nested calls within a callee block.
fn handle_nested_calls(
    block: &crate::ssa::ir::SsaBlock,
    ctx: &InterprocCtx,
    callee_state: &mut SymbolicState,
    depth: usize,
    frame_chain: &[String],
    summary_ctx: Option<&SymexSummaryCtx>,
    heap_ctx: Option<&SymexHeapCtx>,
    internal_findings: &mut Vec<InternalSinkFinding>,
    cutoff_reasons: &mut Vec<CutoffReason>,
) {
    for inst in block.body.iter() {
        if let SsaOp::Call {
            callee,
            args,
            receiver,
            ..
        } = &inst.op
        {
            // Only attempt if the current result is opaque
            let current_val = callee_state.get(inst.value);
            if !matches!(
                current_val,
                SymbolicValue::Call(..) | SymbolicValue::Unknown
            ) {
                continue;
            }
            // Build arg_values for nested call
            let mut nested_args: Vec<(SsaValue, SymbolicValue, bool)> = Vec::new();
            if let Some(r) = receiver {
                nested_args.push((*r, callee_state.get(*r), callee_state.is_tainted(*r)));
            }
            for slot in args {
                if let Some(&v) = slot.first() {
                    nested_args.push((v, callee_state.get(v), callee_state.is_tainted(v)));
                }
            }
            // Recurse
            if let Some(outcome) = execute_callee(
                ctx,
                callee,
                &nested_args,
                callee_state.heap(),
                depth + 1,
                frame_chain,
                summary_ctx,
                heap_ctx,
            ) {
                // Apply callee outcome
                let policy = select_merge_policy(
                    outcome.exit_states.len(),
                    !outcome.cutoff_reasons.is_empty(),
                );
                let merged = merge_exit_states(&outcome.exit_states, policy);
                callee_state.set(inst.value, merged.return_value);
                if merged.return_tainted {
                    callee_state.mark_tainted(inst.value);
                }
                for mutation in &merged.heap_delta {
                    callee_state.heap_mut().store(
                        mutation.key.clone(),
                        mutation.value.clone(),
                        mutation.tainted,
                    );
                }
                // Propagate nested findings and cutoffs
                internal_findings.extend(outcome.internal_findings);
                cutoff_reasons.extend(outcome.cutoff_reasons);
            }
        }
    }
}

//  Exit state merging

/// Merge multiple callee exit states into a single state for the caller.
///
/// - `PhiMerge`: `mk_phi` of return values, union taint/heap (default).
/// - `Widen`: return `Unknown`, union taint. Used under budget pressure.
/// - `MostTainted`: keep the exit state with the most tainted values.
pub fn merge_exit_states(states: &[CalleeExitState], policy: MergePolicy) -> CalleeExitState {
    match states.len() {
        0 => CalleeExitState {
            return_value: SymbolicValue::Unknown,
            return_tainted: false,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        },
        1 => states[0].clone(),
        _ => match policy {
            MergePolicy::PhiMerge => merge_phi(states),
            MergePolicy::Widen => merge_widen(states),
            MergePolicy::MostTainted => merge_most_tainted(states),
        },
    }
}

fn merge_phi(states: &[CalleeExitState]) -> CalleeExitState {
    let phi_ops: Vec<_> = states
        .iter()
        .enumerate()
        .map(|(i, s)| (BlockId(i as u32), s.return_value.clone()))
        .collect();
    let return_value = mk_phi(phi_ops);
    let return_tainted = states.iter().any(|s| s.return_tainted);

    let mut heap_delta: Vec<HeapMutation> = Vec::new();
    let mut seen_keys: HashSet<HeapKey> = HashSet::new();
    for s in states {
        for m in &s.heap_delta {
            if seen_keys.insert(m.key.clone()) {
                heap_delta.push(m.clone());
            }
        }
    }

    let mut taint_delta: HashSet<SsaValue> = HashSet::new();
    for s in states {
        taint_delta.extend(&s.taint_delta);
    }

    CalleeExitState {
        return_value,
        return_tainted,
        heap_delta,
        taint_delta,
        path_constraints: Vec::new(),
    }
}

fn merge_widen(states: &[CalleeExitState]) -> CalleeExitState {
    let return_tainted = states.iter().any(|s| s.return_tainted);

    let mut heap_delta: Vec<HeapMutation> = Vec::new();
    let mut seen_keys: HashSet<HeapKey> = HashSet::new();
    for s in states {
        for m in &s.heap_delta {
            if seen_keys.insert(m.key.clone()) {
                heap_delta.push(m.clone());
            }
        }
    }

    let mut taint_delta: HashSet<SsaValue> = HashSet::new();
    for s in states {
        taint_delta.extend(&s.taint_delta);
    }

    CalleeExitState {
        return_value: SymbolicValue::Unknown,
        return_tainted,
        heap_delta,
        taint_delta,
        path_constraints: Vec::new(),
    }
}

fn merge_most_tainted(states: &[CalleeExitState]) -> CalleeExitState {
    // Pick the state with the most tainted values, breaking ties by first tainted
    states
        .iter()
        .max_by_key(|s| {
            let score = s.taint_delta.len() + if s.return_tainted { 100 } else { 0 };
            score
        })
        .cloned()
        .unwrap_or_else(|| CalleeExitState {
            return_value: SymbolicValue::Unknown,
            return_tainted: false,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        })
}

//  Heap delta

/// Compute the set of heap fields that changed between initial and final state.
fn compute_heap_delta(initial: &SymbolicHeap, final_heap: &SymbolicHeap) -> Vec<HeapMutation> {
    let mut delta = Vec::new();
    for (key, value) in final_heap.entries() {
        let initial_val = initial.load(key);
        let changed = matches!(initial_val, SymbolicValue::Unknown)
            || !sym_value_structurally_eq(&initial_val, value);
        if changed {
            delta.push(HeapMutation {
                key: key.clone(),
                value: value.clone(),
                tainted: final_heap.is_tainted(key),
            });
        }
    }
    delta
}

/// Structural equality check for SymbolicValue (best-effort).
///
/// Full structural equality is expensive for deep trees. This checks the
/// common cases (Concrete, ConcreteStr, Symbol, Unknown) and returns false
/// for complex expressions (conservative, will over-report heap mutations).
fn sym_value_structurally_eq(a: &SymbolicValue, b: &SymbolicValue) -> bool {
    match (a, b) {
        (SymbolicValue::Concrete(x), SymbolicValue::Concrete(y)) => x == y,
        (SymbolicValue::ConcreteStr(x), SymbolicValue::ConcreteStr(y)) => x == y,
        (SymbolicValue::Symbol(x), SymbolicValue::Symbol(y)) => x == y,
        (SymbolicValue::Unknown, SymbolicValue::Unknown) => true,
        _ => false,
    }
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_abstraction_different_taint() {
        let v0 = SsaValue(0);
        let a1 = ArgAbstraction::build(&[(v0, SymbolicValue::Symbol(v0), false)]);
        let a2 = ArgAbstraction::build(&[(v0, SymbolicValue::Symbol(v0), true)]);
        assert_ne!(a1, a2);
    }

    #[test]
    fn arg_abstraction_same_values() {
        let v0 = SsaValue(0);
        let a1 = ArgAbstraction::build(&[(v0, SymbolicValue::Concrete(42), false)]);
        let a2 = ArgAbstraction::build(&[(v0, SymbolicValue::Concrete(42), false)]);
        assert_eq!(a1, a2);
    }

    #[test]
    fn arg_abstraction_different_concrete() {
        let v0 = SsaValue(0);
        let a1 = ArgAbstraction::build(&[(v0, SymbolicValue::Concrete(1), false)]);
        let a2 = ArgAbstraction::build(&[(v0, SymbolicValue::Concrete(2), false)]);
        assert_ne!(a1, a2);
    }

    #[test]
    fn merge_exit_states_empty() {
        let merged = merge_exit_states(&[], MergePolicy::PhiMerge);
        assert!(matches!(merged.return_value, SymbolicValue::Unknown));
        assert!(!merged.return_tainted);
    }

    #[test]
    fn merge_exit_states_single() {
        let state = CalleeExitState {
            return_value: SymbolicValue::Concrete(42),
            return_tainted: true,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let merged = merge_exit_states(&[state], MergePolicy::PhiMerge);
        assert!(matches!(merged.return_value, SymbolicValue::Concrete(42)));
        assert!(merged.return_tainted);
    }

    #[test]
    fn merge_exit_states_multiple_unions_taint() {
        let s1 = CalleeExitState {
            return_value: SymbolicValue::Concrete(1),
            return_tainted: false,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let s2 = CalleeExitState {
            return_value: SymbolicValue::Concrete(2),
            return_tainted: true,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let merged = merge_exit_states(&[s1, s2], MergePolicy::PhiMerge);
        assert!(merged.return_tainted);
        assert!(matches!(merged.return_value, SymbolicValue::Phi(_)));
    }

    #[test]
    fn budget_exhaustion() {
        let budget = InterprocBudget {
            blocks_executed: 500,
            max_blocks: 500,
            frames_created: 0,
            max_frames: 15,
            instructions_executed: 0,
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            symbolic_forks: 0,
            max_symbolic_forks: DEFAULT_MAX_SYMBOLIC_FORKS,
            solver_checks: 0,
            max_solver_checks: DEFAULT_MAX_SOLVER_CHECKS,
            retained_path_states: 0,
            max_retained_path_states: DEFAULT_MAX_RETAINED_PATH_STATES,
        };
        assert!(budget.exhausted());
    }

    #[test]
    fn budget_frames_exhaustion() {
        let budget = InterprocBudget {
            blocks_executed: 0,
            max_blocks: 500,
            frames_created: 15,
            max_frames: 15,
            instructions_executed: 0,
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            symbolic_forks: 0,
            max_symbolic_forks: DEFAULT_MAX_SYMBOLIC_FORKS,
            solver_checks: 0,
            max_solver_checks: DEFAULT_MAX_SOLVER_CHECKS,
            retained_path_states: 0,
            max_retained_path_states: DEFAULT_MAX_RETAINED_PATH_STATES,
        };
        assert!(budget.exhausted());
    }

    #[test]
    fn budget_instructions_exhaustion() {
        let budget = InterprocBudget {
            blocks_executed: 0,
            max_blocks: 500,
            frames_created: 0,
            max_frames: 15,
            instructions_executed: 2000,
            max_instructions: 2000,
            symbolic_forks: 0,
            max_symbolic_forks: DEFAULT_MAX_SYMBOLIC_FORKS,
            solver_checks: 0,
            max_solver_checks: DEFAULT_MAX_SOLVER_CHECKS,
            retained_path_states: 0,
            max_retained_path_states: DEFAULT_MAX_RETAINED_PATH_STATES,
        };
        assert!(budget.exhausted());
    }

    #[test]
    fn budget_not_exhausted() {
        let budget = InterprocBudget::new();
        assert!(!budget.exhausted());
    }

    #[test]
    fn sym_value_eq_concrete() {
        assert!(sym_value_structurally_eq(
            &SymbolicValue::Concrete(5),
            &SymbolicValue::Concrete(5),
        ));
        assert!(!sym_value_structurally_eq(
            &SymbolicValue::Concrete(5),
            &SymbolicValue::Concrete(6),
        ));
    }

    #[test]
    fn sym_value_eq_unknown() {
        assert!(sym_value_structurally_eq(
            &SymbolicValue::Unknown,
            &SymbolicValue::Unknown,
        ));
    }

    #[test]
    fn sym_value_eq_different_kinds() {
        assert!(!sym_value_structurally_eq(
            &SymbolicValue::Concrete(1),
            &SymbolicValue::Unknown,
        ));
    }

    #[test]
    fn cutoff_reason_display() {
        let r = CutoffReason::DepthExceeded { max_depth: 3 };
        assert_eq!(format!("{}", r), "call depth exceeded (max 3)");

        let r = CutoffReason::RecursionLimit {
            function: "foo".into(),
            re_entries: 2,
            max: 2,
        };
        assert_eq!(format!("{}", r), "recursion limit for 'foo' (2/2)");

        let r = CutoffReason::SccRecursionLimit {
            scc_functions: vec!["a".into(), "b".into()],
            total_entries: 3,
            max: 3,
        };
        assert_eq!(format!("{}", r), "SCC recursion limit for [a, b] (3/3)");
    }

    #[test]
    fn budget_exhaustion_reason() {
        let b = InterprocBudget {
            blocks_executed: 500,
            max_blocks: 500,
            ..InterprocBudget::new()
        };
        assert!(matches!(
            b.exhaustion_reason(),
            Some(CutoffReason::BudgetBlocks { .. })
        ));

        let b = InterprocBudget {
            frames_created: 15,
            max_frames: 15,
            ..InterprocBudget::new()
        };
        assert!(matches!(
            b.exhaustion_reason(),
            Some(CutoffReason::BudgetFrames { .. })
        ));

        let b = InterprocBudget::new();
        assert!(b.exhaustion_reason().is_none());
    }

    #[test]
    fn merge_policy_widen() {
        let s1 = CalleeExitState {
            return_value: SymbolicValue::Concrete(1),
            return_tainted: false,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let s2 = CalleeExitState {
            return_value: SymbolicValue::Concrete(2),
            return_tainted: true,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let merged = merge_exit_states(&[s1, s2], MergePolicy::Widen);
        assert!(matches!(merged.return_value, SymbolicValue::Unknown));
        assert!(merged.return_tainted);
    }

    #[test]
    fn merge_policy_most_tainted() {
        let s1 = CalleeExitState {
            return_value: SymbolicValue::Concrete(1),
            return_tainted: false,
            heap_delta: Vec::new(),
            taint_delta: HashSet::new(),
            path_constraints: Vec::new(),
        };
        let mut taint_set = HashSet::new();
        taint_set.insert(SsaValue(0));
        taint_set.insert(SsaValue(1));
        let s2 = CalleeExitState {
            return_value: SymbolicValue::Concrete(2),
            return_tainted: true,
            heap_delta: Vec::new(),
            taint_delta: taint_set,
            path_constraints: Vec::new(),
        };
        let merged = merge_exit_states(&[s1, s2], MergePolicy::MostTainted);
        // Should pick s2 (most tainted)
        assert!(merged.return_tainted);
        assert!(matches!(merged.return_value, SymbolicValue::Concrete(2)));
    }

    #[test]
    fn select_merge_policy_defaults() {
        assert_eq!(select_merge_policy(1, false), MergePolicy::PhiMerge);
        assert_eq!(select_merge_policy(2, false), MergePolicy::PhiMerge);
        assert_eq!(select_merge_policy(4, false), MergePolicy::PhiMerge);
        assert_eq!(select_merge_policy(5, false), MergePolicy::MostTainted);
        assert_eq!(select_merge_policy(2, true), MergePolicy::Widen);
    }

    #[test]
    fn calloutcome_cutoff_preserves_taint() {
        let outcome = CallOutcome::cutoff(CutoffReason::DepthExceeded { max_depth: 3 }, true);
        assert_eq!(outcome.exit_states.len(), 1);
        assert!(outcome.exit_states[0].return_tainted);
        assert!(matches!(
            outcome.exit_states[0].return_value,
            SymbolicValue::Unknown
        ));
        assert_eq!(outcome.cutoff_reasons.len(), 1);
    }

    #[test]
    fn calloutcome_cutoff_no_taint() {
        let outcome = CallOutcome::cutoff(CutoffReason::DepthExceeded { max_depth: 3 }, false);
        assert!(outcome.exit_states.is_empty());
        assert_eq!(outcome.cutoff_reasons.len(), 1);
    }

    #[test]
    fn interproc_stats_default() {
        let stats = InterprocStats::default();
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.cache_misses, 0);
        assert_eq!(stats.total_frames, 0);
        assert_eq!(stats.cutoffs, 0);
        assert_eq!(stats.forks, 0);
    }
}
