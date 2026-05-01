//! Symbolic execution targeting: candidate selection and constraint analysis
//! for taint findings.
//!
//! After SSA taint analysis produces findings, this module selects candidates
//! (non-trivial paths, non-validated) and runs constraint analysis on each
//! path to determine feasibility. Results are stored as `SymbolicVerdict` on
//! the finding, which flows through to Evidence and confidence scoring.
//!
//! Symbolic expression trees (`SymbolicValue`) preserve computation structure
//! through the path walk, enabling richer witness strings.

#![allow(
    clippy::collapsible_if,
    clippy::manual_ignore_case_cmp,
    clippy::needless_borrow
)]

pub mod executor;
pub mod heap;
pub mod interproc;
pub mod loops;
#[cfg(feature = "smt")]
pub mod smt;
pub mod state;
pub mod strings;
pub mod transfer;
pub mod value;
pub mod witness;

pub use state::{PathConstraint, SymbolicState};
pub use value::{MAX_EXPR_DEPTH, Op, SymbolicValue};

use std::collections::{HashMap, HashSet};

use crate::cfg::Cfg;
use crate::evidence::{SymbolicVerdict, Verdict};
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::heap::PointsToResult;
use crate::ssa::ir::{BlockId, SsaBody, SsaValue};
use crate::ssa::type_facts::TypeFactResult;
use crate::summary::GlobalSummaries;
use crate::symbol::Lang;
use crate::taint::Finding;

/// Context for symbolic execution analysis.
///
/// Bundles all parameters needed by the symex pipeline: SSA body, CFG,
/// optimization results, and optional cross-file summary context for
/// interprocedural symbolic modeling.
pub struct SymexContext<'a> {
    pub ssa: &'a SsaBody,
    pub cfg: &'a Cfg,
    pub const_values: &'a HashMap<SsaValue, ConstLattice>,
    pub type_facts: &'a TypeFactResult,
    /// Cross-file summaries for interprocedural symbolic modeling.
    /// When `Some`, callee calls can be modeled via `SsaFuncSummary`
    /// instead of being treated as opaque `Unknown`.
    pub global_summaries: Option<&'a GlobalSummaries>,
    pub lang: Lang,
    pub namespace: &'a str,
    /// Points-to analysis results for object identity resolution in the
    /// field-sensitive symbolic heap.
    pub points_to: Option<&'a PointsToResult>,
    /// Pre-lowered intra-file function bodies for interprocedural symbolic
    /// execution. Keyed by canonical `FuncKey`.
    pub callee_bodies: Option<
        &'a std::collections::HashMap<
            crate::symbol::FuncKey,
            crate::taint::ssa_transfer::CalleeSsaBody,
        >,
    >,
    /// SCC membership: maps normalized function name → SCC index.
    /// Used by interprocedural symex for mutual recursion detection.
    pub scc_membership: Option<&'a HashMap<String, usize>>,
    /// Cross-file callee bodies for interprocedural symbolic execution.
    /// Provides body resolution via `GlobalSummaries.resolve_callee_body()`.
    pub cross_file_bodies: Option<&'a GlobalSummaries>,
}

/// Maximum candidates to analyse per file (budget bound).
const MAX_CANDIDATES: usize = 50;

/// Maximum blocks on a path before we skip symex (too expensive).
const MAX_PATH_BLOCKS: usize = 100;

/// Runtime feature gate for SMT solving.  Default ON when compiled with the
/// `smt` feature; controlled at runtime by
/// `analysis.engine.symex.smt` in `nyx.conf` (or `--smt / --no-smt`).
#[cfg(feature = "smt")]
pub fn smt_enabled() -> bool {
    crate::utils::analysis_options::current().symex.smt
}

/// SMT solving is not available without the `smt` compile-time feature.
#[cfg(not(feature = "smt"))]
pub fn smt_enabled() -> bool {
    false
}

/// Feature gate: check if cross-file symbolic body execution is enabled.
///
/// Controlled by `analysis.engine.symex.cross_file` in `nyx.conf` (default
/// `true`) or the `--cross-file-symex / --no-cross-file-symex` CLI flag.
/// When disabled: body extraction, persistence, loading, and resolution are
/// all skipped.
pub fn cross_file_symex_enabled() -> bool {
    crate::utils::analysis_options::current().symex.cross_file
}

/// Feature gate: check if symbolic execution targeting is enabled.
///
/// Controlled by `analysis.engine.symex.enabled` in `nyx.conf` (default
/// `true`) or the `--symex / --no-symex` CLI flag.
pub fn is_enabled() -> bool {
    crate::utils::analysis_options::current().symex.enabled
}

/// Run symex analysis on eligible findings, mutating them in place.
///
/// Pre-filters: skips path_validated findings and those with fewer than 2
/// flow steps. Respects the per-file candidate budget.
pub fn annotate_findings(findings: &mut [Finding], ctx: &SymexContext) {
    let mut budget = MAX_CANDIDATES;
    for finding in findings.iter_mut() {
        if budget == 0 {
            break;
        }
        if finding.flow_steps.len() < 2 || finding.path_validated {
            continue;
        }
        finding.symbolic = Some(analyse_finding_path(finding, ctx));
        budget -= 1;
    }
}

/// Extract the ordered sequence of SSA blocks along a finding's flow path.
///
/// Maps `flow_steps` CFG nodes through `ssa.cfg_node_map` to SSA blocks,
/// deduplicating consecutive blocks.
pub(super) fn extract_path_blocks(finding: &Finding, ssa: &SsaBody) -> Vec<BlockId> {
    let mut blocks = Vec::new();
    let mut seen = HashSet::new();
    for step in &finding.flow_steps {
        if let Some(&val) = ssa.cfg_node_map.get(&step.cfg_node) {
            if val.0 < ssa.value_defs.len() as u32 {
                let block = ssa.value_defs[val.0 as usize].block;
                if seen.insert(block) {
                    blocks.push(block);
                }
            }
        }
    }
    blocks
}

/// Run constraint and symbolic analysis on a single finding's taint path.
///
/// Delegates to the multi-path exploration engine which walks the CFG from
/// source to sink, forking at branch points where both successors lie on
/// some source-to-sink path. Produces an aggregate verdict across all
/// explored paths.
fn analyse_finding_path(finding: &Finding, ctx: &SymexContext) -> SymbolicVerdict {
    let path_blocks = extract_path_blocks(finding, ctx.ssa);

    if path_blocks.is_empty() {
        return SymbolicVerdict {
            verdict: Verdict::Inconclusive,
            constraints_checked: 0,
            paths_explored: 0,
            witness: None,
            interproc_call_chains: Vec::new(),
            cutoff_notes: Vec::new(),
        };
    }

    if path_blocks.len() < 2 {
        // Short path (single block, no branches), skip the multi-path
        // explorer but still run a linear transfer to extract a witness.
        let witness = linear_witness(finding, ctx, &path_blocks);
        return SymbolicVerdict {
            verdict: Verdict::Inconclusive,
            constraints_checked: 0,
            paths_explored: 1,
            witness,
            interproc_call_chains: Vec::new(),
            cutoff_notes: Vec::new(),
        };
    }

    if path_blocks.len() > MAX_PATH_BLOCKS {
        return SymbolicVerdict {
            verdict: Verdict::Inconclusive,
            constraints_checked: 0,
            paths_explored: 0,
            witness: Some("path too long for symex budget".into()),
            interproc_call_chains: Vec::new(),
            cutoff_notes: Vec::new(),
        };
    }

    let result = executor::explore_finding(finding, ctx);
    result.aggregate_verdict()
}

/// Run a minimal linear symbolic transfer on `path_blocks` and extract
/// a witness. Used for short paths (single block, no branches) that
/// don't need the full multi-path exploration engine.
fn linear_witness(
    finding: &Finding,
    ctx: &SymexContext,
    path_blocks: &[BlockId],
) -> Option<String> {
    let mut sym_state = SymbolicState::new();

    // Seed constants from const_prop
    sym_state.seed_from_const_values(&ctx.const_values);

    // Seed source flow steps as tainted symbols before transfer.
    for step in &finding.flow_steps {
        if let Some(&val) = ctx.ssa.cfg_node_map.get(&step.cfg_node) {
            if matches!(step.op_kind, crate::evidence::FlowStepKind::Source) {
                sym_state.set(val, value::SymbolicValue::Symbol(val));
                sym_state.mark_tainted(val);
            }
        }
    }

    // Build context structs for transfer
    let summary_ctx = ctx.global_summaries.map(|gs| transfer::SymexSummaryCtx {
        global_summaries: gs,
        lang: ctx.lang,
        namespace: ctx.namespace,
        type_facts: Some(ctx.type_facts),
    });
    let heap_ctx = ctx.points_to.map(|pts| transfer::SymexHeapCtx {
        points_to: pts,
        ssa: ctx.ssa,
        lang: ctx.lang,
        const_values: ctx.const_values,
    });

    // Transfer each block in order
    for &bid in path_blocks {
        if let Some(block) = ctx.ssa.blocks.get(bid.0 as usize) {
            transfer::transfer_block(
                &mut sym_state,
                block,
                ctx.cfg,
                ctx.ssa,
                summary_ctx.as_ref(),
                heap_ctx.as_ref(),
                None, // no interproc for short paths
                Some(ctx.lang),
            );
        }
    }

    // After transfer, mark all Symbol values that appear in the sink
    // expression as tainted. The transfer builds the expression tree from
    // base SSA values (parameters, etc.); we mark them tainted so that
    // witness extraction can identify tainted sub-expressions.
    if let Some(&sink_val) = ctx.ssa.cfg_node_map.get(&finding.sink) {
        let sink_sym = sym_state.get(sink_val);
        mark_symbols_tainted(&sink_sym, &mut sym_state);
    }

    // Extract witness
    witness::extract_witness(&sym_state, finding, ctx.ssa, ctx.cfg)
        .or_else(|| sym_state.get_sink_witness(finding, ctx.ssa))
}

/// Recursively mark all `Symbol(v)` values in an expression tree as tainted.
fn mark_symbols_tainted(expr: &value::SymbolicValue, state: &mut SymbolicState) {
    match expr {
        value::SymbolicValue::Symbol(v) => {
            state.mark_tainted(*v);
        }
        value::SymbolicValue::BinOp(_, l, r) | value::SymbolicValue::Concat(l, r) => {
            mark_symbols_tainted(l, state);
            mark_symbols_tainted(r, state);
        }
        value::SymbolicValue::Call(_, args) => {
            for a in args {
                mark_symbols_tainted(a, state);
            }
        }
        value::SymbolicValue::Phi(ops) => {
            for (_, v) in ops {
                mark_symbols_tainted(v, state);
            }
        }
        value::SymbolicValue::ToLower(s)
        | value::SymbolicValue::ToUpper(s)
        | value::SymbolicValue::Trim(s)
        | value::SymbolicValue::StrLen(s)
        | value::SymbolicValue::Replace(s, _, _)
        | value::SymbolicValue::Encode(_, s)
        | value::SymbolicValue::Decode(_, s) => {
            mark_symbols_tainted(s, state);
        }
        value::SymbolicValue::Substr(s, start, end) => {
            mark_symbols_tainted(s, state);
            mark_symbols_tainted(start, state);
            if let Some(e) = end {
                mark_symbols_tainted(e, state);
            }
        }
        value::SymbolicValue::Concrete(_)
        | value::SymbolicValue::ConcreteStr(_)
        | value::SymbolicValue::Unknown => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::ir::{BlockId, SsaBlock, SsaBody, SsaValue, Terminator, ValueDef};
    use crate::ssa::type_facts::TypeFactResult;
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

    #[test]
    fn is_enabled_tracks_runtime_default() {
        // The process-wide runtime is a `OnceLock`; without any prior install,
        // [`is_enabled`] reflects `AnalysisOptions::default().symex.enabled`.
        // Flipping the toggle is covered by `analysis_options` unit tests that
        // don't cross process boundaries.
        assert_eq!(
            is_enabled(),
            crate::utils::AnalysisOptions::default().symex.enabled
        );
    }

    #[test]
    fn extract_path_blocks_basic() {
        use crate::taint::FlowStepRaw;

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

        let finding = Finding {
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
        };

        let blocks = extract_path_blocks(&finding, &ssa);
        assert_eq!(blocks, vec![b0, b1]);
    }

    #[test]
    fn analyse_no_branches_confirmed() {
        use crate::taint::FlowStepRaw;

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

        let finding = Finding {
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
        };

        let ctx = SymexContext {
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
        let verdict = analyse_finding_path(&finding, &ctx);
        assert_eq!(verdict.verdict, Verdict::Confirmed);
        assert_eq!(verdict.constraints_checked, 0);
        assert_eq!(verdict.paths_explored, 1);
    }

    #[test]
    fn annotate_skips_validated() {
        use crate::taint::FlowStepRaw;

        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);

        let mut finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: n1,
            source: n0,
            path: vec![n0, n1],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: true, // should be skipped
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
        };

        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let ctx = SymexContext {
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
        annotate_findings(std::slice::from_mut(&mut finding), &ctx);
        // Should remain None, skipped due to path_validated
        assert!(finding.symbolic.is_none());
    }

    #[test]
    fn annotate_skips_short_path() {
        use crate::taint::FlowStepRaw;

        let n0 = NodeIndex::new(0);

        let mut finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: n0,
            source: n0,
            path: vec![n0],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![FlowStepRaw {
                cfg_node: n0,
                var_name: Some("x".into()),
                op_kind: crate::evidence::FlowStepKind::Source,
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

        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let ctx = SymexContext {
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
        annotate_findings(std::slice::from_mut(&mut finding), &ctx);
        // Should remain None, only 1 flow step
        assert!(finding.symbolic.is_none());
    }
}
