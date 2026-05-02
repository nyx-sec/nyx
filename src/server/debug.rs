//! Debug view-model types and on-demand analysis pipeline.
//!
//! Provides serializable "view" structs that mirror internal engine types
//! (CFG, SSA, taint state, etc.) without requiring the engine types themselves
//! to derive `Serialize`.  Also provides helper functions that re-run the
//! analysis pipeline on a single file/function for debug inspection.

use crate::ast::build_cfg_for_file;
use crate::auth_analysis::model::{
    AnalysisUnit, AuthCheck, AuthorizationModel, CallSite, RouteRegistration, SensitiveOperation,
    ValueRef,
};
use crate::callgraph::{CallGraph, CallGraphAnalysis};
use crate::cfg::{Cfg, EdgeKind, FileCfg, FuncSummaries, StmtKind};
use crate::constraint::{CompOp, ConditionExpr, ConstValue, Operand};
use crate::labels::{Cap, DataLabel};
use crate::pointer::{AbsLoc, PointsToFacts};
use crate::ssa::ir::*;
use crate::ssa::type_facts::{TypeFactResult, TypeKind};
use crate::ssa::{self, OptimizeResult};
use crate::state::symbol::SymbolInterner;
use crate::summary::GlobalSummaries;
use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};
use crate::symbol::{FuncKey, Lang};
use crate::symex::state::SymbolicState;
use crate::taint::domain::VarTaint;
use crate::taint::ssa_transfer::{SsaTaintEvent, SsaTaintState, SsaTaintTransfer};
use crate::utils::config::Config;
use axum::http::StatusCode;
use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoNodeReferences};
use serde::Serialize;
use std::collections::VecDeque;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
//  Line-number helper
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a byte offset to a 1-based line number.
fn byte_offset_to_line(bytes: &[u8], offset: usize) -> usize {
    let offset = offset.min(bytes.len());
    bytes[..offset].iter().filter(|&&b| b == b'\n').count() + 1
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cap → human-readable names
// ─────────────────────────────────────────────────────────────────────────────

fn cap_names(c: Cap) -> Vec<String> {
    let mut names = Vec::new();
    if c.contains(Cap::ENV_VAR) {
        names.push("ENV_VAR".into());
    }
    if c.contains(Cap::HTML_ESCAPE) {
        names.push("HTML_ESCAPE".into());
    }
    if c.contains(Cap::SHELL_ESCAPE) {
        names.push("SHELL_ESCAPE".into());
    }
    if c.contains(Cap::URL_ENCODE) {
        names.push("URL_ENCODE".into());
    }
    if c.contains(Cap::JSON_PARSE) {
        names.push("JSON_PARSE".into());
    }
    if c.contains(Cap::FILE_IO) {
        names.push("FILE_IO".into());
    }
    if c.contains(Cap::FMT_STRING) {
        names.push("FMT_STRING".into());
    }
    if c.contains(Cap::SQL_QUERY) {
        names.push("SQL_QUERY".into());
    }
    if c.contains(Cap::DESERIALIZE) {
        names.push("DESERIALIZE".into());
    }
    if c.contains(Cap::SSRF) {
        names.push("SSRF".into());
    }
    if c.contains(Cap::CODE_EXEC) {
        names.push("CODE_EXEC".into());
    }
    if c.contains(Cap::CRYPTO) {
        names.push("CRYPTO".into());
    }
    names
}

fn label_str(l: &DataLabel) -> String {
    match l {
        DataLabel::Source(c) => format!("Source({})", cap_names(*c).join("|")),
        DataLabel::Sanitizer(c) => format!("Sanitizer({})", cap_names(*c).join("|")),
        DataLabel::Sink(c) => format!("Sink({})", cap_names(*c).join("|")),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  View-model types
// ═════════════════════════════════════════════════════════════════════════════

// ── Function list ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FunctionInfo {
    pub name: String,
    pub namespace: String,
    /// Enclosing container path (class / impl / module / outer function).
    /// Empty for free top-level functions.  Surfaced so the UI can render
    /// closures as `<anon#N> [in outer_fn]`.
    pub container: String,
    /// Structural [`crate::symbol::FuncKind`] slug (`"fn"`, `"method"`,
    /// `"closure"`, ...).  Lets the UI offer a closure-filter toggle.
    pub func_kind: String,
    pub param_count: usize,
    pub line: usize,
    pub source_caps: Vec<String>,
    pub sanitizer_caps: Vec<String>,
    pub sink_caps: Vec<String>,
}

// ── CFG ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CfgNodeView {
    pub id: usize,
    pub kind: String,
    pub span: (usize, usize),
    pub line: usize,
    pub defines: Option<String>,
    pub uses: Vec<String>,
    pub callee: Option<String>,
    pub labels: Vec<String>,
    pub condition_text: Option<String>,
    pub enclosing_func: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CfgEdgeView {
    pub source: usize,
    pub target: usize,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct CfgGraphView {
    pub nodes: Vec<CfgNodeView>,
    pub edges: Vec<CfgEdgeView>,
    pub entry: usize,
}

impl CfgGraphView {
    pub fn from_cfg(cfg: &Cfg, entry: NodeIndex, bytes: &[u8]) -> Self {
        let nodes = cfg
            .node_references()
            .map(|(idx, info)| CfgNodeView {
                id: idx.index(),
                kind: stmt_kind_str(info.kind),
                span: info.ast.span,
                line: byte_offset_to_line(bytes, info.ast.span.0),
                defines: info.taint.defines.clone(),
                uses: info.taint.uses.clone(),
                callee: info.call.callee.clone(),
                labels: info.taint.labels.iter().map(label_str).collect(),
                condition_text: info.condition_text.clone(),
                enclosing_func: info.ast.enclosing_func.clone(),
            })
            .collect();

        let edges = cfg
            .edge_references()
            .map(|e| CfgEdgeView {
                source: e.source().index(),
                target: e.target().index(),
                kind: edge_kind_str(*e.weight()),
            })
            .collect();

        CfgGraphView {
            nodes,
            edges,
            entry: entry.index(),
        }
    }

    /// Build a CFG view for a single function by looking up its dedicated
    /// `BodyCfg` in the `FileCfg`.  This replaces the old BFS-filter approach
    /// that walked the supergraph filtered by `enclosing_func`.
    pub fn from_cfg_function(file_cfg: &FileCfg, func_name: &str, bytes: &[u8]) -> Option<Self> {
        // Find the BodyCfg whose meta.name matches the requested function.
        let body = file_cfg
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some(func_name))?;

        Some(Self::from_cfg(&body.graph, body.entry, bytes))
    }
}

fn stmt_kind_str(k: StmtKind) -> String {
    match k {
        StmtKind::Entry => "Entry",
        StmtKind::Exit => "Exit",
        StmtKind::Seq => "Seq",
        StmtKind::If => "If",
        StmtKind::Loop => "Loop",
        StmtKind::Break => "Break",
        StmtKind::Continue => "Continue",
        StmtKind::Return => "Return",
        StmtKind::Throw => "Throw",
        StmtKind::Call => "Call",
    }
    .into()
}

fn edge_kind_str(k: EdgeKind) -> String {
    match k {
        EdgeKind::Seq => "Seq",
        EdgeKind::True => "True",
        EdgeKind::False => "False",
        EdgeKind::Back => "Back",
        EdgeKind::Exception => "Exception",
    }
    .into()
}

// ── SSA ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SsaInstView {
    pub value: u32,
    pub op: String,
    pub operands: Vec<String>,
    pub var_name: Option<String>,
    pub span: (usize, usize),
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct SsaBlockView {
    pub id: u32,
    pub phis: Vec<SsaInstView>,
    pub body: Vec<SsaInstView>,
    pub terminator: String,
    pub preds: Vec<u32>,
    pub succs: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct SsaBodyView {
    pub blocks: Vec<SsaBlockView>,
    pub entry: u32,
    pub num_values: usize,
}

impl SsaBodyView {
    pub fn from_ssa(ssa: &SsaBody, bytes: &[u8]) -> Self {
        let blocks = ssa
            .blocks
            .iter()
            .map(|block| {
                let phis = block.phis.iter().map(|i| inst_view(i, bytes)).collect();
                let body = block.body.iter().map(|i| inst_view(i, bytes)).collect();
                let terminator = terminator_str(&block.terminator);
                SsaBlockView {
                    id: block.id.0,
                    phis,
                    body,
                    terminator,
                    preds: block.preds.iter().map(|b| b.0).collect(),
                    succs: block.succs.iter().map(|b| b.0).collect(),
                }
            })
            .collect();

        SsaBodyView {
            blocks,
            entry: ssa.entry.0,
            num_values: ssa.num_values(),
        }
    }
}

fn inst_view(inst: &SsaInst, bytes: &[u8]) -> SsaInstView {
    let (op, operands) = op_view(&inst.op);
    SsaInstView {
        value: inst.value.0,
        op,
        operands,
        var_name: inst.var_name.clone(),
        span: inst.span,
        line: byte_offset_to_line(bytes, inst.span.0),
    }
}

fn op_view(op: &SsaOp) -> (String, Vec<String>) {
    match op {
        SsaOp::Phi(operands) => {
            let ops: Vec<String> = operands
                .iter()
                .map(|(bid, val)| format!("B{}:v{}", bid.0, val.0))
                .collect();
            ("Phi".into(), ops)
        }
        SsaOp::Assign(uses) => {
            let ops: Vec<String> = uses.iter().map(|v| format!("v{}", v.0)).collect();
            ("Assign".into(), ops)
        }
        SsaOp::Call {
            callee,
            args,
            receiver,
            ..
        } => {
            let mut ops = Vec::new();
            if let Some(rv) = receiver {
                ops.push(format!("recv=v{}", rv.0));
            }
            ops.push(format!("callee={}", callee));
            for (i, arg) in args.iter().enumerate() {
                let vs: Vec<String> = arg.iter().map(|v| format!("v{}", v.0)).collect();
                ops.push(format!("arg{}=[{}]", i, vs.join(",")));
            }
            ("Call".into(), ops)
        }
        SsaOp::Source => ("Source".into(), vec![]),
        SsaOp::Const(text) => {
            let ops = text.iter().cloned().collect();
            ("Const".into(), ops)
        }
        SsaOp::Param { index } => ("Param".into(), vec![format!("{}", index)]),
        SsaOp::SelfParam => ("SelfParam".into(), vec![]),
        SsaOp::CatchParam => ("CatchParam".into(), vec![]),
        SsaOp::Nop => ("Nop".into(), vec![]),
        SsaOp::Undef => ("Undef".into(), vec![]),
        // FieldProj prints field-id (resolution to name requires the
        // owning SsaBody, which the serializer does not have here).
        // Debug consumers walk to the owning body when the name matters.
        SsaOp::FieldProj {
            receiver, field, ..
        } => (
            "FieldProj".into(),
            vec![
                format!("recv=v{}", receiver.0),
                format!("field={}", field.0),
            ],
        ),
    }
}

fn terminator_str(t: &Terminator) -> String {
    match t {
        Terminator::Goto(bid) => format!("goto B{}", bid.0),
        Terminator::Branch {
            true_blk,
            false_blk,
            condition,
            ..
        } => {
            let cond_str = condition
                .as_ref()
                .map(|c| format!("{:?}", c))
                .unwrap_or_else(|| "?".into());
            format!("branch {} -> B{}, B{}", cond_str, true_blk.0, false_blk.0)
        }
        Terminator::Switch {
            scrutinee,
            targets,
            default,
            ..
        } => {
            let ts: Vec<String> = targets.iter().map(|t| format!("B{}", t.0)).collect();
            format!(
                "switch v{} -> [{}] default B{}",
                scrutinee.0,
                ts.join(", "),
                default.0,
            )
        }
        Terminator::Return(v) => match v {
            Some(val) => format!("return v{}", val.0),
            None => "return".into(),
        },
        Terminator::Unreachable => "unreachable".into(),
    }
}

// ── Taint ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TaintValueView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub caps: Vec<String>,
    pub uses_summary: bool,
}

#[derive(Debug, Serialize)]
pub struct TaintBlockStateView {
    pub block_id: u32,
    pub values: Vec<TaintValueView>,
    pub validated_must: u64,
    pub validated_may: u64,
}

#[derive(Debug, Serialize)]
pub struct TaintEventView {
    pub sink_node: usize,
    pub sink_caps: Vec<String>,
    pub tainted_values: Vec<TaintValueView>,
    pub all_validated: bool,
    pub uses_summary: bool,
}

#[derive(Debug, Serialize)]
pub struct TaintAnalysisView {
    pub block_states: Vec<TaintBlockStateView>,
    pub events: Vec<TaintEventView>,
    /// Whether cross-file global summaries were available from DB.
    pub cross_file_context: bool,
    /// Whether SSA-level summaries were loaded (subset of cross-file context).
    pub ssa_summaries_available: bool,
}

impl TaintAnalysisView {
    pub fn from_results(
        events: &[SsaTaintEvent],
        block_states: &[Option<SsaTaintState>],
        ssa: &SsaBody,
        cross_file_context: bool,
        ssa_summaries_available: bool,
    ) -> Self {
        let block_states_view: Vec<TaintBlockStateView> = block_states
            .iter()
            .enumerate()
            .filter_map(|(i, state_opt)| {
                let state = state_opt.as_ref()?;
                let values: Vec<TaintValueView> = state
                    .values
                    .iter()
                    .map(|(sv, taint)| taint_value_view(*sv, taint, ssa))
                    .collect();
                Some(TaintBlockStateView {
                    block_id: i as u32,
                    values,
                    validated_must: state.validated_must.bits(),
                    validated_may: state.validated_may.bits(),
                })
            })
            .collect();

        let events_view: Vec<TaintEventView> = events
            .iter()
            .map(|e| {
                let tainted_values: Vec<TaintValueView> = e
                    .tainted_values
                    .iter()
                    .map(|(sv, caps, _origins)| TaintValueView {
                        ssa_value: sv.0,
                        var_name: ssa
                            .value_defs
                            .get(sv.0 as usize)
                            .and_then(|d| d.var_name.clone()),
                        caps: cap_names(*caps),
                        uses_summary: false,
                    })
                    .collect();

                TaintEventView {
                    sink_node: e.sink_node.index(),
                    sink_caps: cap_names(e.sink_caps),
                    tainted_values,
                    all_validated: e.all_validated,
                    uses_summary: e.uses_summary,
                }
            })
            .collect();

        TaintAnalysisView {
            block_states: block_states_view,
            events: events_view,
            cross_file_context,
            ssa_summaries_available,
        }
    }
}

fn taint_value_view(sv: SsaValue, taint: &VarTaint, ssa: &SsaBody) -> TaintValueView {
    TaintValueView {
        ssa_value: sv.0,
        var_name: ssa
            .value_defs
            .get(sv.0 as usize)
            .and_then(|d| d.var_name.clone()),
        caps: cap_names(taint.caps),
        uses_summary: taint.uses_summary,
    }
}

// ── Abstract Interpretation ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AbstractValueView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub interval_lo: Option<i64>,
    pub interval_hi: Option<i64>,
    pub string_prefix: Option<String>,
    pub string_suffix: Option<String>,
    pub known_zero: u64,
    pub known_one: u64,
}

#[derive(Debug, Serialize)]
pub struct AbstractBlockView {
    pub block_id: u32,
    pub values: Vec<AbstractValueView>,
}

#[derive(Debug, Serialize)]
pub struct TypeFactView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub type_kind: String,
    pub nullable: bool,
}

#[derive(Debug, Serialize)]
pub struct ConstValueViewEntry {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct AbstractInterpView {
    pub blocks: Vec<AbstractBlockView>,
    pub type_facts: Vec<TypeFactView>,
    pub const_values: Vec<ConstValueViewEntry>,
}

impl AbstractInterpView {
    pub fn from_taint_states(
        block_states: &[Option<SsaTaintState>],
        ssa: &SsaBody,
        opt: &OptimizeResult,
    ) -> Self {
        let blocks: Vec<AbstractBlockView> = block_states
            .iter()
            .enumerate()
            .filter_map(|(i, state_opt)| {
                let state = state_opt.as_ref()?;
                let abs_state = state.abstract_state.as_ref()?;
                let values: Vec<AbstractValueView> = (0..ssa.num_values() as u32)
                    .filter_map(|v| {
                        let av = abs_state.get(SsaValue(v));
                        if av.is_top() {
                            return None;
                        }
                        Some(AbstractValueView {
                            ssa_value: v,
                            var_name: ssa
                                .value_defs
                                .get(v as usize)
                                .and_then(|d| d.var_name.clone()),
                            interval_lo: av.interval.lo,
                            interval_hi: av.interval.hi,
                            string_prefix: av.string.prefix.clone(),
                            string_suffix: av.string.suffix.clone(),
                            known_zero: av.bits.known_zero,
                            known_one: av.bits.known_one,
                        })
                    })
                    .collect();

                if values.is_empty() {
                    return None;
                }

                Some(AbstractBlockView {
                    block_id: i as u32,
                    values,
                })
            })
            .collect();

        // Type facts from optimization pass
        let mut type_facts: Vec<TypeFactView> = opt
            .type_facts
            .facts
            .iter()
            .filter(|(_, tf)| !matches!(tf.kind, crate::ssa::type_facts::TypeKind::Unknown))
            .map(|(sv, tf)| TypeFactView {
                ssa_value: sv.0,
                var_name: ssa
                    .value_defs
                    .get(sv.0 as usize)
                    .and_then(|d| d.var_name.clone()),
                type_kind: format!("{:?}", tf.kind),
                nullable: tf.nullable,
            })
            .collect();
        type_facts.sort_by_key(|v| v.ssa_value);

        // Const values from constant propagation
        let mut const_values: Vec<ConstValueViewEntry> = opt
            .const_values
            .iter()
            .filter(|(_, cl)| {
                !matches!(
                    cl,
                    crate::ssa::const_prop::ConstLattice::Top
                        | crate::ssa::const_prop::ConstLattice::Varying
                )
            })
            .map(|(sv, cl)| {
                let value = match cl {
                    crate::ssa::const_prop::ConstLattice::Str(s) => format!("\"{}\"", s),
                    crate::ssa::const_prop::ConstLattice::Int(n) => format!("{}", n),
                    crate::ssa::const_prop::ConstLattice::Bool(b) => format!("{}", b),
                    crate::ssa::const_prop::ConstLattice::Null => "null".into(),
                    _ => unreachable!(),
                };
                ConstValueViewEntry {
                    ssa_value: sv.0,
                    var_name: ssa
                        .value_defs
                        .get(sv.0 as usize)
                        .and_then(|d| d.var_name.clone()),
                    value,
                }
            })
            .collect();
        const_values.sort_by_key(|v| v.ssa_value);

        AbstractInterpView {
            blocks,
            type_facts,
            const_values,
        }
    }
}

// ── Symbolic Execution ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SymexValueView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub expression: String,
}

#[derive(Debug, Serialize)]
pub struct PathConstraintView {
    pub block: u32,
    pub condition: String,
    pub polarity: bool,
}

#[derive(Debug, Serialize)]
pub struct SymexView {
    pub values: Vec<SymexValueView>,
    pub path_constraints: Vec<PathConstraintView>,
    pub tainted_roots: Vec<u32>,
}

impl SymexView {
    pub fn from_symbolic_state(state: &SymbolicState, ssa: &SsaBody) -> Self {
        let mut values: Vec<SymexValueView> = state
            .iter_values()
            .map(|(&v, sym)| SymexValueView {
                ssa_value: v.0,
                var_name: ssa
                    .value_defs
                    .get(v.0 as usize)
                    .and_then(|d| d.var_name.clone()),
                expression: format!("{}", sym),
            })
            .collect();
        values.sort_by_key(|v| v.ssa_value);

        let path_constraints = state
            .path_constraints()
            .iter()
            .map(|pc| PathConstraintView {
                block: pc.block.0,
                condition: format_condition_expr(&pc.condition),
                polarity: pc.polarity,
            })
            .collect();

        let mut tainted_roots: Vec<u32> = state.tainted_values().iter().map(|v| v.0).collect();
        tainted_roots.sort();

        SymexView {
            values,
            path_constraints,
            tainted_roots,
        }
    }
}

// ── Call Graph ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CallGraphNodeView {
    pub id: usize,
    pub name: String,
    pub file: String,
    pub lang: String,
    pub namespace: String,
    pub arity: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CallGraphEdgeView {
    pub source: usize,
    pub target: usize,
    pub call_site: String,
}

#[derive(Debug, Serialize)]
pub struct CallGraphView {
    pub nodes: Vec<CallGraphNodeView>,
    pub edges: Vec<CallGraphEdgeView>,
    pub sccs: Vec<Vec<usize>>,
    pub unresolved_count: usize,
    pub ambiguous_count: usize,
}

impl CallGraphView {
    pub fn from_call_graph(cg: &CallGraph, analysis: &CallGraphAnalysis) -> Self {
        let nodes: Vec<CallGraphNodeView> = cg
            .graph
            .node_references()
            .map(|(idx, fk)| CallGraphNodeView {
                id: idx.index(),
                name: fk.name.clone(),
                file: fk.namespace.clone(),
                lang: format!("{:?}", fk.lang),
                namespace: fk.namespace.clone(),
                arity: fk.arity,
            })
            .collect();

        let edges: Vec<CallGraphEdgeView> = cg
            .graph
            .edge_references()
            .map(|e| CallGraphEdgeView {
                source: e.source().index(),
                target: e.target().index(),
                call_site: e.weight().call_site.clone(),
            })
            .collect();

        let sccs: Vec<Vec<usize>> = analysis
            .sccs
            .iter()
            .filter(|scc| scc.len() > 1) // Only show non-trivial SCCs
            .map(|scc| scc.iter().map(|n| n.index()).collect())
            .collect();

        CallGraphView {
            nodes,
            edges,
            sccs,
            unresolved_count: cg.unresolved_not_found.len(),
            ambiguous_count: cg.unresolved_ambiguous.len(),
        }
    }
}

// ── Summaries ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FuncSummaryView {
    pub name: String,
    pub file_path: String,
    pub lang: String,
    pub namespace: String,
    /// Enclosing container path (class / impl / module / outer function).
    /// Empty for free top-level functions.
    pub container: String,
    /// Structural [`crate::symbol::FuncKind`] slug, `"fn"`, `"method"`,
    /// `"closure"`, etc.  Lets the UI distinguish anonymous closures from
    /// named functions for filtering.
    pub func_kind: String,
    pub arity: Option<usize>,
    pub param_count: usize,
    pub source_caps: Vec<String>,
    pub sanitizer_caps: Vec<String>,
    pub sink_caps: Vec<String>,
    pub propagates_taint: bool,
    pub propagating_params: Vec<usize>,
    pub tainted_sink_params: Vec<usize>,
    pub callees: Vec<CalleeSiteView>,
    pub ssa_summary: Option<SsaSummaryView>,
}

#[derive(Debug, Serialize)]
pub struct CalleeSiteView {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arity: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub ordinal: u32,
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Serialize)]
pub struct SsaSummaryView {
    pub param_to_return: Vec<ParamReturnView>,
    pub param_to_sink: Vec<ParamSinkView>,
    pub source_caps: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ParamReturnView {
    pub param_index: usize,
    pub transform: String,
}

#[derive(Debug, Serialize)]
pub struct ParamSinkView {
    pub param_index: usize,
    pub sink_caps: Vec<String>,
}

impl FuncSummaryView {
    pub fn from_global(
        key: &FuncKey,
        summary: &crate::summary::FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
    ) -> Self {
        let ssa_view = ssa_summary.map(|ss| SsaSummaryView {
            param_to_return: ss
                .param_to_return
                .iter()
                .map(|(idx, transform)| ParamReturnView {
                    param_index: *idx,
                    transform: transform_str(transform),
                })
                .collect(),
            param_to_sink: ss
                .param_to_sink_caps()
                .into_iter()
                .map(|(idx, caps)| ParamSinkView {
                    param_index: idx,
                    sink_caps: cap_names(caps),
                })
                .collect(),
            source_caps: cap_names(ss.source_caps),
        });

        FuncSummaryView {
            name: key.name.clone(),
            file_path: summary.file_path.clone(),
            lang: format!("{:?}", key.lang),
            namespace: key.namespace.clone(),
            container: key.container.clone(),
            func_kind: key.kind.as_str().to_string(),
            arity: key.arity,
            param_count: summary.param_count,
            source_caps: cap_names(Cap::from_bits_truncate(summary.source_caps)),
            sanitizer_caps: cap_names(Cap::from_bits_truncate(summary.sanitizer_caps)),
            sink_caps: cap_names(Cap::from_bits_truncate(summary.sink_caps)),
            propagates_taint: summary.propagates_taint,
            propagating_params: summary.propagating_params.clone(),
            tainted_sink_params: summary.tainted_sink_params.clone(),
            callees: summary
                .callees
                .iter()
                .map(|c| CalleeSiteView {
                    name: c.name.clone(),
                    arity: c.arity,
                    receiver: c.receiver.clone(),
                    qualifier: c.qualifier.clone(),
                    ordinal: c.ordinal,
                })
                .collect(),
            ssa_summary: ssa_view,
        }
    }
}

fn transform_str(t: &TaintTransform) -> String {
    match t {
        TaintTransform::Identity => "Identity".into(),
        TaintTransform::StripBits(caps) => format!("StripBits({})", cap_names(*caps).join("|")),
        TaintTransform::AddBits(caps) => format!("AddBits({})", cap_names(*caps).join("|")),
    }
}

// ── Pointer / Points-to ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PointerLocationView {
    pub id: u32,
    pub kind: String,
    pub display: String,
    /// Parent location id for `Field { parent, field }` chains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PointerValueView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    /// `LocId`s referencing entries in [`PointerView::locations`].
    pub points_to: Vec<u32>,
    pub is_top: bool,
}

#[derive(Debug, Serialize)]
pub struct PointerFieldEntryView {
    /// Parameter index, or `null` for the implicit receiver.
    pub param_index: Option<u32>,
    pub field: String,
}

#[derive(Debug, Serialize)]
pub struct PointerView {
    pub locations: Vec<PointerLocationView>,
    pub values: Vec<PointerValueView>,
    /// Field reads attributed to params/receiver via the field-points-to
    /// extractor.
    pub field_reads: Vec<PointerFieldEntryView>,
    /// Field writes attributed to params/receiver via the field-points-to
    /// extractor.
    pub field_writes: Vec<PointerFieldEntryView>,
    /// Number of distinct interned locations beyond the reserved Top sentinel.
    pub location_count: usize,
}

impl PointerView {
    pub fn from_facts(facts: &PointsToFacts, ssa: &SsaBody) -> Self {
        // Determine which LocIds are referenced by any pt set so we only
        // emit those (plus Top when referenced).
        let mut referenced: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for v in 0..ssa.num_values() as u32 {
            let set = facts.pt(SsaValue(v));
            for loc in set.iter() {
                referenced.insert(loc.0);
            }
        }

        // Build location views in interner order so parent ids land before
        // child Field locations.
        let mut locations: Vec<PointerLocationView> = Vec::new();
        for raw_id in 0..facts.interner.len() as u32 {
            if !referenced.contains(&raw_id) {
                continue;
            }
            let loc_id = crate::pointer::LocId(raw_id);
            let abs = facts.interner.resolve(loc_id);
            let (kind, display, parent, field) = match abs {
                AbsLoc::Top => ("Top".to_string(), "⊤".to_string(), None, None),
                AbsLoc::Alloc(_, ssa_v) => {
                    ("Alloc".to_string(), format!("alloc#v{}", ssa_v), None, None)
                }
                AbsLoc::Param(_, idx) => {
                    ("Param".to_string(), format!("param[{}]", idx), None, None)
                }
                AbsLoc::SelfParam(_) => ("SelfParam".to_string(), "self".to_string(), None, None),
                AbsLoc::Field { parent, field } => {
                    let field_name = if *field == FieldId::ELEM {
                        "<elem>".to_string()
                    } else if (field.0 as usize) < ssa.field_interner.len() {
                        ssa.field_interner.resolve(*field).to_string()
                    } else {
                        format!("#{}", field.0)
                    };
                    (
                        "Field".to_string(),
                        format!(".{}", field_name),
                        Some(parent.0),
                        Some(field_name),
                    )
                }
            };
            locations.push(PointerLocationView {
                id: raw_id,
                kind,
                display,
                parent,
                field,
            });
        }

        // Per-value pt sets, emit only values with non-empty sets to keep
        // the payload focused on interesting facts.
        let mut values: Vec<PointerValueView> = Vec::new();
        for v in 0..ssa.num_values() as u32 {
            let set = facts.pt(SsaValue(v));
            if set.is_empty() {
                continue;
            }
            values.push(PointerValueView {
                ssa_value: v,
                var_name: ssa
                    .value_defs
                    .get(v as usize)
                    .and_then(|d| d.var_name.clone()),
                points_to: set.iter().map(|loc| loc.0).collect(),
                is_top: set.is_top(),
            });
        }

        // Field reads / writes summary derived from the body + facts.
        let summary = crate::pointer::extract_field_points_to(ssa, facts);
        let to_field_entries = |entries: &[(u32, smallvec::SmallVec<[String; 2]>)]| {
            entries
                .iter()
                .flat_map(|(idx, fields)| {
                    let pi = if *idx == u32::MAX { None } else { Some(*idx) };
                    fields.iter().map(move |f| PointerFieldEntryView {
                        param_index: pi,
                        field: f.clone(),
                    })
                })
                .collect()
        };
        let field_reads = to_field_entries(&summary.param_field_reads);
        let field_writes = to_field_entries(&summary.param_field_writes);

        let location_count = facts.interner.len().saturating_sub(1);
        PointerView {
            locations,
            values,
            field_reads,
            field_writes,
            location_count,
        }
    }
}

// ── Type Facts (standalone view) ─────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DtoFieldView {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct DtoFactView {
    pub class_name: String,
    pub fields: Vec<DtoFieldView>,
}

#[derive(Debug, Serialize)]
pub struct TypeFactDetailView {
    pub ssa_value: u32,
    pub var_name: Option<String>,
    pub line: usize,
    /// Type kind tag, matches the [`TypeKind`] discriminant
    /// (`String`, `Int`, `HttpClient`, `Dto`, …).
    pub kind: String,
    /// True when the value is allowed to be null/None.
    pub nullable: bool,
    /// Container/class name, set for `HttpClient`, `DatabaseConnection`,
    /// `Dto`, etc.  Mirrors [`TypeKind::container_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// DTO field shape, populated only when `kind == "Dto"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dto: Option<DtoFactView>,
}

#[derive(Debug, Serialize)]
pub struct TypeFactsView {
    pub facts: Vec<TypeFactDetailView>,
    /// Total count of values reaching the analysis (for the "X of Y" header).
    pub total_values: usize,
    /// Count of values where the inferred type is `Unknown`.  Surfaced so
    /// the UI can show coverage at a glance.
    pub unknown_count: usize,
}

impl TypeFactsView {
    pub fn from_optimize(opt: &OptimizeResult, ssa: &SsaBody, bytes: &[u8]) -> Self {
        Self::from_type_facts(&opt.type_facts, ssa, bytes)
    }

    pub fn from_type_facts(tf: &TypeFactResult, ssa: &SsaBody, bytes: &[u8]) -> Self {
        let total_values = ssa.num_values();
        let unknown_count = tf
            .facts
            .values()
            .filter(|f| matches!(f.kind, TypeKind::Unknown))
            .count();

        let mut facts: Vec<TypeFactDetailView> = tf
            .facts
            .iter()
            .filter(|(_, f)| !matches!(f.kind, TypeKind::Unknown))
            .map(|(sv, fact)| {
                // Find the defining instruction for this SSA value so we can
                // resolve its source line.  Falls back to 0 when no inst
                // matches (the value lives only in `value_defs`).
                let span: (usize, usize) = ssa
                    .blocks
                    .iter()
                    .find_map(|blk| {
                        blk.phis
                            .iter()
                            .chain(blk.body.iter())
                            .find(|i| i.value == *sv)
                            .map(|i| i.span)
                    })
                    .unwrap_or_default();
                let line = byte_offset_to_line(bytes, span.0);

                let dto = match &fact.kind {
                    TypeKind::Dto(d) => Some(DtoFactView {
                        class_name: d.class_name.clone(),
                        fields: d
                            .fields
                            .iter()
                            .map(|(name, k)| DtoFieldView {
                                name: name.clone(),
                                kind: type_kind_tag(k),
                            })
                            .collect(),
                    }),
                    _ => None,
                };

                TypeFactDetailView {
                    ssa_value: sv.0,
                    var_name: ssa
                        .value_defs
                        .get(sv.0 as usize)
                        .and_then(|d| d.var_name.clone()),
                    line,
                    kind: type_kind_tag(&fact.kind),
                    nullable: fact.nullable,
                    container: fact.kind.container_name(),
                    dto,
                }
            })
            .collect();
        facts.sort_by_key(|v| v.ssa_value);

        TypeFactsView {
            facts,
            total_values,
            unknown_count,
        }
    }
}

/// Stable string tag for a [`TypeKind`] (used by both the TypeFacts view
/// and DTO field rendering).  Uses the variant name so the UI can map
/// each tag to a colour without parsing free-form `Debug` strings.
fn type_kind_tag(k: &TypeKind) -> String {
    match k {
        TypeKind::String => "String".into(),
        TypeKind::Int => "Int".into(),
        TypeKind::Bool => "Bool".into(),
        TypeKind::Object => "Object".into(),
        TypeKind::Array => "Array".into(),
        TypeKind::Null => "Null".into(),
        TypeKind::Unknown => "Unknown".into(),
        TypeKind::HttpResponse => "HttpResponse".into(),
        TypeKind::DatabaseConnection => "DatabaseConnection".into(),
        TypeKind::FileHandle => "FileHandle".into(),
        TypeKind::Url => "Url".into(),
        TypeKind::HttpClient => "HttpClient".into(),
        TypeKind::LocalCollection => "LocalCollection".into(),
        TypeKind::RequestBuilder => "RequestBuilder".into(),
        TypeKind::Dto(_) => "Dto".into(),
    }
}

// ── Auth Analysis ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AuthValueRefView {
    pub source_kind: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct AuthCheckView {
    pub kind: String,
    pub callee: String,
    pub line: usize,
    pub subjects: Vec<AuthValueRefView>,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition_text: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthOperationView {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_class: Option<String>,
    pub callee: String,
    pub line: usize,
    pub text: String,
    pub subjects: Vec<AuthValueRefView>,
}

#[derive(Debug, Serialize)]
pub struct AuthCallSiteView {
    pub name: String,
    pub line: usize,
    pub args: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthUnitView {
    pub kind: String,
    pub name: Option<String>,
    pub line: usize,
    pub params: Vec<String>,
    pub auth_checks: Vec<AuthCheckView>,
    pub operations: Vec<AuthOperationView>,
    pub call_sites: Vec<AuthCallSiteView>,
    pub self_actor_vars: Vec<String>,
    pub typed_bounded_vars: Vec<String>,
    pub authorized_sql_vars: Vec<String>,
    pub const_bound_vars: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthRouteView {
    pub framework: String,
    pub method: String,
    pub path: String,
    pub middleware: Vec<String>,
    pub handler_params: Vec<String>,
    pub line: usize,
    pub unit_idx: usize,
}

#[derive(Debug, Serialize)]
pub struct AuthAnalysisView {
    pub routes: Vec<AuthRouteView>,
    pub units: Vec<AuthUnitView>,
    /// Whether the auth-analysis rule set is enabled for the file's
    /// language.  When `false`, the model is intentionally empty and the
    /// UI should surface that the analysis is skipped (not failing).
    pub enabled: bool,
}

impl AuthAnalysisView {
    pub fn from_model(model: &AuthorizationModel, bytes: &[u8], enabled: bool) -> Self {
        let routes = model.routes.iter().map(|r| route_view(r, bytes)).collect();
        let units = model.units.iter().map(|u| unit_view(u, bytes)).collect();
        AuthAnalysisView {
            routes,
            units,
            enabled,
        }
    }
}

fn value_ref_view(vr: &ValueRef, bytes: &[u8]) -> AuthValueRefView {
    AuthValueRefView {
        source_kind: format!("{:?}", vr.source_kind),
        name: vr.name.clone(),
        base: vr.base.clone(),
        field: vr.field.clone(),
        index: vr.index.clone(),
        line: byte_offset_to_line(bytes, vr.span.0),
    }
}

fn auth_check_view(c: &AuthCheck, bytes: &[u8]) -> AuthCheckView {
    AuthCheckView {
        kind: format!("{:?}", c.kind),
        callee: c.callee.clone(),
        line: c.line,
        subjects: c
            .subjects
            .iter()
            .map(|s| value_ref_view(s, bytes))
            .collect(),
        args: c.args.clone(),
        condition_text: c.condition_text.clone(),
    }
}

fn operation_view(op: &SensitiveOperation, bytes: &[u8]) -> AuthOperationView {
    AuthOperationView {
        kind: format!("{:?}", op.kind),
        sink_class: op.sink_class.map(|c| format!("{:?}", c)),
        callee: op.callee.clone(),
        line: op.line,
        text: op.text.clone(),
        subjects: op
            .subjects
            .iter()
            .map(|s| value_ref_view(s, bytes))
            .collect(),
    }
}

fn call_site_view(c: &CallSite, bytes: &[u8]) -> AuthCallSiteView {
    AuthCallSiteView {
        name: c.name.clone(),
        line: byte_offset_to_line(bytes, c.span.0),
        args: c.args.clone(),
    }
}

fn unit_view(unit: &AnalysisUnit, bytes: &[u8]) -> AuthUnitView {
    let mut self_actor_vars: Vec<String> = unit.self_actor_vars.iter().cloned().collect();
    self_actor_vars.sort();
    let mut typed_bounded_vars: Vec<String> = unit.typed_bounded_vars.iter().cloned().collect();
    typed_bounded_vars.sort();
    let mut authorized_sql_vars: Vec<String> = unit.authorized_sql_vars.iter().cloned().collect();
    authorized_sql_vars.sort();
    let mut const_bound_vars: Vec<String> = unit.const_bound_vars.iter().cloned().collect();
    const_bound_vars.sort();

    AuthUnitView {
        kind: format!("{:?}", unit.kind),
        name: unit.name.clone(),
        line: unit.line,
        params: unit.params.clone(),
        auth_checks: unit
            .auth_checks
            .iter()
            .map(|c| auth_check_view(c, bytes))
            .collect(),
        operations: unit
            .operations
            .iter()
            .map(|op| operation_view(op, bytes))
            .collect(),
        call_sites: unit
            .call_sites
            .iter()
            .map(|c| call_site_view(c, bytes))
            .collect(),
        self_actor_vars,
        typed_bounded_vars,
        authorized_sql_vars,
        const_bound_vars,
    }
}

fn route_view(r: &RouteRegistration, _bytes: &[u8]) -> AuthRouteView {
    AuthRouteView {
        framework: format!("{:?}", r.framework),
        method: format!("{:?}", r.method),
        path: r.path.clone(),
        middleware: r.middleware.clone(),
        handler_params: r.handler_params.clone(),
        line: r.line,
        unit_idx: r.unit_idx,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  On-demand analysis pipeline
// ═════════════════════════════════════════════════════════════════════════════

/// Result of parsing + CFG construction for a single file.
pub struct FileAnalysis {
    pub file_cfg: crate::cfg::FileCfg,
    pub lang: Lang,
    pub bytes: Vec<u8>,
}

impl FileAnalysis {
    /// Top-level body's graph (backward-compatible accessor).
    pub fn cfg(&self) -> &Cfg {
        &self.file_cfg.toplevel().graph
    }
    pub fn entry(&self) -> NodeIndex {
        self.file_cfg.toplevel().entry
    }
    pub fn summaries(&self) -> &FuncSummaries {
        &self.file_cfg.summaries
    }
}

/// Parse a file and build its CFG. Returns an error status code on failure.
pub fn analyse_file(file_path: &Path, config: &Config) -> Result<FileAnalysis, StatusCode> {
    let result =
        build_cfg_for_file(file_path, config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Some((file_cfg, lang)) => {
            let bytes = std::fs::read(file_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(FileAnalysis {
                file_cfg,
                lang,
                bytes,
            })
        }
        None => Err(StatusCode::BAD_REQUEST),
    }
}

/// Extract function info list from local summaries.
pub fn function_list(analysis: &FileAnalysis) -> Vec<FunctionInfo> {
    analysis
        .summaries()
        .iter()
        .map(|(key, summary)| FunctionInfo {
            name: key.name.clone(),
            namespace: key.namespace.clone(),
            container: key.container.clone(),
            func_kind: key.kind.as_str().to_string(),
            param_count: summary.param_count,
            line: byte_offset_to_line(&analysis.bytes, analysis.cfg()[summary.entry].ast.span.0),
            source_caps: cap_names(summary.source_caps),
            sanitizer_caps: cap_names(summary.sanitizer_caps),
            sink_caps: cap_names(summary.sink_caps),
        })
        .collect()
}

/// Lower a single function to SSA and optimize it.
///
/// Returns the per-function body graph alongside the SSA. SSA is lowered
/// against `body.graph`, whose `NodeIndex` space is body-local, the file's
/// top-level CFG (`analysis.cfg()`) has a different index space, so any
/// downstream analysis that indexes by `inst.cfg_node` must use the returned
/// `&Cfg`, not `analysis.cfg()`.
pub fn analyse_function_ssa<'a>(
    analysis: &'a FileAnalysis,
    func_name: &str,
) -> Result<(SsaBody, OptimizeResult, &'a Cfg), StatusCode> {
    // Find the function body by name from the per-body CFGs.
    let body = analysis
        .file_cfg
        .bodies
        .iter()
        .find(|b| b.meta.name.as_deref() == Some(func_name))
        .ok_or(StatusCode::NOT_FOUND)?;

    let ssa_result = crate::ssa::lower::lower_to_ssa_with_params(
        &body.graph,
        body.entry,
        Some(func_name),
        false,
        &body.meta.params,
    );

    let mut ssa = ssa_result.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let opt = ssa::optimize_ssa_with_param_types(
        &mut ssa,
        &body.graph,
        Some(analysis.lang),
        &body.meta.param_types,
    );

    Ok((ssa, opt, &body.graph))
}

/// Lower a function and run the field-sensitive Steensgaard pointer
/// analysis on its body.  Returns the SSA body alongside the resulting
/// [`PointsToFacts`] so the debug view can attribute names to SSA values.
pub fn analyse_function_pointer(
    analysis: &FileAnalysis,
    func_name: &str,
) -> Result<(SsaBody, PointsToFacts), StatusCode> {
    let body = analysis
        .file_cfg
        .bodies
        .iter()
        .find(|b| b.meta.name.as_deref() == Some(func_name))
        .ok_or(StatusCode::NOT_FOUND)?;

    let ssa_result = crate::ssa::lower::lower_to_ssa_with_params(
        &body.graph,
        body.entry,
        Some(func_name),
        false,
        &body.meta.params,
    );

    let mut ssa = ssa_result.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _opt = ssa::optimize_ssa_with_param_types(
        &mut ssa,
        &body.graph,
        Some(analysis.lang),
        &body.meta.param_types,
    );

    let facts = crate::pointer::analyse_body(&ssa, body.meta.id);
    Ok((ssa, facts))
}

/// Run taint analysis on a function's SSA body.
pub fn analyse_function_taint(
    ssa: &SsaBody,
    cfg: &Cfg,
    lang: Lang,
    summaries: &FuncSummaries,
    global_summaries: Option<&GlobalSummaries>,
    opt: &OptimizeResult,
) -> (
    Vec<SsaTaintEvent>,
    Vec<Option<SsaTaintState>>,
    Vec<Option<SsaTaintState>>,
) {
    let interner = SymbolInterner::default();
    let empty_interop = vec![];

    let transfer = SsaTaintTransfer {
        lang,
        namespace: "",
        interner: &interner,
        local_summaries: summaries,
        global_summaries,
        interop_edges: &empty_interop,
        owner_body_id: crate::cfg::BodyId(0),
        parent_body_id: None,
        global_seed: None,
        param_seed: None,
        receiver_seed: None,
        const_values: Some(&opt.const_values),
        type_facts: Some(&opt.type_facts),
        ssa_summaries: None,
        extra_labels: None,
        callee_bodies: None,
        inline_cache: None,
        base_aliases: Some(&opt.alias_result),
        context_depth: 0,
        callback_bindings: None,
        points_to: Some(&opt.points_to),
        dynamic_pts: None,
        import_bindings: None,
        promisify_aliases: None,
        module_aliases: if opt.module_aliases.is_empty() {
            None
        } else {
            Some(&opt.module_aliases)
        },
        static_map: None,
        auto_seed_handler_params: matches!(lang, Lang::JavaScript | Lang::TypeScript),
        cross_file_bodies: global_summaries.and_then(|gs| gs.bodies_by_key()),
        pointer_facts: None,
    };

    crate::taint::ssa_transfer::run_ssa_taint_full_with_exits(ssa, cfg, &transfer)
}

/// Run symbolic execution on a function's SSA body and return the final state.
pub fn analyse_function_symex(
    ssa: &SsaBody,
    cfg: &Cfg,
    lang: Lang,
    opt: &OptimizeResult,
    global_summaries: Option<&GlobalSummaries>,
) -> SymbolicState {
    let mut state = SymbolicState::new();
    state.seed_from_const_values(&opt.const_values);

    let summary_ctx = global_summaries.map(|gs| crate::symex::transfer::SymexSummaryCtx {
        global_summaries: gs,
        lang,
        namespace: "",
        type_facts: Some(&opt.type_facts),
    });
    let heap_ctx = crate::symex::transfer::SymexHeapCtx {
        points_to: &opt.points_to,
        ssa,
        lang,
        const_values: &opt.const_values,
    };

    // BFS over blocks from entry to cover all reachable blocks.
    let mut visited = std::collections::HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(ssa.entry);
    visited.insert(ssa.entry);

    while let Some(bid) = queue.pop_front() {
        let block = ssa.block(bid);
        crate::symex::transfer::transfer_block(
            &mut state,
            block,
            cfg,
            ssa,
            summary_ctx.as_ref(),
            Some(&heap_ctx),
            None, // no interproc context
            Some(lang),
        );
        for &succ in &block.succs {
            if visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    state
}

/// Extract `GlobalSummaries` from a single file on-demand (no DB required).
pub fn analyse_file_summaries(
    file_path: &Path,
    config: &Config,
) -> Result<GlobalSummaries, StatusCode> {
    let bytes = std::fs::read(file_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (func_summaries, ssa_rows, _ssa_bodies, auth_rows) =
        crate::ast::extract_all_summaries_from_bytes(&bytes, file_path, config, None)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut global = crate::summary::merge_summaries(func_summaries, None);

    for (key, ssa_summary) in ssa_rows {
        global.insert_ssa(key, ssa_summary);
    }
    for (key, auth_summary) in auth_rows {
        global.insert_auth(key, auth_summary);
    }

    Ok(global)
}

/// Run the file-level authorization extraction pipeline for the debug UI.
///
/// Returns the structured `AuthorizationModel` (routes, units, sensitive
/// operations, auth checks) plus the file bytes and an `enabled` flag ,
/// the bytes drive line-number resolution in the view, and `enabled`
/// surfaces "auth analysis is off for this language" without conflating
/// it with an empty result.
pub fn analyse_file_auth(
    file_path: &Path,
    config: &Config,
) -> Result<(AuthorizationModel, Vec<u8>, bool), StatusCode> {
    let bytes = std::fs::read(file_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let model = crate::ast::extract_auth_model_for_debug(file_path, config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;
    // Determine whether the auth rules were actually enabled for this
    // file's language, `extract_auth_model_for_debug` returns an empty
    // model both when the rules are disabled and when the file just
    // happens to have no routes.  The view distinguishes the two so the
    // UI can show "analysis disabled" instead of "no routes found".
    let lang_slug = crate::ast::lang_slug_for_path(file_path).unwrap_or("");
    let rules = crate::auth_analysis::config::build_auth_rules(config, lang_slug);
    Ok((model, bytes, rules.enabled))
}

/// Format a `ConditionExpr` as a human-readable string.
fn format_condition_expr(cond: &ConditionExpr) -> String {
    match cond {
        ConditionExpr::Comparison { lhs, op, rhs } => {
            let op_str = match op {
                CompOp::Eq => "==",
                CompOp::Neq => "!=",
                CompOp::Lt => "<",
                CompOp::Gt => ">",
                CompOp::Le => "<=",
                CompOp::Ge => ">=",
            };
            format!("{} {} {}", format_operand(lhs), op_str, format_operand(rhs))
        }
        ConditionExpr::NullCheck { var, is_null } => {
            if *is_null {
                format!("v{} == null", var.0)
            } else {
                format!("v{} != null", var.0)
            }
        }
        ConditionExpr::TypeCheck {
            var,
            type_name,
            positive,
        } => {
            if *positive {
                format!("typeof v{} === \"{}\"", var.0, type_name)
            } else {
                format!("typeof v{} !== \"{}\"", var.0, type_name)
            }
        }
        ConditionExpr::BoolTest { var } => format!("v{}", var.0),
        ConditionExpr::Unknown => "?".to_string(),
    }
}

fn format_operand(op: &Operand) -> String {
    match op {
        Operand::Value(v) => format!("v{}", v.0),
        Operand::Const(c) => match c {
            ConstValue::Int(n) => format!("{}", n),
            ConstValue::Str(s) => format!("\"{}\"", s),
            ConstValue::Bool(b) => format!("{}", b),
            ConstValue::Null => "null".to_string(),
        },
        Operand::Unknown => "?".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::Config;

    #[test]
    fn taint_debug_uses_exit_states_for_single_block_flows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.js");
        std::fs::write(
            &path,
            r#"
function demo() {
  const cmd = process.env.CRON_JOB_CMD;
  eval(cmd);
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let (ssa, opt, _cfg) =
            analyse_function_ssa(&analysis, "demo").expect("function should lower to SSA");
        let body = analysis
            .file_cfg
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some("demo"))
            .expect("should find demo function body");
        let (events, _entry_states, exit_states) = analyse_function_taint(
            &ssa,
            &body.graph,
            analysis.lang,
            analysis.summaries(),
            None,
            &opt,
        );

        assert!(
            !events.is_empty(),
            "expected the test fixture to produce at least one taint event"
        );
        assert!(
            exit_states
                .iter()
                .flatten()
                .any(|state| !state.values.is_empty()),
            "exit-state debug view should show tainted SSA values even for single-block functions"
        );

        let view = TaintAnalysisView::from_results(&events, &exit_states, &ssa, false, false);
        assert!(
            view.block_states
                .iter()
                .any(|state| !state.values.is_empty()),
            "serialized debug taint view should expose the populated exit states"
        );
    }

    #[test]
    fn taint_view_without_global_summaries_marks_no_cross_file_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.js");
        std::fs::write(
            &path,
            r#"
function sink() {
  const x = process.env.SECRET;
  eval(x);
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let (ssa, opt, _cfg) =
            analyse_function_ssa(&analysis, "sink").expect("function should lower to SSA");
        let body = analysis
            .file_cfg
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some("sink"))
            .expect("should find sink function body");
        let (events, _entry_states, exit_states) = analyse_function_taint(
            &ssa,
            &body.graph,
            analysis.lang,
            analysis.summaries(),
            None, // no global summaries
            &opt,
        );

        let view = TaintAnalysisView::from_results(&events, &exit_states, &ssa, false, false);
        assert!(!view.cross_file_context);
        assert!(!view.ssa_summaries_available);
        // The local analysis should still find the taint event
        assert!(
            !view.events.is_empty(),
            "local taint should still find events"
        );
    }

    #[test]
    fn taint_view_with_global_summaries_marks_cross_file_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("consumer.js");
        std::fs::write(
            &path,
            r#"
function consume() {
  const x = process.env.SECRET;
  eval(x);
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let (ssa, opt, _cfg) =
            analyse_function_ssa(&analysis, "consume").expect("function should lower to SSA");
        let body = analysis
            .file_cfg
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some("consume"))
            .expect("should find consume function body");

        // Create non-empty global summaries to simulate having run a scan
        let mut global = crate::summary::GlobalSummaries::default();
        let key = crate::symbol::FuncKey {
            lang: crate::symbol::Lang::JavaScript,
            namespace: "src/helper.js".into(),
            name: "getInput".into(),
            arity: Some(0),
            ..Default::default()
        };
        global.insert_ssa(
            key,
            crate::summary::ssa_summary::SsaFuncSummary {
                param_to_return: vec![],
                param_to_sink: vec![],
                source_caps: crate::labels::Cap::all(),
                param_to_sink_param: vec![],
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
                return_path_facts: smallvec::SmallVec::new(),
                typed_call_receivers: vec![],
                validated_params_to_return: smallvec::SmallVec::new(),
                param_to_gate_filters: vec![],
            },
        );

        let cross_file = !global.is_empty();
        let ssa_avail = !global.snapshot_ssa().is_empty();

        let (events, _entry_states, exit_states) = analyse_function_taint(
            &ssa,
            &body.graph,
            analysis.lang,
            analysis.summaries(),
            Some(&global),
            &opt,
        );

        let view =
            TaintAnalysisView::from_results(&events, &exit_states, &ssa, cross_file, ssa_avail);
        assert!(view.cross_file_context);
        assert!(view.ssa_summaries_available);
    }

    #[test]
    fn cfg_function_view_does_not_bleed_into_sibling_functions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.js");
        std::fs::write(
            &path,
            r#"
const db = require("../db");

async function writeAuditLog({ actorId, action, targetType, targetId, metadata }) {
  await db.query(
    `
      INSERT INTO audit_logs (actor_id, action, target_type, target_id, metadata)
      VALUES ($1, $2, $3, $4, $5)
    `,
    [actorId, action, targetType, targetId, metadata]
  );
}

async function recentAuditLogs() {
  const result = await db.query(
    `
      SELECT a.*, u.full_name AS actor_name
      FROM audit_logs a
      LEFT JOIN users u ON u.id = a.actor_id
      ORDER BY a.created_at DESC
      LIMIT 20
    `
  );
  return result.rows;
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let view =
            CfgGraphView::from_cfg_function(&analysis.file_cfg, "writeAuditLog", &analysis.bytes)
                .expect("function view should exist");

        assert!(
            !view.nodes.is_empty(),
            "expected writeAuditLog to produce CFG nodes"
        );
        assert!(
            view.nodes
                .iter()
                .all(|node| node.enclosing_func.as_deref() == Some("writeAuditLog")),
            "function-scoped CFG view should only contain writeAuditLog nodes"
        );
        assert!(
            view.nodes.iter().any(|node| node.line == 4),
            "expected function entry/header for writeAuditLog"
        );
        assert!(
            view.nodes.iter().any(|node| node.line == 5),
            "expected db.query call inside writeAuditLog"
        );
        assert!(
            view.nodes.iter().all(|node| node.line < 13),
            "sibling function nodes should not appear in writeAuditLog view"
        );
    }

    #[test]
    fn pointer_view_serializes_synthetic_facts() {
        // The Steensgaard analyser is exercised against synthetic SSA
        // bodies in `src/pointer/analysis.rs` because real-world
        // lowering can yield bodies whose Param ops have been folded
        // away.  Here we just pin the view-model wiring: feeding the
        // serialiser an SsaBody with one SelfParam + one FieldProj
        // produces non-empty locations / values / field_reads sections.
        use crate::cfg::BodyId;
        use crate::pointer::analyse_body;
        use crate::ssa::ir::{
            BlockId, FieldInterner, SsaBlock, SsaBody, SsaInst, SsaOp, SsaValue, Terminator,
            ValueDef,
        };
        use petgraph::graph::NodeIndex;
        use smallvec::SmallVec;

        let mut field_interner = FieldInterner::new();
        let mu = field_interner.intern("mu");

        let v_self = SsaValue(0);
        let v_field = SsaValue(1);
        let value_defs = vec![
            ValueDef {
                var_name: Some("c".into()),
                cfg_node: NodeIndex::new(0),
                block: BlockId(0),
            },
            ValueDef {
                var_name: Some("c.mu".into()),
                cfg_node: NodeIndex::new(0),
                block: BlockId(0),
            },
        ];
        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: v_self,
                        op: SsaOp::SelfParam,
                        cfg_node: NodeIndex::new(0),
                        var_name: Some("c".into()),
                        span: (0, 0),
                    },
                    SsaInst {
                        value: v_field,
                        op: SsaOp::FieldProj {
                            receiver: v_self,
                            field: mu,
                            projected_type: None,
                        },
                        cfg_node: NodeIndex::new(0),
                        var_name: Some("c.mu".into()),
                        span: (0, 0),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs,
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
            field_interner,
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let facts = analyse_body(&body, BodyId(0));
        let view = PointerView::from_facts(&facts, &body);
        assert!(
            view.location_count > 0,
            "synthetic body should produce at least one location"
        );
        assert!(
            view.locations.iter().any(|l| l.kind == "SelfParam"),
            "expected a SelfParam location in the serialised view"
        );
        assert!(
            view.locations.iter().any(|l| l.kind == "Field"),
            "expected a Field location in the serialised view"
        );
        assert!(
            view.field_reads.iter().any(|e| e.field == "mu"),
            "expected a `mu` field read; got {:?}",
            view.field_reads,
        );
    }

    /// Regression: `analyse_function_ssa` lowers SSA against `body.graph`
    /// (per-function NodeIndex space). Routes used to pass `analysis.cfg()`
    /// (the file's top-level CFG) to `analyse_function_taint`, which made
    /// every `cfg[inst.cfg_node]` lookup index a foreign graph and panicked
    /// with `index out of bounds` on any non-toplevel function whose body
    /// had more nodes than the toplevel. Reproduce: a small Rust file with
    /// a few top-level items and a `main` whose body branches enough to
    /// allocate body-local NodeIndex values past the toplevel's count.
    #[test]
    fn taint_route_uses_per_function_cfg_for_index_lookups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docgen_like.rs");
        std::fs::write(
            &path,
            r#"
use std::env;
use std::fs;

const BEGIN_MARKER: &str = "<!-- BEGIN -->";
const END_MARKER: &str = "<!-- END -->";

fn main() {
    let args: Vec<String> = env::args().collect();
    let target = args.get(1).cloned().unwrap_or_else(|| "x".to_string());
    let original = match fs::read_to_string(&target) {
        Ok(s) => s,
        Err(_) => return,
    };
    let begin = match original.find(BEGIN_MARKER) {
        Some(i) => i,
        None => return,
    };
    let end = match original.find(END_MARKER) {
        Some(i) => i,
        None => return,
    };
    if end < begin {
        return;
    }
    let _ = fs::write(&target, &original);
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let (ssa, opt, body_cfg) =
            analyse_function_ssa(&analysis, "main").expect("function should lower to SSA");

        // Sanity check that this fixture exercises the bug shape: main's body
        // graph must have more nodes than the file's top-level CFG, so a
        // mistaken `analysis.cfg()` would panic on `cfg[inst.cfg_node]`.
        assert!(
            body_cfg.node_count() > analysis.cfg().node_count(),
            "fixture must have more body nodes than toplevel nodes to exercise the bug"
        );

        // Must not panic.  Pre-fix this would `index out of bounds` inside
        // `transfer_inst` because the SSA was lowered against `body_cfg` but
        // the engine was given `analysis.cfg()`.
        let _ = analyse_function_taint(
            &ssa,
            body_cfg,
            analysis.lang,
            analysis.summaries(),
            None,
            &opt,
        );

        // Belt-and-suspenders: assert that calling with the wrong (top-level)
        // CFG would have panicked. We can't catch the panic across rayon
        // worker threads here, but we can confirm at least one `inst.cfg_node`
        // index lies outside `analysis.cfg()`'s range, that's what triggers
        // the OOB indexing inside `transfer_inst`.
        let toplevel_count = analysis.cfg().node_count();
        let max_inst_idx = ssa
            .blocks
            .iter()
            .flat_map(|b| b.phis.iter().chain(b.body.iter()))
            .map(|inst| inst.cfg_node.index())
            .max()
            .unwrap_or(0);
        assert!(
            max_inst_idx >= toplevel_count,
            "regression: at least one inst.cfg_node ({max_inst_idx}) must exceed the \
             toplevel CFG node count ({toplevel_count}) for this test to exercise the bug"
        );
    }

    #[test]
    fn type_facts_view_groups_security_types() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.java");
        std::fs::write(
            &path,
            r#"
import java.net.http.HttpClient;

public class Demo {
    public void run() {
        HttpClient c = HttpClient.newHttpClient();
        c.send(null, null);
    }
}
"#,
        )
        .unwrap();

        let config = Config::default();
        let analysis = analyse_file(&path, &config).expect("file should analyse");
        let (ssa, opt, _cfg) = analyse_function_ssa(&analysis, "run").expect("ssa should lower");
        let view = TypeFactsView::from_optimize(&opt, &ssa, &analysis.bytes);
        assert!(
            view.facts.iter().any(|f| f.kind == "HttpClient"),
            "expected HttpClient inference for `c = HttpClient.newHttpClient()`; got {:?}",
            view.facts.iter().map(|f| &f.kind).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn auth_view_renders_routes_for_express_handlers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.js");
        std::fs::write(
            &path,
            r#"
const express = require('express');
const app = express();

app.get('/api/users/:id', (req, res) => {
  db.query('SELECT * FROM users WHERE id=$1', [req.params.id]);
});
"#,
        )
        .unwrap();

        let config = Config::default();
        let (model, bytes, enabled) =
            analyse_file_auth(&path, &config).expect("auth analysis should run");
        assert!(enabled, "auth analysis should be enabled for JavaScript");
        let view = AuthAnalysisView::from_model(&model, &bytes, enabled);
        assert!(view.enabled);
        assert!(
            view.routes.iter().any(|r| r.path.contains("/api/users")),
            "expected the express GET route to surface; got {:?}",
            view.routes.iter().map(|r| &r.path).collect::<Vec<_>>(),
        );
        assert!(
            !view.units.is_empty(),
            "expected at least one analysis unit for the handler"
        );
    }
}
