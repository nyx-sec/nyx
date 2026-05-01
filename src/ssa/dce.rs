use std::collections::HashMap;

use super::ir::*;
use crate::cfg::Cfg;
use crate::labels::DataLabel;

/// Eliminate dead definitions from an SSA body.
///
/// A definition is dead if its SsaValue has zero uses across the entire body,
/// except for instructions that must be preserved:
/// - `Source` (taint origin, must survive for correctness)
/// - `Call` (may have side effects)
/// - `CatchParam` (exception binding)
/// - Instructions whose CFG node has Sink labels (sink detection relies on them)
///
/// Returns the number of instructions removed.
pub fn eliminate_dead_defs(body: &mut SsaBody, cfg: &Cfg) -> usize {
    let mut total_removed = 0;

    // Iterate until no more removals (removing a def may make its operands dead)
    loop {
        let use_counts = build_use_counts(body);
        let mut removed_this_pass = 0;

        for block in &mut body.blocks {
            // Remove dead body instructions
            let before = block.body.len();
            block.body.retain(|inst| !is_dead(inst, &use_counts, cfg));
            removed_this_pass += before - block.body.len();

            // Remove dead phi instructions
            let before_phis = block.phis.len();
            block.phis.retain(|inst| !is_dead(inst, &use_counts, cfg));
            removed_this_pass += before_phis - block.phis.len();
        }

        total_removed += removed_this_pass;
        if removed_this_pass == 0 {
            break;
        }
    }

    total_removed
}

/// Build a map of SsaValue → number of uses across all instructions and
/// block terminators.
///
/// Terminator uses must be counted: `Terminator::Return(rv)` references the
/// returned value and `Terminator::Branch { condition, .. }` references the
/// condition variable.  Without counting these, a value used solely by a
/// terminator (the canonical case for short helpers like
/// `def f(s): return s`) is judged dead, and DCE strips every instruction
/// in the body, leaving empty blocks whose terminators reference
/// nonexistent SsaValues, breaking downstream analyses (per-return-path
/// PathFact narrowing, inline-summary extraction, etc.).
fn build_use_counts(body: &SsaBody) -> HashMap<SsaValue, usize> {
    let mut counts: HashMap<SsaValue, usize> = HashMap::new();

    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            for v in inst_used_values(inst) {
                *counts.entry(v).or_insert(0) += 1;
            }
        }
        for v in terminator_used_values(&block.terminator) {
            *counts.entry(v).or_insert(0) += 1;
        }
    }

    counts
}

/// Get all SSA values used by a block terminator.
fn terminator_used_values(term: &Terminator) -> Vec<SsaValue> {
    use crate::constraint::lower::{ConditionExpr, Operand};
    match term {
        Terminator::Return(Some(rv)) => vec![*rv],
        Terminator::Return(None) => Vec::new(),
        Terminator::Branch { condition, .. } => match condition.as_deref() {
            Some(ConditionExpr::BoolTest { var }) => vec![*var],
            Some(ConditionExpr::NullCheck { var, .. }) => vec![*var],
            Some(ConditionExpr::TypeCheck { var, .. }) => vec![*var],
            Some(ConditionExpr::Comparison { lhs, rhs, .. }) => {
                let mut out = Vec::new();
                if let Operand::Value(v) = lhs {
                    out.push(*v);
                }
                if let Operand::Value(v) = rhs {
                    out.push(*v);
                }
                out
            }
            Some(ConditionExpr::Unknown) | None => Vec::new(),
        },
        Terminator::Switch { scrutinee, .. } => vec![*scrutinee],
        Terminator::Goto(_) | Terminator::Unreachable => Vec::new(),
    }
}

/// Check if an instruction is dead and safe to remove.
fn is_dead(inst: &SsaInst, use_counts: &HashMap<SsaValue, usize>, cfg: &Cfg) -> bool {
    let uses = use_counts.get(&inst.value).copied().unwrap_or(0);
    if uses > 0 {
        return false;
    }

    // Never remove side-effectful or semantically required instructions
    match &inst.op {
        SsaOp::Source => return false,
        SsaOp::Call { .. } => return false,
        SsaOp::CatchParam => return false,
        _ => {}
    }

    // Never remove instructions whose CFG node has Sink, Source, or Sanitizer labels
    if cfg.node_weight(inst.cfg_node).is_some_and(|info| {
        info.taint.labels.iter().any(|l| {
            matches!(
                l,
                DataLabel::Sink(_) | DataLabel::Source(_) | DataLabel::Sanitizer(_)
            )
        })
    }) {
        return false;
    }

    true
}

/// Get all SSA values used by an instruction.
fn inst_used_values(inst: &SsaInst) -> Vec<SsaValue> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{NodeInfo, StmtKind};
    use petgraph::Graph;
    use smallvec::SmallVec;

    fn make_cfg_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    #[test]
    fn dead_const_removed() {
        // v0 = const("42"), unused, should be removed
        // v1 = source(), must survive even if unused
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("42".into())),
                        cfg_node: n0,
                        var_name: Some("x".into()),
                        span: (0, 2),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Source,
                        cfg_node: n1,
                        var_name: Some("tainted".into()),
                        span: (3, 10),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("x".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("tainted".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(removed, 1);
        assert_eq!(body.blocks[0].body.len(), 1);
        // Source survives
        assert!(matches!(body.blocks[0].body[0].op, SsaOp::Source));
    }

    #[test]
    fn dead_sanitizer_label_preserved() {
        // v0 has a Sanitizer label on its CFG node, must survive even if unused
        use crate::labels::{Cap, DataLabel};

        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(NodeInfo {
            taint: crate::cfg::TaintMeta {
                labels: smallvec::smallvec![DataLabel::Sanitizer(Cap::HTML_ESCAPE)],
                ..Default::default()
            },
            ..make_cfg_node(StmtKind::Seq)
        });

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Assign(SmallVec::new()),
                    cfg_node: n0,
                    var_name: Some("sanitized".into()),
                    span: (0, 5),
                }],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: Some("sanitized".into()),
                cfg_node: n0,
                block: BlockId(0),
            }],
            cfg_node_map: [(n0, SsaValue(0))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(
            removed, 0,
            "Sanitizer-labeled instruction must not be removed"
        );
        assert_eq!(body.blocks[0].body.len(), 1);
    }

    #[test]
    fn dead_source_label_preserved() {
        // v0 has a Source label on its CFG node, must survive even if unused
        use crate::labels::{Cap, DataLabel};

        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(NodeInfo {
            taint: crate::cfg::TaintMeta {
                labels: smallvec::smallvec![DataLabel::Source(Cap::all())],
                ..Default::default()
            },
            ..make_cfg_node(StmtKind::Seq)
        });

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Assign(SmallVec::new()),
                    cfg_node: n0,
                    var_name: Some("src".into()),
                    span: (0, 3),
                }],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: Some("src".into()),
                cfg_node: n0,
                block: BlockId(0),
            }],
            cfg_node_map: [(n0, SsaValue(0))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(removed, 0, "Source-labeled instruction must not be removed");
    }

    #[test]
    fn dead_sink_label_still_preserved() {
        // Regression: Sink-labeled dead instructions must still be kept
        use crate::labels::{Cap, DataLabel};

        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(NodeInfo {
            taint: crate::cfg::TaintMeta {
                labels: smallvec::smallvec![DataLabel::Sink(Cap::SQL_QUERY)],
                ..Default::default()
            },
            ..make_cfg_node(StmtKind::Seq)
        });

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Assign(SmallVec::new()),
                    cfg_node: n0,
                    var_name: Some("q".into()),
                    span: (0, 2),
                }],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: Some("q".into()),
                cfg_node: n0,
                block: BlockId(0),
            }],
            cfg_node_map: [(n0, SsaValue(0))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(removed, 0, "Sink-labeled instruction must not be removed");
    }

    #[test]
    fn dead_unlabeled_assign_still_removed() {
        // Negative test: unlabeled dead assignments must still be eliminated
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Assign(SmallVec::new()),
                    cfg_node: n0,
                    var_name: Some("dead".into()),
                    span: (0, 4),
                }],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: Some("dead".into()),
                cfg_node: n0,
                block: BlockId(0),
            }],
            cfg_node_map: [(n0, SsaValue(0))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(removed, 1, "unlabeled dead assignment must be removed");
        assert!(body.blocks[0].body.is_empty());
    }

    #[test]
    fn dce_keeps_field_proj_when_used() {
        // v0 = source(); v1 = field_proj(v0, "field"); ret v1
        // The terminator references v1, so the FieldProj's receiver chain
        // (v0) must stay reachable.
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let mut interner = crate::ssa::ir::FieldInterner::new();
        let fid = interner.intern("field");

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Source,
                        cfg_node: n0,
                        var_name: Some("obj".into()),
                        span: (0, 5),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::FieldProj {
                            receiver: SsaValue(0),
                            field: fid,
                            projected_type: None,
                        },
                        cfg_node: n1,
                        var_name: Some("obj.field".into()),
                        span: (10, 20),
                    },
                ],
                terminator: Terminator::Return(Some(SsaValue(1))),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("obj".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("obj.field".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: interner,
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(
            removed, 0,
            "FieldProj reachable from terminator must survive"
        );
        assert_eq!(body.blocks[0].body.len(), 2);
    }

    #[test]
    fn dce_removes_dead_field_proj() {
        // v0 = const("x"); v1 = field_proj(v0, "field"); ret (no v1 use)
        // Both should be removed since neither has a use and neither is
        // a Source/Call/labeled instruction.
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let mut interner = crate::ssa::ir::FieldInterner::new();
        let fid = interner.intern("field");

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("x".into())),
                        cfg_node: n0,
                        var_name: Some("obj".into()),
                        span: (0, 1),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::FieldProj {
                            receiver: SsaValue(0),
                            field: fid,
                            projected_type: None,
                        },
                        cfg_node: n1,
                        var_name: Some("obj.field".into()),
                        span: (2, 12),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("obj".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("obj.field".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: interner,
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        // First pass removes the FieldProj (no uses), second removes the Const
        // (no uses after FieldProj is gone).
        assert_eq!(
            removed, 2,
            "dead FieldProj and its dead receiver const must be removed"
        );
        assert!(body.blocks[0].body.is_empty());
    }

    #[test]
    fn used_def_preserved() {
        // v0 = const("42"), v1 = assign(v0), v0 is used, both survive
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("42".into())),
                        cfg_node: n0,
                        var_name: Some("x".into()),
                        span: (0, 2),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Assign(SmallVec::from_elem(SsaValue(0), 1)),
                        cfg_node: n1,
                        var_name: Some("y".into()),
                        span: (3, 5),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("x".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("y".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        // v1 is dead (unused), but v0 is used by v1 so on first pass only v1 removed,
        // then v0 becomes dead on second pass
        assert_eq!(removed, 2);
        assert_eq!(body.blocks[0].body.len(), 0);
    }

    /// DCE must NEVER remove a Call instruction even when its result has
    /// zero uses, calls have side effects (I/O, throws, mutations) that
    /// cannot be modeled as SSA-value uses. This is the conservative
    /// invariant `is_dead()` enforces; regressing it would silently drop
    /// real-world code from analysis (sinks, sanitizers expressed as
    /// expression-statements, etc.).
    #[test]
    fn dead_call_with_unused_result_preserved() {
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Call));

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Call {
                        callee: "side_effect".into(),
                        callee_text: None,
                        args: Vec::new(),
                        receiver: None,
                    },
                    cfg_node: n0,
                    var_name: None,
                    span: (0, 12),
                }],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: None,
                cfg_node: n0,
                block: BlockId(0),
            }],
            cfg_node_map: [(n0, SsaValue(0))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(
            removed, 0,
            "Call with unused result must be preserved (side effects)"
        );
        assert_eq!(body.blocks[0].body.len(), 1);
        assert!(matches!(body.blocks[0].body[0].op, SsaOp::Call { .. }));
    }

    /// A dead phi must be eliminated. We construct an entry block whose
    /// successor has a phi merging two unused constants and a Return(None).
    /// All defs are dead; DCE should strip every body and phi instruction.
    #[test]
    fn dead_phi_in_otherwise_dead_block_removed() {
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n2 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let entry_block = SsaBlock {
            id: BlockId(0),
            phis: vec![],
            body: vec![
                SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Const(Some("1".into())),
                    cfg_node: n0,
                    var_name: Some("a".into()),
                    span: (0, 1),
                },
                SsaInst {
                    value: SsaValue(1),
                    op: SsaOp::Const(Some("2".into())),
                    cfg_node: n1,
                    var_name: Some("b".into()),
                    span: (1, 2),
                },
            ],
            terminator: Terminator::Goto(BlockId(1)),
            preds: SmallVec::new(),
            succs: SmallVec::from_elem(BlockId(1), 1),
        };
        let join_block = SsaBlock {
            id: BlockId(1),
            phis: vec![SsaInst {
                value: SsaValue(2),
                op: SsaOp::Phi(smallvec::smallvec![
                    (BlockId(0), SsaValue(0)),
                    (BlockId(0), SsaValue(1)),
                ]),
                cfg_node: n2,
                var_name: Some("phi".into()),
                span: (2, 3),
            }],
            body: vec![],
            terminator: Terminator::Return(None),
            preds: SmallVec::from_elem(BlockId(0), 1),
            succs: SmallVec::new(),
        };
        let mut body = SsaBody {
            blocks: vec![entry_block, join_block],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("a".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("b".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("phi".into()),
                    cfg_node: n2,
                    block: BlockId(1),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n2, SsaValue(2))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        // Pass 1: the phi (no uses) goes; that drops the use-counts on v0/v1.
        // Pass 2: v0 and v1 (now unused) go.
        assert_eq!(removed, 3, "dead phi + two operands should be removed");
        assert!(
            body.blocks[1].phis.is_empty(),
            "dead phi must be eliminated"
        );
        assert!(body.blocks[0].body.is_empty());
    }

    /// DCE iteration: removing v1 should make v0 dead on the next pass.
    /// Mirrors `used_def_preserved` but explicit about the chain.
    #[test]
    fn dce_iterates_until_fixpoint() {
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n2 = cfg.add_node(make_cfg_node(StmtKind::Seq));

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("1".into())),
                        cfg_node: n0,
                        var_name: Some("a".into()),
                        span: (0, 1),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Assign(SmallVec::from_elem(SsaValue(0), 1)),
                        cfg_node: n1,
                        var_name: Some("b".into()),
                        span: (1, 2),
                    },
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Assign(SmallVec::from_elem(SsaValue(1), 1)),
                        cfg_node: n2,
                        var_name: Some("c".into()),
                        span: (2, 3),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("a".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("b".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("c".into()),
                    cfg_node: n2,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n2, SsaValue(2))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let removed = eliminate_dead_defs(&mut body, &cfg);
        assert_eq!(
            removed, 3,
            "DCE must reach fixpoint and remove all 3 dead defs in the chain"
        );
        assert!(body.blocks[0].body.is_empty());
    }
}
