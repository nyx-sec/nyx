use std::collections::HashMap;

use super::ir::*;
use crate::cfg::Cfg;

/// Run copy propagation on an SSA body.
///
/// Identifies `Assign([single_use])` instructions where the CFG node has no
/// labels (i.e., no semantic significance like sanitizer/source), then rewrites
/// all uses of the destination value to use the source value directly.
///
/// Returns `(copies_eliminated, resolved_replacement_map)`. The replacement map
/// maps each eliminated destination SsaValue to its transitive root source
/// SsaValue, used downstream by alias analysis to recover base-variable
/// aliasing relationships.
pub fn copy_propagate(body: &mut SsaBody, cfg: &Cfg) -> (usize, HashMap<SsaValue, SsaValue>) {
    // 1. Identify copies: Assign with single operand and no labels on CFG node
    let mut replace_map: HashMap<SsaValue, SsaValue> = HashMap::new();

    for block in &body.blocks {
        for inst in &block.body {
            if let SsaOp::Assign(uses) = &inst.op {
                if uses.len() == 1 {
                    let src = uses[0];
                    let info = &cfg[inst.cfg_node];
                    // A constant-index element read (`parts[0]`) is a value of
                    // its own: branch checks and the synthetic element-read
                    // calls name it, so it must stay distinct from `parts`.
                    if !info.elem_reads.is_empty()
                        && inst
                            .var_name
                            .as_deref()
                            .is_some_and(|n| info.elem_reads.iter().any(|e| &**e == n))
                    {
                        continue;
                    }
                    // Skip if the node has labels, sanitizers, sources, sinks
                    // have semantic meaning that must be preserved.
                    if !info.taint.labels.is_empty() {
                        continue;
                    }
                    // Skip numeric-length reads (`arr.length`, `map.size`, etc.):
                    // the destination is Int-typed (a derived property of the
                    // source) while the source is typically String/Object/
                    // Unknown.  Copy-propagating through this Assign would
                    // erase the Int type fact and defeat HTML_ESCAPE / SQL /
                    // FILE_IO / SHELL sink suppression.
                    if info.is_numeric_length_access {
                        continue;
                    }
                    // A numeric conversion (`$n = (int) $x`) is not a copy of
                    // its operand: the taint transfer clears the value.
                    if info.yields_number {
                        continue;
                    }
                    // Skip Assigns whose CFG node carries a `string_prefix`
                    // (template literals or `"lit" + var` RHS recognised by
                    // `template_prefix_of`).  The abstract-interpretation
                    // `transfer_abstract` consumes that prefix to seed a
                    // StringFact on the Assign's SSA value, which downstream
                    // SSRF suppression reads.  Propagating past this Assign
                    // erases the prefix-bearing SSA value: the Call's args get
                    // rewritten to the bare upstream variable (no prefix), and
                    // `is_call_abstract_safe` falls through to a tainted-flow
                    // emission even on safe fixed-host URLs.
                    if info.string_prefix.is_some() {
                        continue;
                    }
                    // Skip bindings with a declared type
                    // (`c := &http.Client{Timeout: t}` lowers to
                    // `Assign([t])`).  The type belongs to the destination,
                    // not to the single operand, so folding the copy would
                    // hand the call receiver the operand's type instead.
                    if info.decl_type.is_some() {
                        continue;
                    }
                    // Skip Go map-membership lookups (`_, ok := m[k]`).  The
                    // presence flag only shares its operand with the key; it
                    // is not a copy of it.  Folding it would repoint the
                    // `if !ok` condition at the key, and the allowlist
                    // narrowing needs the condition to name the lookup.
                    if info.membership_lookup.is_some() {
                        continue;
                    }
                    replace_map.insert(inst.value, src);
                }
            }
        }
    }

    if replace_map.is_empty() {
        return (0, HashMap::new());
    }

    // 2. Build transitive replacement map: chase chains (SSA is acyclic)
    let mut resolved: HashMap<SsaValue, SsaValue> = HashMap::new();
    for &dst in replace_map.keys() {
        let root = resolve_root(dst, &replace_map);
        resolved.insert(dst, root);
    }

    // 3. Rewrite all uses
    let mut count = 0;
    for block in &mut body.blocks {
        // Rewrite phi operands
        for phi in &mut block.phis {
            if let SsaOp::Phi(operands) = &mut phi.op {
                for (_bid, val) in operands.iter_mut() {
                    if let Some(&root) = resolved.get(val) {
                        *val = root;
                    }
                }
            }
        }

        // Rewrite what the terminator reads.  The copy is turned into a Nop
        // below, so a `Return(Some(v))`, branch condition or switch scrutinee
        // left on it would read a value with no definition.
        rewrite_terminator_uses(&mut block.terminator, &resolved);

        // Rewrite body instructions
        for inst in &mut block.body {
            match &mut inst.op {
                SsaOp::Assign(uses) => {
                    for val in uses.iter_mut() {
                        if let Some(&root) = resolved.get(val) {
                            *val = root;
                        }
                    }
                }
                SsaOp::Call { args, receiver, .. } => {
                    if let Some(rv) = receiver {
                        if let Some(&root) = resolved.get(rv) {
                            *rv = root;
                        }
                    }
                    for arg in args.iter_mut() {
                        for val in arg.iter_mut() {
                            if let Some(&root) = resolved.get(val) {
                                *val = root;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // 4. Convert copy instructions to Nop (DCE will clean up)
    for block in &mut body.blocks {
        for inst in &mut block.body {
            if resolved.contains_key(&inst.value) {
                inst.op = SsaOp::Nop;
                count += 1;
            }
        }
    }

    (count, resolved)
}

/// Point the values a terminator reads at their copy roots.
fn rewrite_terminator_uses(term: &mut Terminator, resolved: &HashMap<SsaValue, SsaValue>) {
    use crate::constraint::lower::{ConditionExpr, Operand};
    let fix = |v: &mut SsaValue| {
        if let Some(&root) = resolved.get(v) {
            *v = root;
        }
    };
    match term {
        Terminator::Return(Some(v)) => fix(v),
        Terminator::Switch { scrutinee, .. } => fix(scrutinee),
        Terminator::Branch { condition, .. } => match condition.as_deref_mut() {
            Some(ConditionExpr::BoolTest { var, .. })
            | Some(ConditionExpr::NullCheck { var, .. })
            | Some(ConditionExpr::TypeCheck { var, .. }) => fix(var),
            Some(ConditionExpr::Comparison { lhs, rhs, .. }) => {
                for operand in [lhs, rhs] {
                    if let Operand::Value(v) = operand {
                        fix(v);
                    }
                }
            }
            Some(ConditionExpr::Unknown) | None => {}
        },
        Terminator::Return(None) | Terminator::Goto(_) | Terminator::Unreachable => {}
    }
}

/// Chase the replacement chain to find the root value.
fn resolve_root(val: SsaValue, map: &HashMap<SsaValue, SsaValue>) -> SsaValue {
    let mut current = val;
    // Safety: SSA is acyclic, but cap iterations to be safe
    for _ in 0..1000 {
        match map.get(&current) {
            Some(&next) if next != current => current = next,
            _ => break,
        }
    }
    current
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
    fn simple_copy_eliminated() {
        // v0 = const("42"), v1 = assign(v0), v2 = assign(v1)
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
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Assign(SmallVec::from_elem(SsaValue(1), 1)),
                        cfg_node: n2,
                        var_name: Some("z".into()),
                        span: (6, 8),
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
                ValueDef {
                    var_name: Some("z".into()),
                    cfg_node: n2,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n2, SsaValue(2))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let (eliminated, copy_map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 2);
        // Both v1 and v2 should map to v0 (the root)
        assert_eq!(copy_map.get(&SsaValue(1)), Some(&SsaValue(0)));
        assert_eq!(copy_map.get(&SsaValue(2)), Some(&SsaValue(0)));

        // v1 and v2 should be Nop now
        assert!(matches!(body.blocks[0].body[1].op, SsaOp::Nop));
        assert!(matches!(body.blocks[0].body[2].op, SsaOp::Nop));
    }

    /// `resolve_root` has a 1000-iteration safety cap to avoid livelock if
    /// a malformed copy map ever contains a cycle (SSA itself is acyclic,
    /// but defensively we want this guarantee on the helper). Confirm the
    /// cap actually fires by feeding a hand-crafted cycle a → b → a.
    #[test]
    fn resolve_root_terminates_on_cyclic_copy_map() {
        let mut map: std::collections::HashMap<SsaValue, SsaValue> =
            std::collections::HashMap::new();
        map.insert(SsaValue(0), SsaValue(1));
        map.insert(SsaValue(1), SsaValue(0));
        // Must terminate; the exact returned value isn't a correctness
        // guarantee under malformed input, but no infinite loop is.
        let _root = resolve_root(SsaValue(0), &map);
    }

    /// A four-deep copy chain v3 = v2 = v1 = v0 must collapse to v0
    /// in a single `copy_propagate` pass, the resolved replacement
    /// map drives downstream alias recovery, so the *transitive*
    /// closure must be exposed, not just the immediate parent.
    #[test]
    fn deep_copy_chain_collapses_to_root() {
        let mut cfg: Cfg = Graph::new();
        let nodes: Vec<_> = (0..4)
            .map(|_| cfg.add_node(make_cfg_node(StmtKind::Seq)))
            .collect();

        let mut block_body = vec![SsaInst {
            value: SsaValue(0),
            op: SsaOp::Const(Some("\"x\"".into())),
            cfg_node: nodes[0],
            var_name: Some("a".into()),
            span: (0, 1),
        }];
        for (i, node) in nodes.iter().enumerate().take(4).skip(1) {
            block_body.push(SsaInst {
                value: SsaValue(i as u32),
                op: SsaOp::Assign(SmallVec::from_elem(SsaValue((i - 1) as u32), 1)),
                cfg_node: *node,
                var_name: Some(format!("v{i}")),
                span: (i, i + 1),
            });
        }

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: block_body,
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: (0..4)
                .map(|i| ValueDef {
                    var_name: Some(format!("v{i}")),
                    cfg_node: nodes[i],
                    block: BlockId(0),
                })
                .collect(),
            cfg_node_map: nodes
                .iter()
                .enumerate()
                .map(|(i, n)| (*n, SsaValue(i as u32)))
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let (eliminated, copy_map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 3, "v1, v2, v3 must all be eliminated");
        for i in 1..4 {
            assert_eq!(
                copy_map.get(&SsaValue(i)),
                Some(&SsaValue(0)),
                "v{i} must resolve transitively to v0"
            );
        }
    }

    // Skip-conditions: copy-prop must NOT erase semantic info attached
    // to a copy's CFG node. These guard the three early-exits in
    // `copy_propagate`: labels, numeric-length, and string_prefix.

    /// Build a single-block SSA body containing
    ///   v0 = Const, v1 = Assign(v0)
    /// with `node1_decorator` applied to v1's CFG node so individual
    /// skip-conditions can be exercised.
    fn build_two_inst_body(decorate: impl FnOnce(&mut NodeInfo)) -> (Cfg, SsaBody) {
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let mut n1_info = make_cfg_node(StmtKind::Seq);
        decorate(&mut n1_info);
        let n1 = cfg.add_node(n1_info);
        let body = SsaBody {
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
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        (cfg, body)
    }

    /// Skip path 1: an Assign whose CFG node carries a label
    /// (sanitizer/source/sink) must NOT be propagated through. Erasing
    /// that label would silently drop a sanitization step from the
    /// taint path.
    #[test]
    fn copy_with_label_on_cfg_node_is_not_propagated() {
        use crate::labels::{Cap, DataLabel};
        use smallvec::smallvec;
        let (cfg, mut body) = build_two_inst_body(|info| {
            info.taint.labels = smallvec![DataLabel::Sanitizer(Cap::SHELL_ESCAPE)];
        });
        let (eliminated, _map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 0, "copy through a labeled node must be skipped");
        assert!(
            matches!(body.blocks[0].body[1].op, SsaOp::Assign(_)),
            "labeled copy must remain an Assign, not be Nop'd"
        );
    }

    /// Skip path 2: numeric-length reads (`arr.length`, `map.size`)
    /// have a different type from their source, propagating through
    /// would erase the Int type fact.
    #[test]
    fn copy_through_numeric_length_access_is_not_propagated() {
        let (cfg, mut body) = build_two_inst_body(|info| {
            info.is_numeric_length_access = true;
        });
        let (eliminated, _map) = copy_propagate(&mut body, &cfg);
        assert_eq!(
            eliminated, 0,
            "copy through numeric-length access must be skipped"
        );
    }

    /// Skip path 3: an Assign carrying a `string_prefix` (template
    /// literal or `"lit" + var` RHS) seeds a StringFact on its SSA
    /// value. Propagating past it erases the prefix-bearing value and
    /// breaks SSRF prefix-lock suppression downstream.
    #[test]
    fn copy_through_string_prefix_node_is_not_propagated() {
        let (cfg, mut body) = build_two_inst_body(|info| {
            info.string_prefix = Some("https://api.example.com/".into());
        });
        let (eliminated, _map) = copy_propagate(&mut body, &cfg);
        assert_eq!(
            eliminated, 0,
            "copy through string_prefix-bearing node must be skipped"
        );
    }

    /// Multi-operand Assigns (e.g. `v2 = v0 + v1`) are NOT copies and
    /// must be left alone. Only single-operand Assigns are copies.
    #[test]
    fn multi_operand_assign_is_not_a_copy() {
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
                        var_name: Some("x".into()),
                        span: (0, 1),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Const(Some("2".into())),
                        cfg_node: n1,
                        var_name: Some("y".into()),
                        span: (2, 3),
                    },
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Assign({
                            let mut v: SmallVec<[SsaValue; 4]> = SmallVec::new();
                            v.push(SsaValue(0));
                            v.push(SsaValue(1));
                            v
                        }),
                        cfg_node: n2,
                        var_name: Some("z".into()),
                        span: (4, 5),
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
                ValueDef {
                    var_name: Some("z".into()),
                    cfg_node: n2,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n2, SsaValue(2))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let (eliminated, _map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 0, "two-operand Assign is not a copy");
        assert!(
            matches!(body.blocks[0].body[2].op, SsaOp::Assign(_)),
            "multi-operand Assign must be preserved"
        );
    }

    /// A Call's argument and receiver slots that reference a
    /// copy-eliminated value must be rewritten to the root.
    #[test]
    fn call_args_and_receiver_rewritten_through_copy() {
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n2 = cfg.add_node(make_cfg_node(StmtKind::Call));
        let mut arg_vec: SmallVec<[SsaValue; 2]> = SmallVec::new();
        arg_vec.push(SsaValue(1));
        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("\"x\"".into())),
                        cfg_node: n0,
                        var_name: Some("a".into()),
                        span: (0, 1),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Assign(SmallVec::from_elem(SsaValue(0), 1)),
                        cfg_node: n1,
                        var_name: Some("b".into()),
                        span: (2, 3),
                    },
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Call {
                            callee: "f".into(),
                            callee_text: None,
                            args: vec![arg_vec],
                            receiver: Some(SsaValue(1)),
                        },
                        cfg_node: n2,
                        var_name: None,
                        span: (4, 7),
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
                    var_name: None,
                    cfg_node: n2,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n2, SsaValue(2))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let (eliminated, _) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 1, "v1 should be eliminated");
        let call_inst = &body.blocks[0].body[2];
        match &call_inst.op {
            SsaOp::Call { args, receiver, .. } => {
                assert_eq!(receiver, &Some(SsaValue(0)), "receiver rewritten to root");
                assert_eq!(args[0][0], SsaValue(0), "call arg rewritten to root");
            }
            other => panic!("expected Call op, got {:?}", other),
        }
    }

    /// Phi operand referencing a copy-eliminated value must be
    /// rewritten to the root.
    #[test]
    fn phi_operand_rewritten_through_copy() {
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n1 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let n2 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        // Block 0: v0=const, v1=assign(v0)
        // Block 1: v2 = phi(B0: v1)
        let mut phi_ops: smallvec::SmallVec<[(BlockId, SsaValue); 2]> = smallvec::SmallVec::new();
        phi_ops.push((BlockId(0), SsaValue(1)));
        let mut body = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![
                        SsaInst {
                            value: SsaValue(0),
                            op: SsaOp::Const(Some("\"v0\"".into())),
                            cfg_node: n0,
                            var_name: Some("a".into()),
                            span: (0, 1),
                        },
                        SsaInst {
                            value: SsaValue(1),
                            op: SsaOp::Assign(SmallVec::from_elem(SsaValue(0), 1)),
                            cfg_node: n1,
                            var_name: Some("b".into()),
                            span: (2, 3),
                        },
                    ],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: SmallVec::new(),
                    succs: {
                        let mut s = SmallVec::new();
                        s.push(BlockId(1));
                        s
                    },
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Phi(phi_ops),
                        cfg_node: n2,
                        var_name: Some("b".into()),
                        span: (4, 5),
                    }],
                    body: vec![],
                    terminator: Terminator::Return(Some(SsaValue(2))),
                    preds: {
                        let mut p = SmallVec::new();
                        p.push(BlockId(0));
                        p
                    },
                    succs: SmallVec::new(),
                },
            ],
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
                    var_name: Some("b".into()),
                    cfg_node: n2,
                    block: BlockId(1),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n2, SsaValue(2))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let (eliminated, _map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 1);
        // The phi in block 1 should now reference v0, not v1.
        let phi = &body.blocks[1].phis[0];
        match &phi.op {
            SsaOp::Phi(ops) => {
                assert_eq!(
                    ops[0].1,
                    SsaValue(0),
                    "phi operand should be rewritten to root v0"
                );
            }
            other => panic!("expected Phi op, got {:?}", other),
        }
    }

    /// `copy_propagate` on a body with no Assign instructions returns
    /// `(0, empty_map)` and leaves the body untouched.
    #[test]
    fn no_op_when_no_copies_exist() {
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![SsaInst {
                    value: SsaValue(0),
                    op: SsaOp::Const(Some("42".into())),
                    cfg_node: n0,
                    var_name: Some("x".into()),
                    span: (0, 2),
                }],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![ValueDef {
                var_name: Some("x".into()),
                cfg_node: n0,
                block: BlockId(0),
            }],
            cfg_node_map: [(n0, SsaValue(0))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };
        let (eliminated, map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 0);
        assert!(map.is_empty());
    }

    /// `return b` lowers to a copy of `b` that only the terminator reads.
    /// The copy becomes a Nop, so the terminator has to move to the root or
    /// the returned value has no definition (and no taint) any more.
    #[test]
    fn return_terminator_follows_the_copy_root() {
        let (cfg, mut body) = build_two_inst_body(|_| {});
        body.blocks[0].terminator = Terminator::Return(Some(SsaValue(1)));
        let (eliminated, _map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 1);
        assert!(matches!(body.blocks[0].body[1].op, SsaOp::Nop));
        assert!(matches!(
            body.blocks[0].terminator,
            Terminator::Return(Some(SsaValue(0)))
        ));
    }

    #[test]
    fn branch_condition_and_switch_scrutinee_follow_the_copy_root() {
        use crate::constraint::lower::{CompOp, ConditionExpr, Operand};
        use petgraph::graph::NodeIndex;
        let (cfg, mut body) = build_two_inst_body(|_| {});
        body.blocks[0].terminator = Terminator::Branch {
            cond: NodeIndex::new(1),
            true_blk: BlockId(0),
            false_blk: BlockId(0),
            condition: Some(Box::new(ConditionExpr::Comparison {
                lhs: Operand::Value(SsaValue(1)),
                op: CompOp::Eq,
                rhs: Operand::Unknown,
            })),
        };
        copy_propagate(&mut body, &cfg);
        match &body.blocks[0].terminator {
            Terminator::Branch {
                condition: Some(c), ..
            } => match &**c {
                ConditionExpr::Comparison { lhs, .. } => {
                    assert!(matches!(lhs, Operand::Value(SsaValue(0))))
                }
                other => panic!("unexpected condition {other:?}"),
            },
            other => panic!("unexpected terminator {other:?}"),
        }

        let (cfg, mut body) = build_two_inst_body(|_| {});
        body.blocks[0].terminator = Terminator::Switch {
            scrutinee: SsaValue(1),
            targets: SmallVec::new(),
            default: BlockId(0),
            case_values: SmallVec::new(),
        };
        copy_propagate(&mut body, &cfg);
        assert!(matches!(
            body.blocks[0].terminator,
            Terminator::Switch {
                scrutinee: SsaValue(0),
                ..
            }
        ));
    }

    /// A copy that is kept (labelled node) must leave its terminator alone.
    #[test]
    fn return_terminator_of_a_kept_copy_is_unchanged() {
        use crate::labels::{Cap, DataLabel};
        use smallvec::smallvec;
        let (cfg, mut body) = build_two_inst_body(|info| {
            info.taint.labels = smallvec![DataLabel::Sanitizer(Cap::SHELL_ESCAPE)];
        });
        body.blocks[0].terminator = Terminator::Return(Some(SsaValue(1)));
        copy_propagate(&mut body, &cfg);
        assert!(matches!(
            body.blocks[0].terminator,
            Terminator::Return(Some(SsaValue(1)))
        ));
    }

    /// `_, ok := allowed[cmd]` shares its operand with the key but is not a
    /// copy of it, so it stays an assignment and the branch on `ok` keeps
    /// naming the lookup.
    #[test]
    fn membership_lookup_is_not_a_copy() {
        let mut cfg: Cfg = Graph::new();
        let n0 = cfg.add_node(make_cfg_node(StmtKind::Seq));
        let mut lookup = make_cfg_node(StmtKind::Seq);
        lookup.membership_lookup = Some(crate::cfg::MembershipLookup {
            result_var: "ok".into(),
            base: "allowed".into(),
            key: "cmd".into(),
            value_var: None,
            filled_elsewhere: false,
        });
        let n1 = cfg.add_node(lookup);

        let mut body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("x".into())),
                        cfg_node: n0,
                        var_name: Some("cmd".into()),
                        span: (0, 2),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Assign(SmallVec::from_elem(SsaValue(0), 1)),
                        cfg_node: n1,
                        var_name: Some("ok".into()),
                        span: (3, 5),
                    },
                ],
                terminator: Terminator::Return(Some(SsaValue(1))),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("cmd".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("ok".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: Default::default(),
            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let (eliminated, copy_map) = copy_propagate(&mut body, &cfg);
        assert_eq!(eliminated, 0);
        assert!(copy_map.is_empty());
        assert!(matches!(body.blocks[0].body[1].op, SsaOp::Assign(_)));
    }
}
