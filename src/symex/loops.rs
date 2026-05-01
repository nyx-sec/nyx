//! Loop analysis for the symbolic executor.
//!
//! Detects back edges, computes natural loop bodies, identifies induction
//! variables, and determines loop exit successors. All analysis is computed
//! once per `explore_finding()` invocation and shared across all paths.
#![allow(clippy::collapsible_if)]

use std::collections::{HashMap, HashSet};

use petgraph::Graph;
use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::graph::NodeIndex;

use crate::ssa::ir::{BlockId, SsaBody, SsaOp, SsaValue, Terminator};

/// Default loop unrolling bound. After this many visits to a loop head,
/// the executor widens and skips to the exit.
pub const MAX_LOOP_UNROLL: u8 = 2;

/// Pre-computed loop information for symex exploration.
///
/// Computed once per `explore_finding()` invocation, shared across all paths.
pub struct LoopInfo {
    /// Back edges: (latch block, loop head block).
    pub back_edges: HashSet<(BlockId, BlockId)>,
    /// Blocks that are loop-head targets of back edges.
    pub loop_heads: HashSet<BlockId>,
    /// Natural loop body per loop head: head → set of blocks in the loop.
    pub loop_bodies: HashMap<BlockId, HashSet<BlockId>>,
    /// SSA values that are simple induction variables (loop counters).
    pub induction_vars: HashSet<SsaValue>,
    /// Dominator tree (retained for exit successor queries).
    #[allow(dead_code)]
    doms: Dominators<NodeIndex>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Analyse loop structure in an SSA body.
///
/// Builds a petgraph from the SSA blocks, computes dominators, detects back
/// edges, natural loop bodies, and induction variables. All results are
/// bundled into a [`LoopInfo`] for use by the executor.
pub fn analyse_loops(ssa: &SsaBody) -> LoopInfo {
    let num_blocks = ssa.blocks.len();

    // Build petgraph from SSA block successors
    let (block_graph, block_nodes, entry_node) = build_block_graph(ssa);

    // Compute dominator tree
    let doms = simple_fast(&block_graph, entry_node);

    // Detect back edges: (src, tgt) where tgt dominates src
    let back_edges = detect_back_edges(ssa, &block_nodes, &doms, num_blocks);

    // Extract loop heads
    let loop_heads: HashSet<BlockId> = back_edges.iter().map(|(_, head)| *head).collect();

    // Compute natural loop bodies
    let loop_bodies = compute_all_loop_bodies(ssa, &back_edges);

    // Detect induction variables
    let induction_vars = detect_induction_vars(ssa, &back_edges, &loop_heads);

    LoopInfo {
        back_edges,
        loop_heads,
        loop_bodies,
        induction_vars,
        doms,
    }
}

impl LoopInfo {
    /// Determine the loop exit successor for a branch at a loop head.
    ///
    /// Uses natural loop body membership: the exit successor is the one
    /// whose target is NOT in the loop body. Returns `None` if both
    /// successors are inside the loop (nested loop) or the block has no
    /// branch terminator.
    pub fn loop_exit_successor(&self, ssa: &SsaBody, head: BlockId) -> Option<BlockId> {
        let body = self.loop_bodies.get(&head)?;
        let block = ssa.blocks.get(head.0 as usize)?;
        match &block.terminator {
            Terminator::Branch {
                true_blk,
                false_blk,
                ..
            } => {
                let true_in = body.contains(true_blk);
                let false_in = body.contains(false_blk);
                match (true_in, false_in) {
                    (true, false) => Some(*false_blk),
                    (false, true) => Some(*true_blk),
                    (false, false) => Some(*true_blk), // both exit, deterministic pick
                    (true, true) => None,              // nested: no clear exit
                }
            }
            _ => None, // Goto or Return, no branching exit
        }
    }

    /// Check if this LoopInfo has any loops at all (useful for fast skip).
    pub fn has_loops(&self) -> bool {
        !self.loop_heads.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a petgraph from SSA block successors.
///
/// Mirrors the pattern in `src/ssa/lower.rs:build_block_graph`.
fn build_block_graph(ssa: &SsaBody) -> (Graph<BlockId, ()>, Vec<NodeIndex>, NodeIndex) {
    let num_blocks = ssa.blocks.len();
    let mut g: Graph<BlockId, ()> = Graph::with_capacity(num_blocks, num_blocks * 2);
    let mut block_nodes: Vec<NodeIndex> = Vec::with_capacity(num_blocks);

    for i in 0..num_blocks {
        block_nodes.push(g.add_node(BlockId(i as u32)));
    }

    for block in &ssa.blocks {
        let src = block_nodes[block.id.0 as usize];
        for &succ in &block.succs {
            if (succ.0 as usize) < num_blocks {
                g.add_edge(src, block_nodes[succ.0 as usize], ());
            }
        }
    }

    let entry_node = block_nodes[ssa.entry.0 as usize];
    (g, block_nodes, entry_node)
}

/// Check if `dominator` dominates `target` in the dominator tree.
///
/// Mirrors the pattern in `src/cfg_analysis/dominators.rs:dominates`.
fn dominates_block(doms: &Dominators<NodeIndex>, dominator: NodeIndex, target: NodeIndex) -> bool {
    if dominator == target {
        return true;
    }
    let mut current = target;
    while let Some(idom) = doms.immediate_dominator(current) {
        if idom == current {
            break; // reached root
        }
        if idom == dominator {
            return true;
        }
        current = idom;
    }
    false
}

/// Detect back edges using dominator analysis.
///
/// An edge (src, tgt) is a back edge if tgt dominates src in the
/// dominator tree. This is sound for all CFG shapes, unlike the
/// block-index heuristic used by the taint engine.
fn detect_back_edges(
    ssa: &SsaBody,
    block_nodes: &[NodeIndex],
    doms: &Dominators<NodeIndex>,
    num_blocks: usize,
) -> HashSet<(BlockId, BlockId)> {
    let mut back_edges = HashSet::new();
    for block in &ssa.blocks {
        let src_idx = block.id.0 as usize;
        if src_idx >= num_blocks {
            continue;
        }
        let src_node = block_nodes[src_idx];
        for &succ in &block.succs {
            let tgt_idx = succ.0 as usize;
            if tgt_idx >= num_blocks {
                continue;
            }
            let tgt_node = block_nodes[tgt_idx];
            if dominates_block(doms, tgt_node, src_node) {
                back_edges.insert((block.id, succ));
            }
        }
    }
    back_edges
}

/// Compute the natural loop body for a single back edge (latch → head).
///
/// The natural loop is {head} ∪ {blocks that can reach latch without
/// going through head}. Uses reverse BFS from the latch, stopping at head.
fn compute_natural_loop_body(ssa: &SsaBody, head: BlockId, latch: BlockId) -> HashSet<BlockId> {
    let mut body = HashSet::new();
    body.insert(head);
    if head == latch {
        return body; // single-block loop
    }
    body.insert(latch);
    let mut worklist = vec![latch];
    while let Some(bid) = worklist.pop() {
        if let Some(block) = ssa.blocks.get(bid.0 as usize) {
            for &pred in &block.preds {
                if pred != head && body.insert(pred) {
                    worklist.push(pred);
                }
            }
        }
    }
    body
}

/// Compute natural loop bodies for all loop heads.
///
/// When multiple back edges target the same head, their bodies are unioned.
fn compute_all_loop_bodies(
    ssa: &SsaBody,
    back_edges: &HashSet<(BlockId, BlockId)>,
) -> HashMap<BlockId, HashSet<BlockId>> {
    let mut bodies: HashMap<BlockId, HashSet<BlockId>> = HashMap::new();
    for &(latch, head) in back_edges {
        let body = compute_natural_loop_body(ssa, head, latch);
        bodies
            .entry(head)
            .and_modify(|existing| {
                existing.extend(body.iter());
            })
            .or_insert(body);
    }
    bodies
}

/// Detect induction variables: phi nodes at loop heads where the back-edge
/// operand is a simple increment/decrement of the phi result.
///
/// Mirrors `detect_induction_phis()` in `src/taint/ssa_transfer.rs`.
fn detect_induction_vars(
    ssa: &SsaBody,
    back_edges: &HashSet<(BlockId, BlockId)>,
    loop_heads: &HashSet<BlockId>,
) -> HashSet<SsaValue> {
    let mut induction_vars = HashSet::new();

    for block in &ssa.blocks {
        if !loop_heads.contains(&block.id) {
            continue;
        }
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

/// Check if `inc_val` is defined as a simple increment of `phi_val`:
/// `inc_val = phi_val + const` or `inc_val = phi_val - const`.
///
/// Mirrors `is_simple_increment()` in `src/taint/ssa_transfer.rs`.
fn is_simple_increment(ssa: &SsaBody, inc_val: SsaValue, phi_val: SsaValue) -> bool {
    let def = ssa.def_of(inc_val);
    let block = ssa.block(def.block);
    for inst in &block.body {
        if inst.value == inc_val {
            if let SsaOp::Assign(ref uses) = inst.op {
                if uses.len() == 2 && uses.contains(&phi_val) {
                    let other = if uses[0] == phi_val { uses[1] } else { uses[0] };
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

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::ir::{SsaBlock, SsaInst, ValueDef};
    use petgraph::graph::NodeIndex as CfgNodeIndex;
    use smallvec::smallvec;

    fn dummy_cfg_node() -> CfgNodeIndex {
        CfgNodeIndex::new(0)
    }

    fn make_value_def(block: BlockId) -> ValueDef {
        ValueDef {
            var_name: None,
            cfg_node: dummy_cfg_node(),
            block,
        }
    }

    fn make_inst(val: u32, op: SsaOp, _block: BlockId) -> SsaInst {
        SsaInst {
            value: SsaValue(val),
            op,
            cfg_node: dummy_cfg_node(),
            var_name: None,
            span: (0, 0),
        }
    }

    // ─── Back-edge detection ─────────────────────────────────────────────

    #[test]
    fn simple_loop_back_edge() {
        // B0 → B1 → B2 → B1 (back edge B2→B1)
        //              → B3 (exit)
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(2),
                        false_blk: BlockId(3),
                        condition: None,
                    },
                    preds: smallvec![BlockId(0), BlockId(2)],
                    succs: smallvec![BlockId(2), BlockId(3)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(3),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        assert_eq!(info.back_edges.len(), 1);
        assert!(info.back_edges.contains(&(BlockId(2), BlockId(1))));
        assert_eq!(info.loop_heads.len(), 1);
        assert!(info.loop_heads.contains(&BlockId(1)));
    }

    #[test]
    fn no_loop_linear() {
        // B0 → B1 → B2
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(2)),
                    preds: smallvec![BlockId(0)],
                    succs: smallvec![BlockId(2)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        assert!(info.back_edges.is_empty());
        assert!(info.loop_heads.is_empty());
        assert!(info.loop_bodies.is_empty());
        assert!(!info.has_loops());
    }

    #[test]
    fn nested_loops() {
        // B0 → B1 (outer head) → B2 (inner head) → B3 → B2 (inner back)
        //                                              → B4 → B1 (outer back)
        //       B1 → B5 (outer exit)
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(2),
                        false_blk: BlockId(5),
                        condition: None,
                    },
                    preds: smallvec![BlockId(0), BlockId(4)],
                    succs: smallvec![BlockId(2), BlockId(5)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(3),
                        false_blk: BlockId(4),
                        condition: None,
                    },
                    preds: smallvec![BlockId(1), BlockId(3)],
                    succs: smallvec![BlockId(3), BlockId(4)],
                },
                SsaBlock {
                    id: BlockId(3),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(2)),
                    preds: smallvec![BlockId(2)],
                    succs: smallvec![BlockId(2)],
                },
                SsaBlock {
                    id: BlockId(4),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(2)],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(5),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        assert_eq!(info.back_edges.len(), 2);
        assert!(info.back_edges.contains(&(BlockId(3), BlockId(2)))); // inner
        assert!(info.back_edges.contains(&(BlockId(4), BlockId(1)))); // outer
        assert_eq!(info.loop_heads.len(), 2);
        assert!(info.loop_heads.contains(&BlockId(1)));
        assert!(info.loop_heads.contains(&BlockId(2)));
    }

    // ─── Natural loop body ───────────────────────────────────────────────

    #[test]
    fn natural_body_simple_loop() {
        // B0 → B1 → B2 → B1, B1 → B3
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(2),
                        false_blk: BlockId(3),
                        condition: None,
                    },
                    preds: smallvec![BlockId(0), BlockId(2)],
                    succs: smallvec![BlockId(2), BlockId(3)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(3),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        let body = info.loop_bodies.get(&BlockId(1)).unwrap();
        assert!(body.contains(&BlockId(1))); // head
        assert!(body.contains(&BlockId(2))); // body
        assert!(!body.contains(&BlockId(0))); // pre-loop
        assert!(!body.contains(&BlockId(3))); // post-loop
    }

    #[test]
    fn natural_body_nested_excludes_outer() {
        // Reuse the nested_loops SSA
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(2),
                        false_blk: BlockId(5),
                        condition: None,
                    },
                    preds: smallvec![BlockId(0), BlockId(4)],
                    succs: smallvec![BlockId(2), BlockId(5)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(3),
                        false_blk: BlockId(4),
                        condition: None,
                    },
                    preds: smallvec![BlockId(1), BlockId(3)],
                    succs: smallvec![BlockId(3), BlockId(4)],
                },
                SsaBlock {
                    id: BlockId(3),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(2)),
                    preds: smallvec![BlockId(2)],
                    succs: smallvec![BlockId(2)],
                },
                SsaBlock {
                    id: BlockId(4),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(2)],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(5),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);

        // Inner loop body: {B2, B3}
        let inner = info.loop_bodies.get(&BlockId(2)).unwrap();
        assert!(inner.contains(&BlockId(2)));
        assert!(inner.contains(&BlockId(3)));
        assert!(!inner.contains(&BlockId(1))); // outer head not in inner
        assert!(!inner.contains(&BlockId(4))); // exit of inner not in inner

        // Outer loop body: {B1, B2, B3, B4}
        let outer = info.loop_bodies.get(&BlockId(1)).unwrap();
        assert!(outer.contains(&BlockId(1)));
        assert!(outer.contains(&BlockId(2)));
        assert!(outer.contains(&BlockId(3)));
        assert!(outer.contains(&BlockId(4)));
        assert!(!outer.contains(&BlockId(5))); // post-loop not in outer
    }

    // ─── Exit successor ──────────────────────────────────────────────────

    #[test]
    fn exit_successor_simple() {
        // B1 (loop head): true→B2 (body), false→B3 (exit)
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(2),
                        false_blk: BlockId(3),
                        condition: None,
                    },
                    preds: smallvec![BlockId(0), BlockId(2)],
                    succs: smallvec![BlockId(2), BlockId(3)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(3),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        assert_eq!(info.loop_exit_successor(&ssa, BlockId(1)), Some(BlockId(3)));
    }

    #[test]
    fn exit_successor_goto_returns_none() {
        // Single-block loop: B0 → B1 → B1 (Goto back to self)
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(0), BlockId(1)],
                    succs: smallvec![BlockId(1)],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        assert_eq!(info.loop_exit_successor(&ssa, BlockId(1)), None);
    }

    #[test]
    fn exit_successor_both_in_body_returns_none() {
        // Nested: outer head B1 branches to B2 (inner head, in outer body) and B3 (also in outer body)
        // B3 → B1 (outer back edge)
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(2),
                        false_blk: BlockId(3),
                        condition: None,
                    },
                    preds: smallvec![BlockId(0), BlockId(3)],
                    succs: smallvec![BlockId(2), BlockId(3)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(3)),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![BlockId(3)],
                },
                SsaBlock {
                    id: BlockId(3),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(1), BlockId(2)],
                    succs: smallvec![BlockId(1)],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        // Both B2 and B3 are in the loop body for head B1
        assert_eq!(info.loop_exit_successor(&ssa, BlockId(1)), None);
    }

    // ─── Induction variables ─────────────────────────────────────────────

    #[test]
    fn induction_var_simple_counter() {
        // B0: v0 = Const("0"), v2 = Const("1")
        // B1: v1 = Phi((B0, v0), (B2, v3))  ← induction var
        // B2: v3 = Assign([v1, v2])          ← v1 + const
        // B2 → B1 (back edge)
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![
                        make_inst(0, SsaOp::Const(Some("0".into())), BlockId(0)),
                        make_inst(2, SsaOp::Const(Some("1".into())), BlockId(0)),
                    ],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![make_inst(
                        1,
                        SsaOp::Phi(smallvec![
                            (BlockId(0), SsaValue(0)),
                            (BlockId(2), SsaValue(3))
                        ]),
                        BlockId(1),
                    )],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(2),
                        false_blk: BlockId(3),
                        condition: None,
                    },
                    preds: smallvec![BlockId(0), BlockId(2)],
                    succs: smallvec![BlockId(2), BlockId(3)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![make_inst(
                        3,
                        SsaOp::Assign(smallvec![SsaValue(1), SsaValue(2)]),
                        BlockId(2),
                    )],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(3),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![
                make_value_def(BlockId(0)), // v0
                make_value_def(BlockId(1)), // v1
                make_value_def(BlockId(0)), // v2
                make_value_def(BlockId(2)), // v3
            ],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        assert!(info.induction_vars.contains(&SsaValue(1)));
    }

    #[test]
    fn non_induction_phi_not_detected() {
        // B0: v0 = Source
        // B1: v1 = Phi((B0, v0), (B2, v2))
        // B2: v2 = Call("f", [v1])  ← NOT a simple increment
        // B2 → B1
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![make_inst(0, SsaOp::Source, BlockId(0))],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![make_inst(
                        1,
                        SsaOp::Phi(smallvec![
                            (BlockId(0), SsaValue(0)),
                            (BlockId(2), SsaValue(2))
                        ]),
                        BlockId(1),
                    )],
                    body: vec![],
                    terminator: Terminator::Branch {
                        cond: dummy_cfg_node(),
                        true_blk: BlockId(2),
                        false_blk: BlockId(3),
                        condition: None,
                    },
                    preds: smallvec![BlockId(0), BlockId(2)],
                    succs: smallvec![BlockId(2), BlockId(3)],
                },
                SsaBlock {
                    id: BlockId(2),
                    phis: vec![],
                    body: vec![make_inst(
                        2,
                        SsaOp::Call {
                            callee: "f".into(),
                            callee_text: None,
                            args: vec![smallvec![SsaValue(1)]],
                            receiver: None,
                        },
                        BlockId(2),
                    )],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(3),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Return(None),
                    preds: smallvec![BlockId(1)],
                    succs: smallvec![],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![
                make_value_def(BlockId(0)), // v0
                make_value_def(BlockId(1)), // v1
                make_value_def(BlockId(2)), // v2
            ],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        assert!(info.induction_vars.is_empty());
    }

    // ─── has_loops ───────────────────────────────────────────────────────

    #[test]
    fn has_loops_with_loop() {
        let ssa = SsaBody {
            blocks: vec![
                SsaBlock {
                    id: BlockId(0),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(1)),
                    preds: smallvec![],
                    succs: smallvec![BlockId(1)],
                },
                SsaBlock {
                    id: BlockId(1),
                    phis: vec![],
                    body: vec![],
                    terminator: Terminator::Goto(BlockId(0)),
                    preds: smallvec![BlockId(0)],
                    succs: smallvec![BlockId(0)],
                },
            ],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let info = analyse_loops(&ssa);
        assert!(info.has_loops());
    }
}
