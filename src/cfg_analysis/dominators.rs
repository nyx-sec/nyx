use crate::cfg::{Cfg, EdgeKind, NodeInfo, StmtKind};
use crate::labels::DataLabel;
use petgraph::algo::dominators::{Dominators, simple_fast};
use petgraph::graph::NodeIndex;
use petgraph::prelude::*;
use petgraph::visit::Bfs;
use std::collections::HashSet;

/// Compute forward dominators from entry.
pub fn compute_dominators(cfg: &Cfg, entry: NodeIndex) -> Dominators<NodeIndex> {
    simple_fast(cfg, entry)
}

/// Compute post-dominators by reversing all edges and computing dominators from exit.
/// Returns None if no Exit node exists.
pub fn compute_post_dominators(cfg: &Cfg) -> Option<Dominators<NodeIndex>> {
    let exit = find_exit_node(cfg)?;
    let reversed = build_reversed_graph(cfg);
    Some(simple_fast(&reversed, exit))
}

/// Reachable node set via BFS from entry.
pub fn reachable_set(cfg: &Cfg, entry: NodeIndex) -> HashSet<NodeIndex> {
    let mut set = HashSet::new();
    let mut bfs = Bfs::new(cfg, entry);
    while let Some(nx) = bfs.next(cfg) {
        set.insert(nx);
    }
    set
}

/// Find the Exit node (StmtKind::Exit).
pub fn find_exit_node(cfg: &Cfg) -> Option<NodeIndex> {
    cfg.node_indices()
        .find(|&idx| cfg[idx].kind == StmtKind::Exit)
}

/// Find all nodes that are sinks (have DataLabel::Sink).
pub fn find_sink_nodes(cfg: &Cfg) -> Vec<NodeIndex> {
    cfg.node_indices()
        .filter(|&idx| {
            cfg[idx]
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(_)))
        })
        .collect()
}

/// Check if `dominator` dominates `target` in the given dominator tree.
pub fn dominates(doms: &Dominators<NodeIndex>, dominator: NodeIndex, target: NodeIndex) -> bool {
    if dominator == target {
        return true;
    }
    // Walk up the dominator tree from target
    let mut current = target;
    while let Some(idom) = doms.immediate_dominator(current) {
        if idom == current {
            // Reached root
            break;
        }
        if idom == dominator {
            return true;
        }
        current = idom;
    }
    false
}

/// Build a reversed copy of the graph (swap edge directions).
fn build_reversed_graph(cfg: &Cfg) -> Graph<NodeInfo, EdgeKind> {
    let mut rev = Graph::<NodeInfo, EdgeKind>::with_capacity(cfg.node_count(), cfg.edge_count());

    // Clone nodes (preserving indices)
    let mut index_map = Vec::with_capacity(cfg.node_count());
    for idx in cfg.node_indices() {
        let new_idx = rev.add_node(cfg[idx].clone());
        index_map.push((idx, new_idx));
    }

    // Add edges in reverse direction
    for edge in cfg.edge_references() {
        let src = edge.source();
        let tgt = edge.target();
        // Find the new indices
        let new_src = index_map
            .iter()
            .find(|(old, _)| *old == tgt)
            .map(|(_, new)| *new)
            .unwrap();
        let new_tgt = index_map
            .iter()
            .find(|(old, _)| *old == src)
            .map(|(_, new)| *new)
            .unwrap();
        rev.add_edge(new_src, new_tgt, *edge.weight());
    }

    rev
}

/// Compute shortest distance (in hops) from `from` to `to`.
pub fn shortest_distance(cfg: &Cfg, from: NodeIndex, to: NodeIndex) -> Option<usize> {
    use std::collections::VecDeque;

    if from == to {
        return Some(0);
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((from, 0usize));
    visited.insert(from);

    while let Some((node, dist)) = queue.pop_front() {
        for succ in cfg.neighbors(node) {
            if succ == to {
                return Some(dist + 1);
            }
            if visited.insert(succ) {
                queue.push_back((succ, dist + 1));
            }
        }
    }

    None
}
