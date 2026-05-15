//! petgraph-backed read-only view over a [`SurfaceMap`].
//!
//! The on-disk shape is two parallel `Vec`s (deterministic ordering,
//! byte-identical JSON), but downstream consumers — the Track G chain
//! composer, the `nyx surface` CLI walker — want graph queries:
//! neighbours, reachability, topological order.  [`petgraph_view`]
//! constructs a `DiGraph<NodeRef<'_>, EdgeRef<'_>>` on demand without
//! cloning the underlying nodes or edges.

use super::{EdgeKind, SurfaceEdge, SurfaceMap, SurfaceNode};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

/// Borrowed handle to one [`SurfaceNode`] inside the petgraph view.
#[derive(Debug, Clone, Copy)]
pub struct NodeRef<'a> {
    pub idx: u32,
    pub node: &'a SurfaceNode,
}

/// Borrowed handle to one [`SurfaceEdge`] inside the petgraph view.
#[derive(Debug, Clone, Copy)]
pub struct EdgeRef<'a> {
    pub edge: &'a SurfaceEdge,
}

impl<'a> EdgeRef<'a> {
    pub fn kind(&self) -> EdgeKind {
        self.edge.kind
    }
}

/// Materialise a petgraph view of `map`.  Node indices in the returned
/// graph match `map.nodes` ordering 1:1, and the `lookup` map lets
/// callers translate from the surface index (`u32`) to the petgraph
/// [`NodeIndex`].  Walking edges respects `map.edges` order.
pub fn petgraph_view(map: &SurfaceMap) -> SurfaceGraphView<'_> {
    let mut graph: DiGraph<NodeRef<'_>, EdgeRef<'_>> = DiGraph::new();
    let mut lookup: HashMap<u32, NodeIndex> = HashMap::with_capacity(map.nodes.len());
    for (i, node) in map.nodes.iter().enumerate() {
        let nx = graph.add_node(NodeRef {
            idx: i as u32,
            node,
        });
        lookup.insert(i as u32, nx);
    }
    for edge in &map.edges {
        if let (Some(&from), Some(&to)) = (lookup.get(&edge.from), lookup.get(&edge.to)) {
            graph.add_edge(from, to, EdgeRef { edge });
        }
    }
    SurfaceGraphView { graph, lookup }
}

/// petgraph view returned by [`petgraph_view`].
pub struct SurfaceGraphView<'a> {
    pub graph: DiGraph<NodeRef<'a>, EdgeRef<'a>>,
    pub lookup: HashMap<u32, NodeIndex>,
}

impl<'a> SurfaceGraphView<'a> {
    /// Resolve a surface index back to its petgraph [`NodeIndex`].
    pub fn node_index(&self, surface_idx: u32) -> Option<NodeIndex> {
        self.lookup.get(&surface_idx).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry_points::HttpMethod;
    use crate::surface::{EntryPoint, Framework, SourceLocation};

    #[test]
    fn petgraph_view_preserves_indices() {
        let mut m = SurfaceMap::new();
        m.nodes.push(SurfaceNode::EntryPoint(EntryPoint {
            location: SourceLocation::new("a.py", 1, 1),
            framework: Framework::Flask,
            method: HttpMethod::GET,
            route: "/a".into(),
            handler_name: "h".into(),
            handler_location: SourceLocation::new("a.py", 2, 1),
            auth_required: false,
        }));
        m.nodes.push(SurfaceNode::EntryPoint(EntryPoint {
            location: SourceLocation::new("b.py", 1, 1),
            framework: Framework::Flask,
            method: HttpMethod::POST,
            route: "/b".into(),
            handler_name: "h".into(),
            handler_location: SourceLocation::new("b.py", 2, 1),
            auth_required: false,
        }));
        m.edges.push(SurfaceEdge {
            from: 0,
            to: 1,
            kind: EdgeKind::Calls,
        });
        let view = petgraph_view(&m);
        assert_eq!(view.graph.node_count(), 2);
        assert_eq!(view.graph.edge_count(), 1);
        let n0 = view.node_index(0).unwrap();
        let n1 = view.node_index(1).unwrap();
        assert!(view.graph.find_edge(n0, n1).is_some());
    }
}
