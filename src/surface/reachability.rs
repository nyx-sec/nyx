//! Transitive-closure pass: connect [`SurfaceNode::EntryPoint`] nodes
//! to the [`SurfaceNode::DataStore`] / [`SurfaceNode::ExternalService`]
//! / [`SurfaceNode::DangerousLocal`] nodes they can reach via the
//! whole-program [`CallGraph`].
//!
//! For each entry-point we first locate the matching call-graph
//! [`FuncKey`] by `(namespace, function_name)` (the entry-point's
//! `handler_location.file` is the project-relative POSIX path used as
//! `FuncKey::namespace`, and `handler_name` is the leaf function
//! name).  From that node we run a BFS over forward call-graph edges
//! up to a small depth bound, and for every visited
//! `(file, function_name)` we look for a matching DataStore /
//! ExternalService / DangerousLocal node in the SurfaceMap, emitting
//! one [`EdgeKind::Reaches`] edge per match.
//!
//! Node match policy: the destination's `location.file` must equal
//! the visited call-graph node's namespace.  This is best-effort but
//! deterministic — an entry-point that calls into a helper which then
//! calls `eval()` will surface the eval as a `Reaches` of the entry
//! point as long as the eval's host file is on the BFS frontier.

use super::{EdgeKind, SurfaceEdge, SurfaceMap, SurfaceNode};
use crate::callgraph::CallGraph;
use crate::summary::GlobalSummaries;
use petgraph::Direction;
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum BFS depth from an entry-point node.  Surface chains beyond
/// six call-graph hops are rare in practice and the cost of a deeper
/// walk is paid per entry-point per scan.  A depth-bounded traversal
/// also prevents recursive cycles from blowing up.
const MAX_BFS_DEPTH: usize = 8;

/// Populate [`EdgeKind::Reaches`] edges on `map`.  Mutates the edge
/// list in place; the caller is expected to follow up with
/// [`SurfaceMap::canonicalize`] before serialisation.
pub fn populate_reaches_edges(
    map: &mut SurfaceMap,
    summaries: &GlobalSummaries,
    call_graph: &CallGraph,
) {
    if map.nodes.is_empty() {
        return;
    }
    let dst_index = build_destination_index(map);
    if dst_index.is_empty() {
        return;
    }
    let _ = summaries;

    let mut new_edges: HashSet<SurfaceEdge> = HashSet::new();
    for (entry_idx, node) in map.nodes.iter().enumerate() {
        let SurfaceNode::EntryPoint(ep) = node else {
            continue;
        };
        let mut reachable_files: HashSet<String> = HashSet::new();
        // Seed with the handler's host file — the entry-point itself
        // counts as reachable, so any DataStore / ExternalService /
        // DangerousLocal in the same file is connected even when the
        // call graph cannot resolve the seed FuncKey.
        reachable_files.insert(ep.handler_location.file.clone());

        // Locate seed FuncKeys whose `namespace` (project-relative
        // POSIX path, optionally prefixed with `@pkg/name::`) matches
        // the entry's file and whose `name` matches the handler.  More
        // than one seed is possible (overloaded methods, duplicate
        // definitions).
        //
        // Phase 23 follow-up: this used to be an `ends_with` substring
        // check on both sides, which silently aliased same-basename
        // files in sibling directories — `subdir/app.py` and
        // `other/app.py` would both seed when the entry-point pointed
        // at `app.py`.  We now compare the file part exactly so a
        // handler in `subdir/app.py` only seeds the FuncKey whose
        // namespace strips to `subdir/app.py`.
        let seeds = call_graph
            .index
            .iter()
            .filter(|(k, _)| k.name == ep.handler_name)
            .filter(|(k, _)| {
                file_part_of_namespace(&k.namespace) == ep.handler_location.file
            })
            .map(|(_, idx)| *idx)
            .collect::<Vec<_>>();

        let mut visited: HashSet<_> = seeds.iter().copied().collect();
        let mut queue: VecDeque<(petgraph::graph::NodeIndex, usize)> =
            seeds.iter().map(|n| (*n, 0)).collect();
        while let Some((node_idx, depth)) = queue.pop_front() {
            if let Some(key) = call_graph.graph.node_weight(node_idx) {
                reachable_files.insert(key.namespace.clone());
            }
            if depth >= MAX_BFS_DEPTH {
                continue;
            }
            for neighbour in call_graph
                .graph
                .neighbors_directed(node_idx, Direction::Outgoing)
            {
                if visited.insert(neighbour) {
                    queue.push_back((neighbour, depth + 1));
                }
            }
        }

        for (dst_idx, dst_file) in &dst_index {
            if reachable_files.contains(dst_file) {
                new_edges.insert(SurfaceEdge {
                    from: entry_idx as u32,
                    to: *dst_idx as u32,
                    kind: EdgeKind::Reaches,
                });
            }
        }
    }

    map.edges.extend(new_edges);
}

/// Strip the optional `@pkg/name::` package prefix from a `FuncKey`
/// namespace, returning the project-relative POSIX file path part.
/// `namespace_with_package` produces `"@scope/name::src/file.ts"` for
/// JS/TS files inside resolved packages; the file part is what
/// matches an entry-point's `handler_location.file`.
fn file_part_of_namespace(ns: &str) -> &str {
    ns.rsplit_once("::").map(|(_, rest)| rest).unwrap_or(ns)
}

/// Build a lookup from destination node index → destination file.
/// Restricted to the three reachable-from-entry-point variants.
fn build_destination_index(map: &SurfaceMap) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    for (idx, node) in map.nodes.iter().enumerate() {
        let file = match node {
            SurfaceNode::DataStore(n) => n.location.file.clone(),
            SurfaceNode::ExternalService(n) => n.location.file.clone(),
            SurfaceNode::DangerousLocal(n) => n.location.file.clone(),
            SurfaceNode::EntryPoint(_) => continue,
        };
        out.push((idx, file));
    }
    out
}

/// Cheap by-file inverted index of the destination nodes — exposed for
/// future callers (chain composer, CLI tree printer) that want a
/// constant-time "what does this file expose" lookup without rerunning
/// reachability.
#[allow(dead_code)]
pub fn destinations_by_file(map: &SurfaceMap) -> HashMap<String, Vec<usize>> {
    let mut out: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, node) in map.nodes.iter().enumerate() {
        let file = match node {
            SurfaceNode::DataStore(n) => &n.location.file,
            SurfaceNode::ExternalService(n) => &n.location.file,
            SurfaceNode::DangerousLocal(n) => &n.location.file,
            SurfaceNode::EntryPoint(_) => continue,
        };
        out.entry(file.clone()).or_default().push(idx);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry_points::HttpMethod;
    use crate::surface::{
        DangerousLocal, EntryPoint, Framework, SourceLocation, SurfaceMap, SurfaceNode,
    };

    fn ep(file: &str, handler: &str) -> SurfaceNode {
        SurfaceNode::EntryPoint(EntryPoint {
            location: SourceLocation::new(file, 1, 1),
            framework: Framework::Flask,
            method: HttpMethod::GET,
            route: "/".into(),
            handler_name: handler.into(),
            handler_location: SourceLocation::new(file, 2, 1),
            auth_required: false,
        })
    }

    fn dl(file: &str, name: &str) -> SurfaceNode {
        SurfaceNode::DangerousLocal(DangerousLocal {
            location: SourceLocation::new(file, 0, 0),
            function_name: name.into(),
            cap_bits: 0x1,
        })
    }

    #[test]
    fn entry_in_same_file_as_dangerous_emits_reaches() {
        let mut map = SurfaceMap::new();
        map.nodes.push(ep("app.py", "index"));
        map.nodes.push(dl("app.py", "do_eval"));
        let gs = GlobalSummaries::new();
        let cg = CallGraph {
            graph: petgraph::graph::DiGraph::new(),
            index: Default::default(),
            unresolved_not_found: vec![],
            unresolved_ambiguous: vec![],
        };
        populate_reaches_edges(&mut map, &gs, &cg);
        assert_eq!(map.edges.len(), 1);
        assert_eq!(map.edges[0].kind, EdgeKind::Reaches);
        assert_eq!(map.edges[0].from, 0);
        assert_eq!(map.edges[0].to, 1);
    }

    #[test]
    fn file_part_of_namespace_strips_package_prefix() {
        assert_eq!(file_part_of_namespace("app.py"), "app.py");
        assert_eq!(file_part_of_namespace("src/main.rs"), "src/main.rs");
        assert_eq!(
            file_part_of_namespace("@scope/name::src/file.ts"),
            "src/file.ts"
        );
        // Last `::` wins, matching `namespace_with_package`'s shape.
        assert_eq!(
            file_part_of_namespace("@a/b::@c/d::lib/x.ts"),
            "lib/x.ts"
        );
    }
}
