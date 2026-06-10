//! Transitive-closure pass: connect [`SurfaceNode::EntryPoint`] nodes
//! to the [`SurfaceNode::DataStore`] / [`SurfaceNode::ExternalService`]
//! / [`SurfaceNode::DangerousLocal`] nodes they can reach via the
//! whole-program [`CallGraph`].
//!
//! For each entry-point we first locate the matching call-graph
//! [`FuncKey`](crate::symbol::FuncKey) by `(namespace, function_name)` (the entry-point's
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

use super::{EdgeKind, SurfaceEdge, SurfaceMap, SurfaceNode, namespace_file};
use crate::callgraph::CallGraph;
use crate::summary::GlobalSummaries;
use petgraph::Direction;
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum BFS depth from an entry-point node.  Surface chains beyond
/// eight call-graph hops are rare in practice and the cost of a deeper
/// walk is paid per entry-point per scan.  A depth-bounded traversal
/// also prevents recursive cycles from blowing up.
const MAX_BFS_DEPTH: usize = 8;

/// One reachable destination node, keyed for **function-level** matching.
struct Dest {
    idx: usize,
    /// Project-relative POSIX file the destination lives in.
    file: String,
    /// Qualified name (`Class::method` / free function) of the function
    /// that owns this destination.  Empty only for legacy maps loaded
    /// from SQLite before the `owner` field landed — those fall back to
    /// file-level matching.
    owner: String,
    /// Edge classes to emit when an entry-point reaches this destination:
    /// [`EdgeKind::ReadsFrom`] / [`EdgeKind::WritesTo`] for a data store
    /// (driven by [`crate::surface::DataStore::access`]; a read-write
    /// site emits both), [`EdgeKind::TalksTo`] for an external service,
    /// [`EdgeKind::Reaches`] for a dangerous local sink.
    edges: smallvec::SmallVec<[EdgeKind; 2]>,
}

/// Populate entry-point → sink reachability edges on `map`
/// ([`EdgeKind::ReadsFrom`] / [`EdgeKind::TalksTo`] / [`EdgeKind::Reaches`]).
/// Mutates the edge list in place; the caller is expected to follow up
/// with [`SurfaceMap::canonicalize`] before serialisation.
///
/// Matching is **function-level** when the entry-point's handler resolves
/// to a call-graph node: a destination is connected only when the
/// function that owns it is actually on the forward BFS frontier from the
/// handler, so two unrelated handlers in the same file no longer both
/// "reach" a co-located `eval()`.  When the handler cannot be resolved in
/// the call graph (anonymous closure handler, unresolved seed) the pass
/// falls back to the conservative same-file heuristic so connectivity is
/// not silently lost.
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

        // Locate seed FuncKeys whose namespace file-part matches the
        // entry's handler file and whose `name` matches the handler.
        // More than one seed is possible (overloads, duplicate defs).
        // Anonymous handlers (empty name) match nothing — handled by the
        // unresolved fallback below.
        let seeds = if ep.handler_name.is_empty() {
            Vec::new()
        } else {
            call_graph
                .index
                .iter()
                .filter(|(k, _)| k.name == ep.handler_name)
                .filter(|(k, _)| namespace_file(&k.namespace) == ep.handler_location.file)
                .map(|(_, idx)| *idx)
                .collect::<Vec<_>>()
        };
        let seed_found = !seeds.is_empty();

        // Forward BFS over the call graph, collecting the set of reachable
        // owner functions as `(file, qualified_name)` keys.  Inserting the
        // *file part* of the namespace (not the raw `@pkg::path` namespace)
        // fixes the prior bug where packaged JS/TS namespaces never matched
        // a destination's bare file, silently killing all transitive reach.
        let mut reachable_fns: HashSet<(String, String)> = HashSet::new();
        let mut reachable_files: HashSet<String> = HashSet::new();
        reachable_files.insert(ep.handler_location.file.clone());

        let mut visited: HashSet<_> = seeds.iter().copied().collect();
        let mut queue: VecDeque<(petgraph::graph::NodeIndex, usize)> =
            seeds.iter().map(|n| (*n, 0)).collect();
        while let Some((node_idx, depth)) = queue.pop_front() {
            if let Some(key) = call_graph.graph.node_weight(node_idx) {
                let file = namespace_file(&key.namespace).to_string();
                reachable_fns.insert((file.clone(), key.qualified_name()));
                reachable_files.insert(file);
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

        for d in &dst_index {
            let reached = if seed_found && !d.owner.is_empty() {
                // Precise: the owning function must be on the BFS frontier.
                reachable_fns.contains(&(d.file.clone(), d.owner.clone()))
            } else {
                // Unresolved seed, or a legacy destination with no owner:
                // conservative same-file fallback (preserves connectivity
                // when the call graph cannot resolve the handler).
                reachable_files.contains(&d.file)
            };
            if reached {
                for kind in &d.edges {
                    new_edges.insert(SurfaceEdge {
                        from: entry_idx as u32,
                        to: d.idx as u32,
                        kind: *kind,
                    });
                }
            }
        }
    }

    map.edges.extend(new_edges);
}

/// Build the destination index: every non-entry-point node tagged with
/// its file, owning function, and the edge class to emit.
fn build_destination_index(map: &SurfaceMap) -> Vec<Dest> {
    let mut out: Vec<Dest> = Vec::new();
    for (idx, node) in map.nodes.iter().enumerate() {
        let (file, owner, edges) = match node {
            SurfaceNode::DataStore(n) => {
                let mut edges: smallvec::SmallVec<[EdgeKind; 2]> = smallvec::SmallVec::new();
                if n.access.reads() {
                    edges.push(EdgeKind::ReadsFrom);
                }
                if n.access.writes() {
                    edges.push(EdgeKind::WritesTo);
                }
                (n.location.file.clone(), n.owner.clone(), edges)
            }
            SurfaceNode::ExternalService(n) => (
                n.location.file.clone(),
                n.owner.clone(),
                smallvec::smallvec![EdgeKind::TalksTo],
            ),
            SurfaceNode::DangerousLocal(n) => (
                n.location.file.clone(),
                n.function_name.clone(),
                smallvec::smallvec![EdgeKind::Reaches],
            ),
            SurfaceNode::EntryPoint(_) => continue,
        };
        out.push(Dest {
            idx,
            file,
            owner,
            edges,
        });
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
        DangerousLocal, DataStore, DataStoreKind, EntryPoint, ExternalService, ExternalServiceKind,
        Framework, SourceLocation, SurfaceMap, SurfaceNode,
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
            label: String::new(),
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
    fn emits_typed_edges_for_store_and_external() {
        // A data store yields ReadsFrom, an external service yields TalksTo
        // (Reaches is reserved for dangerous-local sinks).  Uses the
        // unresolved-seed same-file fallback (empty call graph).
        let mut map = SurfaceMap::new();
        map.nodes.push(ep("app.py", "handler")); // 0
        map.nodes.push(SurfaceNode::DataStore(DataStore {
            location: SourceLocation::new("app.py", 4, 1),
            kind: DataStoreKind::Sql,
            label: "PostgreSQL".into(),
            owner: "handler".into(),
            access: Default::default(),
        })); // 1
        map.nodes
            .push(SurfaceNode::ExternalService(ExternalService {
                location: SourceLocation::new("app.py", 6, 1),
                kind: ExternalServiceKind::HttpApi,
                label: "requests".into(),
                owner: "handler".into(),
            })); // 2
        let gs = GlobalSummaries::new();
        let cg = CallGraph {
            graph: petgraph::graph::DiGraph::new(),
            index: Default::default(),
            unresolved_not_found: vec![],
            unresolved_ambiguous: vec![],
        };
        populate_reaches_edges(&mut map, &gs, &cg);
        assert!(
            map.edges
                .iter()
                .any(|e| e.kind == EdgeKind::ReadsFrom && e.to == 1)
        );
        assert!(
            map.edges
                .iter()
                .any(|e| e.kind == EdgeKind::TalksTo && e.to == 2)
        );
        assert!(map.edges.iter().all(|e| e.kind != EdgeKind::Reaches));
    }

    #[test]
    fn write_access_emits_writes_to_edge() {
        use crate::surface::AccessMode;
        let mut map = SurfaceMap::new();
        map.nodes.push(ep("app.py", "handler")); // 0
        map.nodes.push(SurfaceNode::DataStore(DataStore {
            location: SourceLocation::new("app.py", 4, 1),
            kind: DataStoreKind::Sql,
            label: "PostgreSQL".into(),
            owner: "handler".into(),
            access: AccessMode::Write,
        })); // 1
        map.nodes.push(SurfaceNode::DataStore(DataStore {
            location: SourceLocation::new("app.py", 6, 1),
            kind: DataStoreKind::Sql,
            label: "PostgreSQL exec".into(),
            owner: "handler".into(),
            access: AccessMode::ReadWrite,
        })); // 2
        let gs = GlobalSummaries::new();
        let cg = CallGraph {
            graph: petgraph::graph::DiGraph::new(),
            index: Default::default(),
            unresolved_not_found: vec![],
            unresolved_ambiguous: vec![],
        };
        populate_reaches_edges(&mut map, &gs, &cg);
        // Write-only store: WritesTo, no ReadsFrom.
        assert!(
            map.edges
                .iter()
                .any(|e| e.kind == EdgeKind::WritesTo && e.to == 1)
        );
        assert!(
            !map.edges
                .iter()
                .any(|e| e.kind == EdgeKind::ReadsFrom && e.to == 1)
        );
        // Read-write store: both edges.
        assert!(
            map.edges
                .iter()
                .any(|e| e.kind == EdgeKind::WritesTo && e.to == 2)
        );
        assert!(
            map.edges
                .iter()
                .any(|e| e.kind == EdgeKind::ReadsFrom && e.to == 2)
        );
    }

    #[test]
    fn namespace_file_strips_package_prefix() {
        use crate::surface::namespace_file;
        assert_eq!(namespace_file("app.py"), "app.py");
        assert_eq!(namespace_file("src/main.rs"), "src/main.rs");
        assert_eq!(namespace_file("@scope/name::src/file.ts"), "src/file.ts");
        // Last `::` wins, matching `namespace_with_package`'s shape.
        assert_eq!(namespace_file("@a/b::@c/d::lib/x.ts"), "lib/x.ts");
    }

    #[test]
    fn function_level_match_skips_unrelated_same_file_sink() {
        // Two handlers and one dangerous sink live in the same file, but
        // only `caller` calls `do_eval`.  With a resolvable call graph the
        // unrelated `other` handler must NOT get a Reaches edge — the
        // file-level heuristic used to connect both.
        use crate::symbol::{FuncKey, Lang};
        let mut map = SurfaceMap::new();
        map.nodes.push(ep("app.py", "caller")); // idx 0
        map.nodes.push(ep("app.py", "other")); // idx 1
        // Dangerous sink owned by `do_eval`.
        map.nodes.push(SurfaceNode::DangerousLocal(DangerousLocal {
            location: SourceLocation::new("app.py", 12, 1),
            function_name: "do_eval".into(),
            cap_bits: 0x1,
            label: "code-exec".into(),
        })); // idx 2

        // Call graph: caller -> do_eval ; other is isolated.
        let mut cg = CallGraph {
            graph: petgraph::graph::DiGraph::new(),
            index: Default::default(),
            unresolved_not_found: vec![],
            unresolved_ambiguous: vec![],
        };
        let caller = cg.graph.add_node(FuncKey::new_function(
            Lang::Python,
            "app.py",
            "caller",
            None,
        ));
        let other = cg
            .graph
            .add_node(FuncKey::new_function(Lang::Python, "app.py", "other", None));
        let do_eval = cg.graph.add_node(FuncKey::new_function(
            Lang::Python,
            "app.py",
            "do_eval",
            None,
        ));
        cg.graph.add_edge(
            caller,
            do_eval,
            crate::callgraph::CallEdge {
                call_site: "do_eval".into(),
            },
        );
        cg.index.insert(
            FuncKey::new_function(Lang::Python, "app.py", "caller", None),
            caller,
        );
        cg.index.insert(
            FuncKey::new_function(Lang::Python, "app.py", "other", None),
            other,
        );
        cg.index.insert(
            FuncKey::new_function(Lang::Python, "app.py", "do_eval", None),
            do_eval,
        );

        let gs = GlobalSummaries::new();
        populate_reaches_edges(&mut map, &gs, &cg);
        // Exactly one Reaches edge: caller(0) -> sink(2).  `other`(1) is
        // excluded by function-level matching.
        let reaches: Vec<_> = map
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Reaches)
            .collect();
        assert_eq!(reaches.len(), 1, "got {reaches:?}");
        assert_eq!(reaches[0].from, 0);
        assert_eq!(reaches[0].to, 2);
    }
}
