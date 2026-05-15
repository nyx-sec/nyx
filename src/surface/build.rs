//! Top-level [`SurfaceMap`] builder.
//!
//! Consumes the post-pass-2 [`GlobalSummaries`] + [`CallGraph`] for
//! call-graph reachability and the project's file list for the
//! per-language framework probes.  Phase 21 only invokes the Python +
//! Flask probe; Phase 22 wires the remaining language probes through
//! [`crate::surface::lang`].
//!
//! Build steps (Phase 21):
//!
//! 1. For every Python file, parse it once and invoke
//!    [`crate::surface::lang::python_flask::detect_flask_routes`].
//! 2. Collect the resulting [`SurfaceNode::EntryPoint`] nodes.
//! 3. Canonicalise the map (sort nodes + edges, dedup edges) so two
//!    runs over the same source produce byte-identical JSON.

use crate::callgraph::CallGraph;
use crate::summary::GlobalSummaries;
use crate::surface::{SurfaceMap, lang::python_flask};
use crate::utils::config::Config;
use std::path::{Path, PathBuf};

/// Inputs to [`build_surface_map`].  Wrapped in a struct so the
/// downstream Phase 22 work (additional probes, call-graph-derived
/// `Reaches` edges, label-rule data-source nodes) can extend the
/// signature without touching every caller.
pub struct SurfaceBuildInputs<'a> {
    pub files: &'a [PathBuf],
    pub scan_root: Option<&'a Path>,
    pub global_summaries: &'a GlobalSummaries,
    pub call_graph: &'a CallGraph,
    pub config: &'a Config,
}

/// Build a [`SurfaceMap`] for the project under analysis.
///
/// Best-effort: parse failures on individual files are swallowed so
/// the surface map of a 10k-file project is not killed by one bad
/// Python file.  Returns an empty map when the inputs contain no
/// recognised entry-points.
pub fn build_surface_map(inputs: &SurfaceBuildInputs<'_>) -> SurfaceMap {
    let mut map = SurfaceMap::new();

    // Phase 21: only Python / Flask.  The downstream Phase 22 probes
    // will dispatch on file extension here.
    let mut python_parser = tree_sitter::Parser::new();
    if python_parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        return map;
    }

    for path in inputs.files {
        if !is_python_file(path) {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Some(tree) = python_parser.parse(&bytes, None) else {
            continue;
        };
        let nodes =
            python_flask::detect_flask_routes(&tree, &bytes, path, inputs.scan_root);
        for n in nodes {
            map.nodes.push(n);
        }
    }

    // GlobalSummaries / CallGraph are reserved for Phase 22's
    // `DangerousLocal` + `Reaches`-edge fill-in.  Phase 21 records
    // them in the inputs so callers do not need to be touched again
    // when Phase 22 wires them up.
    let _ = inputs.global_summaries;
    let _ = inputs.call_graph;
    let _ = inputs.config;

    map.canonicalize();
    map
}

fn is_python_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("py") | Some("pyi")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry_points::HttpMethod;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn empty_inputs_produce_empty_map() {
        let dir = tempdir().unwrap();
        let cfg = Config::default();
        let gs = GlobalSummaries::new();
        let cg = CallGraph {
            graph: petgraph::graph::DiGraph::new(),
            index: Default::default(),
            unresolved_not_found: vec![],
            unresolved_ambiguous: vec![],
        };
        let files: Vec<PathBuf> = vec![];
        let inputs = SurfaceBuildInputs {
            files: &files,
            scan_root: Some(dir.path()),
            global_summaries: &gs,
            call_graph: &cg,
            config: &cfg,
        };
        let map = build_surface_map(&inputs);
        assert_eq!(map.node_count(), 0);
        assert_eq!(map.edge_count(), 0);
    }

    #[test]
    fn flask_file_produces_entry_points() {
        let dir = tempdir().unwrap();
        let py = dir.path().join("app.py");
        fs::write(
            &py,
            r#"
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "hi"

@app.post("/submit")
def submit():
    return "ok"
"#,
        )
        .unwrap();
        let cfg = Config::default();
        let gs = GlobalSummaries::new();
        let cg = CallGraph {
            graph: petgraph::graph::DiGraph::new(),
            index: Default::default(),
            unresolved_not_found: vec![],
            unresolved_ambiguous: vec![],
        };
        let files = vec![py.clone()];
        let inputs = SurfaceBuildInputs {
            files: &files,
            scan_root: Some(dir.path()),
            global_summaries: &gs,
            call_graph: &cg,
            config: &cfg,
        };
        let map = build_surface_map(&inputs);
        assert_eq!(map.node_count(), 2);
        let methods: Vec<HttpMethod> = map.entry_points().map(|ep| ep.method).collect();
        assert!(methods.contains(&HttpMethod::GET));
        assert!(methods.contains(&HttpMethod::POST));
    }
}
