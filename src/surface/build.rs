//! Top-level [`SurfaceMap`] builder.
//!
//! Phase 22 dispatch:
//!
//! 1. Per-file framework probes (one parser per language) emit
//!    [`SurfaceNode::EntryPoint`] nodes for every recognised route /
//!    handler.
//! 2. [`super::datastore::detect_data_stores`] walks
//!    [`GlobalSummaries`] and emits [`SurfaceNode::DataStore`] nodes
//!    for every recognised driver call.
//! 3. [`super::external::detect_external_services`] walks summaries +
//!    SSRF caps and emits [`SurfaceNode::ExternalService`] nodes.
//! 4. [`super::dangerous::detect_dangerous_locals`] walks summaries
//!    and emits [`SurfaceNode::DangerousLocal`] nodes for every
//!    function whose `sink_caps` include CODE_EXEC / DESERIALIZE /
//!    SSTI / FMT_STRING.
//! 5. [`super::reachability::populate_reaches_edges`] runs a BFS over
//!    the [`CallGraph`] from each entry-point handler, emitting
//!    [`super::EdgeKind::Reaches`] edges to every reachable
//!    DataStore / ExternalService / DangerousLocal.
//! 6. [`SurfaceMap::canonicalize`] sorts nodes + edges so the
//!    serialised JSON is byte-deterministic across rescans.
//!
//! Per-file errors (parse failure, unsupported language) are
//! swallowed so a single bad file does not kill the whole map.

use crate::callgraph::CallGraph;
use crate::summary::GlobalSummaries;
use crate::surface::{
    SurfaceMap, dangerous, datastore, external,
    lang::{
        go_gin, go_http, java_quarkus, java_servlet, java_spring, js_express, js_koa, php_laravel,
        php_slim, python_django, python_fastapi, python_flask, ruby_rails, ruby_sinatra,
        rust_actix, rust_axum, ts_next,
    },
    reachability,
};
use crate::utils::config::Config;
use std::path::{Path, PathBuf};
use tree_sitter::Parser;

pub struct SurfaceBuildInputs<'a> {
    pub files: &'a [PathBuf],
    pub scan_root: Option<&'a Path>,
    pub global_summaries: &'a GlobalSummaries,
    pub call_graph: &'a CallGraph,
    pub config: &'a Config,
}

pub fn build_surface_map(inputs: &SurfaceBuildInputs<'_>) -> SurfaceMap {
    let mut map = SurfaceMap::new();
    let _ = inputs.config;

    let mut parsers = Parsers::new();
    for path in inputs.files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let kind = classify_file(path);
        let nodes = match kind {
            FileKind::Python => parsers
                .python
                .as_mut()
                .and_then(|p| p.parse(&bytes, None))
                .map(|tree| {
                    let mut all =
                        python_flask::detect_flask_routes(&tree, &bytes, path, inputs.scan_root);
                    all.extend(python_fastapi::detect_fastapi_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all.extend(python_django::detect_django_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all
                })
                .unwrap_or_default(),
            FileKind::JavaScript => parsers
                .javascript
                .as_mut()
                .and_then(|p| p.parse(&bytes, None))
                .map(|tree| {
                    let mut all =
                        js_express::detect_express_routes(&tree, &bytes, path, inputs.scan_root);
                    all.extend(js_koa::detect_koa_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all
                })
                .unwrap_or_default(),
            FileKind::TypeScript => parsers
                .typescript
                .as_mut()
                .and_then(|p| p.parse(&bytes, None))
                .map(|tree| {
                    let mut all =
                        js_express::detect_express_routes(&tree, &bytes, path, inputs.scan_root);
                    all.extend(js_koa::detect_koa_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all.extend(ts_next::detect_next_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all
                })
                .unwrap_or_default(),
            FileKind::Java => parsers
                .java
                .as_mut()
                .and_then(|p| p.parse(&bytes, None))
                .map(|tree| {
                    let mut all =
                        java_spring::detect_spring_routes(&tree, &bytes, path, inputs.scan_root);
                    all.extend(java_servlet::detect_servlet_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all.extend(java_quarkus::detect_quarkus_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all
                })
                .unwrap_or_default(),
            FileKind::Go => parsers
                .go
                .as_mut()
                .and_then(|p| p.parse(&bytes, None))
                .map(|tree| {
                    let mut all =
                        go_http::detect_go_http_routes(&tree, &bytes, path, inputs.scan_root);
                    all.extend(go_gin::detect_gin_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all
                })
                .unwrap_or_default(),
            FileKind::Php => parsers
                .php
                .as_mut()
                .and_then(|p| p.parse(&bytes, None))
                .map(|tree| {
                    let mut all =
                        php_laravel::detect_laravel_routes(&tree, &bytes, path, inputs.scan_root);
                    all.extend(php_slim::detect_slim_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all
                })
                .unwrap_or_default(),
            FileKind::Ruby => parsers
                .ruby
                .as_mut()
                .and_then(|p| p.parse(&bytes, None))
                .map(|tree| {
                    let mut all =
                        ruby_sinatra::detect_sinatra_routes(&tree, &bytes, path, inputs.scan_root);
                    all.extend(ruby_rails::detect_rails_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all
                })
                .unwrap_or_default(),
            FileKind::Rust => parsers
                .rust
                .as_mut()
                .and_then(|p| p.parse(&bytes, None))
                .map(|tree| {
                    let mut all =
                        rust_actix::detect_actix_routes(&tree, &bytes, path, inputs.scan_root);
                    all.extend(rust_axum::detect_axum_routes(
                        &tree,
                        &bytes,
                        path,
                        inputs.scan_root,
                    ));
                    all
                })
                .unwrap_or_default(),
            FileKind::Other => Vec::new(),
        };
        for n in nodes {
            map.nodes.push(n);
        }
    }

    // Phase 22 — Track F.3: data-store / external-service /
    // dangerous-local detection from summaries.
    map.nodes
        .extend(datastore::detect_data_stores(inputs.global_summaries));
    map.nodes
        .extend(external::detect_external_services(inputs.global_summaries));
    map.nodes
        .extend(dangerous::detect_dangerous_locals(inputs.global_summaries));

    // Canonicalise so node indices are stable before reachability
    // builds edges referring to those indices.
    map.canonicalize();

    // Phase 22 — Track F.3: transitive closure over the call graph.
    reachability::populate_reaches_edges(&mut map, inputs.global_summaries, inputs.call_graph);

    // Re-canonicalise: edges added by reachability need to be sorted
    // so the serialised JSON stays byte-deterministic.
    map.canonicalize();
    map
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum FileKind {
    Python,
    JavaScript,
    TypeScript,
    Java,
    Go,
    Php,
    Ruby,
    Rust,
    Other,
}

fn classify_file(path: &Path) -> FileKind {
    match path.extension().and_then(|s| s.to_str()) {
        Some("py") | Some("pyi") => FileKind::Python,
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => FileKind::JavaScript,
        Some("ts") | Some("tsx") | Some("mts") | Some("cts") => FileKind::TypeScript,
        Some("java") => FileKind::Java,
        Some("go") => FileKind::Go,
        Some("php") => FileKind::Php,
        Some("rb") => FileKind::Ruby,
        Some("rs") => FileKind::Rust,
        _ => FileKind::Other,
    }
}

struct Parsers {
    python: Option<Parser>,
    javascript: Option<Parser>,
    typescript: Option<Parser>,
    java: Option<Parser>,
    go: Option<Parser>,
    php: Option<Parser>,
    ruby: Option<Parser>,
    rust: Option<Parser>,
}

impl Parsers {
    fn new() -> Self {
        Self {
            python: parser_for(tree_sitter_python::LANGUAGE.into()),
            javascript: parser_for(tree_sitter_javascript::LANGUAGE.into()),
            typescript: parser_for(tree_sitter_typescript::LANGUAGE_TSX.into()),
            java: parser_for(tree_sitter_java::LANGUAGE.into()),
            go: parser_for(tree_sitter_go::LANGUAGE.into()),
            php: parser_for(tree_sitter_php::LANGUAGE_PHP.into()),
            ruby: parser_for(tree_sitter_ruby::LANGUAGE.into()),
            rust: parser_for(tree_sitter_rust::LANGUAGE.into()),
        }
    }
}

fn parser_for(language: tree_sitter::Language) -> Option<Parser> {
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    Some(parser)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry_points::HttpMethod;
    use crate::surface::SurfaceNode;
    use std::fs;
    use tempfile::tempdir;

    fn empty_inputs<'a>(
        files: &'a [PathBuf],
        scan_root: Option<&'a Path>,
        gs: &'a GlobalSummaries,
        cg: &'a CallGraph,
        cfg: &'a Config,
    ) -> SurfaceBuildInputs<'a> {
        SurfaceBuildInputs {
            files,
            scan_root,
            global_summaries: gs,
            call_graph: cg,
            config: cfg,
        }
    }

    fn empty_call_graph() -> CallGraph {
        CallGraph {
            graph: petgraph::graph::DiGraph::new(),
            index: Default::default(),
            unresolved_not_found: vec![],
            unresolved_ambiguous: vec![],
        }
    }

    #[test]
    fn empty_inputs_produce_empty_map() {
        let dir = tempdir().unwrap();
        let cfg = Config::default();
        let gs = GlobalSummaries::new();
        let cg = empty_call_graph();
        let files: Vec<PathBuf> = vec![];
        let inputs = empty_inputs(&files, Some(dir.path()), &gs, &cg, &cfg);
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
        let cg = empty_call_graph();
        let files = vec![py];
        let inputs = empty_inputs(&files, Some(dir.path()), &gs, &cg, &cfg);
        let map = build_surface_map(&inputs);
        assert_eq!(map.node_count(), 2);
        let methods: Vec<HttpMethod> = map.entry_points().map(|ep| ep.method).collect();
        assert!(methods.contains(&HttpMethod::GET));
        assert!(methods.contains(&HttpMethod::POST));
    }

    #[test]
    fn fastapi_file_produces_entry_points() {
        let dir = tempdir().unwrap();
        let py = dir.path().join("api.py");
        fs::write(
            &py,
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/users')\ndef list_users(): pass\n@app.post('/items')\ndef create(): pass\n",
        )
        .unwrap();
        let cfg = Config::default();
        let gs = GlobalSummaries::new();
        let cg = empty_call_graph();
        let files = vec![py];
        let inputs = empty_inputs(&files, Some(dir.path()), &gs, &cg, &cfg);
        let map = build_surface_map(&inputs);
        assert_eq!(map.node_count(), 2);
    }

    #[test]
    fn dangerous_local_emits_node_and_reaches_edge_to_same_file_entry() {
        use crate::labels::Cap;
        use crate::summary::FuncSummary;
        use crate::symbol::{FuncKey, Lang};
        let dir = tempdir().unwrap();
        let py = dir.path().join("app.py");
        fs::write(
            &py,
            r#"
from flask import Flask
app = Flask(__name__)

@app.route("/eval")
def evaluator():
    return ""
"#,
        )
        .unwrap();
        let cfg = Config::default();
        let mut gs = GlobalSummaries::new();
        gs.insert(
            FuncKey::new_function(Lang::Python, "app.py", "evaluator", None),
            FuncSummary {
                name: "evaluator".to_string(),
                file_path: "app.py".to_string(),
                lang: "python".to_string(),
                sink_caps: Cap::CODE_EXEC.bits(),
                ..Default::default()
            },
        );
        let cg = empty_call_graph();
        let files = vec![py];
        let inputs = empty_inputs(&files, Some(dir.path()), &gs, &cg, &cfg);
        let map = build_surface_map(&inputs);
        assert!(
            map.nodes
                .iter()
                .any(|n| matches!(n, SurfaceNode::DangerousLocal(_)))
        );
        assert!(
            map.edges
                .iter()
                .any(|e| matches!(e.kind, crate::surface::EdgeKind::Reaches))
        );
    }
}
