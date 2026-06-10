//! Top-level [`SurfaceMap`] builder.
//!
//! Phase 22 dispatch:
//!
//! 1. Per-file framework probes (one parser per language) emit
//!    [`SurfaceNode::EntryPoint`](crate::surface::SurfaceNode::EntryPoint) nodes for every recognised route /
//!    handler.
//! 2. [`super::datastore::detect_data_stores`] walks
//!    [`GlobalSummaries`] and emits [`SurfaceNode::DataStore`](crate::surface::SurfaceNode::DataStore) nodes
//!    for every recognised driver call.
//! 3. [`super::external::detect_external_services`] walks summaries +
//!    SSRF caps and emits [`SurfaceNode::ExternalService`](crate::surface::SurfaceNode::ExternalService) nodes.
//! 4. [`super::dangerous::detect_dangerous_locals`] walks summaries
//!    and emits [`SurfaceNode::DangerousLocal`](crate::surface::SurfaceNode::DangerousLocal) nodes for every
//!    function whose `sink_caps` include a local-sink class (code-exec,
//!    deserialize, SSTI, format-string, LDAP / XPath / header /
//!    open-redirect injection, XXE, prototype pollution), located at the
//!    real sink span and labelled with the decoded cap class.
//! 5. [`super::reachability::populate_reaches_edges`] runs a forward,
//!    function-level BFS over the [`CallGraph`] from each entry-point
//!    handler, emitting [`super::EdgeKind::ReadsFrom`] (→ data store),
//!    [`super::EdgeKind::TalksTo`] (→ external service), and
//!    [`super::EdgeKind::Reaches`] (→ dangerous local) edges to every
//!    reachable destination.
//! 6. [`SurfaceMap::canonicalize`] sorts nodes + edges so the
//!    serialised JSON is byte-deterministic across rescans.
//!
//! Per-file errors (parse failure, unsupported language, unreadable file)
//! are swallowed so a single bad file does not kill the whole map, but are
//! counted into [`SurfaceCoverage`] so the skip is observable rather than
//! silent.

use crate::auth_analysis::auth_markers::router_auth_markers_for_lang;
use crate::callgraph::CallGraph;
use crate::entry_points::{EntryKind, HttpMethod};
use crate::summary::GlobalSummaries;
use crate::surface::{
    EntryPoint, Framework, SourceLocation, SurfaceMap, SurfaceNode, dangerous, datastore, external,
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

/// Per-build coverage counters.  Turns the previously-silent
/// "single bad file is swallowed" behaviour into a number an operator can
/// read, so a small attack-surface map can be told apart from "our probes
/// did not understand this project's framework / language".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SurfaceCoverage {
    /// Total files handed to the builder.
    pub files_total: usize,
    /// Files in a language a framework probe exists for.
    pub files_supported: usize,
    /// Supported-language files that parsed cleanly.
    pub files_parsed: usize,
    /// Supported-language files whose tree-sitter parse failed.
    pub files_parse_failed: usize,
    /// Files in a language with no framework probe (`.md`, `.toml`, …).
    pub files_unsupported: usize,
    /// Files that could not be read off disk.
    pub files_unreadable: usize,
    /// Supported-language files that yielded at least one entry-point node.
    pub files_with_entry_points: usize,
}

/// Build a [`SurfaceMap`], discarding coverage.  Thin wrapper over
/// [`build_surface_map_with_coverage`] for callers (the indexed scan
/// path, persistence) that do not surface telemetry.
pub fn build_surface_map(inputs: &SurfaceBuildInputs<'_>) -> SurfaceMap {
    build_surface_map_with_coverage(inputs).0
}

/// Build a [`SurfaceMap`] and report [`SurfaceCoverage`].  The `nyx
/// surface` CLI uses this variant so parse / unsupported skips become a
/// visible number instead of being silently swallowed.
pub fn build_surface_map_with_coverage(
    inputs: &SurfaceBuildInputs<'_>,
) -> (SurfaceMap, SurfaceCoverage) {
    let mut map = SurfaceMap::new();
    let _ = inputs.config;
    let mut cov = SurfaceCoverage {
        files_total: inputs.files.len(),
        ..Default::default()
    };

    let mut parsers = Parsers::new();
    for path in inputs.files {
        let Ok(bytes) = std::fs::read(path) else {
            cov.files_unreadable += 1;
            continue;
        };
        let kind = classify_file(path);
        if kind == FileKind::Other {
            cov.files_unsupported += 1;
            continue;
        }
        cov.files_supported += 1;
        // `Some(nodes)` on a clean parse (possibly empty), `None` when the
        // tree-sitter parse failed — lets coverage distinguish the two.
        let parsed: Option<Vec<SurfaceNode>> = match kind {
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
                }),
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
                }),
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
                }),
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
                }),
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
                }),
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
                }),
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
                }),
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
                }),
            // Unreachable: `Other` is filtered out before this match, but
            // the arm keeps the match exhaustive.
            FileKind::Other => None,
        };
        match parsed {
            Some(nodes) => {
                cov.files_parsed += 1;
                if nodes
                    .iter()
                    .any(|n| matches!(n, SurfaceNode::EntryPoint(_)))
                {
                    cov.files_with_entry_points += 1;
                }
                for n in nodes {
                    map.nodes.push(n);
                }
            }
            None => cov.files_parse_failed += 1,
        }
    }

    // Entry-point recall fallback: the pass-1 summary extractor tags
    // handler functions with `FuncSummary::entry_kind` using its own
    // (independent) framework detection.  Any handler it recognised
    // that the AST probes above missed is synthesised here so the
    // surface map's entry-point set is always a superset of what the
    // taint engine treats as adversary-driven.  Route strings are not
    // recoverable from summaries, so these carry `"(unrouted)"`.
    let synthesised = synth_entry_points_from_summaries(&map.nodes, inputs.global_summaries);
    map.nodes.extend(synthesised);

    // Phase 22 — Track F.3: data-store / external-service /
    // dangerous-local detection from summaries.
    map.nodes
        .extend(datastore::detect_data_stores(inputs.global_summaries));
    map.nodes
        .extend(external::detect_external_services(inputs.global_summaries));
    map.nodes
        .extend(dangerous::detect_dangerous_locals(inputs.global_summaries));

    // Auth-detection upgrade: the probes only see router-level evidence
    // (decorators, annotations, middleware arguments).  A handler that
    // guards itself in its body (`requireAuth(req)` as the first call,
    // Go-style `if !VerifyToken(...)`) is still auth-gated; lift that
    // from the handler summary's callee list.
    upgrade_auth_required_from_summaries(&mut map, inputs.global_summaries);

    // Canonicalise so node indices are stable before reachability
    // builds edges referring to those indices.
    map.canonicalize();

    // Phase 22 — Track F.3: transitive closure over the call graph.
    reachability::populate_reaches_edges(&mut map, inputs.global_summaries, inputs.call_graph);

    // Re-canonicalise: edges added by reachability need to be sorted
    // so the serialised JSON stays byte-deterministic.
    map.canonicalize();
    (map, cov)
}

/// Route placeholder for entry points synthesised from summaries: the
/// pass-1 extractor records *that* a function is a handler but not the
/// route string the framework maps to it.
pub const UNROUTED: &str = "(unrouted)";

/// Map a pass-1 [`EntryKind`] tag to the surface [`Framework`] +
/// [`HttpMethod`] pair.  Kinds with no verb evidence default to `GET`
/// except Next.js server actions, which the framework only ever
/// invokes via `POST`.
fn entry_kind_to_framework(kind: &EntryKind) -> (Framework, HttpMethod) {
    match kind {
        EntryKind::UseServerDirective | EntryKind::FormAction => {
            (Framework::NextServerAction, HttpMethod::POST)
        }
        EntryKind::AppRouteHandler { method } => (Framework::NextAppRouter, *method),
        EntryKind::ExpressRoute { method } => (Framework::Express, *method),
        EntryKind::DjangoView { method } => (Framework::Django, *method),
        EntryKind::FastApiRoute { method } => (Framework::FastApi, *method),
        EntryKind::FlaskRoute { method } => (Framework::Flask, *method),
        EntryKind::SpringMapping { method } => (Framework::Spring, *method),
        EntryKind::JaxRsResource => (Framework::JaxRs, HttpMethod::GET),
        EntryKind::RailsAction => (Framework::Rails, HttpMethod::GET),
        EntryKind::SinatraRoute { method } => (Framework::Sinatra, *method),
        EntryKind::AxumHandler => (Framework::Axum, HttpMethod::GET),
        EntryKind::ActixHandler => (Framework::Actix, HttpMethod::GET),
        EntryKind::RocketRoute => (Framework::Rocket, HttpMethod::GET),
        EntryKind::GoNetHttp => (Framework::NetHttp, HttpMethod::GET),
        EntryKind::GinRoute => (Framework::Gin, HttpMethod::GET),
    }
}

/// Synthesise [`SurfaceNode::EntryPoint`] nodes for handlers the pass-1
/// summary extractor tagged with [`FuncSummary::entry_kind`](crate::summary::FuncSummary::entry_kind)
/// but no AST probe emitted.  De-duped against existing probe output on
/// `(handler file, handler name)` so a probe-detected route always wins
/// (it carries the real route string and span).  Summaries carry no
/// definition span, so synthesised nodes sit at line 0 of the handler
/// file; reachability matches on `(file, name)` and is unaffected.
fn synth_entry_points_from_summaries(
    existing: &[SurfaceNode],
    summaries: &GlobalSummaries,
) -> Vec<SurfaceNode> {
    let mut seen: std::collections::HashSet<(String, String)> = existing
        .iter()
        .filter_map(|n| match n {
            SurfaceNode::EntryPoint(ep) => {
                Some((ep.handler_location.file.clone(), ep.handler_name.clone()))
            }
            _ => None,
        })
        .collect();
    let mut out: Vec<SurfaceNode> = Vec::new();
    for (key, summary) in summaries.iter() {
        let Some(kind) = &summary.entry_kind else {
            continue;
        };
        if key.name.is_empty() {
            continue;
        }
        let file = crate::surface::namespace_file(&key.namespace).to_string();
        if !seen.insert((file.clone(), key.name.clone())) {
            continue;
        }
        let (framework, method) = entry_kind_to_framework(kind);
        let loc = SourceLocation {
            file,
            line: 0,
            col: 0,
        };
        out.push(SurfaceNode::EntryPoint(EntryPoint {
            location: loc.clone(),
            framework,
            method,
            route: UNROUTED.to_string(),
            handler_name: key.name.clone(),
            handler_location: loc,
            auth_required: false,
        }));
    }
    out
}

/// Set `auth_required = true` on entry points whose handler *body*
/// calls a known auth guard, complementing the probes' router-level
/// (decorator / annotation / middleware-argument) detection.
///
/// The handler summary is located by `(handler file, handler name)`;
/// its direct callees' leaf names are matched case-insensitively
/// against the per-language router-auth marker registry
/// ([`router_auth_markers_for_lang`]).  Depth is deliberately 1 — a
/// guard buried two helpers deep is a router concern the call graph
/// models better than a name list.
fn upgrade_auth_required_from_summaries(map: &mut SurfaceMap, summaries: &GlobalSummaries) {
    use std::collections::HashMap;
    let needs_upgrade: Vec<usize> = map
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(i, n)| match n {
            SurfaceNode::EntryPoint(ep) if !ep.auth_required && !ep.handler_name.is_empty() => {
                Some(i)
            }
            _ => None,
        })
        .collect();
    if needs_upgrade.is_empty() {
        return;
    }
    // (file, name) → summaries defining that function.  Built once; the
    // map is small relative to the summary count.
    let mut by_fn: HashMap<
        (&str, &str),
        Vec<(&crate::symbol::FuncKey, &crate::summary::FuncSummary)>,
    > = HashMap::new();
    for (key, summary) in summaries.iter() {
        by_fn
            .entry((crate::surface::namespace_file(&key.namespace), &key.name))
            .or_default()
            .push((key, summary));
    }
    let mut marker_cache: HashMap<crate::symbol::Lang, Vec<&'static str>> = HashMap::new();
    let mut to_set: Vec<usize> = Vec::new();
    for idx in needs_upgrade {
        let SurfaceNode::EntryPoint(ep) = &map.nodes[idx] else {
            continue;
        };
        let Some(cands) = by_fn.get(&(ep.handler_location.file.as_str(), ep.handler_name.as_str()))
        else {
            continue;
        };
        let guarded = cands.iter().any(|(key, summary)| {
            let markers = marker_cache
                .entry(key.lang)
                .or_insert_with(|| router_auth_markers_for_lang(key.lang));
            if markers.is_empty() {
                return false;
            }
            summary.callees.iter().any(|c| {
                let leaf = crate::callgraph::normalize_callee_name(&c.name);
                markers.iter().any(|m| m.eq_ignore_ascii_case(leaf))
            })
        });
        if guarded {
            to_set.push(idx);
        }
    }
    for idx in to_set {
        if let SurfaceNode::EntryPoint(ep) = &mut map.nodes[idx] {
            ep.auth_required = true;
        }
    }
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
    fn synthesises_entry_point_from_summary_entry_kind() {
        use crate::summary::FuncSummary;
        use crate::symbol::{FuncKey, Lang};
        // No source file on disk (probes see nothing), but pass-1 tagged
        // a Gin handler — the fallback must surface it.
        let dir = tempdir().unwrap();
        let cfg = Config::default();
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Go, "routes.go", "ListUsers", None);
        let summary = FuncSummary {
            name: "ListUsers".into(),
            file_path: "routes.go".into(),
            lang: "go".into(),
            entry_kind: Some(EntryKind::GinRoute),
            ..Default::default()
        };
        gs.insert(key, summary);
        let cg = empty_call_graph();
        let files: Vec<PathBuf> = vec![];
        let inputs = empty_inputs(&files, Some(dir.path()), &gs, &cg, &cfg);
        let map = build_surface_map(&inputs);
        let eps: Vec<_> = map.entry_points().collect();
        assert_eq!(eps.len(), 1, "fallback entry-point expected");
        assert_eq!(eps[0].handler_name, "ListUsers");
        assert_eq!(eps[0].framework, Framework::Gin);
        assert_eq!(eps[0].route, UNROUTED);
        assert_eq!(eps[0].handler_location.file, "routes.go");
    }

    #[test]
    fn probe_entry_point_suppresses_summary_fallback() {
        use crate::summary::FuncSummary;
        use crate::symbol::{FuncKey, Lang};
        let dir = tempdir().unwrap();
        let py = dir.path().join("app.py");
        fs::write(
            &py,
            "from flask import Flask\napp = Flask(__name__)\n@app.get('/u')\ndef u(): pass\n",
        )
        .unwrap();
        let cfg = Config::default();
        let mut gs = GlobalSummaries::new();
        // Summary tags the same handler the probe sees.
        let key = FuncKey::new_function(Lang::Python, "app.py", "u", None);
        let summary = FuncSummary {
            name: "u".into(),
            file_path: "app.py".into(),
            lang: "python".into(),
            entry_kind: Some(EntryKind::FlaskRoute {
                method: HttpMethod::GET,
            }),
            ..Default::default()
        };
        gs.insert(key, summary);
        let cg = empty_call_graph();
        let files = vec![py];
        let inputs = empty_inputs(&files, Some(dir.path()), &gs, &cg, &cfg);
        let map = build_surface_map(&inputs);
        let eps: Vec<_> = map.entry_points().collect();
        assert_eq!(eps.len(), 1, "no duplicate from the fallback");
        assert_eq!(eps[0].route, "/u", "probe route (with real path) wins");
    }

    #[test]
    fn body_level_auth_guard_upgrades_auth_required() {
        use crate::summary::{CalleeSite, FuncSummary};
        use crate::symbol::{FuncKey, Lang};
        let dir = tempdir().unwrap();
        let js = dir.path().join("routes.js");
        // Express route with NO middleware arg — probe alone says unauth.
        fs::write(
            &js,
            "const express = require('express');\nconst app = express();\napp.get('/admin', function admin(req, res) { requireAuth(req); res.send('x'); });\n",
        )
        .unwrap();
        let cfg = Config::default();
        let mut gs = GlobalSummaries::new();
        // Handler summary whose body calls requireAuth.
        let key = FuncKey::new_function(Lang::JavaScript, "routes.js", "admin", None);
        let summary = FuncSummary {
            name: "admin".into(),
            file_path: "routes.js".into(),
            lang: "javascript".into(),
            callees: vec![CalleeSite::bare("requireAuth")],
            ..Default::default()
        };
        gs.insert(key, summary);
        let cg = empty_call_graph();
        let files = vec![js];
        let inputs = empty_inputs(&files, Some(dir.path()), &gs, &cg, &cfg);
        let map = build_surface_map(&inputs);
        let ep = map
            .entry_points()
            .find(|ep| ep.handler_name == "admin")
            .expect("express probe finds the named handler");
        assert!(
            ep.auth_required,
            "body-level requireAuth call should upgrade auth_required"
        );
    }

    #[test]
    fn unrelated_callee_does_not_upgrade_auth() {
        use crate::summary::{CalleeSite, FuncSummary};
        use crate::symbol::{FuncKey, Lang};
        let dir = tempdir().unwrap();
        let py = dir.path().join("app.py");
        fs::write(
            &py,
            "from flask import Flask\napp = Flask(__name__)\n@app.get('/x')\ndef x(): pass\n",
        )
        .unwrap();
        let cfg = Config::default();
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "app.py", "x", None);
        let summary = FuncSummary {
            name: "x".into(),
            file_path: "app.py".into(),
            lang: "python".into(),
            // `settings` must not prefix-match any auth marker.
            callees: vec![CalleeSite::bare("settings"), CalleeSite::bare("render")],
            ..Default::default()
        };
        gs.insert(key, summary);
        let cg = empty_call_graph();
        let files = vec![py];
        let inputs = empty_inputs(&files, Some(dir.path()), &gs, &cg, &cfg);
        let map = build_surface_map(&inputs);
        let ep = map.entry_points().next().expect("entry point");
        assert!(!ep.auth_required);
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
