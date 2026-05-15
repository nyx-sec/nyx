//! Phase 22 — cross-language `SurfaceMap` framework probes.
//!
//! One fixture per (language, framework) pair under
//! `tests/dynamic_fixtures/surface/<probe>/`.  Each probe is exercised
//! through the public [`build_surface_map`] entry point and asserted
//! on:
//!
//! 1. At least one [`SurfaceNode::EntryPoint`] is emitted.
//! 2. The recognised entry-point carries the expected [`Framework`]
//!    tag.
//! 3. The recognised entry-point's `route` field contains the expected
//!    substring (the path declared in the fixture).

use nyx_scanner::callgraph::CallGraph;
use nyx_scanner::summary::GlobalSummaries;
use nyx_scanner::surface::{
    Framework, SurfaceMap, SurfaceNode,
    build::{build_surface_map, SurfaceBuildInputs},
};
use nyx_scanner::utils::config::Config;
use std::path::{Path, PathBuf};

const FIXTURE_ROOT: &str = "tests/dynamic_fixtures/surface";

fn empty_call_graph() -> CallGraph {
    CallGraph {
        graph: petgraph::graph::DiGraph::new(),
        index: Default::default(),
        unresolved_not_found: vec![],
        unresolved_ambiguous: vec![],
    }
}

fn build(fixture_dir: &str) -> SurfaceMap {
    let dir = Path::new(FIXTURE_ROOT).join(fixture_dir);
    let mut files: Vec<PathBuf> = Vec::new();
    walk(&dir, &mut files);
    let cfg = Config::default();
    let gs = GlobalSummaries::new();
    let cg = empty_call_graph();
    let inputs = SurfaceBuildInputs {
        files: &files,
        scan_root: Some(&dir),
        global_summaries: &gs,
        call_graph: &cg,
        config: &cfg,
    };
    build_surface_map(&inputs)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn assert_entry(map: &SurfaceMap, framework: Framework, route_substr: &str) {
    let routes: Vec<String> = map
        .nodes
        .iter()
        .filter_map(|n| match n {
            SurfaceNode::EntryPoint(ep) if ep.framework == framework => Some(ep.route.clone()),
            _ => None,
        })
        .collect();
    assert!(
        !routes.is_empty(),
        "no entry-point with framework {:?} found in map = {:#?}",
        framework,
        map.nodes
    );
    assert!(
        routes.iter().any(|r| r.contains(route_substr)),
        "expected a route containing {route_substr:?}; got {routes:?}",
    );
}

#[test]
fn python_flask_fixture() {
    let map = build("python_flask");
    assert_entry(&map, Framework::Flask, "/users");
}

#[test]
fn python_fastapi_fixture() {
    let map = build("python_fastapi");
    assert_entry(&map, Framework::FastApi, "/items");
}

#[test]
fn python_django_fixture() {
    let map = build("python_django");
    assert_entry(&map, Framework::Django, "admin");
}

#[test]
fn js_express_fixture() {
    let map = build("js_express");
    assert_entry(&map, Framework::Express, "/users");
}

#[test]
fn js_koa_fixture() {
    let map = build("js_koa");
    assert_entry(&map, Framework::Koa, "/users");
}

#[test]
fn ts_next_fixture() {
    let map = build("ts_next");
    assert_entry(&map, Framework::NextAppRouter, "users");
}

#[test]
fn java_spring_fixture() {
    let map = build("java_spring");
    assert_entry(&map, Framework::Spring, "/api/users");
}

#[test]
fn java_servlet_fixture() {
    let map = build("java_servlet");
    assert_entry(&map, Framework::JaxRs, "/users");
}

#[test]
fn java_quarkus_fixture() {
    let map = build("java_quarkus");
    assert_entry(&map, Framework::Quarkus, "/api/hello");
}

#[test]
fn go_http_fixture() {
    let map = build("go_http");
    assert_entry(&map, Framework::NetHttp, "/users");
}

#[test]
fn go_gin_fixture() {
    let map = build("go_gin");
    assert_entry(&map, Framework::Gin, "/users");
}

#[test]
fn php_laravel_fixture() {
    let map = build("php_laravel");
    assert_entry(&map, Framework::Laravel, "/users");
}

#[test]
fn php_slim_fixture() {
    let map = build("php_slim");
    assert_entry(&map, Framework::Slim, "/users");
}

#[test]
fn ruby_sinatra_fixture() {
    let map = build("ruby_sinatra");
    assert_entry(&map, Framework::Sinatra, "/users");
}

#[test]
fn ruby_rails_fixture() {
    let map = build("ruby_rails");
    // Controller actions have empty routes because the route table
    // lives in `config/routes.rb` (separate file).  Assert on the
    // handler name surfacing instead.
    let handlers: Vec<String> = map
        .nodes
        .iter()
        .filter_map(|n| match n {
            SurfaceNode::EntryPoint(ep) if ep.framework == Framework::Rails => {
                Some(ep.handler_name.clone())
            }
            _ => None,
        })
        .collect();
    assert!(handlers.contains(&"index".to_string()));
    assert!(handlers.contains(&"show".to_string()));
}

#[test]
fn rust_actix_fixture() {
    let map = build("rust_actix");
    assert_entry(&map, Framework::Actix, "/users");
}

#[test]
fn rust_axum_fixture() {
    let map = build("rust_axum");
    assert_entry(&map, Framework::Axum, "/users");
}
