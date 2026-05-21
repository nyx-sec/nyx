//! Phase 13 (Track L.11) — JS framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/js_frameworks/`, asserting that
//! the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` + per-formal
//! `request_params` match the brief's contract.  Benign fixtures must
//! produce the same adapter binding shape as the vuln fixtures — the
//! adapter only models the route, the differential outcome of a
//! verifier run is what distinguishes the two.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::{HttpMethod, ParamSource, detect_binding};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_js(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "javascript".into(),
        ..Default::default()
    }
}

#[test]
fn express_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/js_frameworks/express/vuln.js";
    let bytes = std::fs::read(path).expect("express vuln fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("express adapter must bind");
    assert_eq!(binding.adapter, "js-express");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    assert!(
        binding
            .request_params
            .iter()
            .any(|p| p.name == "req" && matches!(p.source, ParamSource::Implicit))
    );
}

#[test]
fn express_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/js_frameworks/express/benign.js";
    let bytes = std::fs::read(path).expect("express benign fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("express adapter must bind benign fixture");
    assert_eq!(binding.adapter, "js-express");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn koa_vuln_fixture_binds_router_route() {
    let path = "tests/dynamic_fixtures/js_frameworks/koa/vuln.js";
    let bytes = std::fs::read(path).expect("koa vuln fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("koa adapter must bind");
    assert_eq!(binding.adapter, "js-koa");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    assert!(
        binding
            .request_params
            .iter()
            .any(|p| p.name == "ctx" && matches!(p.source, ParamSource::Implicit))
    );
}

#[test]
fn koa_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/js_frameworks/koa/benign.js";
    let bytes = std::fs::read(path).expect("koa benign fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("koa adapter must bind benign fixture");
    assert_eq!(binding.adapter, "js-koa");
    assert_eq!(binding.route.as_ref().unwrap().path, "/run");
}

#[test]
fn fastify_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/js_frameworks/fastify/vuln.js";
    let bytes = std::fs::read(path).expect("fastify vuln fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("fastify adapter must bind");
    assert_eq!(binding.adapter, "js-fastify");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    assert!(
        binding
            .request_params
            .iter()
            .any(|p| p.name == "request" && matches!(p.source, ParamSource::Implicit))
    );
    assert!(
        binding
            .request_params
            .iter()
            .any(|p| p.name == "reply" && matches!(p.source, ParamSource::Implicit))
    );
}

#[test]
fn fastify_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/js_frameworks/fastify/benign.js";
    let bytes = std::fs::read(path).expect("fastify benign fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("fastify adapter must bind benign fixture");
    assert_eq!(binding.adapter, "js-fastify");
    assert_eq!(binding.route.as_ref().unwrap().path, "/run");
}

#[test]
fn nest_vuln_fixture_binds_controller_route() {
    let path = "tests/dynamic_fixtures/js_frameworks/nest/vuln.js";
    let bytes = std::fs::read(path).expect("nest vuln fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("nest adapter must bind");
    assert_eq!(binding.adapter, "js-nest");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    let cmd_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "cmd")
        .expect("cmd formal");
    match &cmd_binding.source {
        ParamSource::QueryParam(q) => assert_eq!(q, "cmd"),
        other => panic!("expected QueryParam(\"cmd\"), got {other:?}"),
    }
}

#[test]
fn nest_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/js_frameworks/nest/benign.js";
    let bytes = std::fs::read(path).expect("nest benign fixture exists");
    let tree = parse_js(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::JavaScript)
        .expect("nest adapter must bind benign fixture");
    assert_eq!(binding.adapter, "js-nest");
    assert_eq!(binding.route.as_ref().unwrap().path, "/run");
}

#[test]
fn express_adapter_runs_before_fastify_for_express_files() {
    // Regression guard: an Express file does not pull in `fastify`,
    // so the Fastify adapter never fires.  Registration order is
    // alphabetical (`js-express` before `js-fastify`) which keeps the
    // adapter dispatch deterministic.
    let src: &[u8] = b"const express = require('express');\n\
        const app = express();\n\
        function h(req, res) { res.send('ok'); }\n\
        app.get('/x', h);\n";
    let tree = parse_js(src);
    let summary = summary_for("h", "synthetic.js");
    let binding = detect_binding(&summary, tree.root_node(), src, Lang::JavaScript).expect("fires");
    assert_eq!(binding.adapter, "js-express");
}
