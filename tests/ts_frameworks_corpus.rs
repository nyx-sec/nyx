//! Phase 13 (Track L.11) — TypeScript framework adapter integration tests.
//!
//! Mirrors `tests/js_frameworks_corpus.rs` against the TS fixtures.
//! The Express / Koa / Fastify adapters are registered under
//! [`Lang::JavaScript`] only and do not currently dispatch for
//! [`Lang::TypeScript`], so only the Nest adapter — which is
//! registered under both [`Lang::JavaScript`] and [`Lang::TypeScript`]
//! because Nest is TypeScript-first — has TS coverage here.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::{detect_binding, HttpMethod, ParamSource};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_ts(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang =
        tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "typescript".into(),
        ..Default::default()
    }
}

#[test]
fn nest_ts_vuln_fixture_binds_controller_route() {
    let path = "tests/dynamic_fixtures/ts_frameworks/nest/vuln.ts";
    let bytes = std::fs::read(path).expect("nest TS vuln fixture exists");
    let tree = parse_ts(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::TypeScript)
        .expect("ts-nest adapter must bind");
    assert_eq!(binding.adapter, "ts-nest");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
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
        other => panic!("expected QueryParam, got {other:?}"),
    }
}

#[test]
fn nest_ts_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/ts_frameworks/nest/benign.ts";
    let bytes = std::fs::read(path).expect("nest TS benign fixture exists");
    let tree = parse_ts(&bytes);
    let summary = summary_for("runCmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::TypeScript)
        .expect("ts-nest adapter must bind benign fixture");
    assert_eq!(binding.adapter, "ts-nest");
    assert_eq!(binding.route.as_ref().unwrap().path, "/run");
}
