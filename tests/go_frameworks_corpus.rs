//! Phase 17 (Track L.15) — Go framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/go_frameworks/`, asserting that
//! the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` matches the brief.
//! Benign fixtures must produce the same adapter binding shape as
//! the vuln fixtures — the adapter only models the route; the
//! differential outcome of a verifier run is what distinguishes the
//! two.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::{detect_binding, HttpMethod};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_go(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_go::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "go".into(),
        ..Default::default()
    }
}

fn assert_route(path: &str, adapter: &str, route_path: &str) {
    let bytes = std::fs::read(path).expect("fixture exists");
    let tree = parse_go(&bytes);
    let summary = summary_for("Run", path);
    let binding =
        detect_binding(&summary, tree.root_node(), &bytes, Lang::Go).expect("adapter must bind");
    assert_eq!(binding.adapter, adapter, "wrong adapter for {path}");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, route_path);
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn gin_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/gin/vuln.go",
        "go-gin",
        "/run",
    );
}

#[test]
fn gin_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/gin/benign.go",
        "go-gin",
        "/run",
    );
}

#[test]
fn echo_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/echo/vuln.go",
        "go-echo",
        "/run",
    );
}

#[test]
fn echo_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/echo/benign.go",
        "go-echo",
        "/run",
    );
}

#[test]
fn fiber_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/fiber/vuln.go",
        "go-fiber",
        "/run",
    );
}

#[test]
fn fiber_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/fiber/benign.go",
        "go-fiber",
        "/run",
    );
}

#[test]
fn chi_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/chi/vuln.go",
        "go-chi",
        "/run",
    );
}

#[test]
fn chi_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/go_frameworks/chi/benign.go",
        "go-chi",
        "/run",
    );
}

#[test]
fn gin_adapter_ignores_unrelated_function() {
    // Match a non-route function name to confirm the adapter does
    // not over-fire on unrelated helpers in the same file.
    let path = "tests/dynamic_fixtures/go_frameworks/gin/vuln.go";
    let bytes = std::fs::read(path).expect("fixture exists");
    let tree = parse_go(&bytes);
    let summary = summary_for("NonexistentHelper", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Go);
    assert!(binding.is_none());
}
