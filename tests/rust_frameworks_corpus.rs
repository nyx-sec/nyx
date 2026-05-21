//! Phase 17 (Track L.15) — Rust framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/rust_frameworks/`, asserting
//! that the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` matches the brief.
//! Benign fixtures must produce the same adapter binding shape as
//! the vuln fixtures — the adapter only models the route; the
//! differential outcome of a verifier run is what distinguishes the
//! two.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::{HttpMethod, detect_binding};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_rust(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "rust".into(),
        ..Default::default()
    }
}

fn assert_route(path: &str, adapter: &str, expected_path_fragment: &str, method: HttpMethod) {
    let bytes = std::fs::read(path).expect("fixture exists");
    let tree = parse_rust(&bytes);
    let summary = summary_for("run", path);
    let binding =
        detect_binding(&summary, tree.root_node(), &bytes, Lang::Rust).expect("adapter must bind");
    assert_eq!(binding.adapter, adapter, "wrong adapter for {path}");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert!(
        route.path.contains(expected_path_fragment),
        "route path {} should contain {expected_path_fragment}",
        route.path
    );
    assert_eq!(route.method, method);
}

#[test]
fn axum_vuln_fixture_binds_route() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/axum/vuln.rs",
        "rust-axum",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn axum_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/axum/benign.rs",
        "rust-axum",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn actix_vuln_fixture_binds_route_via_attribute() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/actix/vuln.rs",
        "rust-actix",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn actix_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/actix/benign.rs",
        "rust-actix",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn rocket_vuln_fixture_binds_route_via_attribute() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/rocket/vuln.rs",
        "rust-rocket",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn rocket_benign_fixture_binds_same_route_shape() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/rocket/benign.rs",
        "rust-rocket",
        "/run",
        HttpMethod::GET,
    );
}

#[test]
fn warp_vuln_fixture_binds_path_macro() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/warp/vuln.rs",
        "rust-warp",
        "run",
        HttpMethod::GET,
    );
}

#[test]
fn warp_benign_fixture_binds_same_path_macro() {
    assert_route(
        "tests/dynamic_fixtures/rust_frameworks/warp/benign.rs",
        "rust-warp",
        "run",
        HttpMethod::GET,
    );
}

#[test]
fn axum_adapter_ignores_unrelated_function() {
    let path = "tests/dynamic_fixtures/rust_frameworks/axum/vuln.rs";
    let bytes = std::fs::read(path).expect("fixture exists");
    let tree = parse_rust(&bytes);
    let summary = summary_for("nonexistent_helper", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Rust);
    assert!(binding.is_none());
}
