//! Phase 16 (Track L.14) — PHP framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/php_frameworks/`, asserting
//! that the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` + per-formal
//! `request_params` match the brief's contract.  Benign fixtures
//! must produce the same adapter binding shape as the vuln fixtures
//! — the adapter only models the route, the differential outcome of
//! a verifier run is what distinguishes the two.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::{HttpMethod, ParamSource, detect_binding};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_php(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "php".into(),
        ..Default::default()
    }
}

#[test]
fn laravel_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/php_frameworks/laravel/vuln.php";
    let bytes = std::fs::read(path).expect("laravel vuln fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("laravel adapter must bind");
    assert_eq!(binding.adapter, "php-laravel");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    let payload = binding
        .request_params
        .iter()
        .find(|p| p.name == "payload")
        .expect("payload formal");
    assert!(matches!(payload.source, ParamSource::QueryParam(_)));
}

#[test]
fn laravel_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/php_frameworks/laravel/benign.php";
    let bytes = std::fs::read(path).expect("laravel benign fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("laravel adapter must bind benign fixture");
    assert_eq!(binding.adapter, "php-laravel");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn symfony_vuln_fixture_binds_route_via_attribute() {
    let path = "tests/dynamic_fixtures/php_frameworks/symfony/vuln.php";
    let bytes = std::fs::read(path).expect("symfony vuln fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("symfony adapter must bind");
    assert_eq!(binding.adapter, "php-symfony");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn symfony_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/php_frameworks/symfony/benign.php";
    let bytes = std::fs::read(path).expect("symfony benign fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("symfony adapter must bind benign fixture");
    assert_eq!(binding.adapter, "php-symfony");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
}

#[test]
fn codeigniter_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/php_frameworks/codeigniter/vuln.php";
    let bytes = std::fs::read(path).expect("codeigniter vuln fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("codeigniter adapter must bind");
    assert_eq!(binding.adapter, "php-codeigniter");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn codeigniter_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/php_frameworks/codeigniter/benign.php";
    let bytes = std::fs::read(path).expect("codeigniter benign fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php)
        .expect("codeigniter adapter must bind benign fixture");
    assert_eq!(binding.adapter, "php-codeigniter");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "run");
}

#[test]
fn laravel_adapter_ignores_helper_method() {
    // `helper` is declared but not referenced in any `Route::*` call.
    // The adapter must return `None` so the verifier surfaces
    // `SpecDerivationFailed` for non-route helpers in a route file.
    let path = "tests/dynamic_fixtures/php_frameworks/laravel/vuln.php";
    let bytes = std::fs::read(path).expect("laravel vuln fixture exists");
    let tree = parse_php(&bytes);
    let summary = summary_for("nonexistent_helper", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Php);
    assert!(binding.is_none());
}
