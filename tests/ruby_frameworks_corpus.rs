//! Phase 15 (Track L.13) — Ruby framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/ruby/`, asserting that the
//! right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` matches the brief's
//! contract.  Benign fixtures must produce the same adapter binding
//! shape as the vuln fixtures — the adapter only models the route,
//! the differential outcome of a verifier run is what distinguishes
//! the two.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::{HttpMethod, ParamSource, detect_binding};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_ruby(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "ruby".into(),
        ..Default::default()
    }
}

// ── Rails ────────────────────────────────────────────────────────────────────

#[test]
fn rails_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/ruby/rails_action/vuln.rb";
    let bytes = std::fs::read(path).expect("rails vuln fixture exists");
    let tree = parse_ruby(&bytes);
    let summary = summary_for("index", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Ruby)
        .expect("rails adapter must bind");
    assert_eq!(binding.adapter, "ruby-rails");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.method, HttpMethod::GET);
    assert_eq!(route.path, "/index");
}

#[test]
fn rails_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/ruby/rails_action/benign.rb";
    let bytes = std::fs::read(path).expect("rails benign fixture exists");
    let tree = parse_ruby(&bytes);
    let summary = summary_for("index", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Ruby)
        .expect("rails adapter must bind benign fixture");
    assert_eq!(binding.adapter, "ruby-rails");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/index");
}

#[test]
fn rails_routes_draw_overrides_default_path() {
    let src: &[u8] = b"Rails.application.routes.draw do\n  get '/run', to: 'users#index'\nend\n\nclass UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
    let tree = parse_ruby(src);
    let summary = summary_for("index", "synth.rb");
    let binding = detect_binding(&summary, tree.root_node(), src, Lang::Ruby)
        .expect("rails adapter must bind via routes.draw");
    assert_eq!(binding.adapter, "ruby-rails");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

// ── Sinatra ──────────────────────────────────────────────────────────────────

#[test]
fn sinatra_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/ruby/sinatra_route/vuln.rb";
    let bytes = std::fs::read(path).expect("sinatra vuln fixture exists");
    let tree = parse_ruby(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Ruby)
        .expect("sinatra adapter must bind");
    assert_eq!(binding.adapter, "ruby-sinatra");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.method, HttpMethod::GET);
    assert_eq!(route.path, "/run");
    let payload_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "payload")
        .expect("payload block param");
    assert!(matches!(payload_binding.source, ParamSource::QueryParam(_)));
}

#[test]
fn sinatra_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/ruby/sinatra_route/benign.rb";
    let bytes = std::fs::read(path).expect("sinatra benign fixture exists");
    let tree = parse_ruby(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Ruby)
        .expect("sinatra adapter must bind benign fixture");
    assert_eq!(binding.adapter, "ruby-sinatra");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
}

// ── Hanami ───────────────────────────────────────────────────────────────────

#[test]
fn hanami_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/ruby/hanami_action/vuln.rb";
    let bytes = std::fs::read(path).expect("hanami vuln fixture exists");
    let tree = parse_ruby(&bytes);
    let summary = summary_for("call", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Ruby)
        .expect("hanami adapter must bind");
    assert_eq!(binding.adapter, "ruby-hanami");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.method, HttpMethod::GET);
    assert_eq!(route.path, "/run");
    let req_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "req")
        .expect("req formal");
    assert!(matches!(req_binding.source, ParamSource::Implicit));
}

#[test]
fn hanami_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/ruby/hanami_action/benign.rb";
    let bytes = std::fs::read(path).expect("hanami benign fixture exists");
    let tree = parse_ruby(&bytes);
    let summary = summary_for("call", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Ruby)
        .expect("hanami adapter must bind benign fixture");
    assert_eq!(binding.adapter, "ruby-hanami");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
}

// ── Cross-adapter disambiguation ─────────────────────────────────────────────

#[test]
fn sinatra_does_not_fire_on_rails_controller() {
    let path = "tests/dynamic_fixtures/ruby/rails_action/vuln.rb";
    let bytes = std::fs::read(path).expect("rails vuln fixture exists");
    let tree = parse_ruby(&bytes);
    let summary = summary_for("index", path);
    let binding =
        detect_binding(&summary, tree.root_node(), &bytes, Lang::Ruby).expect("adapter binds");
    // First-match-wins ordering must produce `ruby-rails`, not
    // `ruby-sinatra`, even if both adapters could in theory match.
    assert_eq!(binding.adapter, "ruby-rails");
}

#[test]
fn hanami_does_not_fire_on_plain_class_with_call_method() {
    let path = "tests/dynamic_fixtures/ruby/rack_middleware/vuln.rb";
    let bytes = std::fs::read(path).expect("rack vuln fixture exists");
    let tree = parse_ruby(&bytes);
    let summary = summary_for("call", path);
    let binding_opt = detect_binding(&summary, tree.root_node(), &bytes, Lang::Ruby);
    // The rack_middleware fixture has no Hanami::Action import or
    // superclass; Hanami must not claim it.  No other Phase 15 route
    // adapter matches either (no Rails / Sinatra markers), so binding
    // is `None` overall for the Phase 15 route slice.  Sink adapters
    // (header-ruby / redirect-ruby / etc.) also do not fire because
    // the rack fixture's callees are not redirect / header sinks.
    if let Some(b) = binding_opt {
        assert_ne!(b.adapter, "ruby-hanami");
        assert_ne!(b.adapter, "ruby-rails");
        assert_ne!(b.adapter, "ruby-sinatra");
    }
}
