//! Phase 12 (Track L.10) — Python framework adapter integration tests.
//!
//! Each test exercises `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/python_frameworks/`, asserting
//! that the right adapter fires, the binding carries
//! `EntryKind::HttpRoute`, and the `RouteShape` + per-formal
//! `request_params` match the brief's contract.  Benign fixtures
//! must produce the same adapter binding shape as the vuln fixtures
//! — the adapter only models the route, the differential outcome of
//! a verifier run is what distinguishes the two.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::{detect_binding, HttpMethod, ParamSource};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_python(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "python".into(),
        ..Default::default()
    }
}

#[test]
fn flask_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/python_frameworks/flask/vuln.py";
    let bytes = std::fs::read(path).expect("flask vuln fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("flask adapter must bind");
    assert_eq!(binding.adapter, "python-flask");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn flask_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/python_frameworks/flask/benign.py";
    let bytes = std::fs::read(path).expect("flask benign fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("flask adapter must bind benign fixture");
    assert_eq!(binding.adapter, "python-flask");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn fastapi_vuln_fixture_binds_route_with_query_param() {
    let path = "tests/dynamic_fixtures/python_frameworks/fastapi/vuln.py";
    let bytes = std::fs::read(path).expect("fastapi vuln fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("fastapi adapter must bind");
    assert_eq!(binding.adapter, "python-fastapi");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
    let cmd_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "cmd")
        .expect("cmd formal");
    assert!(matches!(cmd_binding.source, ParamSource::QueryParam(_)));
}

#[test]
fn fastapi_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/python_frameworks/fastapi/benign.py";
    let bytes = std::fs::read(path).expect("fastapi benign fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("fastapi adapter must bind benign fixture");
    assert_eq!(binding.adapter, "python-fastapi");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn django_vuln_fixture_binds_route_via_urlconf() {
    let path = "tests/dynamic_fixtures/python_frameworks/django/vuln.py";
    let bytes = std::fs::read(path).expect("django vuln fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("django adapter must bind");
    assert_eq!(binding.adapter, "python-django");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "run/");
    let request_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "request")
        .expect("request formal");
    assert!(matches!(request_binding.source, ParamSource::Implicit));
}

#[test]
fn django_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/python_frameworks/django/benign.py";
    let bytes = std::fs::read(path).expect("django benign fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("django adapter must bind benign fixture");
    assert_eq!(binding.adapter, "python-django");
    assert_eq!(binding.route.as_ref().unwrap().path, "run/");
}

#[test]
fn starlette_vuln_fixture_binds_route_via_routes_list() {
    let path = "tests/dynamic_fixtures/python_frameworks/starlette/vuln.py";
    let bytes = std::fs::read(path).expect("starlette vuln fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("starlette adapter must bind");
    assert_eq!(binding.adapter, "python-starlette");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn starlette_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/python_frameworks/starlette/benign.py";
    let bytes = std::fs::read(path).expect("starlette benign fixture exists");
    let tree = parse_python(&bytes);
    let summary = summary_for("run_cmd", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Python)
        .expect("starlette adapter must bind benign fixture");
    assert_eq!(binding.adapter, "python-starlette");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
}

#[test]
fn fastapi_adapter_runs_before_starlette_for_fastapi_files() {
    // Regression: a FastAPI file imports starlette transitively via
    // `from starlette.responses import ...`, so the Starlette adapter
    // would otherwise fire for it.  Registration order
    // (python-fastapi before python-starlette alphabetically) +
    // the FastAPI adapter's tighter import check protect against
    // mis-routing.
    let src: &[u8] = b"from fastapi import FastAPI\nfrom starlette.responses import PlainTextResponse\napp = FastAPI()\n@app.get(\"/x\")\ndef handler(q: str = \"\"):\n    return q\n";
    let tree = parse_python(src);
    let summary = summary_for("handler", "phantom.py");
    let binding =
        detect_binding(&summary, tree.root_node(), src, Lang::Python).expect("adapter fires");
    assert_eq!(binding.adapter, "python-fastapi");
}
