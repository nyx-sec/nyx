//! Phase 14 (Track L.12) — Java framework adapter integration tests.
//!
//! Each test drives `detect_binding` end-to-end against a fixture
//! file under `tests/dynamic_fixtures/java/`, asserting that the
//! right adapter fires, the binding carries `EntryKind::HttpRoute`,
//! and the `RouteShape` matches the brief's contract.  Benign
//! fixtures must produce the same adapter binding shape as the vuln
//! fixtures — the adapter only models the route, the differential
//! outcome of a verifier run is what distinguishes the two.
//!
//! The Spring fixture lives under `spring_controller/`, the Quarkus
//! fixture under `quarkus_route/`, the Servlet doGet/doPost
//! fixtures under `servlet_doget/` and `servlet_dopost/`, and the
//! Micronaut fixture under `micronaut_route/` (introduced in this
//! phase).

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::framework::{HttpMethod, ParamSource, detect_binding};
use nyx_scanner::evidence::EntryKind;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

fn parse_java(src: &[u8]) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
    parser.set_language(&lang).unwrap();
    parser.parse(src, None).unwrap()
}

fn summary_for(name: &str, file: &str) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: file.into(),
        lang: "java".into(),
        ..Default::default()
    }
}

#[test]
fn spring_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/java/spring_controller/Vuln.java";
    let bytes = std::fs::read(path).expect("spring vuln fixture exists");
    let tree = parse_java(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Java)
        .expect("spring adapter must bind");
    assert_eq!(binding.adapter, "java-spring");
    assert_eq!(binding.kind, EntryKind::HttpRoute);
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn spring_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/java/spring_controller/Benign.java";
    let bytes = std::fs::read(path).expect("spring benign fixture exists");
    let tree = parse_java(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Java)
        .expect("spring adapter must bind benign fixture");
    assert_eq!(binding.adapter, "java-spring");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn quarkus_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/java/quarkus_route/Vuln.java";
    let bytes = std::fs::read(path).expect("quarkus vuln fixture exists");
    let tree = parse_java(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Java)
        .expect("quarkus adapter must bind");
    assert_eq!(binding.adapter, "java-quarkus");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn quarkus_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/java/quarkus_route/Benign.java";
    let bytes = std::fs::read(path).expect("quarkus benign fixture exists");
    let tree = parse_java(&bytes);
    let summary = summary_for("run", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Java)
        .expect("quarkus adapter must bind benign fixture");
    assert_eq!(binding.adapter, "java-quarkus");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn micronaut_vuln_fixture_binds_route_with_path_segment() {
    let path = "tests/dynamic_fixtures/java/micronaut_route/Vuln.java";
    let bytes = std::fs::read(path).expect("micronaut vuln fixture exists");
    let tree = parse_java(&bytes);
    let summary = summary_for("show", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Java)
        .expect("micronaut adapter must bind");
    assert_eq!(binding.adapter, "java-micronaut");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run/{id}");
    assert_eq!(route.method, HttpMethod::GET);
    let id_binding = binding
        .request_params
        .iter()
        .find(|p| p.name == "id")
        .expect("id formal");
    assert!(matches!(id_binding.source, ParamSource::PathSegment(_)));
}

#[test]
fn micronaut_benign_fixture_binds_same_route_shape() {
    let path = "tests/dynamic_fixtures/java/micronaut_route/Benign.java";
    let bytes = std::fs::read(path).expect("micronaut benign fixture exists");
    let tree = parse_java(&bytes);
    let summary = summary_for("show", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Java)
        .expect("micronaut adapter must bind benign fixture");
    assert_eq!(binding.adapter, "java-micronaut");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.path, "/run/{id}");
    assert_eq!(route.method, HttpMethod::GET);
}

#[test]
fn servlet_doget_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/java/servlet_doget/Vuln.java";
    let bytes = std::fs::read(path).expect("servlet doGet vuln fixture exists");
    let tree = parse_java(&bytes);
    let summary = summary_for("doGet", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Java)
        .expect("servlet adapter must bind");
    assert_eq!(binding.adapter, "java-servlet");
    let route = binding.route.as_ref().expect("route");
    assert_eq!(route.method, HttpMethod::GET);
    // Default-package fixture has no `@WebServlet("/x")`, so the
    // path defaults to `"/"`.
    assert_eq!(route.path, "/");
    // The (req, resp) pair should classify as Implicit.
    assert!(
        binding
            .request_params
            .iter()
            .all(|p| matches!(p.source, ParamSource::Implicit))
    );
}

#[test]
fn servlet_dopost_vuln_fixture_binds_route() {
    let path = "tests/dynamic_fixtures/java/servlet_dopost/Vuln.java";
    let bytes = std::fs::read(path).expect("servlet doPost vuln fixture exists");
    let tree = parse_java(&bytes);
    let summary = summary_for("doPost", path);
    let binding = detect_binding(&summary, tree.root_node(), &bytes, Lang::Java)
        .expect("servlet adapter must bind");
    assert_eq!(binding.adapter, "java-servlet");
    assert_eq!(binding.route.as_ref().unwrap().method, HttpMethod::POST);
}

#[test]
fn quarkus_adapter_does_not_fire_on_spring_file() {
    // Regression: Spring sources should not pull the Quarkus adapter
    // even when they happen to expose a JAX-RS-ish method name.
    // Phase 14 disambiguator: Quarkus requires a quarkus / jakarta.ws.rs
    // / javax.ws.rs / @Path stanza in the source.
    let src: &[u8] = b"@RestController\n@RequestMapping(\"/api\")\npublic class C { @GetMapping(\"/x\") public String x() { return \"\"; } }\n";
    let tree = parse_java(src);
    let summary = summary_for("x", "phantom.java");
    let binding =
        detect_binding(&summary, tree.root_node(), src, Lang::Java).expect("adapter fires");
    assert_eq!(binding.adapter, "java-spring");
}

#[test]
fn micronaut_adapter_disambiguates_against_spring_controller() {
    // Both Spring and Micronaut use `@Controller`.  Disambiguate via
    // the `io.micronaut` import + the `@Get` (mixed-case) verb
    // annotation.
    let src: &[u8] = b"import io.micronaut.http.annotation.Controller;\nimport io.micronaut.http.annotation.Get;\n@Controller(\"/x\")\npublic class C { @Get(\"/y\") public String y() { return \"\"; } }\n";
    let tree = parse_java(src);
    let summary = summary_for("y", "phantom.java");
    let binding =
        detect_binding(&summary, tree.root_node(), src, Lang::Java).expect("adapter fires");
    assert_eq!(binding.adapter, "java-micronaut");
}
