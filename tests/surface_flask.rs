//! Phase 21 — `SurfaceMap` Python + Flask vertical.
//!
//! Five-route Flask fixture exercising:
//!
//! * `@app.route("/", methods=["GET"])`   – default GET
//! * `@app.route("/submit", methods=["POST"])` – POST via methods kwarg
//! * `@app.get("/users")`                – verb decorator
//! * `@bp.post("/admin")`                – Blueprint receiver
//! * `@app.route("/secret")` + `@login_required` – auth-guarded
//!
//! Asserts every route node appears with the correct `method`, `route`,
//! `auth_required`, and `handler_name`.  Round-trips the surface map
//! through SQLite and confirms the byte representation is identical to
//! the in-memory canonical JSON.

use nyx_scanner::commands::index::build_index;
use nyx_scanner::commands::scan::scan_with_index_parallel;
use nyx_scanner::database::index::Indexer;
use nyx_scanner::entry_points::HttpMethod;
use nyx_scanner::surface::{Framework, SurfaceMap, SurfaceNode};
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::Path;
use std::sync::Arc;

fn test_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 8;
    cfg.performance.channel_multiplier = 1;
    cfg
}

const FIVE_ROUTE_FIXTURE: &str = r#"
from flask import Flask, Blueprint
from flask_login import login_required

app = Flask(__name__)
bp = Blueprint("admin", __name__)

@app.route("/", methods=["GET"])
def index():
    return "home"

@app.route("/submit", methods=["POST"])
def submit():
    return "ok"

@app.get("/users")
def list_users():
    return "users"

@bp.post("/admin")
def admin_create():
    return "created"

@login_required
@app.route("/secret")
def secret():
    return "shh"
"#;

fn seed_flask_fixture(root: &Path) {
    std::fs::write(root.join("app.py"), FIVE_ROUTE_FIXTURE.as_bytes()).unwrap();
}

#[test]
fn surface_map_captures_five_flask_routes() {
    let project = tempfile::tempdir().unwrap();
    seed_flask_fixture(project.path());
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("surface.sqlite");
    build_index("surface", project.path(), &db_path, &test_cfg(), false)
        .expect("build_index on flask fixture should succeed");
    let pool = Indexer::init(&db_path).expect("re-init pool");
    let _ = scan_with_index_parallel(
        "surface",
        Arc::clone(&pool),
        &test_cfg(),
        false,
        project.path(),
    )
    .expect("indexed scan should succeed");

    let idx = Indexer::from_pool("surface", &pool).expect("from_pool");
    let map = idx
        .load_surface_map()
        .expect("load_surface_map ok")
        .expect("surface map persisted after scan");

    let entries: Vec<_> = map.entry_points().collect();
    assert_eq!(
        entries.len(),
        5,
        "expected five Flask routes, got {entries:#?}",
    );

    let assert_route = |method: HttpMethod, route: &str, handler: &str, auth: bool| {
        let ep = map.entry_for_route(method, route).unwrap_or_else(|| {
            panic!("missing route {method:?} {route}; map = {entries:#?}");
        });
        assert_eq!(ep.framework, Framework::Flask, "framework mismatch on {route}");
        assert_eq!(ep.handler_name, handler, "handler mismatch on {route}");
        assert_eq!(
            ep.auth_required, auth,
            "auth mismatch on {route} (got {})",
            ep.auth_required
        );
        // Handler location must point inside the project file.
        assert!(
            ep.handler_location.file.ends_with("app.py"),
            "handler location not in app.py: {:?}",
            ep.handler_location.file
        );
    };
    assert_route(HttpMethod::GET, "/", "index", false);
    assert_route(HttpMethod::POST, "/submit", "submit", false);
    assert_route(HttpMethod::GET, "/users", "list_users", false);
    assert_route(HttpMethod::POST, "/admin", "admin_create", false);
    assert_route(HttpMethod::GET, "/secret", "secret", true);
}

#[test]
fn surface_map_round_trips_byte_identical_through_sqlite() {
    let project = tempfile::tempdir().unwrap();
    seed_flask_fixture(project.path());
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("rt.sqlite");

    build_index("rt", project.path(), &db_path, &test_cfg(), false).expect("first build_index");
    let pool = Indexer::init(&db_path).expect("first pool");
    let _ = scan_with_index_parallel("rt", Arc::clone(&pool), &test_cfg(), false, project.path())
        .expect("first scan");
    let idx = Indexer::from_pool("rt", &pool).expect("first from_pool");
    let bytes_first = idx
        .load_surface_map_bytes()
        .expect("load bytes 1")
        .expect("surface map persisted 1");
    drop(idx);

    // Rescan against the same DB.  No source change → byte-identical
    // canonical surface map.
    let _ = scan_with_index_parallel("rt", Arc::clone(&pool), &test_cfg(), false, project.path())
        .expect("second scan");
    let idx2 = Indexer::from_pool("rt", &pool).expect("second from_pool");
    let bytes_second = idx2
        .load_surface_map_bytes()
        .expect("load bytes 2")
        .expect("surface map persisted 2");

    assert_eq!(
        bytes_first, bytes_second,
        "surface_map JSON must be byte-identical across rescans"
    );

    // Round-trip through the in-memory representation: canonicalise →
    // serialise should reproduce the on-disk bytes exactly.
    let mut map = SurfaceMap::from_json(&bytes_first).expect("from_json");
    let bytes_after_round_trip = map.to_json().expect("to_json");
    assert_eq!(
        bytes_first, bytes_after_round_trip,
        "canonical JSON must match round-tripped JSON"
    );

    // Light sanity check: the same map deserialised twice still names
    // the five fixture routes (i.e. persistence does not lose nodes).
    let entries: Vec<&str> = map
        .nodes
        .iter()
        .filter_map(|n| match n {
            SurfaceNode::EntryPoint(ep) => Some(ep.route.as_str()),
            _ => None,
        })
        .collect();
    for route in ["/", "/submit", "/users", "/admin", "/secret"] {
        assert!(
            entries.contains(&route),
            "route {route} missing after round trip; got {entries:?}",
        );
    }
}
