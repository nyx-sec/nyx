//! Phase 23 — `nyx surface` subcommand smoke tests.
//!
//! Builds a [`SurfaceMap`] against the Phase 21 Flask fixture, renders
//! it via the three text-mode formatters (text / json / dot) and asserts
//! the output matches the recorded golden file and contains the
//! expected structural markers.

use nyx_scanner::callgraph::CallGraph;
use nyx_scanner::commands::surface::{load_or_build, render_dot, render_text};
use nyx_scanner::summary::GlobalSummaries;
use nyx_scanner::surface::{
    build::{build_surface_map, SurfaceBuildInputs},
    SurfaceMap,
};
use nyx_scanner::utils::config::Config;
use std::path::{Path, PathBuf};

const FLASK_FIXTURE: &str = "tests/dynamic_fixtures/surface/python_flask";
const GOLDEN_PATH: &str = "tests/dynamic_fixtures/surface/cli_output.golden.txt";

fn empty_call_graph() -> CallGraph {
    CallGraph {
        graph: petgraph::graph::DiGraph::new(),
        index: Default::default(),
        unresolved_not_found: vec![],
        unresolved_ambiguous: vec![],
    }
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

fn flask_map() -> (SurfaceMap, PathBuf) {
    let dir = Path::new(FLASK_FIXTURE).to_path_buf();
    let mut files = Vec::new();
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
    let map = build_surface_map(&inputs);
    (map, dir)
}

#[test]
fn text_output_matches_golden_for_flask_fixture() {
    let (map, dir) = flask_map();
    // The golden file was recorded with no scan root prefix so it
    // stays valid across machines.  Pass `None` so the renderer
    // produces the same fixed header.
    let actual = render_text(&map, None);

    // Refresh the golden when running with UPDATE_GOLDEN=1.  Useful
    // when intentionally changing the formatter; mirrors the
    // convention used elsewhere in the test suite.
    if std::env::var("UPDATE_GOLDEN").ok().as_deref() == Some("1") {
        std::fs::write(GOLDEN_PATH, &actual).unwrap();
    }

    let expected = std::fs::read_to_string(GOLDEN_PATH)
        .expect("read tests/dynamic_fixtures/surface/cli_output.golden.txt");
    assert_eq!(
        actual, expected,
        "render_text output drifted from golden; re-run with UPDATE_GOLDEN=1 if intentional.\nfixture: {}",
        dir.display()
    );
}

#[test]
fn dot_output_contains_entry_and_digraph_header() {
    let (map, _) = flask_map();
    let dot = render_dot(&map);
    assert!(dot.starts_with("digraph nyx_surface"), "{dot}");
    assert!(dot.contains("GET /users"), "DOT missing entry route: {dot}");
}

#[test]
fn json_output_round_trips_byte_identical() {
    let (mut map, _) = flask_map();
    let bytes = map.to_json().expect("canonical JSON");
    let mut rt = SurfaceMap::from_json(&bytes).expect("from_json");
    let rt_bytes = rt.to_json().expect("re-serialise");
    assert_eq!(bytes, rt_bytes, "canonical JSON must round-trip identically");
}

#[test]
fn load_or_build_falls_back_to_filesystem_when_no_db() {
    let tmp = tempfile::tempdir().unwrap();
    let py = tmp.path().join("app.py");
    std::fs::write(
        &py,
        "from flask import Flask\napp = Flask(__name__)\n@app.get('/u')\ndef u(): pass\n",
    )
    .unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let cfg = Config::default();
    let map = load_or_build(tmp.path(), db_dir.path(), &cfg).expect("load_or_build");
    assert!(
        map.entry_points().next().is_some(),
        "expected at least one entry-point in fallback path"
    );
}
