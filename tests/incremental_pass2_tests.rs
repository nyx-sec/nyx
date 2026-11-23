//! Incremental pass 2: an indexed rescan reuses the pass-2 result of every
//! unit whose files and recorded cross-file reads are unchanged, and the
//! findings stay identical to a full non-indexed scan after every edit.
//!
//! Each test copies a fixture into a temp dir, keeps one index database for
//! the whole edit sequence, and after every step compares the indexed result
//! with `scan_no_index` on the same tree.  A second indexed scan per step runs
//! with verification on, which re-analyses every reused unit and counts any
//! difference from the cached result.

#[allow(dead_code)]
mod common;

use common::test_config;
use nyx_scanner::commands::incremental::{Pass2Stats, force_verify, last_pass2_stats};
use nyx_scanner::commands::scan::{Diag, scan_with_index_parallel};
use nyx_scanner::database::index::Indexer;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The pass-2 counters are process-wide, so scans in this binary run one
/// at a time.
static SERIAL: Mutex<()> = Mutex::new(());

struct Project {
    _td: tempfile::TempDir,
    root: PathBuf,
    db: PathBuf,
}

impl Project {
    fn from_fixture(name: &str) -> Self {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let p = Self::empty();
        for entry in std::fs::read_dir(&src).expect("fixture dir") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                std::fs::copy(&path, p.root.join(path.file_name().unwrap())).expect("copy");
            }
        }
        p
    }

    fn empty() -> Self {
        let td = tempfile::tempdir().expect("tempdir");
        let root = td.path().join("proj");
        std::fs::create_dir(&root).expect("mkdir");
        let root = root.canonicalize().expect("canonical root");
        let db = td.path().join("index.sqlite");
        Project { _td: td, root, db }
    }

    fn write(&self, rel: &str, body: &str) {
        std::fs::write(self.root.join(rel), body).expect("write");
    }

    fn append(&self, rel: &str, tail: &str) {
        let path = self.root.join(rel);
        let mut body = std::fs::read_to_string(&path).expect("read");
        body.push_str(tail);
        std::fs::write(path, body).expect("write");
    }

    fn remove(&self, rel: &str) {
        std::fs::remove_file(self.root.join(rel)).expect("remove");
    }

    fn indexed(&self, verify: bool) -> (Vec<Diag>, Pass2Stats) {
        force_verify(verify);
        let cfg = test_config(AnalysisMode::Full);
        let pool = Indexer::init(&self.db).expect("init index");
        let diags = scan_with_index_parallel("incr", Arc::clone(&pool), &cfg, false, &self.root)
            .expect("indexed scan");
        force_verify(false);
        (diags, last_pass2_stats())
    }

    fn full(&self) -> Vec<Diag> {
        let cfg = test_config(AnalysisMode::Full);
        nyx_scanner::scan_no_index(&self.root, &cfg).expect("full scan")
    }

    /// Indexed scan, checked against a full scan and against a verifying
    /// rescan.  Returns the counters of the first indexed scan.
    fn step(&self, what: &str) -> Pass2Stats {
        let (diags, stats) = self.indexed(false);
        assert_same(&self.full(), &diags, &self.root, what);
        let (verified, vstats) = self.indexed(true);
        assert_eq!(
            vstats.verify_mismatches, 0,
            "{what}: a reused unit differs from a fresh analysis"
        );
        assert_eq!(
            vstats.units_analysed, 0,
            "{what}: a rescan with no edits must reuse every unit, got {vstats:?}"
        );
        assert_same(&diags, &verified, &self.root, what);
        stats
    }
}

/// Every finding field that comes out of pass 2, with the scan root
/// stripped so two trees could be compared.
fn canonical(diags: &[Diag], root: &Path) -> Vec<String> {
    let root = root.to_string_lossy();
    let mut out: Vec<String> = diags
        .iter()
        .map(|d| {
            serde_json::to_string(d)
                .expect("diag json")
                .replace(root.as_ref(), "<root>")
        })
        .collect();
    out.sort();
    out
}

fn assert_same(expected: &[Diag], actual: &[Diag], root: &Path, what: &str) {
    let a = canonical(expected, root);
    let b = canonical(actual, root);
    if a != b {
        let only_a: Vec<_> = a.iter().filter(|x| !b.contains(x)).collect();
        let only_b: Vec<_> = b.iter().filter(|x| !a.contains(x)).collect();
        panic!(
            "{what}: findings differ\nonly in reference ({}):\n{}\nonly in indexed ({}):\n{}",
            only_a.len(),
            only_a
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            only_b.len(),
            only_b
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

fn lock() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn unchanged_rescan_reuses_every_unit() {
    let _g = lock();
    for fixture in [
        "cross_file_js_sqli",
        "cross_file_ssa_sanitizer",
        "cross_file_scc_convergence",
        "auth_analysis_cross_file_caller_scope",
        "rust_module_path_resolution",
    ] {
        let p = Project::from_fixture(fixture);
        let cold = p.step(&format!("{fixture} cold"));
        assert_eq!(
            cold.units_reused, 0,
            "{fixture}: nothing to reuse on a cold scan"
        );
        assert!(
            cold.units_analysed > 0,
            "{fixture}: cold scan analyses units"
        );
    }
}

#[test]
fn recursive_batch_is_reused_as_one_unit() {
    let _g = lock();
    let p = Project::from_fixture("cross_file_scc_convergence");
    let cold = p.step("scc cold");
    assert!(
        !p.full().is_empty(),
        "fixture must produce the cross-file SCC finding"
    );
    // Editing a file outside the cycle does not reopen it.
    p.write("unrelated.py", "def noop():\n    return 1\n");
    let after = p.step("scc after unrelated add");
    assert!(after.units_analysed < cold.units_analysed);
    // Editing a member re-runs the fixed-point batch.
    p.append("transform.py", "\n# trailing note\n");
    let edited = p.step("scc after member edit");
    assert!(edited.units_analysed >= 1);
}

#[test]
fn trailing_comment_reanalyses_only_the_edited_file() {
    let _g = lock();
    let p = Project::from_fixture("cross_file_js_sqli");
    p.step("cold");
    p.append("search.js", "\n// trailing note\n");
    let stats = p.step("after comment");
    assert_eq!(
        stats.units_analysed, 1,
        "the callee's summary did not change, so its caller must be reused: {stats:?}"
    );
}

#[test]
fn changing_a_callee_updates_its_caller() {
    let _g = lock();
    let p = Project::from_fixture("cross_file_ssa_sanitizer");
    p.step("cold");
    let before = p.full().len();
    p.write(
        "sanitizer.py",
        "import shlex\n\ndef clean_html(data):\n    return shlex.quote(data)\n",
    );
    let stats = p.step("callee now shell-escapes");
    assert!(
        stats.units_analysed >= 2,
        "caller must be re-analysed: {stats:?}"
    );
    p.write("sanitizer.py", "def clean_html(data):\n    return data\n");
    p.step("callee now passes through");
    let _ = before;
}

#[test]
fn new_definition_resolves_a_previously_unresolved_call() {
    let _g = lock();
    let p = Project::empty();
    p.write(
        "app.py",
        "import os\nfrom util import run_it\n\ndef handler():\n    data = os.environ[\"INPUT\"]\n    run_it(data)\n",
    );
    p.write("other.py", "def unrelated(x):\n    return x + 1\n");
    p.step("cold, callee missing");
    let without = p.full();

    p.write(
        "util.py",
        "import subprocess\n\ndef run_it(cmd):\n    subprocess.call(cmd, shell=True)\n",
    );
    p.step("callee added");
    let with = p.full();
    assert!(
        with.len() > without.len(),
        "adding the sink-bearing callee must add a finding"
    );

    p.remove("util.py");
    p.step("callee deleted");
    assert_eq!(canonical(&p.full(), &p.root), canonical(&without, &p.root));
}

#[test]
fn settings_change_drops_the_cache() {
    let _g = lock();
    let p = Project::from_fixture("cross_file_js_sqli");
    p.step("cold");
    let mut cfg = test_config(AnalysisMode::Full);
    cfg.scanner.enable_state_analysis = !cfg.scanner.enable_state_analysis;
    let pool = Indexer::init(&p.db).expect("init");
    scan_with_index_parallel("incr", Arc::clone(&pool), &cfg, false, &p.root).expect("scan");
    let stats = last_pass2_stats();
    assert_eq!(
        stats.units_reused, 0,
        "units from other settings must not be reused"
    );
}

#[test]
fn line_inserted_above_a_callee_reanalyses_only_its_file() {
    let _g = lock();
    let p = Project::empty();
    // A method call on an instance of another file's class is analysed by
    // inlining the callee's body, which records the body as a dependency.
    p.write(
        "util.py",
        "class Ctx:\n    def clean(self, s):\n        return s.strip()\n",
    );
    p.write(
        "app.py",
        "import os\nimport subprocess\nfrom util import Ctx\n\ndef run():\n    c = Ctx()\n    subprocess.call(c.clean(os.environ[\"X\"]), shell=True)\n",
    );
    p.step("cold");
    assert!(!p.full().is_empty(), "the flow through clean must report");
    let body = std::fs::read_to_string(p.root.join("util.py")).unwrap();
    p.write("util.py", &format!("# moved down by a line\n{body}"));
    let stats = p.step("after a line above clean");
    assert_eq!(
        stats.units_analysed, 1,
        "moving clean without changing it must not re-run its caller: {stats:?}"
    );
}

#[test]
fn line_inserted_above_a_callee_with_its_own_source_keeps_parity() {
    let _g = lock();
    let p = Project::empty();
    p.write(
        "src.py",
        "import os\n\ndef read_input():\n    return os.environ[\"INPUT\"]\n",
    );
    p.write(
        "app.py",
        "import subprocess\nfrom src import read_input\n\ndef run():\n    subprocess.call(read_input(), shell=True)\n",
    );
    p.step("cold");
    let body = std::fs::read_to_string(p.root.join("src.py")).unwrap();
    p.write("src.py", &format!("# moved down by a line\n{body}"));
    p.step("after a line above read_input");
}

#[test]
fn same_named_function_that_does_not_change_a_resolution_keeps_its_callers() {
    let _g = lock();
    let p = Project::empty();
    p.write(
        "app.py",
        "import os\nfrom util import run_it\n\ndef handler():\n    data = os.environ[\"INPUT\"]\n    run_it(data)\n",
    );
    p.write(
        "util.py",
        "import subprocess\n\ndef run_it(cmd):\n    subprocess.call(cmd, shell=True)\n",
    );
    p.step("cold");
    // Two parameters: `run_it(data)` still resolves to util.run_it.
    p.write("other.py", "def run_it(a, b):\n    return a\n");
    let stats = p.step("after a two-parameter run_it");
    assert_eq!(
        stats.units_analysed, 1,
        "only the new file is analysed: {stats:?}"
    );
}

#[test]
fn resaving_one_of_two_same_named_definitions_reanalyses_only_it() {
    let _g = lock();
    let p = Project::empty();
    p.write("a.py", "def helper(x):\n    return x\n");
    p.write("b.py", "def helper(x):\n    return x + \"!\"\n");
    p.write(
        "app.py",
        "import os\nimport subprocess\nfrom a import helper\n\ndef run():\n    subprocess.call(helper(os.environ[\"X\"]), shell=True)\n",
    );
    p.step("cold");
    for round in 0..3 {
        p.append("b.py", "\n# note\n");
        let stats = p.step(&format!("after re-saving b.py, round {round}"));
        assert_eq!(
            stats.units_analysed, 1,
            "re-saving b.py must not re-run app.py, which resolves helper the same way: {stats:?}"
        );
    }
}
