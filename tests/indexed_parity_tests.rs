//! Parity tests: same fixture, same mode, indexed vs non-indexed scan paths
//! MUST produce identical diagnostics.
//!
//! This invariant is release-critical. A scanner whose output depends on
//! whether indexing is enabled is not reliable for CI gates, suppressions,
//! or triage workflows. The tests here lock parity as a hard contract.
//!
//! ## What counts as "identical"
//!
//! We compare diagnostics as an unordered multiset of fingerprints:
//!
//! ```text
//! (path_relative_to_fixture, line, col, severity_str, rule_id)
//! ```
//!
//! Path-dependent fields (absolute path, rank_score derived from ordering,
//! evidence snippets that cite absolute paths) are excluded from the
//! fingerprint because they are not expected to diverge in meaning, only
//! in representation.
//!
//! If an engine change is justified in making indexed and non-indexed diverge,
//! the diff must be *explicit* in the test, not papered over by a loose
//! comparison. There are currently no such documented exceptions.

#[allow(dead_code)]
mod common;

use common::test_config;
use nyx_scanner::commands::index::build_index;
use nyx_scanner::commands::scan::{Diag, scan_with_index_parallel};
use nyx_scanner::database::index::Indexer;
use nyx_scanner::utils::config::AnalysisMode;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

// Indexed scan helpers each open a fresh SQLite r2d2 pool (max_size ~ ncpus+4)
// plus rayon-driven tree-sitter parsing across the fixture tree.  Cargo runs
// every `#[test]` in this binary in parallel by default, so 30+ indexed scans
// race to acquire file descriptors at once.  On sandboxes with a low per-process
// fd limit (e.g. the pitboss test harness) this exhausts EMFILE before the
// sqlite WAL/SHM files can be opened, surfacing as `Os { code: 24, … "Too many
// open files" }` panics from `build_index` / `scan_with_index_parallel`.
//
// Serialise the indexed entry points so only one indexed scan is in flight at
// a time.  Non-indexed (`scan_no_index`) tests still run in parallel because
// they hold far fewer fds and never trip the limit.  Total runtime regression
// is small (the indexed scans dominate the wall clock either way) and the
// suite becomes deterministic under fd-constrained environments.
fn indexed_scan_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fingerprint
// ─────────────────────────────────────────────────────────────────────────────

/// Stable cross-path fingerprint for a single diagnostic.
///
/// Intentionally **does not** include:
///  - `path` (absolute): normalized to fixture-relative form instead.
///  - `rank_score` / `rank_reason`: derived from post-processing ordering.
///  - `evidence` snippets: contain absolute paths and formatting variations
///    that are representation-level, not analysis-level.
///  - `confidence`: derived deterministically from the fields we *do* compare;
///    if those match, confidence matches.
///
/// **Does** include:
///  - `(line, col)`, where the finding is reported.
///  - `severity`, the analyst-visible triage axis.
///  - `rule_id`, which detector fired.
///  - `path_validated`, semantic axis used by triage UIs.
///
/// If any of these differ between paths, the engine has genuinely produced
/// different *findings*, not just different metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Fingerprint {
    rel_path: String,
    line: usize,
    col: usize,
    severity: &'static str,
    rule_id: String,
    path_validated: bool,
}

fn fingerprint(diag: &Diag, fixture_root: &Path) -> Fingerprint {
    let abs = Path::new(&diag.path);
    let rel = abs
        .strip_prefix(fixture_root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| diag.path.clone());
    // Normalize Windows-style separators on UNIX for deterministic compare.
    let rel = rel.replace('\\', "/");
    Fingerprint {
        rel_path: rel,
        line: diag.line,
        col: diag.col,
        severity: diag.severity.as_db_str(),
        rule_id: diag.id.clone(),
        path_validated: diag.path_validated,
    }
}

fn fingerprints(diags: &[Diag], fixture_root: &Path) -> Vec<Fingerprint> {
    let mut v: Vec<Fingerprint> = diags.iter().map(|d| fingerprint(d, fixture_root)).collect();
    v.sort();
    v
}

// ─────────────────────────────────────────────────────────────────────────────
//  Scan helpers
// ─────────────────────────────────────────────────────────────────────────────

fn scan_no_index(fixture_root: &Path, mode: AnalysisMode) -> Vec<Diag> {
    let cfg = test_config(mode);
    nyx_scanner::scan_no_index(fixture_root, &cfg).expect("scan_no_index should succeed")
}

/// Cold indexed scan: fresh DB, build index, then run indexed scan.
fn scan_indexed_cold(fixture_root: &Path, mode: AnalysisMode) -> (Vec<Diag>, PathBuf) {
    // See `indexed_scan_lock` rationale: serialise indexed scans to avoid
    // EMFILE panics under fd-constrained sandboxes.
    let _guard = indexed_scan_lock().lock().unwrap_or_else(|e| e.into_inner());
    let cfg = test_config(mode);
    let td = tempfile::tempdir().expect("tempdir");
    let db_path = td.path().join("parity.sqlite");

    build_index("parity", fixture_root, &db_path, &cfg, false).expect("build_index");
    let pool = Indexer::init(&db_path).expect("init pool");
    let diags = scan_with_index_parallel("parity", Arc::clone(&pool), &cfg, false, fixture_root)
        .expect("indexed scan");

    // Keep tempdir alive by returning the db_path; actually return ownership of td.
    // We leak by forgetting the tempdir since the caller only needs the diags.
    // (Leaving tempdir scope drops it; we want it cleaned up, so we *don't* forget.)
    // The tempdir drops here and removes the file, diags are already owned.
    std::mem::drop(td);
    (diags, db_path)
}

/// Warm indexed scan: build index once, then run indexed scan **twice** on the
/// same pool.  The second scan tests that cached artefacts don't perturb
/// output.
fn scan_indexed_warm(fixture_root: &Path, mode: AnalysisMode) -> Vec<Diag> {
    let _guard = indexed_scan_lock().lock().unwrap_or_else(|e| e.into_inner());
    let cfg = test_config(mode);
    let td = tempfile::tempdir().expect("tempdir");
    let db_path = td.path().join("parity.sqlite");

    build_index("parity", fixture_root, &db_path, &cfg, false).expect("build_index");
    let pool = Indexer::init(&db_path).expect("init pool");
    let _cold = scan_with_index_parallel("parity", Arc::clone(&pool), &cfg, false, fixture_root)
        .expect("cold indexed scan");
    let warm = scan_with_index_parallel("parity", Arc::clone(&pool), &cfg, false, fixture_root)
        .expect("warm indexed scan");
    std::mem::drop(td);
    warm
}

// ─────────────────────────────────────────────────────────────────────────────
//  Diff reporting
// ─────────────────────────────────────────────────────────────────────────────

fn format_fingerprint_set_diff(
    label_a: &str,
    a: &[Fingerprint],
    label_b: &str,
    b: &[Fingerprint],
) -> String {
    // Count multiplicity of each fingerprint, divergence can be a changed
    // *count* even when both sides contain the same key.
    let mut count_a: BTreeMap<&Fingerprint, usize> = BTreeMap::new();
    let mut count_b: BTreeMap<&Fingerprint, usize> = BTreeMap::new();
    for fp in a {
        *count_a.entry(fp).or_default() += 1;
    }
    for fp in b {
        *count_b.entry(fp).or_default() += 1;
    }

    let all_keys: std::collections::BTreeSet<&Fingerprint> =
        count_a.keys().chain(count_b.keys()).copied().collect();

    let mut only_a = Vec::new();
    let mut only_b = Vec::new();
    let mut diff_counts = Vec::new();
    for k in all_keys {
        let ca = *count_a.get(k).unwrap_or(&0);
        let cb = *count_b.get(k).unwrap_or(&0);
        match (ca, cb) {
            (a, 0) if a > 0 => only_a.push((k, a)),
            (0, b) if b > 0 => only_b.push((k, b)),
            (a, b) if a != b => diff_counts.push((k, a, b)),
            _ => {}
        }
    }

    let mut out = String::new();
    out.push_str(&format!(
        "\n=== Parity diff ({label_a} vs {label_b}) ===\n\
         {label_a}: {} findings, {label_b}: {} findings\n",
        a.len(),
        b.len()
    ));
    if !only_a.is_empty() {
        out.push_str(&format!("\nOnly in {label_a} ({}):\n", only_a.len()));
        for (fp, n) in only_a {
            out.push_str(&format!(
                "  {} x{n}  {}:{}:{}  [{}]  {}{}\n",
                if n > 1 { "" } else { " " },
                fp.rel_path,
                fp.line,
                fp.col,
                fp.severity,
                fp.rule_id,
                if fp.path_validated {
                    " (validated)"
                } else {
                    ""
                }
            ));
        }
    }
    if !only_b.is_empty() {
        out.push_str(&format!("\nOnly in {label_b} ({}):\n", only_b.len()));
        for (fp, n) in only_b {
            out.push_str(&format!(
                "  {} x{n}  {}:{}:{}  [{}]  {}{}\n",
                if n > 1 { "" } else { " " },
                fp.rel_path,
                fp.line,
                fp.col,
                fp.severity,
                fp.rule_id,
                if fp.path_validated {
                    " (validated)"
                } else {
                    ""
                }
            ));
        }
    }
    if !diff_counts.is_empty() {
        out.push_str(&format!("\nCount mismatch ({}):\n", diff_counts.len()));
        for (fp, na, nb) in diff_counts {
            out.push_str(&format!(
                "  {label_a}={na} {label_b}={nb}  {}:{}:{}  [{}]  {}\n",
                fp.rel_path, fp.line, fp.col, fp.severity, fp.rule_id
            ));
        }
    }
    out
}

fn assert_parity(
    label_a: &str,
    a: &[Fingerprint],
    label_b: &str,
    b: &[Fingerprint],
    fixture_name: &str,
) {
    if a == b {
        return;
    }
    panic!(
        "[{fixture_name}] Parity violation between {label_a} and {label_b}:{}",
        format_fingerprint_set_diff(label_a, a, label_b, b)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Parity test driver
// ─────────────────────────────────────────────────────────────────────────────

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn run_parity(fixture_name: &str, mode: AnalysisMode) {
    let dir = fixture_path(fixture_name);
    let no_index_diags = scan_no_index(&dir, mode);
    let (indexed_diags, _db) = scan_indexed_cold(&dir, mode);

    let a = fingerprints(&no_index_diags, &dir);
    let b = fingerprints(&indexed_diags, &dir);
    assert_parity("no-index", &a, "indexed-cold", &b, fixture_name);
}

fn run_parity_warm(fixture_name: &str, mode: AnalysisMode) {
    let dir = fixture_path(fixture_name);
    let no_index_diags = scan_no_index(&dir, mode);
    let warm_diags = scan_indexed_warm(&dir, mode);

    let a = fingerprints(&no_index_diags, &dir);
    let b = fingerprints(&warm_diags, &dir);
    assert_parity("no-index", &a, "indexed-warm", &b, fixture_name);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fixtures under parity contract, Full mode
// ─────────────────────────────────────────────────────────────────────────────
//
// Representative mix covering all 10 supported languages plus cross-file
// resolution, framework-specific rules, and auth analysis.  Every fixture
// listed here is a hard parity invariant: a regression must either be fixed
// or explicitly documented (see bottom of this file).

const FULL_MODE_PARITY_FIXTURES: &[&str] = &[
    // Cross-file taint resolution across languages
    "cross_file_js_sqli",
    "cross_file_py_const_passthrough",
    "cross_file_go_handler_exec",
    "cross_file_java_sqli",
    "cross_file_taint",
    "cross_file_ssa_propagation",
    "cross_file_ssa_sanitizer",
    "cross_file_scc_convergence",
    // Single-language cross-file + framework
    "rust_web_app",
    "rust_framework_rules",
    "rust_module_path_resolution",
    "express_app",
    "flask_app",
    "go_server",
    "java_service",
    // Auth analysis
    "auth_analysis_integration",
    "auth_analysis_frameworks_integration",
    // AST / pattern heavy
    "patterns",
    // Termination + state
    "taint_termination",
    "state",
    // Noise-reduction / suppression
    "route_registration_noise",
];

#[test]
fn parity_full_cross_file_js_sqli() {
    run_parity("cross_file_js_sqli", AnalysisMode::Full);
}

#[test]
fn parity_full_cross_file_py_const_passthrough() {
    run_parity("cross_file_py_const_passthrough", AnalysisMode::Full);
}

#[test]
fn parity_full_cross_file_go_handler_exec() {
    run_parity("cross_file_go_handler_exec", AnalysisMode::Full);
}

#[test]
fn parity_full_cross_file_java_sqli() {
    run_parity("cross_file_java_sqli", AnalysisMode::Full);
}

#[test]
fn parity_full_cross_file_taint() {
    run_parity("cross_file_taint", AnalysisMode::Full);
}

#[test]
fn parity_full_cross_file_ssa_propagation() {
    run_parity("cross_file_ssa_propagation", AnalysisMode::Full);
}

#[test]
fn parity_full_cross_file_ssa_sanitizer() {
    run_parity("cross_file_ssa_sanitizer", AnalysisMode::Full);
}

#[test]
fn parity_full_cross_file_scc_convergence() {
    run_parity("cross_file_scc_convergence", AnalysisMode::Full);
}

#[test]
fn parity_full_rust_web_app() {
    run_parity("rust_web_app", AnalysisMode::Full);
}

#[test]
fn parity_full_rust_framework_rules() {
    run_parity("rust_framework_rules", AnalysisMode::Full);
}

#[test]
fn parity_full_rust_module_path_resolution() {
    run_parity("rust_module_path_resolution", AnalysisMode::Full);
}

#[test]
fn parity_full_express_app() {
    run_parity("express_app", AnalysisMode::Full);
}

#[test]
fn parity_full_flask_app() {
    run_parity("flask_app", AnalysisMode::Full);
}

#[test]
fn parity_full_go_server() {
    run_parity("go_server", AnalysisMode::Full);
}

#[test]
fn parity_full_java_service() {
    run_parity("java_service", AnalysisMode::Full);
}

#[test]
fn parity_full_auth_analysis_integration() {
    run_parity("auth_analysis_integration", AnalysisMode::Full);
}

#[test]
fn parity_full_auth_analysis_frameworks_integration() {
    run_parity("auth_analysis_frameworks_integration", AnalysisMode::Full);
}

#[test]
fn parity_full_patterns() {
    run_parity("patterns", AnalysisMode::Full);
}

#[test]
fn parity_full_taint_termination() {
    run_parity("taint_termination", AnalysisMode::Full);
}

#[test]
fn parity_full_state() {
    run_parity("state", AnalysisMode::Full);
}

#[test]
fn parity_full_route_registration_noise() {
    run_parity("route_registration_noise", AnalysisMode::Full);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Non-Full analysis modes, the Taint-mode filter divergence lives here
// ─────────────────────────────────────────────────────────────────────────────
//
// Taint mode is the narrowest CFG-capable mode.  Historically the indexed
// path filtered output to `taint*`/`cfg-*` rule ids while the non-indexed
// path did not, silently dropping state-model and auth-analysis findings
// from indexed scans.  This test pins the fix.

#[test]
fn parity_taint_cross_file_js_sqli() {
    run_parity("cross_file_js_sqli", AnalysisMode::Taint);
}

#[test]
fn parity_taint_cross_file_py_const_passthrough() {
    run_parity("cross_file_py_const_passthrough", AnalysisMode::Taint);
}

#[test]
fn parity_taint_auth_analysis_integration() {
    // This fixture exercises auth_analysis rules, which were previously
    // dropped by the indexed Taint-mode filter.
    run_parity("auth_analysis_integration", AnalysisMode::Taint);
}

#[test]
fn parity_cfg_mode_cross_file_js_sqli() {
    run_parity("cross_file_js_sqli", AnalysisMode::Cfg);
}

#[test]
fn parity_ast_mode_patterns() {
    run_parity("patterns", AnalysisMode::Ast);
}

/// The `state/` fixture is dense with state-model findings (`rs.resource.*`,
/// `auth.*`).  These are produced by `run_cfg_analyses` under *any* CFG-
/// capable mode, including Taint-only.  A historical filter in the indexed
/// path dropped everything that wasn't `taint*`/`cfg-*` from Taint-mode
/// output, silently swallowing state findings, this test pins that fix.
#[test]
fn parity_taint_state_fixture() {
    run_parity("state", AnalysisMode::Taint);
}

#[test]
fn parity_cfg_state_fixture() {
    run_parity("state", AnalysisMode::Cfg);
}

#[test]
fn parity_ast_state_fixture() {
    run_parity("state", AnalysisMode::Ast);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Warm-scan parity, detects caching bugs in the indexed path
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parity_warm_cross_file_js_sqli() {
    run_parity_warm("cross_file_js_sqli", AnalysisMode::Full);
}

#[test]
fn parity_warm_auth_analysis_integration() {
    run_parity_warm("auth_analysis_integration", AnalysisMode::Full);
}

#[test]
fn parity_warm_patterns_ast_mode() {
    run_parity_warm("patterns", AnalysisMode::Ast);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sweep: every fixture in FULL_MODE_PARITY_FIXTURES must pass Full-mode parity
// ─────────────────────────────────────────────────────────────────────────────
//
// The explicit per-fixture tests above give quick signal on what broke; this
// sweep locks the list itself so adding a fixture to the "release-critical"
// set is a deliberate choice.  Run with: `cargo test parity_full_sweep -- --nocapture`.

#[test]
fn parity_full_sweep_all_fixtures() {
    let mut failures: Vec<(String, String)> = Vec::new();
    for name in FULL_MODE_PARITY_FIXTURES {
        let dir = fixture_path(name);
        let a = fingerprints(&scan_no_index(&dir, AnalysisMode::Full), &dir);
        let (indexed, _db) = scan_indexed_cold(&dir, AnalysisMode::Full);
        let b = fingerprints(&indexed, &dir);
        if a != b {
            failures.push((
                (*name).to_string(),
                format_fingerprint_set_diff("no-index", &a, "indexed-cold", &b),
            ));
        }
    }

    if !failures.is_empty() {
        let mut msg = format!(
            "parity sweep failed for {} / {} fixtures:\n",
            failures.len(),
            FULL_MODE_PARITY_FIXTURES.len()
        );
        for (fixture, diff) in &failures {
            msg.push_str(&format!("\n── {fixture} ──{diff}\n"));
        }
        panic!("{msg}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Principled divergences (documented exceptions)
// ─────────────────────────────────────────────────────────────────────────────
//
// None. Release-critical modes (Full, Taint, Cfg, Ast) must match bit-for-bit
// on the finding fingerprint.  If you think you need to add an exception,
// the test above should be the primary gate, don't loosen parity without
// writing a test that demonstrates *why* the divergence is acceptable.
