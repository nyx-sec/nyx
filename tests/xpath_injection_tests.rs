//! Phase 03 integration tests for `Cap::XPATH_INJECTION`.
//!
//! Each supported language has three fixtures under
//! `tests/fixtures/xpath_injection/<lang>/`:
//!
//! * `unsafe_xpath_query.*` — taint flows from a request / env source into
//!   an XPath evaluate / select / query API.  Must produce at least one
//!   `taint-xpath-injection` finding at HIGH severity.
//! * `safe_xpath_query.*` — same data flow, but routed through a
//!   developer-named `escape_xpath` / `escapeXpath` / `sanitize_*` helper.
//!   Must produce zero `taint-xpath-injection` findings.
//! * `baseline_constant_xpath.*` — expression is a literal constant.  Must
//!   produce zero `taint-xpath-injection` findings.

mod common;

use common::count_by_prefix;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

const RULE_PREFIX: &str = "taint-xpath-injection";

fn xpath_fixture_dir(lang: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("xpath_injection")
        .join(lang)
}

fn xpath_test_config() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.scanner.enable_state_analysis = true;
    cfg.scanner.enable_auth_analysis = true;
    cfg.scanner.include_nonprod = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 64;
    cfg.performance.channel_multiplier = 1;
    cfg
}

fn scan_dir(path: &Path) -> Vec<Diag> {
    let cfg = xpath_test_config();
    nyx_scanner::scan_no_index(path, &cfg).expect("scan_no_index should succeed")
}

fn diags_for_file(dir: &Path, file_suffix: &str) -> Vec<Diag> {
    let all = scan_dir(dir);
    all.into_iter()
        .filter(|d| {
            std::path::Path::new(&d.path)
                .file_name()
                .and_then(|s| s.to_str())
                == Some(file_suffix)
        })
        .collect()
}

fn assert_unsafe(lang: &str, file_suffix: &str) {
    let dir = xpath_fixture_dir(lang);
    let diags = diags_for_file(&dir, file_suffix);
    let count = count_by_prefix(&diags, RULE_PREFIX);
    assert!(
        count >= 1,
        "{lang}/{file_suffix}: expected >=1 {RULE_PREFIX} finding, got {count}.\n\
         All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{} [{}] {}", d.path, d.line, d.severity.as_db_str(), d.id))
            .collect::<Vec<_>>(),
    );
    let high = diags
        .iter()
        .filter(|d| d.id.starts_with(RULE_PREFIX) && d.severity.as_db_str() == "HIGH")
        .count();
    assert!(
        high >= 1,
        "{lang}/{file_suffix}: expected >=1 HIGH-severity {RULE_PREFIX} finding, got {high}.\n\
         All matching: {:#?}",
        diags
            .iter()
            .filter(|d| d.id.starts_with(RULE_PREFIX))
            .map(|d| format!("{}:{} [{}]", d.path, d.line, d.severity.as_db_str()))
            .collect::<Vec<_>>(),
    );
}

fn assert_clean(lang: &str, file_suffix: &str) {
    let dir = xpath_fixture_dir(lang);
    let diags = diags_for_file(&dir, file_suffix);
    let matching: Vec<_> = diags.iter().filter(|d| d.id.starts_with(RULE_PREFIX)).collect();
    assert!(
        matching.is_empty(),
        "{lang}/{file_suffix}: expected 0 {RULE_PREFIX} findings, got {}:\n{:#?}",
        matching.len(),
        matching
            .iter()
            .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
            .collect::<Vec<_>>(),
    );
}

// ── Java ─────────────────────────────────────────────────────────────────

#[test]
fn java_xpath_evaluate_with_tainted_expr_fires() {
    assert_unsafe("java", "UnsafeXPathQuery.java");
}

#[test]
fn java_escape_xpath_sanitizes() {
    assert_clean("java", "SafeXPathQuery.java");
}

#[test]
fn java_baseline_constant_expr_does_not_fire() {
    assert_clean("java", "BaselineConstantXpath.java");
}

#[test]
fn java_parameterised_xpath_does_not_fire() {
    assert_clean("java", "ParameterizedXpath.java");
}

#[test]
fn java_tainted_expr_with_resolver_does_not_fire() {
    // Receiver-config sidecar (`src/ssa/xpath_config.rs`) clears
    // XPATH_INJECTION on `xpath.evaluate(taintedExpr, ...)` when the
    // bound XPath instance had `setXPathVariableResolver` called on it
    // first.  Without the sidecar this fixture would fire.
    assert_clean("java", "TaintedParameterizedXpath.java");
}

// ── Python ───────────────────────────────────────────────────────────────

#[test]
fn python_xpath_with_tainted_expr_fires() {
    assert_unsafe("python", "unsafe_xpath_query.py");
}

#[test]
fn python_escape_xpath_sanitizes() {
    assert_clean("python", "safe_xpath_query.py");
}

#[test]
fn python_baseline_constant_expr_does_not_fire() {
    assert_clean("python", "baseline_constant_xpath.py");
}

// ── PHP ──────────────────────────────────────────────────────────────────

#[test]
fn php_domxpath_query_with_tainted_expr_fires() {
    assert_unsafe("php", "unsafe_xpath_query.php");
}

#[test]
fn php_escape_xpath_sanitizes() {
    assert_clean("php", "safe_xpath_query.php");
}

#[test]
fn php_baseline_constant_expr_does_not_fire() {
    assert_clean("php", "baseline_constant_xpath.php");
}

// ── JavaScript ───────────────────────────────────────────────────────────

#[test]
fn javascript_xpath_select_with_tainted_expr_fires() {
    assert_unsafe("javascript", "unsafe_xpath_query.js");
}

#[test]
fn javascript_escape_xpath_sanitizes() {
    assert_clean("javascript", "safe_xpath_query.js");
}

#[test]
fn javascript_baseline_constant_expr_does_not_fire() {
    assert_clean("javascript", "baseline_constant_xpath.js");
}

// ── TypeScript ───────────────────────────────────────────────────────────

#[test]
fn typescript_xpath_select_with_tainted_expr_fires() {
    assert_unsafe("typescript", "unsafe_xpath_query.ts");
}

#[test]
fn typescript_escape_xpath_sanitizes() {
    assert_clean("typescript", "safe_xpath_query.ts");
}

#[test]
fn typescript_baseline_constant_expr_does_not_fire() {
    assert_clean("typescript", "baseline_constant_xpath.ts");
}

// ── Ruby ────────────────────────────────────────────────────────────────

#[test]
fn ruby_nokogiri_xpath_with_tainted_expr_fires() {
    assert_unsafe("ruby", "unsafe_xpath_query.rb");
}

#[test]
fn ruby_escape_xpath_sanitizes() {
    assert_clean("ruby", "safe_xpath_query.rb");
}

#[test]
fn ruby_baseline_constant_expr_does_not_fire() {
    assert_clean("ruby", "baseline_constant_xpath.rb");
}

// ── C ───────────────────────────────────────────────────────────────────

#[test]
fn c_xml_xpath_eval_with_tainted_expr_fires() {
    assert_unsafe("c", "unsafe_xpath_query.c");
}

#[test]
fn c_sanitize_helper_clears_cap() {
    assert_clean("c", "safe_xpath_query.c");
}

#[test]
fn c_baseline_constant_expr_does_not_fire() {
    assert_clean("c", "baseline_constant_xpath.c");
}

// ── C++ ─────────────────────────────────────────────────────────────────

#[test]
fn cpp_xml_xpath_eval_with_tainted_expr_fires() {
    assert_unsafe("cpp", "unsafe_xpath_query.cpp");
}

#[test]
fn cpp_sanitize_helper_clears_cap() {
    assert_clean("cpp", "safe_xpath_query.cpp");
}

#[test]
fn cpp_baseline_constant_expr_does_not_fire() {
    assert_clean("cpp", "baseline_constant_xpath.cpp");
}
