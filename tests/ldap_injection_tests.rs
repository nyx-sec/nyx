//! Phase 02 integration tests for `Cap::LDAP_INJECTION`.
//!
//! Each supported language has three fixtures under
//! `tests/fixtures/ldap_injection/<lang>/`:
//!
//! * `unsafe_ldap_search.*` — taint flows from a request / env source into
//!   an LDAP search/query API.  Must produce at least one
//!   `taint-ldap-injection` finding at HIGH severity.
//! * `safe_ldap_search.*` — same data flow, but routed through the
//!   language-specific LDAP-filter escape sanitizer.  Must produce zero
//!   `taint-ldap-injection` findings.
//! * `baseline_constant_ldap.*` — filter is a literal constant.  Must
//!   produce zero `taint-ldap-injection` findings.
//!
//! The Java fixture additionally relies on type-qualified resolution
//! rewriting `ctx.search` → `LdapClient.search` via the new
//! `TypeKind::LdapClient` declared-type mapping (constraint solver).
//! JS/TS, Python, Ruby, and Go fixtures rely on the same mechanism keyed
//! off the constructor (`ldap.createClient` / `ldap.initialize` /
//! `Net::LDAP.new` / `ldap.DialURL`).

mod common;

use common::count_by_prefix;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

const RULE_PREFIX: &str = "taint-ldap-injection";

fn ldap_fixture_dir(lang: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("ldap_injection")
        .join(lang)
}

/// Test-local config override: enable `include_nonprod` so fixtures under
/// `tests/fixtures/...` (which `is_nonprod_path` would otherwise classify
/// as nonprod and downgrade by one severity tier) report their actual
/// registry severity.  Mirrors `common::test_config` in every other respect.
fn ldap_test_config() -> Config {
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
    let cfg = ldap_test_config();
    nyx_scanner::scan_no_index(path, &cfg).expect("scan_no_index should succeed")
}

fn diags_for_file(dir: &Path, file_suffix: &str) -> Vec<Diag> {
    let all = scan_dir(dir);
    // Match on the trailing path component, not a substring suffix; otherwise
    // `unsafe_ldap_search.php` would be picked up by `safe_ldap_search.php`'s
    // `ends_with` filter and the safe-fixture clean assertion would
    // accidentally see findings from its sibling.
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
    let dir = ldap_fixture_dir(lang);
    let diags = diags_for_file(&dir, file_suffix);
    let count = count_by_prefix(&diags, RULE_PREFIX);
    assert_eq!(
        count, 1,
        "{lang}/{file_suffix}: expected exactly 1 {RULE_PREFIX} finding, got {count}.\n\
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
    assert_eq!(
        high, 1,
        "{lang}/{file_suffix}: expected exactly 1 HIGH-severity {RULE_PREFIX} finding, got {high}.\n\
         All matching: {:#?}",
        diags
            .iter()
            .filter(|d| d.id.starts_with(RULE_PREFIX))
            .map(|d| format!("{}:{} [{}]", d.path, d.line, d.severity.as_db_str()))
            .collect::<Vec<_>>(),
    );
}

fn assert_clean(lang: &str, file_suffix: &str) {
    let dir = ldap_fixture_dir(lang);
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
fn java_dir_context_search_with_tainted_filter_fires() {
    assert_unsafe("java", "UnsafeLdapSearch.java");
}

#[test]
fn java_filter_encode_sanitizes() {
    assert_clean("java", "SafeLdapSearch.java");
}

#[test]
fn java_baseline_constant_filter_does_not_fire() {
    assert_clean("java", "BaselineConstantLdap.java");
}

// ── Python ───────────────────────────────────────────────────────────────

#[test]
fn python_search_s_with_tainted_filter_fires() {
    assert_unsafe("python", "unsafe_ldap_search.py");
}

#[test]
fn python_escape_filter_chars_sanitizes() {
    assert_clean("python", "safe_ldap_search.py");
}

#[test]
fn python_baseline_constant_filter_does_not_fire() {
    assert_clean("python", "baseline_constant_ldap.py");
}

// ── PHP ──────────────────────────────────────────────────────────────────

#[test]
fn php_ldap_search_with_tainted_filter_fires() {
    assert_unsafe("php", "unsafe_ldap_search.php");
}

#[test]
fn php_ldap_escape_sanitizes() {
    assert_clean("php", "safe_ldap_search.php");
}

#[test]
fn php_baseline_constant_filter_does_not_fire() {
    assert_clean("php", "baseline_constant_ldap.php");
}

// ── JavaScript ───────────────────────────────────────────────────────────

#[test]
fn javascript_ldapjs_search_with_tainted_filter_fires() {
    assert_unsafe("javascript", "unsafe_ldap_search.js");
}

#[test]
fn javascript_ldap_escape_sanitizes() {
    assert_clean("javascript", "safe_ldap_search.js");
}

#[test]
fn javascript_baseline_constant_filter_does_not_fire() {
    assert_clean("javascript", "baseline_constant_ldap.js");
}

// ── TypeScript ───────────────────────────────────────────────────────────

#[test]
fn typescript_ldapjs_search_with_tainted_filter_fires() {
    assert_unsafe("typescript", "unsafe_ldap_search.ts");
}

#[test]
fn typescript_ldap_escape_sanitizes() {
    assert_clean("typescript", "safe_ldap_search.ts");
}

#[test]
fn typescript_baseline_constant_filter_does_not_fire() {
    assert_clean("typescript", "baseline_constant_ldap.ts");
}

// ── C ───────────────────────────────────────────────────────────────────

#[test]
fn c_ldap_search_ext_s_with_tainted_filter_fires() {
    assert_unsafe("c", "unsafe_ldap_search.c");
}

#[test]
fn c_sanitize_helper_clears_cap() {
    assert_clean("c", "safe_ldap_search.c");
}

#[test]
fn c_baseline_constant_filter_does_not_fire() {
    assert_clean("c", "baseline_constant_ldap.c");
}

// ── C++ ─────────────────────────────────────────────────────────────────

#[test]
fn cpp_ldap_search_ext_s_with_tainted_filter_fires() {
    assert_unsafe("cpp", "unsafe_ldap_search.cpp");
}

#[test]
fn cpp_sanitize_helper_clears_cap() {
    assert_clean("cpp", "safe_ldap_search.cpp");
}

#[test]
fn cpp_baseline_constant_filter_does_not_fire() {
    assert_clean("cpp", "baseline_constant_ldap.cpp");
}

// ── Ruby ────────────────────────────────────────────────────────────────

#[test]
fn ruby_net_ldap_search_with_tainted_filter_fires() {
    assert_unsafe("ruby", "unsafe_ldap_search.rb");
}

#[test]
fn ruby_filter_escape_sanitizes() {
    assert_clean("ruby", "safe_ldap_search.rb");
}

#[test]
fn ruby_baseline_constant_filter_does_not_fire() {
    assert_clean("ruby", "baseline_constant_ldap.rb");
}

// ── Go ──────────────────────────────────────────────────────────────────

#[test]
fn go_ldap_search_request_with_tainted_filter_fires() {
    assert_unsafe("go", "unsafe_ldap_search.go");
}

#[test]
fn go_escape_filter_sanitizes() {
    assert_clean("go", "safe_ldap_search.go");
}

#[test]
fn go_baseline_constant_filter_does_not_fire() {
    assert_clean("go", "baseline_constant_ldap.go");
}
