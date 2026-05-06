//! Phase 04 integration tests for `Cap::HEADER_INJECTION`.
//!
//! Each supported language has two fixtures under
//! `tests/fixtures/header_injection/<lang>/`:
//!
//! * `unsafe_set_header.*` — taint flows from a request source into a
//!   header-write API.  Must produce >=1 `taint-header-injection` HIGH.
//! * `safe_set_header.*` — same data flow, routed through a developer-named
//!   `stripCRLF` / `strip_crlf` helper.  Must produce 0 findings.

mod common;

use common::count_by_prefix;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

const RULE_PREFIX: &str = "taint-header-injection";

fn fixture_dir(lang: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("header_injection")
        .join(lang)
}

fn test_config() -> Config {
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
    nyx_scanner::scan_no_index(path, &test_config()).expect("scan_no_index should succeed")
}

fn diags_for_file(dir: &Path, file_suffix: &str) -> Vec<Diag> {
    scan_dir(dir)
        .into_iter()
        .filter(|d| {
            std::path::Path::new(&d.path)
                .file_name()
                .and_then(|s| s.to_str())
                == Some(file_suffix)
        })
        .collect()
}

fn assert_unsafe(lang: &str, file_suffix: &str) {
    let dir = fixture_dir(lang);
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
}

fn assert_clean(lang: &str, file_suffix: &str) {
    let dir = fixture_dir(lang);
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

#[test]
fn javascript_set_header_with_tainted_value_fires() {
    assert_unsafe("javascript", "unsafe_set_header.js");
}

#[test]
fn javascript_strip_crlf_sanitizes() {
    assert_clean("javascript", "safe_set_header.js");
}

#[test]
fn typescript_set_header_with_tainted_value_fires() {
    assert_unsafe("typescript", "unsafe_set_header.ts");
}

#[test]
fn typescript_strip_crlf_sanitizes() {
    assert_clean("typescript", "safe_set_header.ts");
}

#[test]
fn java_set_header_with_tainted_value_fires() {
    assert_unsafe("java", "UnsafeSetHeader.java");
}

#[test]
fn java_strip_crlf_sanitizes() {
    assert_clean("java", "SafeSetHeader.java");
}

#[test]
fn python_headers_add_with_tainted_value_fires() {
    assert_unsafe("python", "unsafe_set_header.py");
}

#[test]
fn python_strip_crlf_sanitizes() {
    assert_clean("python", "safe_set_header.py");
}

#[test]
fn php_header_with_tainted_value_fires() {
    assert_unsafe("php", "unsafe_set_header.php");
}

#[test]
fn php_strip_crlf_sanitizes() {
    assert_clean("php", "safe_set_header.php");
}

#[test]
fn ruby_subscript_set_with_tainted_value_fires() {
    assert_unsafe("ruby", "unsafe_subscript_set.rb");
}

#[test]
fn ruby_subscript_set_with_strip_crlf_sanitized() {
    assert_clean("ruby", "safe_subscript_set.rb");
}

#[test]
fn javascript_subscript_set_with_tainted_value_fires() {
    assert_unsafe("javascript", "unsafe_subscript_set.js");
}

#[test]
fn javascript_subscript_set_with_strip_crlf_sanitized() {
    assert_clean("javascript", "safe_subscript_set.js");
}

#[test]
fn typescript_subscript_set_with_tainted_value_fires() {
    assert_unsafe("typescript", "unsafe_subscript_set.ts");
}

#[test]
fn typescript_subscript_set_with_strip_crlf_sanitized() {
    assert_clean("typescript", "safe_subscript_set.ts");
}

#[test]
fn python_subscript_set_with_tainted_value_fires() {
    assert_unsafe("python", "unsafe_subscript_set.py");
}

#[test]
fn python_subscript_set_with_strip_crlf_sanitized() {
    assert_clean("python", "safe_subscript_set.py");
}

#[test]
fn go_set_header_with_tainted_value_fires() {
    assert_unsafe("go", "unsafe_set_header.go");
}

#[test]
fn go_strip_crlf_sanitizes() {
    assert_clean("go", "safe_set_header.go");
}

#[test]
fn rust_set_header_with_tainted_value_fires() {
    assert_unsafe("rust", "unsafe_set_header.rs");
}

#[test]
fn rust_strip_crlf_sanitizes() {
    assert_clean("rust", "safe_set_header.rs");
}

/// Phase 04 acceptance: PHP `header("Location: " . $url)` must surface both
/// `taint-header-injection` and `taint-open-redirect` findings on the same
/// call site.  The flat HEADER_INJECTION rule (gated `=header`, payload arg 0)
/// and the OPEN_REDIRECT co-tag (gated on the `Location:` first-arg prefix)
/// share the call node, so the multi-gate SSA dispatch must emit one finding
/// per cap.  The fixture lives under `open_redirect/php/`.
#[test]
fn php_header_location_cofires_header_injection_and_open_redirect() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("open_redirect")
        .join("php");
    let diags = diags_for_file(&dir, "unsafe_redirect.php");
    let header_count = count_by_prefix(&diags, "taint-header-injection");
    let redirect_count = count_by_prefix(&diags, "taint-open-redirect");
    assert!(
        header_count >= 1 && redirect_count >= 1,
        "expected both taint-header-injection (>=1, got {header_count}) and \
         taint-open-redirect (>=1, got {redirect_count}) on \
         open_redirect/php/unsafe_redirect.php.\n\
         All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{} [{}] {}", d.path, d.line, d.severity.as_db_str(), d.id))
            .collect::<Vec<_>>(),
    );
}
