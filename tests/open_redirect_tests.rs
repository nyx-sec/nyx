//! Phase 05 integration tests for `Cap::OPEN_REDIRECT`.
//!
//! Fixtures under `tests/fixtures/open_redirect/<lang>/`:
//!
//! * `unsafe_redirect.*` — taint flows from a request source into a
//!   redirect API.  Must produce >=1 `taint-open-redirect` finding.
//! * `safe_redirect.*` — same flow routed through a developer-named
//!   `validateRedirectUrl` / `validate_redirect_url` allowlist.  Must
//!   produce 0 findings.

mod common;

use common::count_by_prefix;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

const RULE_PREFIX: &str = "taint-open-redirect";

fn fixture_dir(lang: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("open_redirect")
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
fn javascript_redirect_with_tainted_url_fires() {
    assert_unsafe("javascript", "unsafe_redirect.js");
}

#[test]
fn javascript_validate_url_sanitizes() {
    assert_clean("javascript", "safe_redirect.js");
}

#[test]
fn typescript_redirect_with_tainted_url_fires() {
    assert_unsafe("typescript", "unsafe_redirect.ts");
}

#[test]
fn typescript_validate_url_sanitizes() {
    assert_clean("typescript", "safe_redirect.ts");
}

#[test]
fn python_redirect_with_tainted_url_fires() {
    assert_unsafe("python", "unsafe_redirect.py");
}

#[test]
fn python_validate_url_sanitizes() {
    assert_clean("python", "safe_redirect.py");
}

#[test]
fn java_send_redirect_with_tainted_url_fires() {
    assert_unsafe("java", "UnsafeRedirect.java");
}

#[test]
fn java_validate_url_sanitizes() {
    assert_clean("java", "SafeRedirect.java");
}
