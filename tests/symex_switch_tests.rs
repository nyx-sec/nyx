//! Symex switch / match per-case path-constraint coverage.
//!
//! Each fixture is scanned in isolation (single-file copy to a tempdir to
//! prevent the language harness from picking up siblings of a different
//! language). The fixtures exercise the per-case fork in
//! `src/symex/executor.rs::step_switch` plus the synthesized
//! `<scrutinee> == <case_literal>` condition wired by
//! `src/cfg/blocks.rs::build_switch` for Rust match, Go switch, and Java
//! arrow-switch.

mod common;

use common::test_config;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("symex")
        .join(name)
}

fn scan_isolated(fixture: &Path) -> Vec<Diag> {
    let tmp = tempfile::TempDir::with_prefix("nyx_symex_switch_").expect("tempdir");
    let dest = tmp.path().join(fixture.file_name().unwrap());
    std::fs::copy(fixture, &dest).expect("copy fixture");
    let cfg = test_config(AnalysisMode::Full);
    nyx_scanner::scan_no_index(tmp.path(), &cfg).expect("scan_no_index should succeed")
}

fn count_relevant(diags: &[Diag]) -> usize {
    diags
        .iter()
        .filter(|d| {
            let id = d.id.as_str();
            id.starts_with("taint-")
                || id.contains(".sqli.")
                || id.contains(".cmdi.")
                || id.contains(".xss.")
                || id.contains(".ssrf.")
                || id == "cfg-unguarded-sink"
        })
        .count()
}

/// All three fixtures exercise the same shape: an unsanitized arm that
/// must report at least one finding from a taint/AST sink-pattern rule,
/// and a sanitized arm whose findings (if any) are not promoted to a
/// hard regression. The exact finding count is left loose because
/// per-case suppression precision depends on whether the constraint
/// solver can refine the scrutinee (integer literals do, enum paths
/// do not, see `match_suppresses_safe_arm.rs`).
fn assert_at_least_one_finding(diags: &[Diag], label: &str) {
    let n = count_relevant(diags);
    assert!(
        n >= 1,
        "[{label}] expected ≥1 relevant finding (raw arm), got {n}.\n  diags = {:#?}",
        diags
            .iter()
            .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn symex_match_suppresses_safe_arm() {
    let path = fixture_path("match_suppresses_safe_arm.rs");
    let diags = scan_isolated(&path);
    // Each match arm is lowered on its own, so the tainted `user_cmd` must
    // surface as a taint flow on the Raw arm body (lines 22-29), and the
    // allowlist-guarded Safe arm (lines 31-36) must not get a taint flow.
    let in_lines = |lo: usize, hi: usize| -> Vec<&Diag> {
        diags
            .iter()
            .filter(|d| d.path.ends_with("match_suppresses_safe_arm.rs"))
            .filter(|d| d.line >= lo && d.line <= hi)
            .filter(|d| d.id.starts_with("taint-"))
            .collect()
    };
    let all = || {
        diags
            .iter()
            .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
            .collect::<Vec<_>>()
    };
    assert!(
        !in_lines(22, 29).is_empty(),
        "[rust_match] expected a taint finding on the Raw arm body (lines 22-29).\n  diags = {:#?}",
        all()
    );
    assert!(
        in_lines(31, 36).is_empty(),
        "[rust_match] the Safe arm (lines 31-36) must not get a taint finding.\n  diags = {:#?}",
        all()
    );
}

#[test]
fn symex_switch_go() {
    let path = fixture_path("switch_go.go");
    let diags = scan_isolated(&path);
    assert_at_least_one_finding(&diags, "go_switch");
}

#[test]
fn symex_switch_java() {
    let path = fixture_path("switch_java.java");
    let diags = scan_isolated(&path);
    assert_at_least_one_finding(&diags, "java_arrow_switch");
}
