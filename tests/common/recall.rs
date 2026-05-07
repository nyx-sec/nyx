//! Recall-gap fixture harness.
//!
//! Exposes `scan_fixture`, `assert_finding`, and `ExpectedFinding` for the
//! integration test binary `tests/recall_gaps.rs`. Phases 02–11 each own one
//! fixture under `tests/fixtures/realistic/` and one matching test.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

pub use nyx_scanner::commands::scan::Diag as Finding;
use nyx_scanner::utils::config::Config;

/// Copy `tests/fixtures/realistic/<rel_path>` into a fresh temp directory and
/// run a two-pass filesystem scan against the copy. Isolating in tempdir
/// prevents SQLite or `nyx.conf` artefacts from leaking between tests.
pub fn scan_fixture(rel_path: &str) -> Vec<Finding> {
    let src: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/realistic")
        .join(rel_path);
    assert!(
        src.exists(),
        "recall fixture not found: {}",
        src.display()
    );
    let tmp = tempfile::tempdir().expect("tempdir for recall fixture");
    copy_dir_recursive(&src, tmp.path()).expect("copy fixture into tempdir");

    let cfg = Config::default();
    nyx_scanner::scan_no_index(tmp.path(), &cfg).expect("scan_no_index on recall fixture")
}

/// Shape used by `recall_gaps.rs` tests to assert a specific finding exists.
///
/// - `rule_id` matches the rule prefix of `Diag.id`. Taint findings carry a
///   trailing ` (source N:M)` suffix; this struct compares only the prefix.
/// - `file_suffix` matches `Diag.path.ends_with(file_suffix)` so callers do
///   not have to reproduce the tempdir prefix.
/// - `sink_line` matches `Diag.line` exactly (1-based).
/// - `source_line`, when `Some`, matches the `N` parsed from the trailing
///   ` (source N:M)` suffix on `Diag.id`.
#[derive(Debug, Clone)]
pub struct ExpectedFinding {
    pub rule_id: &'static str,
    pub file_suffix: &'static str,
    pub sink_line: usize,
    pub source_line: Option<usize>,
}

/// Assert that at least one finding in `findings` matches `expected`.
pub fn assert_finding(findings: &[Finding], expected: ExpectedFinding) {
    let hit = findings.iter().any(|f| {
        rule_id_prefix(&f.id) == expected.rule_id
            && f.path.ends_with(expected.file_suffix)
            && f.line == expected.sink_line
            && match expected.source_line {
                None => true,
                Some(want) => parse_source_line(&f.id) == Some(want),
            }
    });
    assert!(
        hit,
        "expected recall finding not produced: {expected:?}\nactual findings:\n{}",
        findings
            .iter()
            .map(|f| format!("  {} :: {}:{} [{}]", f.id, f.path, f.line, f.severity.as_db_str()))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

fn rule_id_prefix(id: &str) -> &str {
    match id.find(" (source ") {
        Some(idx) => &id[..idx],
        None => id,
    }
}

fn parse_source_line(id: &str) -> Option<usize> {
    let needle = " (source ";
    let start = id.find(needle)? + needle.len();
    let rest = &id[start..];
    let end = rest.find(':').or_else(|| rest.find(')'))?;
    rest[..end].parse().ok()
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let name = entry.file_name();
        if name == ".gitkeep" {
            continue;
        }
        let to = dst.join(&name);
        if from.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}
