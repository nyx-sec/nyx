//! Phase 08 + Phase 09 integration tests for `Cap::PROTOTYPE_POLLUTION`.
//!
//! Phase 08 (library-mediated) fixtures live under
//! `tests/fixtures/prototype_pollution/<lang>/`:
//!
//! * `unsafe_lodash_merge.*` — `_.merge(target, req.body)` shape; must
//!   produce >=1 `taint-prototype-pollution` finding.
//! * `unsafe_object_assign.js` — `Object.assign(target, req.body)` shape;
//!   must produce >=1 finding (JS-only fixture).
//! * `safe_lodash_merge_const.*` — constant-source merge; must produce 0
//!   findings.
//!
//! Phase 09 (full-SSA dynamic-key sink) fixtures live under
//! `tests/fixtures/prototype_pollution/full/`:
//!
//! * `unsafe_dynamic_key.js` — `target[req.query.k] = req.query.v`; must
//!   produce >=1 finding via the synthetic `__index_set__` node.
//! * `safe_reject_list.js` — `if (k === "__proto__" || …) return;` guard;
//!   must produce 0 findings.
//! * `safe_object_create_null.js` — receiver assigned `Object.create(null)`;
//!   must produce 0 findings.
//! * `safe_allowlist.js` — `if (k === "name" || k === "id") obj[k] = v`
//!   on the true arm; must produce 0 findings.

mod common;

use common::count_by_prefix;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

const RULE_PREFIX: &str = "taint-prototype-pollution";

fn fixture_dir(lang: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("prototype_pollution")
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
fn javascript_lodash_merge_with_tainted_source_fires() {
    assert_unsafe("javascript", "unsafe_lodash_merge.js");
}

#[test]
fn javascript_object_assign_with_tainted_source_fires() {
    assert_unsafe("javascript", "unsafe_object_assign.js");
}

#[test]
fn javascript_lodash_merge_constant_source_does_not_fire() {
    assert_clean("javascript", "safe_lodash_merge_const.js");
}

#[test]
fn javascript_object_assign_constant_source_does_not_fire() {
    assert_clean("javascript", "safe_object_assign_const.js");
}

#[test]
fn typescript_lodash_merge_with_tainted_source_fires() {
    assert_unsafe("typescript", "unsafe_lodash_merge.ts");
}

#[test]
fn typescript_lodash_merge_constant_source_does_not_fire() {
    assert_clean("typescript", "safe_lodash_merge_const.ts");
}

#[test]
fn typescript_object_assign_with_tainted_source_fires() {
    assert_unsafe("typescript", "unsafe_object_assign.ts");
}

#[test]
fn typescript_object_assign_constant_source_does_not_fire() {
    assert_clean("typescript", "safe_object_assign_const.ts");
}

// ── Phase 09: full-SSA dynamic-key sink ───────────────────────────────────

#[test]
fn full_ssa_dynamic_key_with_tainted_key_fires() {
    assert_unsafe("full", "unsafe_dynamic_key.js");
}

#[test]
fn full_ssa_reject_list_guard_does_not_fire() {
    assert_clean("full", "safe_reject_list.js");
}

#[test]
fn full_ssa_object_create_null_receiver_does_not_fire() {
    assert_clean("full", "safe_object_create_null.js");
}

#[test]
fn full_ssa_allowlist_guard_does_not_fire() {
    assert_clean("full", "safe_allowlist.js");
}
