//! Python prototype-pollution opt-in gate (`NYX_PYTHON_PROTO_POLLUTION=1`).
//!
//! Lives in its own test binary so the `GATED_REGISTRY` `Lazy` initialises
//! after this binary's startup env-var setting; merging into other test
//! files would race with their first-access initialisation.
//!
//! Fixture:
//!
//! * `unsafe_dict_update.py` — `target.update(json.loads(body))` shape; the
//!   `dict.update` gate (PROTO_POLLUTION_GATES in `src/labels/python.rs`)
//!   should fire once the env-var is set.

mod common;

use common::count_by_prefix;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

const RULE_PREFIX: &str = "taint-prototype-pollution";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("prototype_pollution")
        .join("python")
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

#[test]
fn python_dict_update_with_tainted_source_fires() {
    // SAFETY: env::set_var is unsafe in 2024 edition; safe here because
    // this test binary's `GATED_REGISTRY` Lazy is not yet initialised
    // (no other test in this binary scans before this call) and the
    // setting is process-local with no other threads observing.
    unsafe {
        std::env::set_var("NYX_PYTHON_PROTO_POLLUTION", "1");
    }
    let dir = fixture_dir();
    let diags = diags_for_file(&dir, "unsafe_dict_update.py");
    let count = count_by_prefix(&diags, RULE_PREFIX);
    assert!(
        count >= 1,
        "python/unsafe_dict_update.py: expected >=1 {RULE_PREFIX} finding, got {count}.\n\
         All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!(
                "{}:{} [{}] {}",
                d.path,
                d.line,
                d.severity.as_db_str(),
                d.id
            ))
            .collect::<Vec<_>>(),
    );
}
