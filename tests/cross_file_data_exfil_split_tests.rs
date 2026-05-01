//! Integration test for cross-file `param_to_gate_filters` propagation.
//!
//! A wrapper function whose two parameters target distinct gated-sink
//! classes on a single inner call (here, `fetch`'s SSRF gate on the URL
//! arg vs the DATA_EXFIL gate on the body arg) must keep cap attribution
//! per-position when callers reach it across a file boundary.  Without
//! [`SsaFuncSummary::param_to_gate_filters`], the wrapper's summary
//! collapses both params into a single `SSRF | DATA_EXFIL` mask, and
//! every caller incorrectly fires both classes regardless of which
//! argument was tainted.
//!
//! The fixture pairs the wrapper with two callers, each tainting one
//! parameter and asserting only the cap class corresponding to that
//! parameter's gate fires.

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn cross_file_data_exfil_split() {
    let dir = fixture_path("cross_file_data_exfil_split");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}

/// Python parallel of the JS cross-file split fixture.  A wrapper
/// `forward(url, body)` calls `requests.post(url, json=body)` so the URL
/// flows to the SSRF gate and the body kwarg flows to the DATA_EXFIL
/// gate.  Per-position cap attribution must hold across the file
/// boundary: a caller that taints only the URL fires SSRF (no
/// DATA_EXFIL), and a caller that taints only the body with a Sensitive
/// source fires DATA_EXFIL (no SSRF).
#[test]
fn cross_file_python_data_exfil() {
    let dir = fixture_path("cross_file_python_data_exfil");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
}
