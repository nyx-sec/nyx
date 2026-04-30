//! Demand-driven backwards taint analysis integration tests.
//!
//! These tests exercise the full scan pipeline with the
//! `backwards_analysis` switch flipped on (via the `NYX_BACKWARDS`
//! environment variable that `analysis_options::current()` consults when
//! no runtime has been installed).
//!
//! The four fixture-backed sub-cases live on a single `#[test]` so the
//! env-var flip is serialised in-process (no `serial_test` dev-dep
//! needed).  Inside the test we iterate the fixtures in-order, toggling
//! the env var before each sub-case so each exercises the intended
//! backwards on/off configuration.
//!
//! Assertions:
//!   * Forward findings stay byte-stable in count / id (no regression).
//!   * With backwards ON, a matching forward finding picks up a
//!     `backwards-confirmed` cutoff note on `evidence.symbolic`.
//!   * With backwards OFF, no forward finding carries such a note
//!     (regression guard: the switch is honoured).
//!   * Source-free fixtures emit no backwards-only standalones.

#![allow(clippy::expect_fun_call)]

mod common;

use common::{scan_fixture_dir, validate_expectations};
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn has_backwards_note(diag: &Diag, note: &str) -> bool {
    diag.evidence
        .as_ref()
        .and_then(|e| e.symbolic.as_ref())
        .is_some_and(|sv| sv.cutoff_notes.iter().any(|n| n == note))
}

fn count_backwards_confirmed(diags: &[Diag]) -> usize {
    diags
        .iter()
        .filter(|d| has_backwards_note(d, "backwards-confirmed"))
        .count()
}

fn set_backwards(enabled: bool) {
    // SAFETY: this test runs as the only `#[test]` function in the
    // binary, so the process has only the ambient test-harness threads
    // at this point.  We mutate a process-wide env var between
    // sub-cases.
    unsafe {
        if enabled {
            std::env::set_var("NYX_BACKWARDS", "1");
        } else {
            std::env::remove_var("NYX_BACKWARDS");
        }
    }
}

#[test]
fn demand_driven_suite() {
    // ── 1. reach_source: backwards ON confirms the forward finding.
    set_backwards(true);
    let dir = fixture_path("demand_driven_reach_source");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
    let confirmed = count_backwards_confirmed(&diags);
    assert!(
        confirmed >= 1,
        "reach_source: expected ≥1 backwards-confirmed finding; got diags: {}",
        diags
            .iter()
            .map(|d| format!("{}:{}", d.id, d.line))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // ── 2. prove_infeasible: first cut keeps the forward finding.
    set_backwards(true);
    let dir = fixture_path("demand_driven_prove_infeasible");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    // ── 3. catch_new_fn: first cut reports forward; no reverse-edge yet.
    set_backwards(true);
    let dir = fixture_path("demand_driven_catch_new_fn");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);

    // ── 4. no_source: no findings emitted in either direction.
    set_backwards(true);
    let dir = fixture_path("demand_driven_no_source");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
    assert_eq!(
        count_backwards_confirmed(&diags),
        0,
        "no_source: no backwards-confirmed notes on a source-free fixture"
    );

    // ── 5. data_exfil cap parity: the backwards engine must
    //         round-trip `Cap::DATA_EXFIL` exactly like SQL/CMD/SSRF.
    //         The forward engine fires `taint-data-exfiltration`
    //         on a cookie → fetch-body flow; backwards must reach
    //         the request.cookies source and confirm.
    set_backwards(true);
    let dir = fixture_path("demand_driven_data_exfil");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
    let exfil_confirmed = diags
        .iter()
        .filter(|d| {
            d.id.starts_with("taint-data-exfiltration")
                && has_backwards_note(d, "backwards-confirmed")
        })
        .count();
    assert!(
        exfil_confirmed >= 1,
        "data_exfil: expected ≥1 backwards-confirmed taint-data-exfiltration finding; got diags: {}",
        diags
            .iter()
            .map(|d| format!("{}:{}", d.id, d.line))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // ── 6. backwards OFF is a strict no-op: no confirmed notes.
    set_backwards(false);
    let dir = fixture_path("demand_driven_reach_source");
    let diags = scan_fixture_dir(&dir, AnalysisMode::Full);
    validate_expectations(&diags, &dir);
    assert_eq!(
        count_backwards_confirmed(&diags),
        0,
        "backwards OFF must not emit any backwards-confirmed annotations"
    );
}
