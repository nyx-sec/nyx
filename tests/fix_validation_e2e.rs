//! End-to-end tests for `nyx scan --baseline` / `--gate` (§M6.5, Pillar A).
//!
//! Demonstrates the "woah" loop from §15.5:
//! 1. Scan a vulnerable Python project — finding emits with `stable_hash`.
//! 2. Simulate `Confirmed` dynamic verdict (as `--verify` would produce).
//! 3. Write a stripped baseline (no source code, only hash + verdict).
//! 4. Fix the vulnerability and rescan.
//! 5. Diff against the baseline: finding flips to `FlippedNotConfirmed`.
//! 6. `--gate=resolve-all-confirmed` passes (exits 0).
//! 7. Introduce a new vulnerability and simulate `Confirmed` on it.
//! 8. `--gate=no-new-confirmed` fails (would exit 2).

mod common;

use nyx_scanner::baseline::{
    check_gate, compute_verdict_diff, diags_to_baseline_entries, load_baseline, write_baseline,
    BaselineEntry, Transition, GATE_NO_NEW_CONFIRMED, GATE_RESOLVE_ALL_CONFIRMED,
};
use nyx_scanner::commands::scan::compute_stable_hash;
use nyx_scanner::evidence::{Evidence, VerifyResult, VerifyStatus};
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;
use tempfile::NamedTempFile;

/// Run `scan_no_index` and assign stable hashes to every finding.
fn scan_with_hashes(dir: &Path) -> Vec<nyx_scanner::commands::scan::Diag> {
    let mut diags = common::scan_fixture_dir(dir, AnalysisMode::Full);
    for d in &mut diags {
        d.stable_hash = compute_stable_hash(d);
    }
    diags
}

/// Attach a simulated dynamic verdict to every finding in the list.
fn set_verdict(
    diags: &mut Vec<nyx_scanner::commands::scan::Diag>,
    status: VerifyStatus,
) {
    for d in diags.iter_mut() {
        let fid = format!("{:016x}", d.stable_hash);
        let ev = d.evidence.get_or_insert_with(Evidence::default);
        ev.dynamic_verdict = Some(VerifyResult {
            finding_id: fid,
            status,
            triggered_payload: if status == VerifyStatus::Confirmed {
                Some("' OR 1=1--".to_string())
            } else {
                None
            },
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
        });
    }
}

const VULN_DIR: &str = "tests/fixtures/baseline_sqli_vuln";
const FIXED_DIR: &str = "tests/fixtures/baseline_sqli_fixed";
const NEW_DIR: &str = "tests/fixtures/baseline_sqli_new";

// ── §15.5 "woah" loop end-to-end ────────────────────────────────────────────

/// Step 1-3: Scan the vulnerable version, simulate Confirmed, write baseline.
#[test]
fn vuln_scan_emits_finding_with_stable_hash() {
    let vuln_path = Path::new(VULN_DIR);
    let diags = scan_with_hashes(vuln_path);
    assert!(
        !diags.is_empty(),
        "Expected SQL injection finding in {VULN_DIR}"
    );
    assert!(
        diags.iter().all(|d| d.stable_hash != 0),
        "All findings must have non-zero stable_hash after compute_stable_hash"
    );
}

/// Step 4-6: Fix → rescan → diff → gate passes.
#[test]
fn fix_resolves_confirmed_finding() {
    let vuln_path = Path::new(VULN_DIR);
    let fixed_path = Path::new(FIXED_DIR);

    // Step 1: scan vulnerable, simulate Confirmed verdict.
    let mut vuln_diags = scan_with_hashes(vuln_path);
    assert!(!vuln_diags.is_empty(), "Need at least one SQL injection finding");
    set_verdict(&mut vuln_diags, VerifyStatus::Confirmed);

    // Step 2: write stripped baseline.
    let baseline_file = NamedTempFile::new().unwrap();
    write_baseline(baseline_file.path(), &vuln_diags).unwrap();

    // Step 3: load baseline and verify it has no source code.
    let raw = std::fs::read_to_string(baseline_file.path()).unwrap();
    assert!(
        !raw.contains("execute"),
        "baseline must not contain source code snippets (found 'execute')"
    );
    let baseline_entries = load_baseline(baseline_file.path()).unwrap();
    assert!(!baseline_entries.is_empty());
    assert_eq!(
        baseline_entries[0].dynamic_verdict,
        Some(VerifyStatus::Confirmed)
    );

    // Step 4: scan fixed version.
    let fixed_diags = scan_with_hashes(fixed_path);

    // Step 5: diff.
    let diff = compute_verdict_diff(&baseline_entries, &fixed_diags);

    // The vulnerable finding should be Resolved (gone from fixed code).
    // Alternatively it could be FlippedNotConfirmed if the scanner still
    // finds a flow (it shouldn't for the parameterized query).
    let resolved_or_flipped = diff.entries.iter().any(|e| {
        e.baseline_status == Some(VerifyStatus::Confirmed)
            && matches!(
                e.transition,
                Transition::Resolved | Transition::FlippedNotConfirmed
            )
    });
    assert!(
        resolved_or_flipped,
        "Expected the Confirmed finding to be Resolved or FlippedNotConfirmed after the fix. \
         Diff entries: {:#?}",
        diff.entries
    );

    // Step 6: gate passes.
    assert!(
        check_gate(&diff, GATE_RESOLVE_ALL_CONFIRMED),
        "resolve-all-confirmed gate must pass after the fix"
    );
}

/// Step 7-8: new Confirmed finding → no-new-confirmed gate fails.
#[test]
fn new_confirmed_fails_no_new_confirmed_gate() {
    let vuln_path = Path::new(VULN_DIR);
    let new_path = Path::new(NEW_DIR);

    // Baseline: the original vulnerability, confirmed.
    let mut vuln_diags = scan_with_hashes(vuln_path);
    set_verdict(&mut vuln_diags, VerifyStatus::Confirmed);
    let baseline_entries = diags_to_baseline_entries(&vuln_diags);

    // Current: the "fixed+new" version — original finding gone, new one appears.
    let mut new_diags = scan_with_hashes(new_path);
    // Simulate Confirmed on any new findings not in the baseline.
    let baseline_hashes: std::collections::HashSet<u64> =
        baseline_entries.iter().map(|e| e.stable_hash).collect();
    for d in new_diags.iter_mut() {
        if !baseline_hashes.contains(&d.stable_hash) {
            let fid = format!("{:016x}", d.stable_hash);
            let ev = d.evidence.get_or_insert_with(Evidence::default);
            ev.dynamic_verdict = Some(VerifyResult {
                finding_id: fid,
                status: VerifyStatus::Confirmed,
                triggered_payload: Some("' OR 1=1--".to_string()),
                reason: None,
                inconclusive_reason: None,
                detail: None,
                attempts: vec![],
                toolchain_match: None,
            });
        }
    }

    let diff = compute_verdict_diff(&baseline_entries, &new_diags);

    // There must be at least one New+Confirmed entry.
    let has_new_confirmed = diff.entries.iter().any(|e| {
        e.transition == Transition::New && e.current_status == Some(VerifyStatus::Confirmed)
    });
    assert!(
        has_new_confirmed,
        "Expected a new Confirmed finding in the diff. Diff entries: {:#?}",
        diff.entries
    );

    // Gate must fail.
    assert!(
        !check_gate(&diff, GATE_NO_NEW_CONFIRMED),
        "no-new-confirmed gate must fail when a new Confirmed finding exists"
    );
}

/// `stable_hash` is stable across identical scans (same path, rule, line, col, caps).
#[test]
fn stable_hash_deterministic_across_scans() {
    let vuln_path = Path::new(VULN_DIR);
    let diags1 = scan_with_hashes(vuln_path);
    let diags2 = scan_with_hashes(vuln_path);

    assert!(!diags1.is_empty());
    assert_eq!(
        diags1.len(),
        diags2.len(),
        "finding count must be deterministic"
    );

    let hashes1: std::collections::HashSet<u64> = diags1.iter().map(|d| d.stable_hash).collect();
    let hashes2: std::collections::HashSet<u64> = diags2.iter().map(|d| d.stable_hash).collect();
    assert_eq!(
        hashes1, hashes2,
        "stable_hash must be identical across two scans of the same codebase"
    );
}

/// Baseline-write file contains required fields and no source snippets.
#[test]
fn baseline_write_contains_required_fields_no_source() {
    let vuln_path = Path::new(VULN_DIR);
    let mut diags = scan_with_hashes(vuln_path);
    set_verdict(&mut diags, VerifyStatus::Confirmed);

    let f = NamedTempFile::new().unwrap();
    write_baseline(f.path(), &diags).unwrap();

    let content = std::fs::read_to_string(f.path()).unwrap();
    let entries: Vec<BaselineEntry> = serde_json::from_str(&content).unwrap();

    assert!(!entries.is_empty());
    for e in &entries {
        assert_ne!(e.stable_hash, 0, "stable_hash must be non-zero");
        assert!(!e.path.is_empty(), "path must be set");
        assert!(!e.rule_id.is_empty(), "rule_id must be set");
        assert!(!e.severity.is_empty(), "severity must be set");
    }
    // No source code snippets.
    assert!(
        !content.contains("SELECT"),
        "baseline must not contain SQL source code"
    );
}

/// `load_baseline` accepts a full Diag JSON (from `nyx scan --format json`).
#[test]
fn load_baseline_accepts_full_diag_json() {
    let vuln_path = Path::new(VULN_DIR);
    let diags = scan_with_hashes(vuln_path);
    assert!(!diags.is_empty());

    let diag_json = serde_json::to_string(&diags).unwrap();
    let f = NamedTempFile::new().unwrap();
    std::fs::write(f.path(), &diag_json).unwrap();

    let loaded = load_baseline(f.path()).unwrap();
    assert_eq!(loaded.len(), diags.len());
    // Hashes must round-trip.
    let loaded_hashes: std::collections::HashSet<u64> =
        loaded.iter().map(|e| e.stable_hash).collect();
    let diag_hashes: std::collections::HashSet<u64> =
        diags.iter().map(|d| d.stable_hash).collect();
    assert_eq!(loaded_hashes, diag_hashes);
}
