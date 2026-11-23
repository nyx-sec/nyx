//! Symex branch feasibility: a path symex reports as infeasible drops the
//! finding's confidence, so the proof has to hold.
//!
//! * `go_nil_check_path_feasible.go` reduces gitea's `cmd/serv.go` shape: an
//!   `err` from a call and a `var command *exec.Cmd` declaration are compared
//!   against `nil` before tainted `exec.Command` calls.  The type pass records
//!   both values without null evidence, which the constraint environment used
//!   to read as "never nil", so the sink behind `command == nil` was reported
//!   as infeasible.
//! * `*_bool_flag_branch_feasible.*` branch on boolean constants.  The else
//!   branch of `if dryRun` (with `dryRun = false`) runs, so its sink must stay
//!   feasible; `!quiet` (with `quiet = true`) never holds, so its sink is
//!   infeasible.  The truthiness test used to drop both the branch polarity
//!   and the `!`, refining `dryRun` to true on the else branch.

mod common;

use common::test_config;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::evidence::Verdict;
use nyx_scanner::utils::config::AnalysisMode;
use std::path::Path;

fn scan_fixture(name: &str) -> Vec<Diag> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("symex")
        .join(name);
    let tmp = tempfile::TempDir::with_prefix("nyx_symex_branch_").expect("tempdir");
    std::fs::copy(&fixture, tmp.path().join(name)).expect("copy fixture");
    let cfg = test_config(AnalysisMode::Full);
    nyx_scanner::scan_no_index(tmp.path(), &cfg).expect("scan_no_index should succeed")
}

/// Symex verdict of the taint finding whose sink is on `line`.
fn taint_verdict(diags: &[Diag], line: usize) -> Option<Verdict> {
    let finding = diags
        .iter()
        .find(|d| d.id.starts_with("taint-") && d.line == line)
        .unwrap_or_else(|| {
            panic!(
                "expected a taint finding on line {line}, got {:?}",
                diags
                    .iter()
                    .map(|d| format!("{}:{}", d.line, d.id))
                    .collect::<Vec<_>>()
            )
        });
    finding
        .evidence
        .as_ref()
        .and_then(|e| e.symbolic.as_ref())
        .map(|s| s.verdict)
}

#[test]
fn nil_checked_sinks_are_not_proved_infeasible() {
    let diags = scan_fixture("go_nil_check_path_feasible.go");
    for line in [18, 21] {
        assert_ne!(
            taint_verdict(&diags, line),
            Some(Verdict::Infeasible),
            "line {line}: a nil check on a typed value must not make the path infeasible"
        );
    }
}

fn assert_bool_flag_verdicts(fixture: &str, live_line: usize, dead_line: usize) {
    let diags = scan_fixture(fixture);
    assert_ne!(
        taint_verdict(&diags, live_line),
        Some(Verdict::Infeasible),
        "{fixture}:{live_line}: the else branch of a false flag runs"
    );
    assert_eq!(
        taint_verdict(&diags, dead_line),
        Some(Verdict::Infeasible),
        "{fixture}:{dead_line}: a negated true flag never holds"
    );
}

#[test]
fn js_bool_flag_branches_follow_polarity() {
    assert_bool_flag_verdicts("js_bool_flag_branch_feasible.js", 11, 15);
}

#[test]
fn py_bool_flag_branches_follow_polarity() {
    assert_bool_flag_verdicts("py_bool_flag_branch_feasible.py", 13, 16);
}
