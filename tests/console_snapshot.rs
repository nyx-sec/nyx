//! Snapshot-style tests for the `[DYN: ...]` annotation in console output.
//!
//! Each `VerifyStatus` variant must produce the correct dim annotation line
//! beneath the finding block when `evidence.dynamic_verdict` is set.

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::evidence::{
    AttemptSummary, Evidence, InconclusiveReason, UnsupportedReason, VerifyResult, VerifyStatus,
};
use nyx_scanner::fmt::render_console;
use nyx_scanner::patterns::{FindingCategory, Severity};

// ── Helper ───────────────────────────────────────────────────────────────────

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut in_escape = false;
    for ch in s.chars() {
        if ch == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn base_diag() -> Diag {
    Diag {
        path: "src/main.rs".into(),
        line: 42,
        col: 5,
        severity: Severity::High,
        id: "taint-unsanitised-flow".into(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: Some("unsanitised input flows to exec".into()),
        labels: vec![],
        confidence: None,
        evidence: None,
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: Vec::new(),
        stable_hash: 0,
    }
}

fn diag_with_verdict(status: VerifyStatus) -> Diag {
    let verdict = match status {
        VerifyStatus::Confirmed => VerifyResult {
            finding_id: "abc123".into(),
            status,
            triggered_payload: Some("sqli-tautology".into()),
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![AttemptSummary {
                payload_label: "sqli-tautology".into(),
                exit_code: Some(0),
                timed_out: false,
                triggered: true,
                sink_hit: true,
            }],
            toolchain_match: Some("exact".into()),
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
        VerifyStatus::PartiallyConfirmed => VerifyResult {
            finding_id: "abc123".into(),
            status,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: Some(
                "sink-reachability probe fired but the oracle marker was not observed; exploit chain did not complete".into(),
            ),
            attempts: vec![AttemptSummary {
                payload_label: "sqli-tautology".into(),
                exit_code: Some(0),
                timed_out: false,
                triggered: false,
                sink_hit: true,
            }],
            toolchain_match: Some("exact".into()),
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
        VerifyStatus::NotConfirmed => VerifyResult {
            finding_id: "abc123".into(),
            status,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![AttemptSummary {
                payload_label: "sqli-tautology".into(),
                exit_code: Some(0),
                timed_out: false,
                triggered: false,
                sink_hit: false,
            }],
            toolchain_match: Some("exact".into()),
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
        VerifyStatus::Unsupported => VerifyResult {
            finding_id: "abc123".into(),
            status,
            triggered_payload: None,
            reason: Some(UnsupportedReason::NoPayloadsForCap),
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
        VerifyStatus::Inconclusive => VerifyResult {
            finding_id: "abc123".into(),
            status,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: Some(InconclusiveReason::BuildFailed),
            detail: Some("build failed after 3 attempts: linker error".into()),
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        },
    };

    let mut d = base_diag();
    d.evidence = Some(Evidence {
        dynamic_verdict: Some(verdict),
        ..Default::default()
    });
    d
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn console_confirmed_shows_payload_id() {
    let diag = diag_with_verdict(VerifyStatus::Confirmed);
    let output = render_console(&[diag], "proj", None, &[]);
    let stripped = strip_ansi(&output);
    assert!(
        stripped.contains("[DYN: confirmed via sqli-tautology]"),
        "expected DYN confirmed annotation, got:\n{stripped}"
    );
}

#[test]
fn console_not_confirmed_shows_annotation() {
    let diag = diag_with_verdict(VerifyStatus::NotConfirmed);
    let output = render_console(&[diag], "proj", None, &[]);
    let stripped = strip_ansi(&output);
    assert!(
        stripped.contains("[DYN: not confirmed]"),
        "expected DYN not-confirmed annotation, got:\n{stripped}"
    );
}

#[test]
fn console_partially_confirmed_shows_sink_reached() {
    let diag = diag_with_verdict(VerifyStatus::PartiallyConfirmed);
    let output = render_console(&[diag], "proj", None, &[]);
    let stripped = strip_ansi(&output);
    assert!(
        stripped.contains("[DYN: partially confirmed (sink reached)]"),
        "expected DYN partially-confirmed annotation, got:\n{stripped}"
    );
}

#[test]
fn console_unsupported_shows_reason() {
    let diag = diag_with_verdict(VerifyStatus::Unsupported);
    let output = render_console(&[diag], "proj", None, &[]);
    let stripped = strip_ansi(&output);
    assert!(
        stripped.contains("[DYN: unsupported (no payloads for cap)]"),
        "expected DYN unsupported annotation, got:\n{stripped}"
    );
}

#[test]
fn console_inconclusive_shows_reason() {
    let diag = diag_with_verdict(VerifyStatus::Inconclusive);
    let output = render_console(&[diag], "proj", None, &[]);
    let stripped = strip_ansi(&output);
    assert!(
        stripped.contains("[DYN: inconclusive (build failed)]"),
        "expected DYN inconclusive annotation, got:\n{stripped}"
    );
}

#[test]
fn console_no_annotation_when_no_dynamic_verdict() {
    let diag = base_diag();
    let output = render_console(&[diag], "proj", None, &[]);
    let stripped = strip_ansi(&output);
    assert!(
        !stripped.contains("[DYN:"),
        "expected no DYN annotation when evidence is None:\n{stripped}"
    );
}

#[test]
fn console_no_annotation_when_evidence_has_no_verdict() {
    let mut diag = base_diag();
    diag.evidence = Some(Evidence::default());
    let output = render_console(&[diag], "proj", None, &[]);
    let stripped = strip_ansi(&output);
    assert!(
        !stripped.contains("[DYN:"),
        "expected no DYN annotation when dynamic_verdict is None:\n{stripped}"
    );
}
