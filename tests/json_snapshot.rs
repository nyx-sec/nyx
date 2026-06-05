//! Snapshot-style tests for `evidence.dynamic_verdict` in JSON output.
//!
//! When `--verify` is active and produces a verdict, the serialized `Diag`
//! must carry `evidence.dynamic_verdict` with the correct status string and
//! all other fields.  When no verdict is set the key must be absent (due to
//! `skip_serializing_if = "Option::is_none"`).

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::evidence::{AttemptSummary, Evidence, VerifyResult, VerifyStatus};
use nyx_scanner::patterns::{FindingCategory, Severity};

fn base_diag() -> Diag {
    Diag {
        path: "src/main.rs".into(),
        line: 10,
        col: 5,
        severity: Severity::High,
        id: "taint-unsanitised-flow".into(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: None,
        evidence: None,
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        triage_state: "open".to_string(),
        triage_note: String::new(),
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: Vec::new(),
        stable_hash: 0,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn json_dynamic_verdict_confirmed_serialises_correctly() {
    let mut diag = base_diag();
    diag.evidence = Some(Evidence {
        dynamic_verdict: Some(VerifyResult {
            finding_id: "deadbeef01234567".into(),
            status: VerifyStatus::Confirmed,
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
        }),
        ..Default::default()
    });

    let json = serde_json::to_string(&diag).expect("serialisation must succeed");

    assert!(
        json.contains("\"dynamic_verdict\""),
        "JSON must contain dynamic_verdict key: {json}"
    );
    assert!(
        json.contains("\"Confirmed\""),
        "JSON must contain Confirmed status: {json}"
    );
    assert!(
        json.contains("\"sqli-tautology\""),
        "JSON must contain triggered payload: {json}"
    );
    assert!(
        json.contains("\"finding_id\""),
        "JSON must contain finding_id: {json}"
    );
}

#[test]
fn json_dynamic_verdict_not_confirmed_serialises_correctly() {
    let mut diag = base_diag();
    diag.evidence = Some(Evidence {
        dynamic_verdict: Some(VerifyResult {
            finding_id: "abcd1234abcd1234".into(),
            status: VerifyStatus::NotConfirmed,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: Some("exact".into()),
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        }),
        ..Default::default()
    });

    let json = serde_json::to_string(&diag).expect("serialisation must succeed");

    assert!(
        json.contains("\"NotConfirmed\""),
        "JSON must contain NotConfirmed status: {json}"
    );
    // triggered_payload is None → must not appear (skip_serializing_if)
    assert!(
        !json.contains("\"triggered_payload\""),
        "triggered_payload None must be omitted: {json}"
    );
}

#[test]
fn json_no_dynamic_verdict_when_not_set() {
    let mut diag = base_diag();
    diag.evidence = Some(Evidence::default());

    let json = serde_json::to_string(&diag).expect("serialisation must succeed");

    // dynamic_verdict is None → must not appear (skip_serializing_if)
    assert!(
        !json.contains("dynamic_verdict"),
        "dynamic_verdict must be absent when not set: {json}"
    );
}

#[test]
fn json_no_evidence_no_dynamic_verdict() {
    let diag = base_diag();

    let json = serde_json::to_string(&diag).expect("serialisation must succeed");

    assert!(
        !json.contains("evidence"),
        "evidence must be absent when None: {json}"
    );
    assert!(
        !json.contains("dynamic_verdict"),
        "dynamic_verdict must be absent when evidence is None: {json}"
    );
}

#[test]
fn json_unsupported_verdict_has_reason() {
    use nyx_scanner::evidence::UnsupportedReason;

    let mut diag = base_diag();
    diag.evidence = Some(Evidence {
        dynamic_verdict: Some(VerifyResult {
            finding_id: "0000000000000000".into(),
            status: VerifyStatus::Unsupported,
            triggered_payload: None,
            reason: Some(UnsupportedReason::ConfidenceTooLow),
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        }),
        ..Default::default()
    });

    let json = serde_json::to_string(&diag).expect("serialisation must succeed");

    assert!(
        json.contains("\"Unsupported\""),
        "JSON must contain Unsupported status: {json}"
    );
    assert!(
        json.contains("\"ConfidenceTooLow\""),
        "JSON must contain typed reason: {json}"
    );
}
