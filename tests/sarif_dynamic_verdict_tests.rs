//! SARIF output tests for the dynamic verification vendor extension (§5.4).
//!
//! Acceptance criterion: SARIF output contains both
//! `partialFingerprints.dynamic_verdict_status` and
//! `properties.nyx_dynamic_verdict` for every `VerifyStatus` variant, and
//! both keys are absent when no dynamic verdict is attached.

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::evidence::{
    AttemptSummary, Evidence, InconclusiveReason, UnsupportedReason, VerifyResult, VerifyStatus,
};
use nyx_scanner::output::build_sarif;
use nyx_scanner::patterns::{FindingCategory, Severity};
use std::path::Path;

fn base_diag() -> Diag {
    Diag {
        path: "/scan_root/src/main.rs".into(),
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
        finding_id: "deadbeef01234567".into(),
        alternative_finding_ids: Vec::new(),
        stable_hash: 0,
    }
}

fn diag_with_verdict(verdict: VerifyResult) -> Diag {
    let mut d = base_diag();
    d.evidence = Some(Evidence {
        dynamic_verdict: Some(verdict),
        ..Default::default()
    });
    d
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn sarif_result(diag: Diag) -> serde_json::Value {
    let sarif = build_sarif(&[diag], Path::new("/scan_root"));
    sarif["runs"][0]["results"][0].clone()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn sarif_confirmed_verdict_sets_partial_fingerprint() {
    let verdict = VerifyResult {
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
    };

    let result = sarif_result(diag_with_verdict(verdict));

    assert_eq!(
        result["partialFingerprints"]["dynamic_verdict_status"], "Confirmed",
        "partialFingerprints.dynamic_verdict_status must be 'Confirmed'"
    );
    assert!(
        result["properties"]["nyx_dynamic_verdict"].is_object(),
        "properties.nyx_dynamic_verdict must be an object: {}",
        result["properties"]["nyx_dynamic_verdict"]
    );
    assert_eq!(
        result["properties"]["nyx_dynamic_verdict"]["status"], "Confirmed",
        "nyx_dynamic_verdict.status must be 'Confirmed'"
    );
}

#[test]
fn sarif_not_confirmed_verdict_sets_partial_fingerprint() {
    let verdict = VerifyResult {
        finding_id: "deadbeef01234567".into(),
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
    };

    let result = sarif_result(diag_with_verdict(verdict));

    assert_eq!(
        result["partialFingerprints"]["dynamic_verdict_status"], "NotConfirmed",
        "partialFingerprints.dynamic_verdict_status must be 'NotConfirmed'"
    );
    assert!(
        result["properties"]["nyx_dynamic_verdict"].is_object(),
        "properties.nyx_dynamic_verdict must be an object"
    );
}

#[test]
fn sarif_unsupported_verdict_sets_partial_fingerprint() {
    let verdict = VerifyResult {
        finding_id: "deadbeef01234567".into(),
        status: VerifyStatus::Unsupported,
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
    };

    let result = sarif_result(diag_with_verdict(verdict));

    assert_eq!(
        result["partialFingerprints"]["dynamic_verdict_status"], "Unsupported",
        "partialFingerprints.dynamic_verdict_status must be 'Unsupported'"
    );
    assert!(
        result["properties"]["nyx_dynamic_verdict"].is_object(),
        "properties.nyx_dynamic_verdict must be an object"
    );
    assert_eq!(
        result["properties"]["nyx_dynamic_verdict"]["reason"], "NoPayloadsForCap",
        "nyx_dynamic_verdict must carry the unsupported reason"
    );
}

#[test]
fn sarif_inconclusive_verdict_sets_partial_fingerprint() {
    let verdict = VerifyResult {
        finding_id: "deadbeef01234567".into(),
        status: VerifyStatus::Inconclusive,
        triggered_payload: None,
        reason: None,
        inconclusive_reason: Some(InconclusiveReason::BuildFailed),
        detail: Some("build failed after 3 attempts".into()),
        attempts: vec![],
        toolchain_match: None,
        differential: None,
        replay_stable: None,
        wrong: None,
        hardening_outcome: None,
    };

    let result = sarif_result(diag_with_verdict(verdict));

    assert_eq!(
        result["partialFingerprints"]["dynamic_verdict_status"], "Inconclusive",
        "partialFingerprints.dynamic_verdict_status must be 'Inconclusive'"
    );
    assert!(
        result["properties"]["nyx_dynamic_verdict"].is_object(),
        "properties.nyx_dynamic_verdict must be an object"
    );
    assert_eq!(
        result["properties"]["nyx_dynamic_verdict"]["inconclusive_reason"], "BuildFailed",
        "nyx_dynamic_verdict must carry the inconclusive reason"
    );
}

#[test]
fn sarif_no_dynamic_verdict_omits_both_keys() {
    let diag = base_diag();
    let result = sarif_result(diag);

    assert!(
        result["partialFingerprints"].is_null()
            || result["partialFingerprints"] == serde_json::Value::Null,
        "partialFingerprints must be absent when no dynamic verdict: {}",
        result["partialFingerprints"]
    );
    assert!(
        result["properties"]["nyx_dynamic_verdict"].is_null()
            || result["properties"]["nyx_dynamic_verdict"] == serde_json::Value::Null,
        "properties.nyx_dynamic_verdict must be absent when no dynamic verdict"
    );
}

#[test]
fn sarif_confirmed_verdict_nyx_dynamic_verdict_contains_triggered_payload() {
    let verdict = VerifyResult {
        finding_id: "deadbeef01234567".into(),
        status: VerifyStatus::Confirmed,
        triggered_payload: Some("cmd-injection-semicolon".into()),
        reason: None,
        inconclusive_reason: None,
        detail: None,
        attempts: vec![],
        toolchain_match: Some("exact".into()),
        differential: None,
        replay_stable: None,
        wrong: None,
        hardening_outcome: None,
    };

    let result = sarif_result(diag_with_verdict(verdict));

    assert_eq!(
        result["properties"]["nyx_dynamic_verdict"]["triggered_payload"], "cmd-injection-semicolon",
        "triggered_payload must appear in nyx_dynamic_verdict"
    );
}

#[test]
fn sarif_all_statuses_produce_partial_fingerprint() {
    let statuses = [
        (VerifyStatus::Confirmed, "Confirmed"),
        (VerifyStatus::PartiallyConfirmed, "PartiallyConfirmed"),
        (VerifyStatus::NotConfirmed, "NotConfirmed"),
        (VerifyStatus::Unsupported, "Unsupported"),
        (VerifyStatus::Inconclusive, "Inconclusive"),
    ];

    for (status, expected_str) in statuses {
        let verdict = VerifyResult {
            finding_id: "deadbeef01234567".into(),
            status,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        };

        let result = sarif_result(diag_with_verdict(verdict));

        assert_eq!(
            result["partialFingerprints"]["dynamic_verdict_status"], expected_str,
            "status {expected_str}: partialFingerprints.dynamic_verdict_status mismatch"
        );
        assert!(
            result["properties"]["nyx_dynamic_verdict"].is_object(),
            "status {expected_str}: properties.nyx_dynamic_verdict must be an object"
        );
    }
}
