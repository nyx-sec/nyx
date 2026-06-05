#![allow(clippy::field_reassign_with_default)]
//! Phase 30 (Track C — security): coverage for
//! [`crate::dynamic::policy::evaluate`] deny rules.
//!
//! One test per [`DenyRule`] variant (`credentials`, `private-key`,
//! `production-endpoint`) plus an allow-path assertion and an end-to-
//! end check that [`verify_finding`] short-circuits to
//! [`InconclusiveReason::PolicyDeniedDynamic`] without invoking the
//! sandbox.

#![cfg(feature = "dynamic")]

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::dynamic::policy::{self, DenyRule, PolicyDecision};
use nyx_scanner::dynamic::verify::{VerifyOptions, verify_finding};
use nyx_scanner::evidence::{
    Confidence, Evidence, FlowStep, FlowStepKind, InconclusiveReason, SpanEvidence, VerifyStatus,
};
use nyx_scanner::patterns::{FindingCategory, Severity};

fn empty_diag() -> Diag {
    Diag {
        path: "src/app.py".to_owned(),
        line: 10,
        col: 0,
        severity: Severity::High,
        id: "py.cmdi.os_system".to_owned(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: Some(Confidence::High),
        evidence: Some(Evidence::default()),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        triage_state: "open".to_string(),
        triage_note: String::new(),
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: vec![],
        stable_hash: 0xdeadbeefcafebabe,
    }
}

fn flow_step_with_snippet(snippet: &str) -> FlowStep {
    FlowStep {
        step: 1,
        kind: FlowStepKind::Source,
        file: "src/app.py".to_owned(),
        line: 4,
        col: 0,
        snippet: Some(snippet.to_owned()),
        variable: None,
        callee: None,
        function: None,
        is_cross_file: false,
    }
}

fn span_with_snippet(snippet: &str) -> SpanEvidence {
    SpanEvidence {
        path: "src/app.py".to_owned(),
        line: 4,
        col: 0,
        kind: "source".to_owned(),
        snippet: Some(snippet.to_owned()),
    }
}

#[test]
fn allow_returns_for_diag_without_secrets() {
    let diag = empty_diag();
    assert!(matches!(policy::evaluate(&diag), PolicyDecision::Allow));
}

#[test]
fn credentials_rule_fires_on_aws_key_in_flow_step_snippet() {
    let mut diag = empty_diag();
    let mut ev = Evidence::default();
    ev.flow_steps = vec![flow_step_with_snippet("key=AKIAFAKETEST00000000")];
    diag.evidence = Some(ev);
    match policy::evaluate(&diag) {
        PolicyDecision::Deny {
            rule,
            field,
            excerpt,
        } => {
            assert_eq!(rule, DenyRule::CREDENTIALS);
            assert!(
                field.starts_with("flow_steps[") && field.ends_with(".snippet"),
                "deny must record the source field, got {field:?}"
            );
            assert!(
                !excerpt.contains("AKIAFAKETEST00000000"),
                "excerpt must scrub the raw token, got {excerpt:?}"
            );
        }
        other => panic!("expected Deny(credentials), got {other:?}"),
    }
}

#[test]
fn credentials_rule_fires_on_bearer_header_note() {
    let mut diag = empty_diag();
    let mut ev = Evidence::default();
    ev.notes = vec!["Authorization: Bearer sk-test-abc123def456".to_owned()];
    diag.evidence = Some(ev);
    let decision = policy::evaluate(&diag);
    assert!(decision.is_deny(), "expected Deny, got {decision:?}");
}

#[test]
fn private_key_rule_fires_on_pem_block_in_snippet() {
    let mut diag = empty_diag();
    let mut ev = Evidence::default();
    ev.source = Some(span_with_snippet("-----BEGIN OPENSSH PRIVATE KEY-----"));
    diag.evidence = Some(ev);
    match policy::evaluate(&diag) {
        PolicyDecision::Deny { rule, .. } => {
            assert_eq!(rule, DenyRule::PRIVATE_KEY);
        }
        other => panic!("expected Deny(private-key), got {other:?}"),
    }
}

#[test]
fn private_key_rule_fires_on_rsa_pem_in_note() {
    let mut diag = empty_diag();
    let mut ev = Evidence::default();
    ev.notes = vec!["-----BEGIN RSA PRIVATE KEY-----".to_owned()];
    diag.evidence = Some(ev);
    match policy::evaluate(&diag) {
        PolicyDecision::Deny { rule, .. } => {
            assert_eq!(rule, DenyRule::PRIVATE_KEY);
        }
        other => panic!("expected Deny(private-key), got {other:?}"),
    }
}

#[test]
fn production_endpoint_rule_fires_on_path_containing_prod_subdomain() {
    let mut diag = empty_diag();
    diag.path = "src/clients/api.prod.example.com_client.py".to_owned();
    let decision = policy::evaluate(&diag);
    match decision {
        PolicyDecision::Deny { rule, .. } => {
            assert_eq!(rule, DenyRule::PRODUCTION_ENDPOINT);
        }
        other => panic!("expected Deny(production-endpoint), got {other:?}"),
    }
}

#[test]
fn production_endpoint_rule_fires_on_flow_step_callee() {
    let mut diag = empty_diag();
    diag.path = "src/app.py".to_owned();
    let mut ev = Evidence::default();
    ev.flow_steps = vec![FlowStep {
        step: 1,
        kind: FlowStepKind::Call,
        file: "src/app.py".to_owned(),
        line: 4,
        col: 0,
        snippet: None,
        variable: None,
        callee: Some("requests.get(\"https://api-prod.example.com/v1\")".to_owned()),
        function: None,
        is_cross_file: false,
    }];
    diag.evidence = Some(ev);
    let decision = policy::evaluate(&diag);
    assert!(decision.is_deny(), "expected Deny, got {decision:?}");
}

#[test]
fn credentials_rule_fires_before_other_rules() {
    // A diag that matches BOTH credentials (regex) and production-endpoint
    // (substring) must surface the credentials rule — credentials are
    // higher-blast-radius and a leaked token would dwarf an exposed prod
    // endpoint name.  Order asserted by the policy.evaluate impl.
    let mut diag = empty_diag();
    let mut ev = Evidence::default();
    ev.notes = vec!["deploying key=AKIAFAKETEST00000000 to api.prod.example.com".to_owned()];
    diag.evidence = Some(ev);
    match policy::evaluate(&diag) {
        PolicyDecision::Deny { rule, .. } => {
            assert_eq!(rule, DenyRule::CREDENTIALS);
        }
        other => panic!("expected credentials to win, got {other:?}"),
    }
}

#[test]
fn verify_finding_short_circuits_without_sandbox() {
    // Route the verifier through the deny path and confirm it returns
    // `Inconclusive(PolicyDeniedDynamic)` without ever starting a
    // sandbox.  The diag deliberately mentions a credential so a real
    // run would have built a Python harness; reaching that code would
    // touch the filesystem, so the test would fail under the sandbox
    // by failing to find python3.  Instead we observe an immediate
    // verdict.
    let mut diag = empty_diag();
    let mut ev = Evidence::default();
    ev.notes = vec!["password=hunter2-supersecret-test".to_owned()];
    diag.evidence = Some(ev);

    let result = verify_finding(&diag, &VerifyOptions::default());

    assert_eq!(result.status, VerifyStatus::Inconclusive);
    let reason = result
        .inconclusive_reason
        .expect("PolicyDeniedDynamic must populate inconclusive_reason");
    match reason {
        InconclusiveReason::PolicyDeniedDynamic {
            rule,
            field,
            excerpt,
        } => {
            assert_eq!(rule, DenyRule::CREDENTIALS);
            assert!(
                field.starts_with("evidence.notes["),
                "deny must record the source field, got {field:?}"
            );
            assert!(
                !excerpt.contains("hunter2-supersecret-test"),
                "excerpt must scrub the raw secret, got {excerpt:?}"
            );
        }
        other => panic!("expected PolicyDeniedDynamic, got {other:?}"),
    }
    assert!(
        result.attempts.is_empty(),
        "sandbox must not have run; attempts should be empty"
    );
    assert!(result.toolchain_match.is_none());
}
