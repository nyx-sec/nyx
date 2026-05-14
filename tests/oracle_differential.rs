//! Phase 07 — differential confirmation rule (`differential::evaluate`).
//!
//! These tests pin the pure-function behaviour of the differential rule
//! (§4.1): given the (vulnerable, benign-control) oracle firing booleans
//! produce the right verdict.  Each case has a matching paragraph in the
//! plan's acceptance criteria.
//!
//! The harness here does *not* spawn a sandbox — it exercises the rule
//! independently of payload corpus, sandbox availability, or per-language
//! toolchains.  Integration coverage that runs both payloads end-to-end
//! lives in `tests/{python,rust}_fixtures.rs` and the golden harness from
//! Phase 05.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::differential::{build_outcome, evaluate};
use nyx_scanner::dynamic::probe::{ProbeArg, ProbeKind, ProbeWitness, SinkProbe};
use nyx_scanner::evidence::DifferentialVerdict;

// ── Rule table ──────────────────────────────────────────────────────────────
//
// | vuln fires | benign fires | verdict                       |
// |------------|--------------|-------------------------------|
// | true       | true         | OracleCollisionSuspected   (a) |
// | true       | false        | Confirmed                  (b) |
// | false      | false        | NotConfirmed               (c) |
// | false      | true         | ReversedDifferential       (d) |

#[test]
fn case_a_both_fire_is_oracle_collision() {
    assert_eq!(
        evaluate(true, true),
        DifferentialVerdict::OracleCollisionSuspected,
        "both vulnerable and benign firing must downgrade to OracleCollisionSuspected"
    );
}

#[test]
fn case_b_only_vuln_fires_is_confirmed() {
    assert_eq!(
        evaluate(true, false),
        DifferentialVerdict::Confirmed,
        "vuln fires + benign silent is the canonical Confirmed shape"
    );
}

#[test]
fn case_c_neither_fires_is_not_confirmed() {
    assert_eq!(
        evaluate(false, false),
        DifferentialVerdict::NotConfirmed,
        "zero firings is plain NotConfirmed (nothing to triage)"
    );
}

#[test]
fn case_d_only_benign_fires_is_reversed_differential() {
    assert_eq!(
        evaluate(false, true),
        DifferentialVerdict::ReversedDifferential,
        "only-benign-fires surfaces a misconfigured corpus, never a real Confirmed"
    );
}

// ── build_outcome plumbing ───────────────────────────────────────────────────
//
// `build_outcome` is what the runner actually calls — it stamps the
// verdict and converts native [`SinkProbe`] records into the serde-stable
// shape stored on `VerifyResult`.  These tests pin the conversion.

fn sample_probe(callee: &str, arg: &str, label: &str) -> SinkProbe {
    SinkProbe {
        sink_callee: callee.into(),
        args: vec![ProbeArg::String(arg.into())],
        captured_at_ns: 1,
        payload_id: label.into(),
        kind: ProbeKind::Normal,
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn build_outcome_confirmed_carries_both_traces() {
    let vuln = vec![sample_probe("os.system", "; echo NYX_PWN_CMDI", "cmdi-echo-marker")];
    let benign = vec![sample_probe("os.system", "benign_safe_cmdi", "cmdi-benign")];
    let outcome = build_outcome(
        "cmdi-echo-marker",
        true,
        &vuln,
        "cmdi-benign",
        false,
        &benign,
    );
    assert_eq!(outcome.verdict, DifferentialVerdict::Confirmed);
    assert_eq!(outcome.vuln_label, "cmdi-echo-marker");
    assert_eq!(outcome.benign_label, "cmdi-benign");
    assert_eq!(outcome.vuln_probes.len(), 1);
    assert_eq!(outcome.benign_probes.len(), 1);
    assert_eq!(outcome.vuln_probes[0].sink_callee, "os.system");
    assert_eq!(outcome.vuln_probes[0].payload_id, "cmdi-echo-marker");
    assert_eq!(outcome.benign_probes[0].payload_id, "cmdi-benign");
}

#[test]
fn build_outcome_oracle_collision_keeps_both_traces() {
    let vuln = vec![sample_probe("os.system", "a", "v")];
    let benign = vec![sample_probe("os.system", "b", "b")];
    let outcome = build_outcome("v", true, &vuln, "b", true, &benign);
    assert_eq!(outcome.verdict, DifferentialVerdict::OracleCollisionSuspected);
    assert_eq!(outcome.vuln_probes.len(), 1);
    assert_eq!(outcome.benign_probes.len(), 1);
}

#[test]
fn build_outcome_not_confirmed_records_empty_traces() {
    let outcome = build_outcome("v", false, &[], "b", false, &[]);
    assert_eq!(outcome.verdict, DifferentialVerdict::NotConfirmed);
    assert!(outcome.vuln_probes.is_empty());
    assert!(outcome.benign_probes.is_empty());
}

#[test]
fn build_outcome_reversed_records_benign_only_trace() {
    let benign = vec![sample_probe("os.system", "x", "b")];
    let outcome = build_outcome("v", false, &[], "b", true, &benign);
    assert_eq!(outcome.verdict, DifferentialVerdict::ReversedDifferential);
    assert!(outcome.vuln_probes.is_empty());
    assert_eq!(outcome.benign_probes.len(), 1);
}

// ── Serde stability ──────────────────────────────────────────────────────────
//
// `VerifyResult.differential` is part of the public verdict JSON shape
// (consumed by SARIF emitters, the React frontend, and the verdict cache).
// Pin the wire format.

#[test]
fn differential_outcome_serialises_as_pascal_case_verdict() {
    let outcome = build_outcome("v", true, &[], "b", false, &[]);
    let json = serde_json::to_value(&outcome).expect("serialise");
    assert_eq!(json["verdict"], "Confirmed");
    assert_eq!(json["vuln_label"], "v");
    assert_eq!(json["benign_label"], "b");
}

#[test]
fn differential_verdict_round_trips_through_json() {
    for v in [
        DifferentialVerdict::Confirmed,
        DifferentialVerdict::OracleCollisionSuspected,
        DifferentialVerdict::NotConfirmed,
        DifferentialVerdict::ReversedDifferential,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: DifferentialVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}
