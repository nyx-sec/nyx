//! Differential confirmation rule for dynamic verification (Phase 07 / 26).
//!
//! `Confirmed` requires **at least one** vulnerable payload's oracle to
//! fire **and every** paired benign control's oracle to *not* fire
//! (§4.1, extended for multi-payload aggregation in Phase 26).  This
//! module is the single source of truth for that rule.  Everything else
//! (runner, verifier, tests) collapses to "collect firing sets + call
//! [`evaluate_sets`]".
//!
//! # Rule table (set aggregation)
//!
//! | any vuln fires | any benign fires | verdict                    |
//! |----------------|------------------|----------------------------|
//! | true           | false            | `Confirmed`                 |
//! | true           | true             | `OracleCollisionSuspected`  |
//! | false          | false            | `NotConfirmed`              |
//! | false          | true             | `ReversedDifferential`      |
//!
//! The scalar [`evaluate`] is the single-payload, single-control
//! specialisation of [`evaluate_sets`] and delegates to it.
//!
//! "Fires" means [`crate::dynamic::oracle::oracle_fired`] returned `true`
//! against the run's [`SandboxOutcome`] + drained [`SinkProbe`] set —
//! invariant across `Oracle::OutputContains` and `Oracle::SinkProbe`.

use crate::dynamic::probe::SinkProbe;
use crate::evidence::{
    DifferentialOutcome, DifferentialProbeArg, DifferentialProbeRecord, DifferentialVerdict,
};

/// Apply the differential confirmation rule over **sets** of firing
/// results (Phase 26 multi-payload aggregation).
///
/// `vuln_fired` is one boolean per vulnerable payload attempt;
/// `benign_fired` is one boolean per paired benign control that actually
/// ran.  Aggregation is "any vuln vs any benign" with global ambient-noise
/// scoring across the run: a *single* benign control firing anywhere
/// vetoes `Confirmed` (the oracle cannot discriminate), and a *single*
/// vulnerable payload firing is enough positive evidence.
///
/// Empty slices behave as "nothing fired" on that side, so
/// `evaluate_sets(&[], &[])` is `NotConfirmed`.
pub fn evaluate_sets(vuln_fired: &[bool], benign_fired: &[bool]) -> DifferentialVerdict {
    let any_vuln = vuln_fired.iter().any(|&b| b);
    let any_benign = benign_fired.iter().any(|&b| b);
    match (any_vuln, any_benign) {
        (true, false) => DifferentialVerdict::Confirmed,
        (true, true) => DifferentialVerdict::OracleCollisionSuspected,
        (false, false) => DifferentialVerdict::NotConfirmed,
        (false, true) => DifferentialVerdict::ReversedDifferential,
    }
}

/// Apply the differential confirmation rule to a single
/// (vulnerable, benign-control) pair.
///
/// Single-element specialisation of [`evaluate_sets`].
/// `vuln_probe_fires` and `benign_probe_fires` are the boolean firing
/// results of [`crate::dynamic::oracle::oracle_fired`] for the
/// vulnerable payload and its paired benign control respectively.  The
/// rule has no side effects and does not consult the raw probe trace —
/// callers attach those separately via [`DifferentialOutcome`] for
/// forensic display.
pub fn evaluate(vuln_probe_fires: bool, benign_probe_fires: bool) -> DifferentialVerdict {
    evaluate_sets(&[vuln_probe_fires], &[benign_probe_fires])
}

/// Build a [`DifferentialOutcome`] for inclusion in a
/// [`crate::evidence::VerifyResult`].
///
/// Translates the runner's native [`SinkProbe`] traces into the
/// feature-agnostic [`DifferentialProbeRecord`] shape stored on
/// `VerifyResult`.  The verdict comes from [`evaluate`] applied to the
/// caller's already-computed firing booleans (the runner has them in
/// hand from the oracle call).
pub fn build_outcome(
    vuln_label: &str,
    vuln_probe_fires: bool,
    vuln_probes: &[SinkProbe],
    benign_label: &str,
    benign_probe_fires: bool,
    benign_probes: &[SinkProbe],
) -> DifferentialOutcome {
    DifferentialOutcome {
        verdict: evaluate(vuln_probe_fires, benign_probe_fires),
        vuln_label: vuln_label.to_owned(),
        benign_label: benign_label.to_owned(),
        vuln_probes: vuln_probes.iter().map(sink_probe_to_record).collect(),
        benign_probes: benign_probes.iter().map(sink_probe_to_record).collect(),
        known_guards: Vec::new(),
    }
}

/// Build a self-confirming [`DifferentialOutcome`] for OOB-nonce payloads.
///
/// When a payload carries
/// [`crate::dynamic::corpus::CuratedPayload::oob_nonce_slot`] = `true` and
/// the [`crate::dynamic::oob::OobListener`] observed the per-finding nonce
/// callback, the OOB observation is independent network-level evidence
/// that the sink fired.  A benign URL structurally cannot hit a per-
/// finding nonce, so no paired benign control is required.  The runner
/// emits this outcome with [`DifferentialVerdict::ConfirmedProvenOob`]
/// in place of the usual two-payload differential rule.
pub fn build_oob_self_confirmed_outcome(
    vuln_label: &str,
    vuln_probes: &[SinkProbe],
) -> DifferentialOutcome {
    DifferentialOutcome {
        verdict: DifferentialVerdict::ConfirmedProvenOob,
        vuln_label: vuln_label.to_owned(),
        benign_label: String::new(),
        vuln_probes: vuln_probes.iter().map(sink_probe_to_record).collect(),
        benign_probes: Vec::new(),
        known_guards: Vec::new(),
    }
}

fn sink_probe_to_record(p: &SinkProbe) -> DifferentialProbeRecord {
    use crate::dynamic::probe::ProbeArg;
    DifferentialProbeRecord {
        sink_callee: p.sink_callee.clone(),
        args: p
            .args
            .iter()
            .map(|a| match a {
                ProbeArg::String(s) => DifferentialProbeArg::String(s.clone()),
                ProbeArg::Bytes(b) => DifferentialProbeArg::Bytes(b.clone()),
                ProbeArg::Int(i) => DifferentialProbeArg::Int(*i),
            })
            .collect(),
        captured_at_ns: p.captured_at_ns,
        payload_id: p.payload_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_a_both_fire_is_collision() {
        assert_eq!(
            evaluate(true, true),
            DifferentialVerdict::OracleCollisionSuspected
        );
    }

    #[test]
    fn rule_b_only_vuln_fires_is_confirmed() {
        assert_eq!(evaluate(true, false), DifferentialVerdict::Confirmed);
    }

    #[test]
    fn rule_c_neither_fires_is_not_confirmed() {
        assert_eq!(evaluate(false, false), DifferentialVerdict::NotConfirmed);
    }

    #[test]
    fn rule_d_only_benign_fires_is_reversed() {
        assert_eq!(
            evaluate(false, true),
            DifferentialVerdict::ReversedDifferential
        );
    }

    #[test]
    fn sets_any_vuln_no_benign_is_confirmed() {
        // One of several vuln payloads firing is enough; no benign fired.
        assert_eq!(
            evaluate_sets(&[false, true, false], &[false, false]),
            DifferentialVerdict::Confirmed
        );
    }

    #[test]
    fn sets_one_benign_firing_vetoes_confirmed() {
        // A single benign control firing anywhere downgrades to collision,
        // even when a vuln payload also fired (global ambient-noise veto).
        assert_eq!(
            evaluate_sets(&[true, true], &[false, true, false]),
            DifferentialVerdict::OracleCollisionSuspected
        );
    }

    #[test]
    fn sets_no_vuln_no_benign_is_not_confirmed() {
        assert_eq!(
            evaluate_sets(&[false, false], &[false]),
            DifferentialVerdict::NotConfirmed
        );
    }

    #[test]
    fn sets_no_vuln_some_benign_is_reversed() {
        assert_eq!(
            evaluate_sets(&[false], &[true]),
            DifferentialVerdict::ReversedDifferential
        );
    }

    #[test]
    fn sets_empty_is_not_confirmed() {
        assert_eq!(evaluate_sets(&[], &[]), DifferentialVerdict::NotConfirmed);
    }

    #[test]
    fn sets_empty_benign_with_vuln_is_confirmed() {
        // No benign control ran at all → no veto possible → Confirmed.
        assert_eq!(evaluate_sets(&[true], &[]), DifferentialVerdict::Confirmed);
    }

    #[test]
    fn scalar_evaluate_matches_singleton_sets() {
        for &v in &[false, true] {
            for &b in &[false, true] {
                assert_eq!(evaluate(v, b), evaluate_sets(&[v], &[b]));
            }
        }
    }

    #[test]
    fn oob_self_confirmed_outcome_carries_only_vuln_trace() {
        use crate::dynamic::probe::{ProbeArg, ProbeKind, ProbeWitness, SinkProbe};
        let vuln = vec![SinkProbe {
            sink_callee: "lxml.etree.XMLParser.parse".into(),
            args: vec![ProbeArg::String("<!DOCTYPE … &xxe;".into())],
            captured_at_ns: 1,
            payload_id: "xxe-python-oob-nonce".into(),
            kind: ProbeKind::Normal,
            witness: ProbeWitness::empty(),
        }];
        let outcome = build_oob_self_confirmed_outcome("xxe-python-oob-nonce", &vuln);
        assert_eq!(outcome.verdict, DifferentialVerdict::ConfirmedProvenOob);
        assert_eq!(outcome.vuln_label, "xxe-python-oob-nonce");
        assert!(outcome.benign_label.is_empty());
        assert_eq!(outcome.vuln_probes.len(), 1);
        assert!(outcome.benign_probes.is_empty());
    }

    #[test]
    fn build_outcome_carries_both_traces() {
        use crate::dynamic::probe::{ProbeArg, ProbeKind, ProbeWitness, SinkProbe};
        let vuln = vec![SinkProbe {
            sink_callee: "os.system".into(),
            args: vec![ProbeArg::String("; echo X".into())],
            captured_at_ns: 1,
            payload_id: "cmdi-echo-marker".into(),
            kind: ProbeKind::Normal,
            witness: ProbeWitness::empty(),
        }];
        let benign = vec![SinkProbe {
            sink_callee: "os.system".into(),
            args: vec![ProbeArg::String("safe".into())],
            captured_at_ns: 2,
            payload_id: "cmdi-benign".into(),
            kind: ProbeKind::Normal,
            witness: ProbeWitness::empty(),
        }];
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
    }
}
