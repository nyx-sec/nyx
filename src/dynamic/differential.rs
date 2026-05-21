//! Differential confirmation rule for dynamic verification (Phase 07).
//!
//! `Confirmed` requires the vulnerable payload's oracle to fire **and**
//! the paired benign control's oracle to *not* fire (§4.1).  This module
//! is the single source of truth for that rule.  Everything else (runner,
//! verifier, tests) collapses to "look up paired benign + call
//! [`evaluate`]".
//!
//! # Rule table
//!
//! | vuln fires | benign fires | verdict                       |
//! |------------|--------------|-------------------------------|
//! | true       | false        | `Confirmed`                    |
//! | true       | true         | `OracleCollisionSuspected`     |
//! | false      | false        | `NotConfirmed`                 |
//! | false      | true         | `ReversedDifferential`         |
//!
//! "Fires" means [`crate::dynamic::oracle::oracle_fired`] returned `true`
//! against the run's [`SandboxOutcome`] + drained [`SinkProbe`] set —
//! invariant across `Oracle::OutputContains` and `Oracle::SinkProbe`.

use crate::dynamic::probe::SinkProbe;
use crate::evidence::{
    DifferentialOutcome, DifferentialProbeArg, DifferentialProbeRecord, DifferentialVerdict,
};

/// Apply the differential confirmation rule.
///
/// `vuln_probe_fires` and `benign_probe_fires` are the boolean firing
/// results of [`crate::dynamic::oracle::oracle_fired`] for the
/// vulnerable payload and its paired benign control respectively.  The
/// rule has no side effects and does not consult the raw probe trace —
/// callers attach those separately via [`DifferentialOutcome`] for
/// forensic display.
pub fn evaluate(vuln_probe_fires: bool, benign_probe_fires: bool) -> DifferentialVerdict {
    match (vuln_probe_fires, benign_probe_fires) {
        (true, false) => DifferentialVerdict::Confirmed,
        (true, true) => DifferentialVerdict::OracleCollisionSuspected,
        (false, false) => DifferentialVerdict::NotConfirmed,
        (false, true) => DifferentialVerdict::ReversedDifferential,
    }
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
