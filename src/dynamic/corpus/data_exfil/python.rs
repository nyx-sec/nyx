//! python `Cap::DATA_EXFIL` payloads.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const ALLOWLIST: &[&str] = &["127.0.0.1", "localhost"];

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"attacker.test",
        label: "data-exfil-python-external",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::OutboundHostNotIn {
                allowlist: ALLOWLIST,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/data_exfil/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::OutboundHostNotIn {
            allowlist: ALLOWLIST,
        }],
        benign_control: Some(PayloadRef {
            label: "data-exfil-python-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"127.0.0.1",
        label: "data-exfil-python-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::OutboundHostNotIn {
                allowlist: ALLOWLIST,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/data_exfil/python/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
