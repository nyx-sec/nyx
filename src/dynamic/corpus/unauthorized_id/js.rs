//! js `Cap::UNAUTHORIZED_ID` payloads.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"bob",
        label: "idor-js-cross-tenant",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::IdorBoundaryCrossed],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/unauthorized_id/js/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::IdorBoundaryCrossed],
        benign_control: Some(PayloadRef {
            label: "idor-js-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"alice",
        label: "idor-js-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::IdorBoundaryCrossed],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/unauthorized_id/js/benign.js"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
