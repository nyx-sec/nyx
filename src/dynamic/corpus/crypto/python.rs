//! Python `Cap::CRYPTO` payloads — `random.randint` weak-key
//! generation.
//!
//! Vuln payload: marker bytes that route the harness through
//! `random.randint(0, 0xFFFF)`; the harness emits a
//! [`crate::dynamic::probe::ProbeKind::WeakKey`] probe and the
//! [`crate::dynamic::oracle::ProbePredicate::WeakKeyEntropy`]
//! predicate fires.
//!
//! Benign control: marker bytes that route the harness through
//! `secrets.token_bytes(32)`.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const WEAK_BITS: u32 = 16;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_CRYPTO_WEAK",
        label: "crypto-python-weak-random",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        benign_control: Some(PayloadRef {
            label: "crypto-python-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_CRYPTO_STRONG",
        label: "crypto-python-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/python/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
