//! Java `Cap::CRYPTO` payloads — `java.util.Random.nextBytes`
//! weak-key generation.
//!
//! Vuln payload: marker bytes that signal the harness to drive its
//! `java.util.Random` key-generation path.  The harness emits a key
//! bounded inside a 16-bit search space and writes a
//! [`crate::dynamic::probe::ProbeKind::WeakKey`] probe — the
//! [`crate::dynamic::oracle::ProbePredicate::WeakKeyEntropy`]
//! predicate fires for `key_int < 2^16`.
//!
//! Benign control: marker bytes that route the harness through
//! `java.security.SecureRandom`, producing a 256-bit key whose
//! integer view trivially exceeds the budget.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const WEAK_BITS: u32 = 16;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_CRYPTO_WEAK",
        label: "crypto-java-weak-random",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/java/vuln.java"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        benign_control: Some(PayloadRef {
            label: "crypto-java-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_CRYPTO_STRONG",
        label: "crypto-java-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/java/benign.java"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
