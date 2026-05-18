//! Rust `Cap::CRYPTO` payloads — `rand::thread_rng` weak-key
//! generation truncated to 16 bits.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const WEAK_BITS: u32 = 16;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_CRYPTO_WEAK",
        label: "crypto-rust-weak-random",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/rust/vuln.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        benign_control: Some(PayloadRef {
            label: "crypto-rust-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_CRYPTO_STRONG",
        label: "crypto-rust-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: WEAK_BITS }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/rust/benign.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
