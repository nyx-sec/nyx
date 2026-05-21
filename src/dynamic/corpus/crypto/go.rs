//! Go `Cap::CRYPTO` payloads — `math/rand.Intn` weak-key
//! generation.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const WEAK_BITS: u32 = 16;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_CRYPTO_WEAK",
        label: "crypto-go-weak-random",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy {
                max_bits: WEAK_BITS,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/go/vuln.go"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::WeakKeyEntropy {
            max_bits: WEAK_BITS,
        }],
        benign_control: Some(PayloadRef {
            label: "crypto-go-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_CRYPTO_STRONG",
        label: "crypto-go-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy {
                max_bits: WEAK_BITS,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/go/benign.go"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
