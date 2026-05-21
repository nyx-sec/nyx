//! PHP `Cap::CRYPTO` payloads — `mt_rand` weak-key generation.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const WEAK_BITS: u32 = 16;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_CRYPTO_WEAK",
        label: "crypto-php-weak-random",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy {
                max_bits: WEAK_BITS,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/php/vuln.php"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::WeakKeyEntropy {
            max_bits: WEAK_BITS,
        }],
        benign_control: Some(PayloadRef {
            label: "crypto-php-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_CRYPTO_STRONG",
        label: "crypto-php-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::WeakKeyEntropy {
                max_bits: WEAK_BITS,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/crypto/php/benign.php"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
