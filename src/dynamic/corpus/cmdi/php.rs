//! PHP `Cap::CODE_EXEC` payloads.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"; echo NYX_PWN_CMDI",
        label: "cmdi-echo-marker-php",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/php/cmdi/cmdi_direct.php",
            "tests/benchmark/corpus/php/cmdi/cmdi_indirect.php",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "cmdi-benign-php",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"benign_safe_cmdi_NYX_BENIGN",
        label: "cmdi-benign-php",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/php/cmdi/cmdi_direct.php",
            "tests/benchmark/corpus/php/cmdi/cmdi_indirect.php",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
