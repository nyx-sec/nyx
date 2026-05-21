//! TypeScript `Cap::CODE_EXEC` payloads.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"; echo NYX_PWN_CMDI",
        label: "cmdi-echo-marker-typescript",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/typescript/cmdi/cmdi_async_wrapper.ts",
            "tests/benchmark/corpus/typescript/cmdi/cmdi_exec_template.ts",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "cmdi-benign-typescript",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"benign_safe_cmdi_NYX_BENIGN",
        label: "cmdi-benign-typescript",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/typescript/cmdi/cmdi_async_wrapper.ts",
            "tests/benchmark/corpus/typescript/cmdi/cmdi_exec_template.ts",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
