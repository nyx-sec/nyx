//! Go `Cap::CODE_EXEC` payloads.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b":; echo NYX_PWN_$((113*7))_CMDI",
        label: "cmdi-echo-marker-go",
        oracle: Oracle::OutputContains("NYX_PWN_791_CMDI"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/go/cmdi/cmdi_direct.go",
            "tests/benchmark/corpus/go/cmdi/cmdi_indirect.go",
            "tests/benchmark/corpus/go/cmdi/cmdi_unvalidated_queue_element.go",
            "tests/benchmark/corpus/go/cmdi/vuln_error_log_then_sink.go",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "cmdi-benign-go",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"benign_safe_cmdi_NYX_BENIGN",
        label: "cmdi-benign-go",
        oracle: Oracle::OutputContains("NYX_PWN_791_CMDI"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/go/cmdi/cmdi_direct.go",
            "tests/benchmark/corpus/go/cmdi/cmdi_indirect.go",
            "tests/benchmark/corpus/go/cmdi/cmdi_unvalidated_queue_element.go",
            "tests/benchmark/corpus/go/cmdi/vuln_error_log_then_sink.go",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
