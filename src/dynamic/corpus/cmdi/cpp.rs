//! C++ `Cap::CODE_EXEC` payloads.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"; echo NYX_PWN_CMDI",
        label: "cmdi-echo-marker-cpp",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/cpp/cmdi/cmdi_class_inline_method.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_exec.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_getline.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_lambda_passthrough.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_popen.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_stl_vector_string.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_system.cpp",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef { label: "cmdi-benign-cpp" }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"benign_safe_cmdi_NYX_BENIGN",
        label: "cmdi-benign-cpp",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/cpp/cmdi/cmdi_class_inline_method.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_exec.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_getline.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_lambda_passthrough.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_popen.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_stl_vector_string.cpp",
            "tests/benchmark/corpus/cpp/cmdi/cmdi_system.cpp",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
