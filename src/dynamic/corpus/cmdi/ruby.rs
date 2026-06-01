//! Ruby `Cap::CODE_EXEC` payloads.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b":; echo NYX_PWN_$((113*7))_CMDI",
        label: "cmdi-echo-marker-ruby",
        oracle: Oracle::OutputContains("NYX_PWN_791_CMDI"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/ruby/cmdi/cmdi_backtick.rb",
            "tests/benchmark/corpus/ruby/cmdi/cmdi_kernel_open.rb",
            "tests/benchmark/corpus/ruby/cmdi/cmdi_system.rb",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "cmdi-benign-ruby",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"benign_safe_cmdi_NYX_BENIGN",
        label: "cmdi-benign-ruby",
        oracle: Oracle::OutputContains("NYX_PWN_791_CMDI"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/ruby/cmdi/cmdi_backtick.rb",
            "tests/benchmark/corpus/ruby/cmdi/cmdi_kernel_open.rb",
            "tests/benchmark/corpus/ruby/cmdi/cmdi_system.rb",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
