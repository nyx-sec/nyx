//! Command-injection payloads exercised by Rust fixtures
//! (`tests/benchmark/corpus/rust/cmdi/`).
//!
//! Bytes are shell-syntax, not Rust-specific; Track J phases 03–11 add
//! per-language slices (Python `os.system`, PHP `exec`, …) as new fixtures
//! land.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"; echo NYX_PWN_CMDI",
        label: "cmdi-echo-marker",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/rust/cmdi/cmdi_command.rs",
            "tests/benchmark/corpus/rust/cmdi/cmdi_args.rs",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "cmdi-benign",
        }),
        no_benign_control_rationale: None,
    },
    // Benign control: plain text that should never produce the cmdi marker.
    CuratedPayload {
        bytes: b"benign_safe_cmdi_NYX_BENIGN",
        label: "cmdi-benign",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 4,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/rust/cmdi/cmdi_command.rs",
            "tests/benchmark/corpus/rust/cmdi/cmdi_args.rs",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
