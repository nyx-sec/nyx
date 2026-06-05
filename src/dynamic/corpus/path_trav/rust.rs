//! Path-traversal payloads exercised by Rust fixtures
//! (`tests/benchmark/corpus/rust/path_traversal/`).
//!
//! Vuln payload reads `/etc/passwd`; benign payload names a file that does
//! not exist so the same oracle marker cannot fire.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"../../../../etc/passwd",
        label: "path-traversal-passwd",
        oracle: Oracle::OutputContains("root:"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/rust/path_traversal/path_file_open.rs",
            "tests/benchmark/corpus/rust/path_traversal/path_read.rs",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "path-traversal-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"benign_safe_file_that_does_not_exist_NYX_BENIGN",
        label: "path-traversal-benign",
        oracle: Oracle::OutputContains("root:"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/path_traversal/path_file_open.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
