//! Python `Cap::CODE_EXEC` payloads.
//!
//! Same shell-syntax bytes as [`super::rust::PAYLOADS`]; the per-language
//! slice exists so the lookup is a per-language assertion rather than a
//! cross-language fallback through [`super::super::registry::payloads_for`].

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"; echo NYX_PWN_CMDI",
        label: "cmdi-echo-marker-python",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/python/cmdi/cmdi_direct.py",
            "tests/benchmark/corpus/python/cmdi/cmdi_indirect.py",
            "tests/benchmark/corpus/python/cmdi/cmdi_popen_shell.py",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef { label: "cmdi-benign-python" }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"benign_safe_cmdi_NYX_BENIGN",
        label: "cmdi-benign-python",
        oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/python/cmdi/cmdi_direct.py",
            "tests/benchmark/corpus/python/cmdi/cmdi_indirect.py",
            "tests/benchmark/corpus/python/cmdi/cmdi_popen_shell.py",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
