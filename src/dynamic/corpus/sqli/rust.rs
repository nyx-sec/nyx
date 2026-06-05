//! SQLi payloads exercised by Rust fixtures (`tests/benchmark/corpus/rust/sqli/`).
//!
//! Payload bytes are SQL-syntax, not Rust-specific; the `Lang::Rust` slot
//! reflects the fixture that currently drives them.  Track J phases 03–11
//! add per-language slices as new fixtures land.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"' OR '1'='1",
        label: "sqli-tautology",
        oracle: Oracle::OutputContains("NYX_SQL_CONFIRMED"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/sqli/sqli_rusqlite_format.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "sqli-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"' UNION SELECT 'NYX_SQL_CONFIRMED'--",
        label: "sqli-union-nyx",
        oracle: Oracle::OutputContains("NYX_SQL_CONFIRMED"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/sqli/sqli_rusqlite_format.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "sqli-benign",
        }),
        no_benign_control_rationale: None,
    },
    // Benign control: ordinary value that should never produce the SQL marker.
    CuratedPayload {
        bytes: b"benign_safe_sqli_NYX_BENIGN",
        label: "sqli-benign",
        oracle: Oracle::OutputContains("NYX_SQL_CONFIRMED"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 4,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/sqli/sqli_rusqlite_format.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
