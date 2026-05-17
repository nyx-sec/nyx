//! XSS payloads exercised by Rust fixtures
//! (`tests/benchmark/corpus/rust/xss/axum_html/`).
//!
//! Vuln: raw script tag echoed to output.
//! Benign: harmless text that should NOT produce the XSS marker.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"<script>NYX_XSS_CONFIRMED</script>",
        label: "xss-script-marker",
        oracle: Oracle::OutputContains("<script>NYX_XSS_CONFIRMED</script>"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/xss/axum_html/main.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef { label: "xss-benign-text" }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"Hello World",
        label: "xss-benign-text",
        oracle: Oracle::OutputContains("<script>NYX_XSS_CONFIRMED</script>"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/xss/axum_html/main.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
