//! SSRF payloads exercised by Rust fixtures
//! (`tests/benchmark/corpus/rust/ssrf/`).
//!
//! Two variants:
//!   1. `file://` scheme — static payload, `OutputContains` oracle. Works in
//!      the process backend without OOB infrastructure.
//!   2. OOB nonce slot — URL generated at runtime from the OOB listener.
//!      Confirms SSRF by recording the callback nonce.
//!
//! Oracle notes:
//!   `OutputContains("daemon:")` matches both Linux (`daemon:x:1:1:`) and
//!   macOS (`daemon:*:1:1:`) `/etc/passwd` formats and must NOT collide with
//!   FILE_IO's `"root:"` marker (see marker_uniqueness test).

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"file:///etc/passwd",
        label: "ssrf-file-scheme",
        oracle: Oracle::OutputContains("daemon:"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/ssrf/ssrf_reqwest.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef { label: "ssrf-benign" }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        // `bytes` is unused when `oob_nonce_slot = true`; the runner
        // materialises the URL from the OOB listener at call time.
        bytes: b"",
        label: "ssrf-oob-nonce",
        oracle: Oracle::OobCallback { host: "127.0.0.1" },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 2,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/ssrf/ssrf_reqwest.rs"],
        oob_nonce_slot: true,
        probe_predicates: &[],
        // OOB-nonce payloads are self-confirming via the listener; no benign
        // counterpart is meaningful (a benign URL can never hit the nonce
        // listener), so this entry sits at `NoControl`.
        benign_control: None,
        no_benign_control_rationale: Some(
            "OOB-nonce payload self-confirms via the per-finding listener callback; \
             no benign URL can hit the nonce path, so no paired control is meaningful.",
        ),
    },
    // Benign control for the file-scheme SSRF variant.  Fetched the same
    // way as the vuln payload but cannot resolve to a body containing the
    // `daemon:` marker.
    CuratedPayload {
        bytes: b"benign_safe_ssrf_NYX_BENIGN",
        label: "ssrf-benign",
        oracle: Oracle::OutputContains("daemon:"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 4,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/ssrf/ssrf_reqwest.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
