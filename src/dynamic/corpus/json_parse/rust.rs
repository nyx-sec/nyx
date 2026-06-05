//! Rust `Cap::JSON_PARSE` payloads.
//!
//! The depth pair shares a single fixture; the payload tag
//! (`NYX_JSON_DEEP` vs `NYX_JSON_SHALLOW`) picks the branch.  Rust has
//! no prototype-pollution surface so the canary half of the slice is
//! intentionally omitted.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const MAX_DEPTH: u32 = 64;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_JSON_DEEP",
        label: "json-parse-rust-depth-bomb",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth {
                max_depth: MAX_DEPTH,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse_depth/rust/vuln.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::JsonParseExcessiveDepth {
            max_depth: MAX_DEPTH,
        }],
        benign_control: Some(PayloadRef {
            label: "json-parse-rust-depth-shallow",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_JSON_SHALLOW",
        label: "json-parse-rust-depth-shallow",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth {
                max_depth: MAX_DEPTH,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse_depth/rust/vuln.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
