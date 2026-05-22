//! JavaScript `Cap::JSON_PARSE` payloads.
//!
//! Covers two oracle shapes: the prototype-canary pair reuses the
//! Phase 10 PROTOTYPE_POLLUTION canary
//! ([`crate::dynamic::oracle::ProbePredicate::PrototypeCanaryTouched`])
//! against a `JSON.parse`-then-deep-merge fixture, and the depth-bomb
//! pair drives `JSON.parse` past the 64-level depth budget for the
//! [`crate::dynamic::oracle::ProbePredicate::JsonParseExcessiveDepth`]
//! oracle.  The depth pair shares a single fixture; the payload tag
//! (`NYX_JSON_DEEP` vs `NYX_JSON_SHALLOW`) picks the branch.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const CANARY: &str = "__nyx_canary";
const MAX_DEPTH: u32 = 64;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: br#"{"__proto__":{"__nyx_canary":"pwned"}}"#,
        label: "json-parse-js-proto-key",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse/javascript/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        benign_control: Some(PayloadRef {
            label: "json-parse-js-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: br#"{"data":{"__nyx_canary":"pwned"}}"#,
        label: "json-parse-js-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse/javascript/benign.js"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_JSON_DEEP",
        label: "json-parse-js-depth-bomb",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth {
                max_depth: MAX_DEPTH,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse_depth/javascript/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::JsonParseExcessiveDepth {
            max_depth: MAX_DEPTH,
        }],
        benign_control: Some(PayloadRef {
            label: "json-parse-js-depth-shallow",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_JSON_SHALLOW",
        label: "json-parse-js-depth-shallow",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth {
                max_depth: MAX_DEPTH,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse_depth/javascript/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
