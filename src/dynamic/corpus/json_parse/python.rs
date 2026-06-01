//! Python `Cap::JSON_PARSE` payloads.
//!
//! The canary cases cover pollution-style parses. The depth cases drive
//! `json.loads` past the depth oracle while sharing one fixture for the
//! vulnerable and benign attempts.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::{Canary, ProbePredicate};

const CANARY: &str = Canary::PLACEHOLDER;
const MAX_DEPTH: u32 = 64;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: br#"{"__proto__":{"__nyx_canary":"pwned"}}"#,
        label: "json-parse-python-proto-key",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        benign_control: Some(PayloadRef {
            label: "json-parse-python-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: br#"{"data":{"__nyx_canary":"pwned"}}"#,
        label: "json-parse-python-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse/python/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_JSON_DEEP",
        label: "json-parse-python-depth-bomb",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth {
                max_depth: MAX_DEPTH,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse_depth/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::JsonParseExcessiveDepth {
            max_depth: MAX_DEPTH,
        }],
        benign_control: Some(PayloadRef {
            label: "json-parse-python-depth-shallow",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_JSON_SHALLOW",
        label: "json-parse-python-depth-shallow",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::JsonParseExcessiveDepth {
                max_depth: MAX_DEPTH,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/json_parse_depth/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
