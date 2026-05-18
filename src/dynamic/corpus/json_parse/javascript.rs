//! JavaScript `Cap::JSON_PARSE` payloads — `JSON.parse` then deep
//! assign / `Object.assign` chain.
//!
//! Same canary oracle as the Phase 10 PROTOTYPE_POLLUTION corpus
//! ([`crate::dynamic::oracle::ProbePredicate::PrototypeCanaryTouched`]).
//! The harness routes both payloads through `JSON.parse` first to
//! exercise the parse-then-assign flow specifically (whereas the
//! Phase 10 corpus passes the JSON literal directly to the deep-merge
//! sink without an intervening parse).

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const CANARY: &str = "__nyx_canary";

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
];
