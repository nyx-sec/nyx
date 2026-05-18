//! Python `Cap::JSON_PARSE` payloads — `json.loads` then
//! attribute-pollution via `setattr` / `dict.update` on a shared
//! sentinel object.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const CANARY: &str = "__nyx_canary";

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
];
