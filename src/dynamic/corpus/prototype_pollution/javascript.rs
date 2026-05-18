//! JavaScript `Cap::PROTOTYPE_POLLUTION` payloads.
//!
//! Vuln payload: a JSON literal whose top-level key is `__proto__`.
//! When the host's deep-merge / `Object.assign` / JSON-parse-then-
//! deep-assign sink walks the key into the merge target, the
//! `__proto__` reference reaches `Object.prototype` and writes
//! `__nyx_canary`.  The harness's instrumented setter trap records a
//! `ProbeKind::PrototypePollution { property: "__nyx_canary", … }`
//! probe; the predicate
//! [`crate::dynamic::oracle::ProbePredicate::PrototypeCanaryTouched`]
//! fires on the captured canary write.
//!
//! Benign control: a JSON literal whose top-level key is the regular
//! property `data`.  Naive deep-merge walks `target.data` rather than
//! `target.__proto__`, so the prototype chain stays untouched and the
//! predicate stays clear.  The matching fixture
//! (`tests/dynamic_fixtures/prototype_pollution/javascript/benign.js`)
//! additionally demonstrates the canonical mitigation pattern of
//! using `Object.create(null)` as the merge target — static analysis
//! of the fixture surfaces the prototype-less target while the
//! runtime differential is driven by the absence of a `__proto__` key
//! in the payload bytes.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const CANARY: &str = "__nyx_canary";

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: br#"{"__proto__":{"__nyx_canary":"pwned"}}"#,
        label: "prototype-pollution-js-proto-key",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 14,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/prototype_pollution/javascript/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        benign_control: Some(PayloadRef {
            label: "prototype-pollution-js-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: br#"{"data":{"__nyx_canary":"pwned"}}"#,
        label: "prototype-pollution-js-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 14,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/prototype_pollution/javascript/benign.js"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
