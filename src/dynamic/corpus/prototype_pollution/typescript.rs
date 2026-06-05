//! TypeScript `Cap::PROTOTYPE_POLLUTION` payloads.
//!
//! Mirrors [`super::javascript`] — the runtime is Node.js in both
//! cases, so the payload shape and oracle predicate are identical.
//! The per-language slice exists so the lang-aware corpus resolver
//! pairs TS vuln payloads against TS benign controls without crossing
//! the JS slice (and so the fixture paths point at the TS-specific
//! fixtures the static-analysis side consumes).

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::{Canary, ProbePredicate};

const CANARY: &str = Canary::PLACEHOLDER;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: br#"{"__proto__":{"__nyx_canary":"pwned"}}"#,
        label: "prototype-pollution-ts-proto-key",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 14,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/prototype_pollution/typescript/vuln.ts"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        benign_control: Some(PayloadRef {
            label: "prototype-pollution-ts-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: br#"{"data":{"__nyx_canary":"pwned"}}"#,
        label: "prototype-pollution-ts-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::PrototypeCanaryTouched { canary: CANARY }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 14,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/prototype_pollution/typescript/benign.ts"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
