//! Java Thymeleaf `Cap::SSTI` payloads.
//!
//! Vuln payload: `[[${7*7}]]` — Thymeleaf evaluates the SpEL-style
//! expression inside the inlined-output marker and renders `49`.
//! Benign control sends the literal `7*7` text; without the `[[${...}]]`
//! markers Thymeleaf passes the payload through unchanged.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"[[${7*7}]]",
        label: "ssti-thymeleaf-eval",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ssti/java_thymeleaf/vuln.java"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        benign_control: Some(PayloadRef {
            label: "ssti-thymeleaf-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"7*7",
        label: "ssti-thymeleaf-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ssti/java_thymeleaf/benign.java"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
