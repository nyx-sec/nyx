//! PHP Twig `Cap::SSTI` payloads.
//!
//! Vuln payload: `{{7*7}}` — Twig evaluates the expression and the
//! rendered template body is `49`.  Benign control sends the literal
//! `7*7` text; Twig has no `{{ ... }}` markers around it and echoes
//! the payload verbatim.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"{{7*7}}",
        label: "ssti-twig-eval",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/ssti/php_twig/vuln.php",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        benign_control: Some(PayloadRef {
            label: "ssti-twig-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"7*7",
        label: "ssti-twig-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/ssti/php_twig/benign.php",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
