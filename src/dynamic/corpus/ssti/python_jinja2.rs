//! Python Jinja2 `Cap::SSTI` payloads.
//!
//! Vuln payload: `{{7*7}}` — Jinja2 evaluates the expression and the
//! rendered template body is `49`.  The harness's
//! [`crate::dynamic::oracle::ProbePredicate::TemplateEvalEqual`] check
//! compares the captured `{"render": "49"}` JSON body against
//! `expected = 49` and the oracle fires.
//!
//! Benign control: literal `7*7` — Jinja2 has no `{{ ... }}` markers to
//! evaluate so the engine echoes the payload verbatim.  The rendered
//! body is `7*7`, the oracle's integer parse fails, and the oracle
//! does not fire.  Together with the vuln payload this satisfies the
//! §4.1 differential confirmation rule.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"{{7*7}}",
        label: "ssti-jinja2-eval",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ssti/python_jinja2/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        benign_control: Some(PayloadRef {
            label: "ssti-jinja2-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"7*7",
        label: "ssti-jinja2-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ssti/python_jinja2/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
