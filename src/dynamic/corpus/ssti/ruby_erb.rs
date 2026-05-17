//! Ruby ERB `Cap::SSTI` payloads.
//!
//! Vuln payload: `<%= 7*7 %>` — ERB evaluates the embedded Ruby
//! expression and the rendered template body is `49`.  Benign control
//! ships the literal `7*7` text which ERB has no `<%= ... %>` marker
//! around and so passes through verbatim.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"<%= 7*7 %>",
        label: "ssti-erb-eval",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/ssti/ruby_erb/vuln.rb",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        benign_control: Some(PayloadRef {
            label: "ssti-erb-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"7*7",
        label: "ssti-erb-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/ssti/ruby_erb/benign.rb",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
