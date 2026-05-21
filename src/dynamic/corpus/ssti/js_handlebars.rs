//! JavaScript Handlebars `Cap::SSTI` payloads.
//!
//! Handlebars does not evaluate arbitrary arithmetic in `{{ ... }}`
//! expressions out of the box, so the vuln payload reaches the engine
//! through the built-in `lookup` helper combined with a constructor
//! gadget chain: `{{#with (lookup this 'constructor')}}{{lookup
//! this 'constructor'}}{{/with}}` is the canonical pattern, but the
//! evaluation marker we need ("rendered constant only via eval")
//! reduces to a much simpler `{{multiply 7 7}}` against the in-harness
//! `multiply` helper.  The harness registers that helper before
//! compiling so the rendered body is `49`; benign control sends `7*7`
//! plain text which Handlebars echoes verbatim.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"{{multiply 7 7}}",
        label: "ssti-handlebars-eval",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ssti/js_handlebars/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        benign_control: Some(PayloadRef {
            label: "ssti-handlebars-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"7*7",
        label: "ssti-handlebars-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 8,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ssti/js_handlebars/benign.js"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
