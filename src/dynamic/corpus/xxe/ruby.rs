//! Ruby `Cap::XXE` payloads — REXML / Nokogiri document parsers.
//!
//! Vuln payload: an XML document declaring an external entity that
//! the harness's instrumented parser expands inside `<data>`; the
//! shim writes `ProbeKind::Xxe { entity_expanded: true }` once it
//! sees the entity body substitute into the parsed output.
//!
//! Benign control: a well-formed XML document with no doctype, so
//! the parser has no entity to resolve and the shim writes
//! `entity_expanded: false`.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: br#"<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<data>&xxe;</data>"#,
        label: "xxe-ruby-doctype-entity",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::XxeEntityExpanded {
                require_expanded: true,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 9,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/xxe/ruby/vuln.rb",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::XxeEntityExpanded {
            require_expanded: true,
        }],
        benign_control: Some(PayloadRef {
            label: "xxe-ruby-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: br#"<?xml version="1.0"?>
<data>hello</data>"#,
        label: "xxe-ruby-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::XxeEntityExpanded {
                require_expanded: true,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 9,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/xxe/ruby/benign.rb",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
