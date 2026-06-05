//! Java `Cap::XPATH_INJECTION` payloads — `javax.xml.xpath.XPath.evaluate`
//! expression injection.
//!
//! Vuln payload: an XPath fragment whose `' or '1'='1` tail breaks
//! out of the host template's `[@name='…']` predicate and rewraps
//! the selector as `//user[@name='' or '1'='1']`, matching every
//! node the staged document carries.  The harness's instrumented
//! `XPath.evaluate` records
//! `ProbeKind::Xpath { nodes_returned: 3 }`.
//!
//! Benign control: the same intended username quoted via the
//! harness's XPath-escape helper, leaving the expression pinned to a
//! single node — `nodes_returned: 1`, oracle clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"alice' or '1'='1",
        label: "xpath-java-expression-wildcard",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 11,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xpath_injection/java/Vuln.java"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        benign_control: Some(PayloadRef {
            label: "xpath-java-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"alice",
        label: "xpath-java-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 11,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xpath_injection/java/Benign.java"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
