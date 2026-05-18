//! PHP `Cap::XPATH_INJECTION` payloads — `DOMXPath::query` expression
//! injection.
//!
//! Vuln payload: an XPath fragment whose `' or '1'='1` tail breaks
//! out of the host template's `[@name='…']` predicate; the
//! synthesized expression becomes `//user[@name='' or '1'='1']` and
//! matches every node in the staged document.  The harness's
//! instrumented `DOMXPath::query` records
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
        label: "xpath-php-expression-wildcard",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 11,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xpath_injection/php/vuln.php"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        benign_control: Some(PayloadRef {
            label: "xpath-php-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"alice",
        label: "xpath-php-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 11,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xpath_injection/php/benign.php"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
