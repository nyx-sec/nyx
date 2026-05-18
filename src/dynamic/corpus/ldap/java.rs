//! Java `Cap::LDAP_INJECTION` payloads — `LdapTemplate.search` /
//! `DirContext.search` filter injection.
//!
//! Vuln payload: a filter fragment whose `*)(uid=*` tail breaks out of
//! the host template's `(uid=…)` clause and rewraps the search as
//! `(|(uid=…)(uid=*))`, matching every user the directory carries.
//! The harness's instrumented LDAP client (talking to
//! [`crate::dynamic::stubs::ldap_server`]) records
//! `ProbeKind::Ldap { entries_returned: 3 }`.
//!
//! Benign control: the same intended username quoted through
//! `EscapeDN` so the LDAP filter stays pinned to a single entry; the
//! shim records `entries_returned: 1` and the oracle does not fire.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"alice*)(uid=*",
        label: "ldap-java-filter-wildcard",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::LdapResultCountGreaterThan { n: 1 }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 10,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ldap_injection/java/Vuln.java"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::LdapResultCountGreaterThan { n: 1 }],
        benign_control: Some(PayloadRef {
            label: "ldap-java-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"alice",
        label: "ldap-java-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::LdapResultCountGreaterThan { n: 1 }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 10,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/ldap_injection/java/Benign.java"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
