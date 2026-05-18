//! Python `Cap::OPEN_REDIRECT` payloads — `flask.redirect`
//! off-origin redirect.
//!
//! Vuln payload: an attacker-controlled absolute URL spliced into
//! `flask.redirect(value)` without host validation; the captured
//! `Location:` header points off-origin and the
//! [`crate::dynamic::oracle::ProbePredicate::RedirectHostNotIn`]
//! predicate fires.
//!
//! Benign control: same shape but redirects to the relative path
//! `/dashboard`, so the captured location has no authority component
//! and the predicate stays clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const ALLOWLIST: &[&str] = &["example.com"];

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"https://attacker.test/",
        label: "open-redirect-python-absolute",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn { allowlist: ALLOWLIST }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 13,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::RedirectHostNotIn { allowlist: ALLOWLIST }],
        benign_control: Some(PayloadRef {
            label: "open-redirect-python-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"/dashboard",
        label: "open-redirect-python-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn { allowlist: ALLOWLIST }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 13,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/python/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
