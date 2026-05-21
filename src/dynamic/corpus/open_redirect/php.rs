//! PHP `Cap::OPEN_REDIRECT` payloads — `Response::redirect` /
//! Symfony `RedirectResponse(...)` off-origin redirect.
//!
//! Vuln payload: an absolute attacker URL passed to
//! `header("Location: $value")` or
//! `new \Symfony\Component\HttpFoundation\RedirectResponse($value)`
//! without host validation.  The harness records a
//! `ProbeKind::Redirect { location, request_host }` probe and the
//! predicate fires on the off-allowlist host.
//!
//! Benign control: same shape but redirects to the same-origin path
//! `/dashboard`, so the captured `location` has no authority
//! component and the predicate stays clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const ALLOWLIST: &[&str] = &["example.com"];

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"https://attacker.test/",
        label: "open-redirect-php-absolute",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: ALLOWLIST,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 13,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/php/vuln.php"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::RedirectHostNotIn {
            allowlist: ALLOWLIST,
        }],
        benign_control: Some(PayloadRef {
            label: "open-redirect-php-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"/dashboard",
        label: "open-redirect-php-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: ALLOWLIST,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 13,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/php/benign.php"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
