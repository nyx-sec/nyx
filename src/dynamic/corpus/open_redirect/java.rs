//! Java `Cap::OPEN_REDIRECT` payloads —
//! `HttpServletResponse.sendRedirect` off-origin redirect.
//!
//! Vuln payload: a fully-qualified attacker URL
//! (`https://attacker.test/`).  Spliced into the host's
//! `response.sendRedirect(value)` call without host validation, the
//! servlet response's `Location:` header points off-origin.  The
//! harness's instrumented `sendRedirect` shim records a
//! `ProbeKind::Redirect { location: <raw>, request_host:
//! "example.com" }` probe; the predicate
//! [`crate::dynamic::oracle::ProbePredicate::RedirectHostNotIn`] sees
//! the off-allowlist host and fires.
//!
//! Benign control: same logical entry point, but the harness's benign
//! code path redirects to the relative path `/dashboard` (no host
//! component).  The captured `location` has no off-origin authority
//! and the predicate stays clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const ALLOWLIST: &[&str] = &["example.com"];

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"https://attacker.test/",
        label: "open-redirect-java-absolute",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn { allowlist: ALLOWLIST }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 13,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/java/Vuln.java"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::RedirectHostNotIn { allowlist: ALLOWLIST }],
        benign_control: Some(PayloadRef {
            label: "open-redirect-java-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"/dashboard",
        label: "open-redirect-java-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn { allowlist: ALLOWLIST }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 13,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/java/Benign.java"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
