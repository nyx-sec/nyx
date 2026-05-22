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
//!
//! OOB-nonce variant (added 2026-05-22): when the runner attaches an
//! [`crate::dynamic::oob::OobListener`] the harness follows the
//! captured `Location:` URL via a real
//! `file_get_contents($location, stream_context_create(...))` against
//! the loopback nonce URL so the listener records the per-finding
//! callback.  Ordered first so the runner exercises the OOB observation
//! path before the absolute-URL vuln below triggers and short-circuits
//! iteration; runs without a listener skip cleanly (runner
//! `oob_nonce_slot` branch).

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

const ALLOWLIST: &[&str] = &["example.com"];

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        // `bytes` is unused when `oob_nonce_slot = true`; the runner
        // substitutes a per-finding loopback URL (see runner.rs:405-413).
        bytes: b"",
        label: "open-redirect-php-oob-nonce",
        oracle: Oracle::OobCallback { host: "127.0.0.1" },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/php/vuln.php"],
        oob_nonce_slot: true,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: Some(
            "OOB-nonce open-redirect payload self-confirms via the per-finding listener \
             callback when the harness follows the captured Location URL with \
             file_get_contents under a stream context timeout; no benign URL can hit \
             the nonce path.",
        ),
    },
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
