//! Go `Cap::OPEN_REDIRECT` payloads — `gin.Context.Redirect` /
//! `http.Redirect` off-origin redirect.
//!
//! Vuln payload: an absolute attacker URL spliced into
//! `c.Redirect(http.StatusFound, value)` (or
//! `http.Redirect(w, r, value, ...)`) without host validation; the
//! harness records a `ProbeKind::Redirect` probe whose `location`
//! points off-origin.
//!
//! Benign control: same shape but redirects to the same-origin path
//! `/dashboard`, so the captured `location` has no authority
//! component and the predicate stays clear.
//!
//! OOB-nonce variant (added 2026-05-22): when the runner attaches an
//! [`crate::dynamic::oob::OobListener`] the harness follows the
//! captured `Location:` URL via a real `net/http.Get` against the
//! loopback nonce URL so the listener records the per-finding
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
        label: "open-redirect-go-oob-nonce",
        oracle: Oracle::OobCallback { host: "127.0.0.1" },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/go/vuln.go"],
        oob_nonce_slot: true,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: Some(
            "OOB-nonce open-redirect payload self-confirms via the per-finding listener \
             callback when the harness follows the captured Location URL with net/http.Get; \
             no benign URL can hit the nonce path.",
        ),
    },
    CuratedPayload {
        bytes: b"https://attacker.test/",
        label: "open-redirect-go-absolute",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: ALLOWLIST,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 13,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/go/vuln.go"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::RedirectHostNotIn {
            allowlist: ALLOWLIST,
        }],
        benign_control: Some(PayloadRef {
            label: "open-redirect-go-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"/dashboard",
        label: "open-redirect-go-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::RedirectHostNotIn {
                allowlist: ALLOWLIST,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 13,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/open_redirect/go/benign.go"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
