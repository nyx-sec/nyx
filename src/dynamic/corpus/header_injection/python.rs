//! Python `Cap::HEADER_INJECTION` payloads —
//! `flask.Response.headers.__setitem__` CRLF injection.
//!
//! Vuln payload: a session cookie value followed by `\r\nSet-Cookie:
//! nyx-injected=pwn`.  Spliced into the host's
//! `response.headers["Set-Cookie"] = value` assignment without CRLF
//! stripping, the WSGI layer carries the attacker's second header on
//! the wire.  The harness's instrumented response writer records a
//! `ProbeKind::HeaderEmit { name: "Set-Cookie", value: <raw bytes> }`
//! probe with the unescaped CRLF intact.
//!
//! Benign control: same logical cookie value pre-encoded with
//! `urllib.parse.quote`.  The carried bytes become
//! `nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn` — no literal
//! CRLF — and the [`ProbePredicate::HeaderInjected`] predicate stays
//! clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-python-crlf",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-python-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-python-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/python/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
