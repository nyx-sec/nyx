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
    // Phase 08 tier-(b): raw-socket wire-frame smuggling payload.
    // Same CRLF-bearing bytes as the Flask payload above, but pinned
    // to the `python_raw` fixture (a `BaseHTTPRequestHandler` writing
    // raw bytes via `self.wfile.write`).  The wire frame captured off
    // the response socket carries two distinct `Set-Cookie:` lines, so
    // `HeaderSmuggledInWire { primary: "Set-Cookie", smuggled:
    // "Set-Cookie" }` fires — proving the smuggled header survived to
    // the actual wire instead of being CRLF-stripped en route.
    //
    // Distinct payload (not just an extra predicate on the Flask row)
    // because Flask's werkzeug response serializer strips CRLF at the
    // wire-write boundary, so the wire-frame predicate would never
    // fire against the canonical Flask fixture.  See
    // `.pitboss/play/deferred.md` (Phase 08 wire-frame option A) for
    // the framework-level CRLF-strip empirical from session-0018.
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-python-raw-wire-smuggle",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderSmuggledInWire {
                primary: "Set-Cookie",
                smuggled: "Set-Cookie",
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/python_raw/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderSmuggledInWire {
            primary: "Set-Cookie",
            smuggled: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-python-raw-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-python-raw-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderSmuggledInWire {
                primary: "Set-Cookie",
                smuggled: "Set-Cookie",
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/python_raw/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
