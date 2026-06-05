//! JavaScript `Cap::HEADER_INJECTION` payloads —
//! `http.ServerResponse#setHeader` CRLF injection.
//!
//! Vuln payload: a cookie value followed by `\r\nSet-Cookie:
//! nyx-injected=pwn`.  Spliced into the host's
//! `res.setHeader('Set-Cookie', value)` call without CRLF stripping.
//!
//! Benign control: same logical cookie value pre-encoded with
//! `encodeURIComponent`.  Captured value carries `%0D%0A` so the
//! predicate stays clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-js-crlf",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/js/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-js-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-js-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/js/benign.js"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
    // Phase 08 tier-(b): raw-socket wire-frame smuggling payload.
    // Same CRLF-bearing bytes as the Node payload above, but pinned to
    // the `js_raw` fixture (a `net.createServer` callback writing raw
    // bytes via `socket.write`).  The wire frame captured off the
    // response socket carries two distinct `Set-Cookie:` lines, so
    // `HeaderSmuggledInWire { primary: "Set-Cookie", smuggled:
    // "Set-Cookie" }` fires — proving the smuggled header survived to
    // the actual wire instead of being CRLF-stripped en route.
    //
    // Distinct payload (not just an extra predicate on the Node row)
    // because Node's `http.ServerResponse#setHeader` validator strips
    // CRLF at the wire-write boundary, so the wire-frame predicate
    // would never fire against the canonical Node fixture.  See
    // `.pitboss/play/deferred.md` (Phase 08 wire-frame option A) for
    // the framework-level CRLF-strip empirical from session-0018.
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-js-raw-wire-smuggle",
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
        fixture_paths: &["tests/dynamic_fixtures/header_injection/js_raw/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderSmuggledInWire {
            primary: "Set-Cookie",
            smuggled: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-js-raw-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-js-raw-benign",
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
        fixture_paths: &["tests/dynamic_fixtures/header_injection/js_raw/vuln.js"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
