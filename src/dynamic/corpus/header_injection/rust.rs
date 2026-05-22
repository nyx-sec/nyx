//! Rust `Cap::HEADER_INJECTION` payloads — `axum`-style
//! `HeaderMap::insert` CRLF injection.
//!
//! Vuln payload: a cookie value followed by `\r\nSet-Cookie:
//! nyx-injected=pwn`.  Spliced into a hand-rolled `HeaderMap` insert
//! that bypasses the `HeaderValue::from_str` validity check (e.g.
//! `HeaderValue::from_bytes(...).unwrap()` over a tainted slice).
//!
//! Benign control: same logical cookie value pre-encoded with the
//! `percent-encoding` crate.  Captured value carries `%0D%0A` so the
//! predicate stays clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-rust-crlf",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/rust/vuln.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-rust-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-rust-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/rust/benign.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
    // Phase 08 tier-(b): raw-socket wire-frame smuggling payload.
    // Same CRLF-bearing bytes as the axum payload above, but pinned to
    // the `rust_raw` fixture (a `std::net::TcpListener` driven by
    // `create_server` + `run_once` that writes raw bytes via
    // `TcpStream::write_all`).  The wire frame captured off the
    // response socket carries two distinct `Set-Cookie:` lines, so
    // `HeaderSmuggledInWire { primary: "Set-Cookie", smuggled:
    // "Set-Cookie" }` fires — proving the smuggled header survived to
    // the actual wire instead of being CRLF-stripped en route.
    //
    // Distinct payload (not just an extra predicate on the axum row)
    // because every framework's response serializer strips CRLF at
    // the wire-write boundary, so the wire-frame predicate would
    // never fire against the canonical axum fixture.  See
    // `.pitboss/play/deferred.md` (Phase 08 wire-frame option A) for
    // the framework-level CRLF-strip empirical from session-0018.
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-rust-raw-wire-smuggle",
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
        fixture_paths: &["tests/dynamic_fixtures/header_injection/rust_raw/vuln.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderSmuggledInWire {
            primary: "Set-Cookie",
            smuggled: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-rust-raw-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-rust-raw-benign",
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
        fixture_paths: &["tests/dynamic_fixtures/header_injection/rust_raw/vuln.rs"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
