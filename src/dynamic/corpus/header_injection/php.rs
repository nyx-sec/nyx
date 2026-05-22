//! PHP `Cap::HEADER_INJECTION` payloads — `header()` CRLF injection.
//!
//! Vuln payload: a cookie value followed by `\r\nSet-Cookie:
//! nyx-injected=pwn`.  Concatenated into the host's `header("Set-
//! Cookie: " . $value)` call without CRLF stripping, the wire response
//! carries the attacker's second header.  The harness's instrumented
//! `header()` records a `ProbeKind::HeaderEmit` probe with the
//! unescaped CRLF intact.
//!
//! Benign control: same logical cookie value pre-encoded with PHP's
//! `urlencode`.  Captured value carries `%0D%0A` so the predicate
//! stays clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-php-crlf",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/php/vuln.php"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-php-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-php-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/php/benign.php"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
    // Phase 08 tier-(b): raw-socket wire-frame smuggling payload.
    // Same CRLF-bearing bytes as the `header()` payload above, but
    // pinned to the `php_raw` fixture (a `stream_socket_server` driven
    // by `create_server` + `run_once` that writes raw bytes via
    // `fwrite($conn, $raw)`).  The wire frame captured off the
    // response socket carries two distinct `Set-Cookie:` lines, so
    // `HeaderSmuggledInWire { primary: "Set-Cookie", smuggled:
    // "Set-Cookie" }` fires — proving the smuggled header survived to
    // the actual wire instead of being CRLF-stripped en route.
    //
    // Distinct payload (not just an extra predicate on the `header()`
    // row) because PHP's built-in `header()` rejects raw CRLF since
    // 5.1.2 and modern Slim / Laravel / Symfony response serializers
    // strip CRLF at the wire-write boundary, so the wire-frame
    // predicate would never fire against the canonical `header()`
    // fixture.
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-php-raw-wire-smuggle",
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
        fixture_paths: &["tests/dynamic_fixtures/header_injection/php_raw/vuln.php"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderSmuggledInWire {
            primary: "Set-Cookie",
            smuggled: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-php-raw-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-php-raw-benign",
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
        fixture_paths: &["tests/dynamic_fixtures/header_injection/php_raw/vuln.php"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
