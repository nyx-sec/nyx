//! Go `Cap::HEADER_INJECTION` payloads —
//! `http.ResponseWriter.Header().Set` CRLF injection.
//!
//! Vuln payload: a cookie value followed by `\r\nSet-Cookie:
//! nyx-injected=pwn`.  Spliced into the host's `w.Header().Set("Set-
//! Cookie", value)` call without CRLF stripping.
//!
//! Benign control: same logical cookie value pre-encoded with
//! `net/url.QueryEscape`.  Captured value carries `%0D%0A` so the
//! predicate stays clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-go-crlf",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/go/vuln.go"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-go-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-go-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/go/benign.go"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
