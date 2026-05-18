//! Java `Cap::HEADER_INJECTION` payloads —
//! `HttpServletResponse.setHeader` CRLF injection.
//!
//! Vuln payload: a cookie value followed by `\r\nSet-Cookie:
//! nyx-injected=pwn`.  Concatenated into the host's
//! `response.setHeader("Set-Cookie", value)` call without CRLF
//! stripping, the wire response carries the attacker's second
//! header.  The harness's instrumented `setHeader` records a
//! `ProbeKind::HeaderEmit { name: "Set-Cookie", value: <raw bytes> }`
//! probe with the unescaped CRLF intact.
//!
//! Benign control: same logical session-id, but the harness's
//! benign code path runs the value through `URLEncoder.encode(...,
//! "UTF-8")` so the carried bytes become
//! `nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn`.  The
//! captured value has no literal `\r\n`; the
//! [`ProbePredicate::HeaderInjected`] predicate stays clear.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"nyx-session\r\nSet-Cookie: nyx-injected=pwn",
        label: "header-injection-java-crlf",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/java/Vuln.java"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
        benign_control: Some(PayloadRef {
            label: "header-injection-java-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn",
        label: "header-injection-java-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::HeaderInjected {
                header_name: "Set-Cookie",
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 12,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/header_injection/java/Benign.java"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
