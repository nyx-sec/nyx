//! Go `Cap::XXE` payloads — `encoding/xml.Decoder` with `Strict: false`.
//!
//! Vuln payload: an XML document declaring an external entity that
//! the harness's instrumented `xml.Decoder` (running non-strict so
//! the doctype is parsed at all) expands inside `<data>`; the shim
//! writes `ProbeKind::Xxe { entity_expanded: true }` once it sees the
//! entity body substitute into the decoded element value.
//!
//! Benign control: a well-formed XML document with no doctype, so the
//! decoder has no entity to resolve and the shim writes
//! `entity_expanded: false`.
//!
//! OOB-nonce variant (added 2026-05-21): when the runner attaches an
//! [`crate::dynamic::oob::OobListener`] the harness's
//! `nyxBuildXxeDocument` helper performs a real `http.Client.Get`
//! against the loopback URL so the listener records the per-finding
//! nonce.  Ordered first so iteration exercises OOB before the
//! doctype-entity vuln triggers and short-circuits.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"",
        label: "xxe-go-oob-nonce",
        oracle: Oracle::OobCallback { host: "127.0.0.1" },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/go/vuln.go"],
        oob_nonce_slot: true,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: Some(
            "OOB-nonce XXE payload self-confirms via the per-finding listener \
             callback when the Go harness performs the loopback GET before \
             building the DTD; no benign URL can hit the nonce path.",
        ),
    },
    CuratedPayload {
        bytes: br#"<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<data>&xxe;</data>"#,
        label: "xxe-go-doctype-entity",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::XxeEntityExpanded {
                require_expanded: true,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 9,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/go/vuln.go"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::XxeEntityExpanded {
            require_expanded: true,
        }],
        benign_control: Some(PayloadRef {
            label: "xxe-go-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: br#"<?xml version="1.0"?>
<data>hello</data>"#,
        label: "xxe-go-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::XxeEntityExpanded {
                require_expanded: true,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 9,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/go/benign.go"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
