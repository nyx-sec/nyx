//! Python `Cap::XXE` payloads — `lxml.etree.XMLParser(resolve_entities=True)`.
//!
//! Vuln payload: an XML document declaring an external entity that
//! the harness's instrumented parser (`resolve_entities=True`)
//! expands inside `<data>`; the shim writes
//! `ProbeKind::Xxe { entity_expanded: true }` once it sees the entity
//! body substitute into the parsed tree.
//!
//! Benign control: a well-formed XML document with no doctype, so the
//! parser has nothing to resolve and the shim writes
//! `entity_expanded: false`.
//!
//! OOB-nonce variant (added 2026-05-21): when the runner attaches an
//! [`crate::dynamic::oob::OobListener`], the runner materialises this
//! payload's bytes as a loopback URL and the Python harness wraps the
//! URL into `<!ENTITY xxe SYSTEM "URL">`.  Expat's external-entity hook
//! performs a real `urllib.request.urlopen` against the URL so the
//! listener records the per-finding nonce.  Ordered first so the runner
//! exercises the OOB observation path before the doctype-entity vuln
//! triggers and short-circuits the iteration; runs without a listener
//! skip cleanly (the runner's `oob_nonce_slot` branch `continue`s when
//! [`crate::dynamic::sandbox::SandboxOptions::oob_listener`] is None).

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    // OOB-nonce XXE variant.  Ordered first so the harness exercises the
    // OOB observation path before the doctype-entity vuln below triggers
    // and breaks iteration.  Self-confirming via [`Oracle::OobCallback`];
    // no paired benign control because a benign URL can never hit the
    // per-finding nonce path.  Runs only when an [`OobListener`] is
    // attached; the runner's `oob_nonce_slot` branch skips otherwise.
    CuratedPayload {
        bytes: b"",
        label: "xxe-python-oob-nonce",
        oracle: Oracle::OobCallback { host: "127.0.0.1" },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 15,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/python/vuln.py"],
        oob_nonce_slot: true,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: Some(
            "OOB-nonce XXE payload self-confirms via the per-finding listener \
             callback when expat's external-entity hook fetches the loopback \
             URL; no benign URL can hit the nonce path so no paired control \
             is meaningful.",
        ),
    },
    CuratedPayload {
        bytes: br#"<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<data>&xxe;</data>"#,
        label: "xxe-python-doctype-entity",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::XxeEntityExpanded {
                require_expanded: true,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 9,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::XxeEntityExpanded {
            require_expanded: true,
        }],
        benign_control: Some(PayloadRef {
            label: "xxe-python-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: br#"<?xml version="1.0"?>
<data>hello</data>"#,
        label: "xxe-python-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::XxeEntityExpanded {
                require_expanded: true,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 9,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/xxe/python/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
