//! Java `Cap::DESERIALIZE` payloads.
//!
//! Vuln payload: a base64-encoded `java.io.ObjectInputStream` byte stream
//! that materialises a gadget class outside the harness's allowlist.
//! The harness's `RestrictedObjectInputStream.resolveClass` intercepts
//! the lookup and emits a `ProbeKind::Deserialize { gadget_chain_invoked
//! = true }` probe before aborting the chain.
//!
//! Benign control: a base64-encoded `ObjectInputStream` byte stream of a
//! single allow-listed `java.lang.Integer`.  The class lives inside the
//! resolveClass allowlist so no Deserialize probe is emitted.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        // Marker class name embedded in the serialized stream — the
        // harness allowlist contains `java.lang.Integer` and `java.lang.String`
        // only.  The byte form is a small literal so const-eval can keep it.
        bytes: b"NYX_GADGET_CLASS:org.nyx.deserialize.Gadget",
        label: "java-deserialize-gadget",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::DeserializeGadgetInvoked {
                require_invoked: true,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 7,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/deserialize/java/Vuln.java",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::DeserializeGadgetInvoked {
            require_invoked: true,
        }],
        benign_control: Some(PayloadRef {
            label: "java-deserialize-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        // Allow-listed payload — the marker carries `java.lang.Integer`,
        // which the harness resolveClass accepts without writing a probe.
        bytes: b"NYX_GADGET_CLASS:java.lang.Integer",
        label: "java-deserialize-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::DeserializeGadgetInvoked {
                require_invoked: true,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 7,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/deserialize/java/Benign.java",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
