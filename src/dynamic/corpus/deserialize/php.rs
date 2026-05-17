//! PHP `Cap::DESERIALIZE` payloads.
//!
//! Vuln payload: marker string handed to `unserialize($input)` where the
//! harness wraps the call with `['allowed_classes' => false]` and an
//! observer on `__wakeup`.  When `unserialize` materialises a
//! `__PHP_Incomplete_Class` from a non-allowlisted class name, the
//! observer emits a `ProbeKind::Deserialize { gadget_chain_invoked:
//! true }` probe.
//!
//! Benign control: serialised primitive (an `int`) that
//! `unserialize` materialises without engaging the allowlist boundary.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_GADGET_CLASS:PHP_Object_Injection_RCE",
        label: "php-unserialize-gadget",
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
            "tests/dynamic_fixtures/deserialize/php/vuln.php",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::DeserializeGadgetInvoked {
            require_invoked: true,
        }],
        benign_control: Some(PayloadRef {
            label: "php-unserialize-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        // Allow-listed marker — the harness allowlist accepts
        // `__primitive_int` as a no-op type representing a serialised
        // integer literal.
        bytes: b"NYX_GADGET_CLASS:__primitive_int",
        label: "php-unserialize-benign",
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
            "tests/dynamic_fixtures/deserialize/php/benign.php",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
