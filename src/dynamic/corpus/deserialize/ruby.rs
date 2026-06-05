//! Ruby `Cap::DESERIALIZE` payloads.
//!
//! Vuln payload: marker string consumed by the harness shim which calls
//! `Marshal.load(input)` with `Marshal.const_defined?`-style
//! instrumentation that records a `ProbeKind::Deserialize {
//! gadget_chain_invoked: true }` probe whenever a non-allowlisted
//! constant is materialised.  The harness allowlist contains `Integer`
//! / `String` / `Array`.
//!
//! Benign control: marker requests only the allow-listed `Integer`
//! constant.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_GADGET_CLASS:Nyx::Gadget::RCE",
        label: "ruby-marshal-gadget",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::DeserializeGadgetInvoked {
                require_invoked: true,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 7,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/deserialize/ruby/vuln.rb"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::DeserializeGadgetInvoked {
            require_invoked: true,
        }],
        benign_control: Some(PayloadRef {
            label: "ruby-marshal-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_GADGET_CLASS:Integer",
        label: "ruby-marshal-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::DeserializeGadgetInvoked {
                require_invoked: true,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 7,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/deserialize/ruby/benign.rb"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
