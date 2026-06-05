//! Python `Cap::DESERIALIZE` payloads.
//!
//! Vuln payload: marker string consumed by the harness shim which calls
//! `pickle.Unpickler(...).load()` with `find_class` overridden to record
//! a `ProbeKind::Deserialize { gadget_chain_invoked: true }` whenever a
//! non-allowlisted class is requested.  The harness allowlists
//! `builtins.list` / `builtins.dict` / `builtins.int`; the marker class
//! `nyx.gadget.RCE` is outside that set.
//!
//! Benign control: payload requests only allow-listed builtins.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::ProbePredicate;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"NYX_GADGET_CLASS:nyx.gadget.RCE",
        label: "python-pickle-gadget",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::DeserializeGadgetInvoked {
                require_invoked: true,
            }],
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 7,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/deserialize/python/vuln.py"],
        oob_nonce_slot: false,
        probe_predicates: &[ProbePredicate::DeserializeGadgetInvoked {
            require_invoked: true,
        }],
        benign_control: Some(PayloadRef {
            label: "python-pickle-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"NYX_GADGET_CLASS:builtins.list",
        label: "python-pickle-benign",
        oracle: Oracle::SinkProbe {
            predicates: &[ProbePredicate::DeserializeGadgetInvoked {
                require_invoked: true,
            }],
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 7,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/deserialize/python/benign.py"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
