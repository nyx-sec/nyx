//! Format-string (`Cap::FMT_STRING`) payloads exercised by C fixtures
//! (`tests/dynamic_fixtures/c/free_fn/`).
//!
//! The vuln payload confirms via a sink-site Crash probe rather than an
//! output marker.  The bytes themselves are not load-bearing — the
//! detection contract is "process aborts inside the entry call AFTER the
//! crash-guard installs".  Fixtures choose how to crash on the payload;
//! the canonical example is a `printf`-family sink that interprets `%n`
//! against a controlled destination pointer on a guard-compiled binary.
//!
//! The benign control must reach the same entry without crashing; its
//! bytes carry `NYX_BENIGN` so fixture code can short-circuit before
//! the fault path.

use super::super::{CuratedPayload, Oracle, PayloadProvenance, PayloadRef};
use crate::dynamic::oracle::SignalSet;

pub const PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"%n%n%n%n%n%n%n%n%n%n",
        label: "fmt-string-percent-n-crash",
        oracle: Oracle::SinkCrash {
            signals: SignalSet::all(),
        },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 5,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/dynamic_fixtures/c/free_fn/sink_fault.c",
            "tests/dynamic_fixtures/c/free_fn/setup_fault.c",
        ],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: Some(PayloadRef {
            label: "fmt-string-benign",
        }),
        no_benign_control_rationale: None,
    },
    CuratedPayload {
        bytes: b"benign_safe_fmt_NYX_BENIGN",
        label: "fmt-string-benign",
        oracle: Oracle::SinkCrash {
            signals: SignalSet::all(),
        },
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 5,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/dynamic_fixtures/c/free_fn/sink_fault.c"],
        oob_nonce_slot: false,
        probe_predicates: &[],
        benign_control: None,
        no_benign_control_rationale: None,
    },
];
