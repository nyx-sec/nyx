//! Phase 11 (Track J.9) — `Cap::UNAUTHORIZED_ID` corpus acceptance.
//!
//! Asserts the corpus + IDOR oracle for all seven backend-capable
//! languages.  The vuln payload supplies an `owner_id` belonging to
//! another user; the
//! [`nyx_scanner::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
//! predicate fires when `caller_id != owner_id`.  Per-lang harness
//! dispatchers are deferred — see `.pitboss/play/deferred.md`.
//!
//! `cargo nextest run --features dynamic --test unauthorized_id_corpus`.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::corpus::{payloads_for_lang, resolve_benign_control_lang};
use nyx_scanner::dynamic::oracle::{Oracle, ProbePredicate, oracle_fired};
use nyx_scanner::dynamic::probe::{ProbeKind, ProbeWitness, SinkProbe};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;
use std::time::Duration;

const LANGS: &[Lang] = &[
    Lang::Python,
    Lang::Ruby,
    Lang::Java,
    Lang::Php,
    Lang::JavaScript,
    Lang::Go,
    Lang::Rust,
];

fn outcome() -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(0),
        stdout: vec![],
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: false,
        duration: Duration::from_millis(1),
        hardening_outcome: None,
    }
}

fn idor_probe(caller: &str, owner: &str) -> SinkProbe {
    SinkProbe {
        sink_callee: "__nyx_idor_lookup".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "idor-test".into(),
        kind: ProbeKind::IdorAccess {
            caller_id: caller.into(),
            owner_id: owner.into(),
        },
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn corpus_registers_unauthorized_id_for_each_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::UNAUTHORIZED_ID, *lang);
        assert!(!slice.is_empty(), "UNAUTHORIZED_ID missing for {lang:?}");
        assert!(slice.iter().any(|p| !p.is_benign));
        assert!(slice.iter().any(|p| p.is_benign));
    }
}

#[test]
fn idor_payloads_pair_benign_per_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::UNAUTHORIZED_ID, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).expect("vuln");
        let resolved = resolve_benign_control_lang(vuln, Cap::UNAUTHORIZED_ID, *lang)
            .expect("benign control resolves");
        assert!(resolved.is_benign);
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => assert!(
                predicates
                    .iter()
                    .any(|p| matches!(p, ProbePredicate::IdorBoundaryCrossed))
            ),
            other => panic!("expected SinkProbe, got {other:?}"),
        }
    }
}

#[test]
fn idor_predicate_fires_on_boundary_crossing() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::IdorBoundaryCrossed],
    };
    assert!(oracle_fired(
        &oracle,
        &outcome(),
        &[idor_probe("alice", "bob")]
    ));
    assert!(!oracle_fired(
        &oracle,
        &outcome(),
        &[idor_probe("alice", "alice")]
    ));
    assert!(!oracle_fired(&oracle, &outcome(), &[]));
}
