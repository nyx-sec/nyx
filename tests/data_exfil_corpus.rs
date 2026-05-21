//! Phase 11 (Track J.9) — `Cap::DATA_EXFIL` corpus acceptance.
//!
//! Asserts the corpus + outbound-network oracle for all seven
//! backend-capable languages.  The vuln payload supplies an
//! attacker-controlled host (`attacker.test`); the
//! [`nyx_scanner::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
//! predicate fires when the captured `host` falls outside the
//! loopback allowlist (`&["127.0.0.1", "localhost"]`).  Per-lang
//! harness dispatchers are deferred — see
//! `.pitboss/play/deferred.md`.
//!
//! `cargo nextest run --features dynamic --test data_exfil_corpus`.

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

const ALLOWLIST: &[&str] = &["127.0.0.1", "localhost"];

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

fn outbound_probe(host: &str) -> SinkProbe {
    SinkProbe {
        sink_callee: "__nyx_mock_http".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "data-exfil-test".into(),
        kind: ProbeKind::OutboundNetwork { host: host.into() },
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn corpus_registers_data_exfil_for_each_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::DATA_EXFIL, *lang);
        assert!(!slice.is_empty(), "DATA_EXFIL missing for {lang:?}");
        assert!(slice.iter().any(|p| !p.is_benign));
        assert!(slice.iter().any(|p| p.is_benign));
    }
}

#[test]
fn data_exfil_payloads_pair_benign_per_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::DATA_EXFIL, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).expect("vuln");
        let resolved = resolve_benign_control_lang(vuln, Cap::DATA_EXFIL, *lang)
            .expect("benign control resolves");
        assert!(resolved.is_benign);
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => assert!(
                predicates
                    .iter()
                    .any(|p| matches!(p, ProbePredicate::OutboundHostNotIn { .. }))
            ),
            other => panic!("expected SinkProbe, got {other:?}"),
        }
    }
}

#[test]
fn outbound_predicate_fires_off_allowlist() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::OutboundHostNotIn {
            allowlist: ALLOWLIST,
        }],
    };
    assert!(oracle_fired(
        &oracle,
        &outcome(),
        &[outbound_probe("attacker.test")]
    ));
    assert!(!oracle_fired(
        &oracle,
        &outcome(),
        &[outbound_probe("127.0.0.1")]
    ));
    assert!(!oracle_fired(
        &oracle,
        &outcome(),
        &[outbound_probe("Localhost")]
    ));
    assert!(!oracle_fired(&oracle, &outcome(), &[]));
}
