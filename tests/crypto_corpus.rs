//! Phase 11 (Track J.9) — `Cap::CRYPTO` corpus acceptance.
//!
//! Asserts the new cap end-to-end at the corpus + oracle layer:
//! per-language vuln/benign slices register, lang-aware benign-control
//! resolution pairs them inside the correct slice, and the
//! `WeakKeyEntropy` predicate fires only when a `WeakKey { key_int }`
//! probe whose `key_int` is strictly less than `2^max_bits` lands on
//! the channel.  Per-lang harness dispatchers are deferred — see
//! `.pitboss/play/deferred.md`.
//!
//! `cargo nextest run --features dynamic --test crypto_corpus`.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::corpus::{payloads_for_lang, resolve_benign_control_lang};
use nyx_scanner::dynamic::oracle::{oracle_fired, Oracle, ProbePredicate};
use nyx_scanner::dynamic::probe::{ProbeKind, ProbeWitness, SinkProbe};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;
use std::time::Duration;

const LANGS: &[Lang] = &[
    Lang::Java,
    Lang::Python,
    Lang::Php,
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

fn weak_key_probe(key_int: u64) -> SinkProbe {
    SinkProbe {
        sink_callee: "__nyx_weak_key".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "crypto-test".into(),
        kind: ProbeKind::WeakKey { key_int },
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn corpus_registers_crypto_for_each_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::CRYPTO, *lang);
        assert!(!slice.is_empty(), "CRYPTO has no payloads for {lang:?}");
        assert!(
            slice.iter().any(|p| !p.is_benign),
            "{lang:?} CRYPTO missing vuln payload",
        );
        assert!(
            slice.iter().any(|p| p.is_benign),
            "{lang:?} CRYPTO missing benign control",
        );
    }
}

#[test]
fn crypto_payloads_pair_benign_controls_per_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::CRYPTO, *lang);
        let vuln = slice
            .iter()
            .find(|p| !p.is_benign)
            .expect("vuln payload");
        let resolved = resolve_benign_control_lang(vuln, Cap::CRYPTO, *lang)
            .expect("benign control resolves");
        assert!(resolved.is_benign);
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(predicates.iter().any(|p| matches!(
                    p,
                    ProbePredicate::WeakKeyEntropy { max_bits: 16 }
                )));
            }
            other => panic!("expected SinkProbe, got {other:?}"),
        }
    }
}

#[test]
fn weak_key_entropy_fires_below_budget() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: 16 }],
    };
    let probes = vec![weak_key_probe(0x1234)];
    assert!(oracle_fired(&oracle, &outcome(), &probes));
}

#[test]
fn weak_key_entropy_clears_above_budget() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: 16 }],
    };
    let probes = vec![weak_key_probe(u64::MAX / 2)];
    assert!(!oracle_fired(&oracle, &outcome(), &probes));
}

#[test]
fn weak_key_entropy_clears_with_no_probe() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: 16 }],
    };
    assert!(!oracle_fired(&oracle, &outcome(), &[]));
}

#[test]
fn crypto_unsupported_for_other_langs() {
    for lang in [Lang::C, Lang::Cpp, Lang::Ruby, Lang::JavaScript, Lang::TypeScript] {
        assert!(
            payloads_for_lang(Cap::CRYPTO, lang).is_empty(),
            "CRYPTO has unexpected payloads for {lang:?}",
        );
    }
}
