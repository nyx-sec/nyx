//! Phase 11 (Track J.9) — `Cap::JSON_PARSE` corpus acceptance.
//!
//! Asserts the corpus + oracle layer for the pollution oracle that
//! reuses the Phase 10 prototype canary across the three languages
//! whose JSON parsers have a published pollution surface: JavaScript,
//! Python, Ruby.  Per-lang harness dispatchers are deferred — see
//! `.pitboss/play/deferred.md`.
//!
//! `cargo nextest run --features dynamic --test json_parse_corpus`.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::corpus::{payloads_for_lang, resolve_benign_control_lang};
use nyx_scanner::dynamic::oracle::{oracle_fired, Oracle, ProbePredicate};
use nyx_scanner::dynamic::probe::{ProbeKind, ProbeWitness, SinkProbe};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;
use std::time::Duration;

const LANGS: &[Lang] = &[Lang::JavaScript, Lang::Python, Lang::Ruby];

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

fn canary_probe(property: &str) -> SinkProbe {
    SinkProbe {
        sink_callee: "__nyx_pp_canary_set".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "json-parse-test".into(),
        kind: ProbeKind::PrototypePollution {
            property: property.into(),
            value: "pwned".into(),
        },
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn corpus_registers_json_parse_for_each_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::JSON_PARSE, *lang);
        assert!(!slice.is_empty(), "JSON_PARSE missing for {lang:?}");
        assert!(slice.iter().any(|p| !p.is_benign));
        assert!(slice.iter().any(|p| p.is_benign));
    }
}

#[test]
fn json_parse_pairs_benign_per_lang_via_canary_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::JSON_PARSE, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).expect("vuln");
        let resolved = resolve_benign_control_lang(vuln, Cap::JSON_PARSE, *lang)
            .expect("benign control resolves");
        assert!(resolved.is_benign);
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => assert!(predicates.iter().any(|p| matches!(
                p,
                ProbePredicate::PrototypeCanaryTouched { canary: "__nyx_canary" }
            ))),
            other => panic!("expected SinkProbe, got {other:?}"),
        }
    }
}

#[test]
fn canary_predicate_fires_only_on_canary_property() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::PrototypeCanaryTouched {
            canary: "__nyx_canary",
        }],
    };
    assert!(oracle_fired(&oracle, &outcome(), &[canary_probe("__nyx_canary")]));
    assert!(!oracle_fired(&oracle, &outcome(), &[canary_probe("__data__")]));
    assert!(!oracle_fired(&oracle, &outcome(), &[]));
}

#[test]
fn json_parse_unsupported_for_other_langs() {
    for lang in [
        Lang::Rust,
        Lang::C,
        Lang::Cpp,
        Lang::Java,
        Lang::Go,
        Lang::Php,
        Lang::TypeScript,
    ] {
        assert!(
            payloads_for_lang(Cap::JSON_PARSE, lang).is_empty(),
            "JSON_PARSE has unexpected payloads for {lang:?}",
        );
    }
}
