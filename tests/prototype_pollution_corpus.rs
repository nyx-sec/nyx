//! Phase 10 (Track J.8) — PROTOTYPE_POLLUTION corpus acceptance.
//!
//! Asserts the new cap end-to-end: corpus slices register per-language
//! vuln/benign pairs for JavaScript and TypeScript, the lang-aware
//! resolver pairs them inside the correct slice, the JS-shared harness
//! emitter splices in the canary trap + deep-merge sink + sink-hit
//! sentinel, the framework adapters fire on the canonical sink
//! constructions (`lodash.merge`, `Object.assign`, `JSON.parse` +
//! deep-merge helper), and the `PrototypeCanaryTouched` predicate fires
//! only when a `PrototypePollution` probe lands on the channel.
//!
//! `cargo nextest run --features dynamic --test prototype_pollution_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::corpus::{
    audit_marker_collisions, benign_payload_for_lang, payloads_for_lang,
    resolve_benign_control_lang, Oracle,
};
use nyx_scanner::dynamic::framework::registry::adapters_for;
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::oracle::{oracle_fired, ProbePredicate};
use nyx_scanner::dynamic::probe::{ProbeKind, ProbeWitness, SinkProbe};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;
use std::time::Duration;

const LANGS: &[Lang] = &[Lang::JavaScript, Lang::TypeScript];

fn make_spec(lang: Lang, entry_file: &str, entry_name: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase10test0001".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id: "phase10".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::PROTOTYPE_POLLUTION,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase10test0001".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
    }
}

#[test]
fn corpus_registers_prototype_pollution_for_js_and_ts() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::PROTOTYPE_POLLUTION, *lang);
        assert!(
            !slice.is_empty(),
            "PROTOTYPE_POLLUTION has no payloads for {lang:?}"
        );
        let has_vuln = slice.iter().any(|p| !p.is_benign);
        let has_benign = slice.iter().any(|p| p.is_benign);
        assert!(has_vuln, "{lang:?} PROTOTYPE_POLLUTION missing vuln payload");
        assert!(
            has_benign,
            "{lang:?} PROTOTYPE_POLLUTION missing benign control"
        );
    }
}

#[test]
fn prototype_pollution_unsupported_for_other_langs() {
    for lang in [
        Lang::Rust,
        Lang::C,
        Lang::Cpp,
        Lang::Java,
        Lang::Go,
        Lang::Php,
        Lang::Python,
        Lang::Ruby,
    ] {
        assert!(
            payloads_for_lang(Cap::PROTOTYPE_POLLUTION, lang).is_empty(),
            "unexpected PROTOTYPE_POLLUTION payloads for {lang:?}",
        );
    }
}

#[test]
fn benign_control_resolves_within_lang_slice() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::PROTOTYPE_POLLUTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let resolved = resolve_benign_control_lang(vuln, Cap::PROTOTYPE_POLLUTION, *lang)
            .expect("paired control");
        assert!(resolved.is_benign);
        let direct = benign_payload_for_lang(Cap::PROTOTYPE_POLLUTION, *lang).unwrap();
        assert_eq!(direct.label, resolved.label);
    }
}

#[test]
fn payload_oracle_carries_prototype_canary_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::PROTOTYPE_POLLUTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(
                    predicates.iter().any(|p| matches!(
                        p,
                        ProbePredicate::PrototypeCanaryTouched { .. }
                    )),
                    "{lang:?} vuln payload missing PrototypeCanaryTouched predicate",
                );
            }
            other => panic!("expected SinkProbe oracle for {lang:?}, got {other:?}"),
        }
    }
}

#[test]
fn vuln_payload_bytes_carry_proto_key_benign_bytes_do_not() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::PROTOTYPE_POLLUTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let benign = slice.iter().find(|p| p.is_benign).unwrap();
        let vuln_text = std::str::from_utf8(vuln.bytes).unwrap();
        let benign_text = std::str::from_utf8(benign.bytes).unwrap();
        assert!(
            vuln_text.contains("__proto__"),
            "{lang:?} vuln payload must carry the __proto__ pollution key",
        );
        assert!(
            !benign_text.contains("__proto__"),
            "{lang:?} benign control must not carry __proto__",
        );
    }
}

#[test]
fn marker_collisions_clean_with_phase_10_additions() {
    assert!(audit_marker_collisions().is_empty());
}

#[test]
fn probe_kind_prototype_pollution_serdes() {
    let original = ProbeKind::PrototypePollution {
        property: "__nyx_canary".into(),
        value: "pwned".into(),
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("PrototypePollution"));
    assert!(json.contains("property"));
    assert!(json.contains("__nyx_canary"));
    let parsed: ProbeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn prototype_canary_predicate_fires_on_polluted_probe() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::PrototypeCanaryTouched {
            canary: "__nyx_canary",
        }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "__nyx_pp_canary_set".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase10".into(),
        kind: ProbeKind::PrototypePollution {
            property: "__nyx_canary".into(),
            value: "pwned".into(),
        },
        witness: ProbeWitness::empty(),
    }];
    let outcome = SandboxOutcome {
        exit_code: Some(0),
        stdout: vec![],
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: true,
        duration: Duration::from_millis(1),
        hardening_outcome: None,
    };
    assert!(oracle_fired(&oracle, &outcome, &probes));
}

#[test]
fn prototype_canary_predicate_clears_when_no_pp_probe() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::PrototypeCanaryTouched {
            canary: "__nyx_canary",
        }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "noop".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase10".into(),
        kind: ProbeKind::Normal,
        witness: ProbeWitness::empty(),
    }];
    let outcome = SandboxOutcome {
        exit_code: Some(0),
        stdout: vec![],
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: true,
        duration: Duration::from_millis(1),
        hardening_outcome: None,
    };
    assert!(!oracle_fired(&oracle, &outcome, &probes));
}

#[test]
fn lang_emitter_dispatches_to_prototype_pollution_harness() {
    for (lang, entry_file, entry_name) in [
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/prototype_pollution/javascript/vuln.js",
            "run",
        ),
        (
            Lang::TypeScript,
            "tests/dynamic_fixtures/prototype_pollution/typescript/vuln.ts",
            "run",
        ),
    ] {
        let spec = make_spec(lang, entry_file, entry_name);
        let harness =
            lang::emit(&spec).unwrap_or_else(|e| panic!("emit failed for {lang:?}: {e:?}"));
        assert!(
            harness.source.contains("PrototypePollution"),
            "{lang:?} prototype-pollution harness must carry the PrototypePollution probe kind",
        );
        assert!(
            harness.source.contains("__nyx_canary"),
            "{lang:?} harness must reference the canary property name",
        );
        assert!(
            harness.source.contains("Object.defineProperty(Object.prototype"),
            "{lang:?} harness must install the canary trap on Object.prototype",
        );
        assert!(
            harness.source.contains("nyxDeepMerge"),
            "{lang:?} harness must inline the deep-merge sink",
        );
        assert!(
            harness.source.contains("__NYX_SINK_HIT__"),
            "{lang:?} harness must emit the sink-hit sentinel",
        );
    }
}

#[test]
fn framework_adapters_detect_prototype_pollution_sinks() {
    // lodash.merge fixture: vuln + benign both fire the
    // `pp-lodash-merge-js` / `pp-lodash-merge-ts` adapter because
    // they call `_.merge` and import lodash.  Phase 10 lodash adapter
    // does not differentiate the target type — that differentiation
    // lives at the dynamic differential level.
    for (lang, fixture, sink_callee) in [
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/prototype_pollution/javascript/vuln.js",
            "merge",
        ),
        (
            Lang::TypeScript,
            "tests/dynamic_fixtures/prototype_pollution/typescript/vuln.ts",
            "merge",
        ),
    ] {
        let bytes = std::fs::read(fixture).expect("fixture exists");
        let ts_lang = ts_language_for(lang);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(&bytes, None).unwrap();
        let mut summary = FuncSummary {
            name: "deepMerge".into(),
            file_path: fixture.to_owned(),
            lang: slug(lang).into(),
            ..Default::default()
        };
        summary
            .callees
            .push(nyx_scanner::summary::CalleeSite::bare(sink_callee));
        let registry_slice = adapters_for(lang);
        assert!(!registry_slice.is_empty(), "{lang:?} adapter slice empty");
        let binding = nyx_scanner::dynamic::framework::detect_binding(
            &summary,
            tree.root_node(),
            &bytes,
            lang,
        );
        let b = binding.unwrap_or_else(|| {
            panic!("{lang:?} adapter must detect the prototype-pollution fixture")
        });
        assert_eq!(b.kind, EntryKind::Function);
        assert!(b.adapter.starts_with("pp-"));
    }
}

#[test]
fn object_assign_adapter_fires_on_direct_object_assign() {
    let src = b"function run(payload) { return Object.assign({}, payload); }\n";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter::Language::from(
            tree_sitter_javascript::LANGUAGE,
        ))
        .unwrap();
    let tree = parser.parse(src.as_slice(), None).unwrap();
    let mut summary = FuncSummary {
        name: "run".into(),
        file_path: "object_assign.js".into(),
        lang: "javascript".into(),
        ..Default::default()
    };
    summary
        .callees
        .push(nyx_scanner::summary::CalleeSite::bare("Object.assign"));
    let binding = nyx_scanner::dynamic::framework::detect_binding(
        &summary,
        tree.root_node(),
        src.as_slice(),
        Lang::JavaScript,
    );
    let b = binding.expect("Object.assign adapter must fire");
    assert!(b.adapter.starts_with("pp-"));
}

#[test]
fn json_deep_assign_adapter_fires_on_json_parse_plus_deep_merge() {
    let src = b"function deepMerge(t, s) { for (const k of Object.keys(s)) t[k] = s[k]; }\n\
        function run(payload) { return deepMerge({}, JSON.parse(payload)); }\n";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter::Language::from(
            tree_sitter_javascript::LANGUAGE,
        ))
        .unwrap();
    let tree = parser.parse(src.as_slice(), None).unwrap();
    let mut summary = FuncSummary {
        name: "run".into(),
        file_path: "json_parse.js".into(),
        lang: "javascript".into(),
        ..Default::default()
    };
    summary
        .callees
        .push(nyx_scanner::summary::CalleeSite::bare("JSON.parse"));
    let binding = nyx_scanner::dynamic::framework::detect_binding(
        &summary,
        tree.root_node(),
        src.as_slice(),
        Lang::JavaScript,
    );
    let b = binding.expect("JSON.parse + deep-merge adapter must fire");
    assert!(b.adapter.starts_with("pp-"));
}

fn ts_language_for(lang: Lang) -> tree_sitter::Language {
    match lang {
        Lang::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        Lang::TypeScript => {
            tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT)
        }
        other => panic!("unsupported test lang {other:?}"),
    }
}

fn slug(lang: Lang) -> &'static str {
    match lang {
        Lang::JavaScript => "javascript",
        Lang::TypeScript => "typescript",
        _ => "other",
    }
}
