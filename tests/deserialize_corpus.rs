//! Phase 03 (Track J.1) — DESERIALIZE corpus acceptance.
//!
//! Asserts the new cap end-to-end: corpus slices register per-language
//! vuln/benign pairs, the lang-aware resolver pairs them inside the
//! correct slice, the per-language harness emitters splice in the
//! `RestrictedObjectInputStream` / `find_class` / allowed-classes
//! shims, and the framework adapters fire on the matching sink call.
//!
//! `cargo nextest run --features dynamic --test deserialize_corpus`.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::corpus::{
    audit_marker_collisions, benign_payload_for_lang, payloads_for_lang,
    resolve_benign_control_lang, Oracle,
};
use nyx_scanner::dynamic::framework::registry::adapters_for;
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::oracle::ProbePredicate;
use nyx_scanner::dynamic::probe::ProbeKind;
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

const LANGS: &[Lang] = &[Lang::Java, Lang::Python, Lang::Php, Lang::Ruby];

fn make_spec(lang: Lang, entry_file: &str, entry_name: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase03test0001".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id: "phase03".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::DESERIALIZE,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase03test0001".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
    }
}

#[test]
fn corpus_registers_deserialize_for_every_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::DESERIALIZE, *lang);
        assert!(
            !slice.is_empty(),
            "DESERIALIZE has no payloads for {lang:?}",
        );
        let has_vuln = slice.iter().any(|p| !p.is_benign);
        let has_benign = slice.iter().any(|p| p.is_benign);
        assert!(has_vuln, "{lang:?} DESERIALIZE missing vuln payload");
        assert!(has_benign, "{lang:?} DESERIALIZE missing benign control");
    }
}

#[test]
fn deserialize_unsupported_caps_unchanged_for_other_langs() {
    // Phase 03 only fills Java/Python/PHP/Ruby — Rust/C/Go/JS/TS stay empty.
    for lang in [
        Lang::Rust,
        Lang::C,
        Lang::Cpp,
        Lang::Go,
        Lang::JavaScript,
        Lang::TypeScript,
    ] {
        assert!(
            payloads_for_lang(Cap::DESERIALIZE, lang).is_empty(),
            "unexpected DESERIALIZE payloads registered for {lang:?}",
        );
    }
}

#[test]
fn benign_control_resolves_within_lang_slice() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::DESERIALIZE, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let resolved =
            resolve_benign_control_lang(vuln, Cap::DESERIALIZE, *lang).expect("paired control");
        assert!(resolved.is_benign);
        // benign_payload_for_lang returns the same entry.
        let direct = benign_payload_for_lang(Cap::DESERIALIZE, *lang).unwrap();
        assert_eq!(direct.label, resolved.label);
    }
}

#[test]
fn payload_oracle_carries_deserialize_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::DESERIALIZE, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(
                    predicates.iter().any(|p| matches!(
                        p,
                        ProbePredicate::DeserializeGadgetInvoked { require_invoked: true }
                    )),
                    "{lang:?} vuln payload missing DeserializeGadgetInvoked predicate",
                );
            }
            other => panic!("expected SinkProbe oracle for {lang:?}, got {other:?}"),
        }
    }
}

#[test]
fn marker_collisions_clean_with_phase_03_additions() {
    assert!(audit_marker_collisions().is_empty());
}

#[test]
fn probe_kind_deserialize_serdes() {
    let original = ProbeKind::Deserialize {
        gadget_chain_invoked: true,
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("Deserialize"));
    assert!(json.contains("gadget_chain_invoked"));
    let parsed: ProbeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn lang_emitter_dispatches_to_deserialize_harness() {
    // `sink_callee_marker` is the per-language deserialize sink call
    // string the harness writes into the JSON probe record — the
    // resolveClass / find_class / unserialize / Marshal.load boundary
    // the brief calls out.  Pinning the marker here keeps the test
    // honest about which guard each lang's harness names.
    for (lang, entry_file, entry_name, sink_callee_marker) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/deserialize/java/vuln.java",
            "run",
            "ObjectInputStream.resolveClass",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/deserialize/python/vuln.py",
            "run",
            "pickle.Unpickler.find_class",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/deserialize/php/vuln.php",
            "run",
            "unserialize",
        ),
        (
            Lang::Ruby,
            "tests/dynamic_fixtures/deserialize/ruby/vuln.rb",
            "run",
            "Marshal.load",
        ),
    ] {
        let spec = make_spec(lang, entry_file, entry_name);
        let harness = lang::emit(&spec)
            .unwrap_or_else(|e| panic!("emit failed for {lang:?}: {e:?}"));
        assert!(
            harness.source.contains("NYX_GADGET_CLASS:"),
            "{lang:?} deserialize harness must parse NYX_GADGET_CLASS marker",
        );
        assert!(
            harness.source.contains(sink_callee_marker),
            "{lang:?} deserialize harness must name {sink_callee_marker:?} as the \
             resolveClass / find_class equivalent sink callee",
        );
    }
}

#[test]
fn framework_adapters_detect_deserialize_sink() {
    // Java + Python + PHP + Ruby all register their J.1 sink adapter;
    // detect_binding routes through the registry and stamps an
    // EntryKind::Function binding when the fixture contains the
    // canonical sink call.
    for (lang, fixture) in [
        (Lang::Java, "tests/dynamic_fixtures/deserialize/java/vuln.java"),
        (Lang::Python, "tests/dynamic_fixtures/deserialize/python/vuln.py"),
        (Lang::Php, "tests/dynamic_fixtures/deserialize/php/vuln.php"),
        (Lang::Ruby, "tests/dynamic_fixtures/deserialize/ruby/vuln.rb"),
    ] {
        let bytes = std::fs::read(fixture).expect("fixture exists");
        let ts_lang = ts_language_for(lang);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(&bytes, None).unwrap();
        let summary = FuncSummary {
            name: "run".into(),
            file_path: fixture.to_owned(),
            lang: slug(lang).into(),
            ..Default::default()
        };
        let registry_slice = adapters_for(lang);
        assert!(
            !registry_slice.is_empty(),
            "{lang:?} adapter slice empty",
        );
        let binding = nyx_scanner::dynamic::framework::detect_binding(
            &summary,
            tree.root_node(),
            &bytes,
            lang,
        );
        let b = binding.unwrap_or_else(|| {
            panic!("{lang:?} adapter must detect the deserialize sink fixture")
        });
        assert_eq!(b.kind, EntryKind::Function);
        assert!(!b.adapter.is_empty());
    }
}

fn ts_language_for(lang: Lang) -> tree_sitter::Language {
    match lang {
        Lang::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Lang::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Lang::Php => tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
        Lang::Ruby => tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE),
        other => panic!("unsupported test lang {other:?}"),
    }
}

fn slug(lang: Lang) -> &'static str {
    match lang {
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Php => "php",
        Lang::Ruby => "ruby",
        _ => "other",
    }
}
