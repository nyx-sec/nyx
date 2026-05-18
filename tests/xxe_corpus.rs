//! Phase 05 (Track J.3) — XXE corpus acceptance.
//!
//! Asserts the new cap end-to-end: corpus slices register per-engine
//! vuln/benign pairs for Java / Python / PHP / Ruby / Go, the
//! lang-aware resolver pairs them inside the correct slice, the
//! per-language harness emitters splice in the synthetic XML parser +
//! entity-expansion probe + sink-hit sentinel, and the framework
//! adapters fire on the canonical sink call.
//!
//! `cargo nextest run --features dynamic --test xxe_corpus`.

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

const LANGS: &[Lang] = &[Lang::Java, Lang::Python, Lang::Php, Lang::Ruby, Lang::Go];

fn make_spec(lang: Lang, entry_file: &str, entry_name: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase05test0001".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id: "phase05".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::XXE,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase05test0001".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
    }
}

#[test]
fn corpus_registers_xxe_for_every_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::XXE, *lang);
        assert!(!slice.is_empty(), "XXE has no payloads for {lang:?}");
        let has_vuln = slice.iter().any(|p| !p.is_benign);
        let has_benign = slice.iter().any(|p| p.is_benign);
        assert!(has_vuln, "{lang:?} XXE missing vuln payload");
        assert!(has_benign, "{lang:?} XXE missing benign control");
    }
}

#[test]
fn xxe_unsupported_caps_unchanged_for_other_langs() {
    // Phase 05 only fills Java / Python / PHP / Ruby / Go — Rust / C
    // / Cpp / JS / TS stay empty.
    for lang in [
        Lang::Rust,
        Lang::C,
        Lang::Cpp,
        Lang::JavaScript,
        Lang::TypeScript,
    ] {
        assert!(
            payloads_for_lang(Cap::XXE, lang).is_empty(),
            "unexpected XXE payloads registered for {lang:?}",
        );
    }
}

#[test]
fn benign_control_resolves_within_lang_slice() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::XXE, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let resolved =
            resolve_benign_control_lang(vuln, Cap::XXE, *lang).expect("paired control");
        assert!(resolved.is_benign);
        let direct = benign_payload_for_lang(Cap::XXE, *lang).unwrap();
        assert_eq!(direct.label, resolved.label);
    }
}

#[test]
fn payload_oracle_carries_xxe_entity_expanded_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::XXE, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(
                    predicates.iter().any(|p| matches!(
                        p,
                        ProbePredicate::XxeEntityExpanded { require_expanded: true }
                    )),
                    "{lang:?} vuln payload missing XxeEntityExpanded{{require_expanded:true}}",
                );
            }
            other => panic!("expected SinkProbe oracle for {lang:?}, got {other:?}"),
        }
    }
}

#[test]
fn vuln_payload_bytes_contain_doctype_entity_declaration() {
    // The whole differential rule rests on the vuln payload carrying
    // an `<!ENTITY … SYSTEM "…">` decl and the benign control NOT
    // carrying one — pin both invariants so a future corpus tweak
    // does not silently break the oracle.
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::XXE, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let benign = slice.iter().find(|p| p.is_benign).unwrap();
        let vuln_text = std::str::from_utf8(vuln.bytes).unwrap();
        let benign_text = std::str::from_utf8(benign.bytes).unwrap();
        assert!(
            vuln_text.contains("<!ENTITY") && vuln_text.contains("SYSTEM"),
            "{lang:?} vuln payload must declare a SYSTEM entity",
        );
        assert!(
            !benign_text.contains("<!ENTITY"),
            "{lang:?} benign control must not declare an entity",
        );
    }
}

#[test]
fn marker_collisions_clean_with_phase_05_additions() {
    assert!(audit_marker_collisions().is_empty());
}

#[test]
fn probe_kind_xxe_serdes() {
    let original = ProbeKind::Xxe {
        entity_expanded: true,
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("Xxe"));
    assert!(json.contains("entity_expanded"));
    let parsed: ProbeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn lang_emitter_dispatches_to_xxe_harness() {
    // Per-lang `sink_callee_marker` pins which parser-construction
    // string the harness names in its probe record — the
    // `DocumentBuilder.parse` / `lxml.etree.XMLParser` /
    // `simplexml_load_string` / `REXML::Document.new` /
    // `xml.Decoder.Decode` boundary the brief calls out.
    for (lang, entry_file, entry_name, sink_callee_marker) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/xxe/java/vuln.java",
            "run",
            "DocumentBuilder.parse",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/xxe/python/vuln.py",
            "run",
            "lxml.etree.XMLParser.parse",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/xxe/php/vuln.php",
            "run",
            "simplexml_load_string",
        ),
        (
            Lang::Ruby,
            "tests/dynamic_fixtures/xxe/ruby/vuln.rb",
            "run",
            "REXML::Document.new",
        ),
        (
            Lang::Go,
            "tests/dynamic_fixtures/xxe/go/vuln.go",
            "Run",
            "xml.Decoder.Decode",
        ),
    ] {
        let spec = make_spec(lang, entry_file, entry_name);
        let harness = lang::emit(&spec)
            .unwrap_or_else(|e| panic!("emit failed for {lang:?}: {e:?}"));
        assert!(
            harness.source.contains("entity_expanded"),
            "{lang:?} xxe harness must carry the entity_expanded probe field",
        );
        assert!(
            harness.source.contains(sink_callee_marker),
            "{lang:?} xxe harness must name {sink_callee_marker:?} as the parser sink callee",
        );
        assert!(
            harness.source.contains("__NYX_SINK_HIT__"),
            "{lang:?} xxe harness must emit the sink-hit sentinel",
        );
        assert!(
            harness.source.contains("<!ENTITY") || harness.source.contains("ENTITY"),
            "{lang:?} xxe harness must include the entity-detection scanner",
        );
    }
}

#[test]
fn framework_adapters_detect_xxe_sink() {
    // Each lang registers its J.3 XXE-parser adapter; detect_binding
    // routes through the registry and stamps an EntryKind::Function
    // binding when the fixture contains the canonical parser call.
    for (lang, fixture, sink_callee) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/xxe/java/vuln.java",
            "parse",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/xxe/python/vuln.py",
            "fromstring",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/xxe/php/vuln.php",
            "simplexml_load_string",
        ),
        (
            Lang::Ruby,
            "tests/dynamic_fixtures/xxe/ruby/vuln.rb",
            "new",
        ),
        (
            Lang::Go,
            "tests/dynamic_fixtures/xxe/go/vuln.go",
            "NewDecoder",
        ),
    ] {
        let bytes = std::fs::read(fixture).expect("fixture exists");
        let ts_lang = ts_language_for(lang);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(&bytes, None).unwrap();
        let mut summary = FuncSummary {
            name: "run".into(),
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
        let b = binding
            .unwrap_or_else(|| panic!("{lang:?} adapter must detect the XXE fixture"));
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
        Lang::Go => tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
        other => panic!("unsupported test lang {other:?}"),
    }
}

fn slug(lang: Lang) -> &'static str {
    match lang {
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Php => "php",
        Lang::Ruby => "ruby",
        Lang::Go => "go",
        _ => "other",
    }
}
