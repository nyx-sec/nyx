//! Phase 19 (Track M.1) — `ClassMethod` end-to-end acceptance.
//!
//! Asserts the new `EntryKind::ClassMethod { class, method }` variant
//! is supported by every per-language emitter so the
//! `Inconclusive(EntryKindUnsupported { attempted: ClassMethod })`
//! rate drops to 0% across the ten supported languages.  Each
//! sub-test constructs a `HarnessSpec` whose `entry_kind` is
//! `ClassMethod`, drives it through `lang::emit`, and checks the
//! harness source carries the matching `class` + `method` literal
//! plus the per-lang structural marker (probe shim, build command,
//! mock-class declaration when applicable).
//!
//! `cargo nextest run --features dynamic --test class_method_corpus`.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
use nyx_scanner::dynamic::stubs::{mock_source, MockKind};
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;

const LANGS: &[Lang] = &[
    Lang::Python,
    Lang::JavaScript,
    Lang::TypeScript,
    Lang::Java,
    Lang::Php,
    Lang::Ruby,
    Lang::Go,
    Lang::Rust,
    Lang::C,
    Lang::Cpp,
];

fn entry_file(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => "tests/dynamic_fixtures/class_method/python/vuln.py",
        Lang::JavaScript => "tests/dynamic_fixtures/class_method/javascript/vuln.js",
        Lang::TypeScript => "tests/dynamic_fixtures/class_method/typescript/vuln.ts",
        Lang::Java => "tests/dynamic_fixtures/class_method/java/Vuln.java",
        Lang::Php => "tests/dynamic_fixtures/class_method/php/vuln.php",
        Lang::Ruby => "tests/dynamic_fixtures/class_method/ruby/vuln.rb",
        Lang::Go => "tests/dynamic_fixtures/class_method/go/vuln.go",
        Lang::Rust => "tests/dynamic_fixtures/class_method/rust/vuln.rs",
        Lang::C => "tests/dynamic_fixtures/class_method/c/vuln.c",
        Lang::Cpp => "tests/dynamic_fixtures/class_method/cpp/vuln.cpp",
    }
}

fn class_for(lang: Lang) -> (&'static str, &'static str) {
    match lang {
        Lang::Python => ("UserRepository", "find_by_name"),
        Lang::Java => ("UserRepository", "findByName"),
        Lang::C => ("UserService", "run"),
        _ => ("UserService", "run"),
    }
}

fn make_spec(lang: Lang) -> HarnessSpec {
    let (class, method) = class_for(lang);
    HarnessSpec {
        finding_id: "phase19classmth1".into(),
        entry_file: entry_file(lang).into(),
        entry_name: method.into(),
        entry_kind: EntryKind::ClassMethod {
            class: class.into(),
            method: method.into(),
        },
        lang,
        toolchain_id: "phase19".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::CODE_EXEC,
        constraint_hints: vec![],
        sink_file: entry_file(lang).into(),
        sink_line: 1,
        spec_hash: "phase19classmth1".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
        java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
    }
}

#[test]
fn class_method_supported_by_every_lang_emitter() {
    for lang in LANGS {
        let supported = lang::entry_kinds_supported(*lang);
        assert!(
            supported.contains(&EntryKindTag::ClassMethod),
            "{lang:?} must advertise ClassMethod after Phase 19; supported = {supported:?}",
        );
    }
}

#[test]
fn class_method_emit_does_not_short_circuit_to_entry_kind_unsupported() {
    for lang in LANGS {
        let spec = make_spec(*lang);
        let result = lang::emit(&spec);
        assert!(
            result.is_ok(),
            "{lang:?} emit returned {result:?} for ClassMethod spec"
        );
    }
}

#[test]
fn class_method_harness_carries_class_and_method_literal() {
    for lang in LANGS {
        let spec = make_spec(*lang);
        let h = lang::emit(&spec).expect("emit ok");
        let (class, method) = class_for(*lang);
        assert!(
            h.source.contains(class),
            "{lang:?} harness source must reference class {class:?}",
        );
        assert!(
            h.source.contains(method),
            "{lang:?} harness source must reference method {method:?}",
        );
    }
}

#[test]
fn class_method_harness_splices_phase_19_mock_classes_where_lang_has_classes() {
    // Languages with a class system embed the MockHttpClient /
    // MockDatabaseConnection / MockLogger declarations the
    // `stubs::mocks` registry publishes.  Go uses a struct registry
    // routed through the entry package and does not splice the
    // doubles into the harness source; C has no class system.
    // Rust's ClassMethod path uses Default::default() — no mocks.
    let class_system_langs = [
        Lang::Python,
        Lang::JavaScript,
        Lang::TypeScript,
        Lang::Java,
        Lang::Php,
        Lang::Ruby,
    ];
    for lang in class_system_langs {
        let spec = make_spec(lang);
        let h = lang::emit(&spec).expect("emit ok");
        let mock_http = mock_source(MockKind::HttpClient, lang);
        assert!(
            h.source.contains("MockHttpClient"),
            "{lang:?} harness must splice MockHttpClient",
        );
        assert!(!mock_http.is_empty());
    }
}

#[test]
fn class_method_python_dispatch_reads_payload_and_invokes_method() {
    let spec = make_spec(Lang::Python);
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("NYX_PAYLOAD"));
    assert!(h.source.contains("UserRepository"));
    assert!(h.source.contains("find_by_name"));
    assert!(h.source.contains("_nyx_build_receiver"));
}

#[test]
fn class_method_java_emits_reflective_dispatch() {
    let spec = make_spec(Lang::Java);
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("Class.forName"));
    assert!(h.source.contains("nyxBuildReceiver"));
    assert!(h.source.contains("UserRepository"));
}

#[test]
fn class_method_go_uses_reflect_receivers_registry() {
    let spec = make_spec(Lang::Go);
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("entry.NyxAutoReceivers"));
    assert!(h.source.contains("MethodByName"));
    let registry = h
        .extra_files
        .iter()
        .find(|(name, _)| name == "entry/nyx_auto_registry.go")
        .expect("auto registry emitted");
    assert!(registry.1.contains("NyxAutoReceivers"));
    assert!(registry.1.contains("UserService{}"));
}

#[test]
fn class_method_rust_uses_default_constructor() {
    let spec = make_spec(Lang::Rust);
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("UserService::default()"));
    assert!(h.source.contains("instance.run"));
}

#[test]
fn class_method_c_collapses_to_class_underscore_method_symbol() {
    let spec = make_spec(Lang::C);
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("UserService_run"));
}

#[test]
fn class_method_cpp_constructs_default_then_calls_method() {
    let spec = make_spec(Lang::Cpp);
    let h = lang::emit(&spec).expect("emit ok");
    assert!(h.source.contains("UserService instance;"));
    assert!(h.source.contains("instance.run"));
}
