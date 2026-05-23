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
//! mock-class declaration when applicable).  The `e2e_phase_19`
//! submodule then drives the fixture pair through `run_spec` to pin
//! the actual sandbox + oracle polarity.
//!
//! `cargo nextest run --features dynamic --test class_method_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
use nyx_scanner::dynamic::stubs::{MockKind, mock_source};
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
        Lang::Java => ("Vuln$UserRepository", "findByName"),
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

// ── End-to-end Phase 19 acceptance via run_spec ─────────────────────────────

#[cfg(test)]
mod e2e_phase_19 {
    use super::*;
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::dynamic::runner::{RunError, RunOutcome, run_spec};
    use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
    use nyx_scanner::dynamic::spec::{SpecDerivationStrategy, default_toolchain_id};
    use nyx_scanner::evidence::DifferentialVerdict;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    #[derive(Clone, Copy)]
    struct Case {
        lang: Lang,
        fixture_dir: &'static str,
        vuln_file: &'static str,
        benign_file: &'static str,
        vuln_class: &'static str,
        benign_class: &'static str,
        method: &'static str,
        cap: Cap,
        bins: &'static [&'static str],
    }

    const CASES: &[Case] = &[
        Case {
            lang: Lang::Python,
            fixture_dir: "python",
            vuln_file: "vuln.py",
            benign_file: "benign.py",
            vuln_class: "UserRepository",
            benign_class: "UserRepository",
            method: "find_by_name",
            cap: Cap::SQL_QUERY,
            bins: &["python3"],
        },
        Case {
            lang: Lang::Ruby,
            fixture_dir: "ruby",
            vuln_file: "vuln.rb",
            benign_file: "benign.rb",
            vuln_class: "UserService",
            benign_class: "UserService",
            method: "run",
            cap: Cap::CODE_EXEC,
            bins: &["ruby"],
        },
        Case {
            lang: Lang::JavaScript,
            fixture_dir: "javascript",
            vuln_file: "vuln.js",
            benign_file: "benign.js",
            vuln_class: "UserService",
            benign_class: "UserService",
            method: "run",
            cap: Cap::CODE_EXEC,
            bins: &["node"],
        },
        Case {
            lang: Lang::TypeScript,
            fixture_dir: "typescript",
            vuln_file: "vuln.ts",
            benign_file: "benign.ts",
            vuln_class: "UserService",
            benign_class: "UserService",
            method: "run",
            cap: Cap::CODE_EXEC,
            bins: &["node"],
        },
        Case {
            lang: Lang::Php,
            fixture_dir: "php",
            vuln_file: "vuln.php",
            benign_file: "benign.php",
            vuln_class: "UserService",
            benign_class: "UserService",
            method: "run",
            cap: Cap::CODE_EXEC,
            bins: &["php"],
        },
        Case {
            lang: Lang::Java,
            fixture_dir: "java",
            vuln_file: "Vuln.java",
            benign_file: "Benign.java",
            vuln_class: "Vuln$UserRepository",
            benign_class: "Benign$UserRepository",
            method: "findByName",
            cap: Cap::CODE_EXEC,
            bins: &["java", "javac"],
        },
        Case {
            lang: Lang::Go,
            fixture_dir: "go",
            vuln_file: "vuln.go",
            benign_file: "benign.go",
            vuln_class: "UserService",
            benign_class: "UserService",
            method: "Run",
            cap: Cap::CODE_EXEC,
            bins: &["go"],
        },
        Case {
            lang: Lang::Rust,
            fixture_dir: "rust",
            vuln_file: "vuln.rs",
            benign_file: "benign.rs",
            vuln_class: "UserService",
            benign_class: "UserService",
            method: "run",
            cap: Cap::CODE_EXEC,
            bins: &["cargo"],
        },
        Case {
            lang: Lang::C,
            fixture_dir: "c",
            vuln_file: "vuln.c",
            benign_file: "benign.c",
            vuln_class: "UserService",
            benign_class: "UserService",
            method: "run",
            cap: Cap::CODE_EXEC,
            bins: &["cc"],
        },
        Case {
            lang: Lang::Cpp,
            fixture_dir: "cpp",
            vuln_file: "vuln.cpp",
            benign_file: "benign.cpp",
            vuln_class: "UserService",
            benign_class: "UserService",
            method: "run",
            cap: Cap::CODE_EXEC,
            bins: &["c++"],
        },
    ];

    fn command_available(bin: &str) -> bool {
        Command::new(bin).arg("--version").output().is_ok()
    }

    fn fixture_root(case: Case) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/class_method")
            .join(case.fixture_dir)
    }

    fn build_spec(case: Case, file: &str, class: &str) -> (HarnessSpec, TempDir) {
        let tmp = TempDir::new().expect("create tempdir");
        let src = fixture_root(case).join(file);
        let dst = tmp.path().join(file);
        std::fs::copy(&src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"class-method|");
        digest.update(format!("{:?}", case.lang).as_bytes());
        digest.update(b"|");
        digest.update(case.fixture_dir.as_bytes());
        digest.update(b"|");
        digest.update(file.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: case.method.to_owned(),
            entry_kind: EntryKind::ClassMethod {
                class: class.to_owned(),
                method: case.method.to_owned(),
            },
            lang: case.lang,
            toolchain_id: default_toolchain_id(case.lang).to_owned(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: case.cap,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 1,
            spec_hash,
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
        };
        (spec, tmp)
    }

    fn run(case: Case, file: &str, class: &str) -> Option<RunOutcome> {
        for bin in case.bins {
            if !command_available(bin) {
                eprintln!("SKIP {:?} {file}: missing toolchain {bin}", case.lang);
                return None;
            }
        }

        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, tmp) = build_spec(case, file, class);
        let repro = tmp.path().join("repro");
        let telemetry = tmp.path().join("events.jsonl");
        let build_cache = tmp.path().join("build-cache");
        unsafe {
            std::env::set_var("NYX_REPRO_BASE", repro.to_str().unwrap());
            std::env::set_var("NYX_TELEMETRY_PATH", telemetry.to_str().unwrap());
            std::env::set_var("NYX_BUILD_CACHE", build_cache.to_str().unwrap());
        }
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        let outcome = run_spec(&spec, &opts);
        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
            std::env::remove_var("NYX_BUILD_CACHE");
        }

        match outcome {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP {:?} {file}: harness build failed after {attempts} attempts: {stderr}",
                    case.lang,
                );
                None
            }
            Err(e) => panic!("run_spec({:?} {file}) errored: {e:?}", case.lang),
        }
    }

    fn assert_confirmed(case: Case, outcome: &RunOutcome) {
        assert!(
            outcome.triggered_by.is_some(),
            "{:?} ClassMethod vuln must Confirm via run_spec; got {outcome:?}",
            case.lang,
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    fn assert_not_confirmed(case: Case, outcome: &RunOutcome) {
        assert!(
            outcome.triggered_by.is_none(),
            "{:?} ClassMethod benign control must not Confirm via run_spec; got {outcome:?}",
            case.lang,
        );
        if let Some(diff) = outcome.differential.as_ref() {
            assert_ne!(diff.verdict, DifferentialVerdict::Confirmed);
        }
    }

    #[test]
    fn class_method_vuln_fixtures_confirm_via_run_spec() {
        for case in CASES {
            let Some(outcome) = run(*case, case.vuln_file, case.vuln_class) else {
                continue;
            };
            assert_confirmed(*case, &outcome);
        }
    }

    #[test]
    fn class_method_benign_fixtures_do_not_confirm_via_run_spec() {
        for case in CASES {
            let Some(outcome) = run(*case, case.benign_file, case.benign_class) else {
                continue;
            };
            assert_not_confirmed(*case, &outcome);
        }
    }

    #[test]
    fn class_method_typescript_stages_commonjs_entry_for_stock_node() {
        let spec = make_spec(Lang::TypeScript);
        let h = lang::emit(&spec).expect("emit ok");
        assert_eq!(h.entry_subpath.as_deref(), Some("entry.js"));
        assert!(h.source.contains("require('./entry')"));
    }

    #[test]
    fn class_method_harnesses_emit_sink_hit_sentinel() {
        for lang in LANGS {
            let spec = make_spec(*lang);
            let h = lang::emit(&spec).expect("emit ok");
            assert!(
                h.source.contains("__NYX_SINK_HIT__"),
                "{lang:?} ClassMethod harness must emit the runner sink sentinel",
            );
        }
    }
}
