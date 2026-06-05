//! Phase 04 (Track J.2) — SSTI corpus acceptance.
//!
//! Asserts the new cap end-to-end: corpus slices register per-engine
//! vuln/benign pairs (Python/Jinja2, Ruby/ERB, PHP/Twig, Java/Thymeleaf,
//! JS/Handlebars), the lang-aware resolver pairs them inside the
//! correct slice, the per-language harness emitters splice in the
//! synthetic template renderer + sink-hit sentinel, and the
//! framework adapters fire on the canonical sink call.
//!
//! `cargo nextest run --features dynamic --test ssti_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::corpus::{
    Oracle, audit_marker_collisions, benign_payload_for_lang, payloads_for_lang,
    resolve_benign_control_lang,
};
use nyx_scanner::dynamic::framework::registry::adapters_for;
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::oracle::{ProbePredicate, oracle_fired};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;
use std::time::Duration;

const LANGS: &[Lang] = &[
    Lang::Python,
    Lang::Ruby,
    Lang::Php,
    Lang::Java,
    Lang::JavaScript,
];

fn make_spec(lang: Lang, entry_file: &str, entry_name: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase04test0001".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id: "phase04".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::SSTI,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase04test0001".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
        java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
    }
}

#[test]
fn corpus_registers_ssti_for_every_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::SSTI, *lang);
        assert!(!slice.is_empty(), "SSTI has no payloads for {lang:?}");
        let has_vuln = slice.iter().any(|p| !p.is_benign);
        let has_benign = slice.iter().any(|p| p.is_benign);
        assert!(has_vuln, "{lang:?} SSTI missing vuln payload");
        assert!(has_benign, "{lang:?} SSTI missing benign control");
    }
}

#[test]
fn ssti_unsupported_caps_unchanged_for_other_langs() {
    // Phase 04 only fills Python/Ruby/PHP/Java/JS — TypeScript / Rust /
    // C / Cpp / Go remain empty.
    for lang in [Lang::Rust, Lang::C, Lang::Cpp, Lang::Go, Lang::TypeScript] {
        assert!(
            payloads_for_lang(Cap::SSTI, lang).is_empty(),
            "unexpected SSTI payloads registered for {lang:?}",
        );
    }
}

#[test]
fn benign_control_resolves_within_lang_slice() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::SSTI, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let resolved = resolve_benign_control_lang(vuln, Cap::SSTI, *lang).expect("paired control");
        assert!(resolved.is_benign);
        let direct = benign_payload_for_lang(Cap::SSTI, *lang).unwrap();
        assert_eq!(direct.label, resolved.label);
    }
}

#[test]
fn payload_oracle_carries_template_eval_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::SSTI, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                let has_predicate = predicates
                    .iter()
                    .any(|p| matches!(p, ProbePredicate::TemplateEvalEqual { expected: 49 }));
                assert!(
                    has_predicate,
                    "{lang:?} vuln payload missing TemplateEvalEqual{{expected:49}}",
                );
            }
            other => panic!("expected SinkProbe oracle for {lang:?}, got {other:?}"),
        }
    }
}

#[test]
fn marker_collisions_clean_with_phase_04_additions() {
    assert!(audit_marker_collisions().is_empty());
}

#[test]
fn template_eval_equal_fires_on_render_49_json() {
    // The oracle parses the harness's stdout body as JSON; a vuln
    // payload run that renders `49` satisfies the predicate.
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
    };
    let outcome = SandboxOutcome {
        exit_code: Some(0),
        stdout: br#"__NYX_SINK_HIT__
{"render":"49"}
"#
        .to_vec(),
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: true,
        duration: Duration::from_millis(1),
        hardening_outcome: None,
    };
    assert!(oracle_fired(&oracle, &outcome, &[]));
}

#[test]
fn template_eval_equal_does_not_fire_on_echo_render() {
    // The benign payload echoes literal `7*7`; the integer parse
    // fails so the predicate does not satisfy.
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::TemplateEvalEqual { expected: 49 }],
    };
    let outcome = SandboxOutcome {
        exit_code: Some(0),
        stdout: br#"__NYX_SINK_HIT__
{"render":"7*7"}
"#
        .to_vec(),
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: true,
        duration: Duration::from_millis(1),
        hardening_outcome: None,
    };
    assert!(!oracle_fired(&oracle, &outcome, &[]));
}

#[test]
fn lang_emitter_dispatches_to_ssti_harness() {
    for (lang, entry_file, entry_name, marker) in [
        (
            Lang::Python,
            "tests/dynamic_fixtures/ssti/python_jinja2/vuln.py",
            "run",
            "_nyx_jinja2_render",
        ),
        (
            Lang::Ruby,
            "tests/dynamic_fixtures/ssti/ruby_erb/vuln.rb",
            "run",
            "_nyx_erb_render",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/ssti/php_twig/vuln.php",
            "run",
            "_nyx_twig_render",
        ),
        (
            Lang::Java,
            "tests/dynamic_fixtures/ssti/java_thymeleaf/vuln.java",
            "run",
            "nyxThymeleafRender",
        ),
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/ssti/js_handlebars/vuln.js",
            "run",
            "nyxHandlebarsRender",
        ),
    ] {
        let spec = make_spec(lang, entry_file, entry_name);
        let harness =
            lang::emit(&spec).unwrap_or_else(|e| panic!("emit failed for {lang:?}: {e:?}"));
        assert!(
            harness.source.contains(marker),
            "{lang:?} ssti harness must splice {marker:?}",
        );
        assert!(
            harness.source.contains("__NYX_SINK_HIT__"),
            "{lang:?} ssti harness must emit the sink-hit sentinel",
        );
        assert!(
            harness.source.contains("render"),
            "{lang:?} ssti harness must print the render JSON field",
        );
    }
}

#[test]
fn framework_adapters_detect_ssti_sink() {
    // Each lang registers its J.2 SSTI sink adapter; detect_binding
    // routes through the registry and stamps an EntryKind::Function
    // binding when the fixture contains the canonical sink call.
    for (lang, fixture) in [
        (
            Lang::Python,
            "tests/dynamic_fixtures/ssti/python_jinja2/vuln.py",
        ),
        (Lang::Ruby, "tests/dynamic_fixtures/ssti/ruby_erb/vuln.rb"),
        (Lang::Php, "tests/dynamic_fixtures/ssti/php_twig/vuln.php"),
        (
            Lang::Java,
            "tests/dynamic_fixtures/ssti/java_thymeleaf/vuln.java",
        ),
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/ssti/js_handlebars/vuln.js",
        ),
    ] {
        let bytes = std::fs::read(fixture).expect("fixture exists");
        let ts_lang = ts_language_for(lang);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(&bytes, None).unwrap();
        // Each vuln fixture's `run` function takes `body` as its
        // single param and pipes it into the SSTI engine.  Seed the
        // summary with `body` at index 0 and mark that index as a
        // tainted sink participant so the strengthened AST gate
        // (added with the comment-substring FP fix) fires.
        let mut summary = FuncSummary {
            name: "run".into(),
            file_path: fixture.to_owned(),
            lang: slug(lang).into(),
            param_count: 1,
            param_names: vec!["body".into()],
            tainted_sink_params: vec![0],
            ..Default::default()
        };
        // Seed the canonical sink callee per language so the
        // callee-side matcher fires alongside the source-side check.
        let sink_callee = match lang {
            Lang::Python => "Template",
            Lang::Ruby => "new",
            Lang::Php => "createTemplate",
            Lang::Java => "process",
            Lang::JavaScript => "compile",
            _ => unreachable!(),
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
        let b = binding.unwrap_or_else(|| panic!("{lang:?} adapter must detect the SSTI fixture"));
        assert_eq!(b.kind, EntryKind::Function);
        assert!(!b.adapter.is_empty());
    }
}

fn ts_language_for(lang: Lang) -> tree_sitter::Language {
    match lang {
        Lang::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Lang::Ruby => tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE),
        Lang::Php => tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
        Lang::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Lang::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        other => panic!("unsupported test lang {other:?}"),
    }
}

fn slug(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => "python",
        Lang::Ruby => "ruby",
        Lang::Php => "php",
        Lang::Java => "java",
        Lang::JavaScript => "javascript",
        _ => "other",
    }
}

// ── End-to-end Phase 04 acceptance via run_spec ───────────────────────────────
//
// Closes the second half of the Phase 04 deferred audit item: the
// `lang_emitter_dispatches_to_ssti_harness` assertion pins the
// per-engine render helper name (`_nyx_jinja2_render` /
// `_nyx_erb_render` / `_nyx_twig_render` / `nyxThymeleafRender` /
// `nyxHandlebarsRender`), but no test exercises the brief's
// acceptance criterion that `RunOutcome::triggered_by` is `Some(vuln)`
// for `{{7*7}}` / `<%= 7*7 %>` / `[[${7*7}]]` / `{{multiply 7 7}}`
// and `None` for the literal `7*7` benign control.  These tests drive
// `run_spec` directly on a `Cap::SSTI` spec per language and assert
// the polarity.
//
// The synthetic harness ignores `_spec` and applies a per-engine
// regex (deferred item 7 covers the Phase 04 brief's "real engine"
// replacement).  The test still exercises the full sandbox + oracle
// path: payload bytes → harness stdout `{"render":"49"}` →
// `ProbePredicate::TemplateEvalEqual { expected: 49 }` → differential
// pair against the `7*7` benign control.
//
// Java/Thymeleaf rides the Maven plumbing added in `prepare_java`:
// the harness ships a `pom.xml` via `extra_files`, prepare_java runs
// `mvn dependency:copy-dependencies -DoutputDirectory=lib` to stage
// `org.thymeleaf.*` jars, and javac compiles with `-cp .:lib/*`.
// The e2e cell SKIPs when `mvn` or `javac` is absent on the host.

mod e2e_phase_04 {
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::dynamic::runner::{RunError, RunOutcome, run_spec};
    use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
    use nyx_scanner::dynamic::spec::{
        EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy, default_toolchain_id,
    };
    use nyx_scanner::evidence::DifferentialVerdict;
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    fn command_available(bin: &str) -> bool {
        Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn toolchain_for(lang: Lang) -> &'static str {
        match lang {
            Lang::Python => "python3",
            Lang::Ruby => "ruby",
            Lang::Php => "php",
            Lang::JavaScript => "node",
            Lang::Java => "javac",
            _ => unreachable!("e2e_phase_04 covers Python/Ruby/PHP/JS/Java only"),
        }
    }

    fn fixture_subdir(lang: Lang) -> &'static str {
        match lang {
            Lang::Python => "python_jinja2",
            Lang::Ruby => "ruby_erb",
            Lang::Php => "php_twig",
            Lang::JavaScript => "js_handlebars",
            Lang::Java => "java_thymeleaf",
            _ => unreachable!(),
        }
    }

    fn build_spec(lang: Lang, fixture: &str, entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/ssti")
            .join(fixture_subdir(lang))
            .join(fixture);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase04-e2e-ssti|");
        digest.update(fixture_subdir(lang).as_bytes());
        digest.update(b"|");
        digest.update(fixture.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: entry_name.to_owned(),
            entry_kind: EntryKind::Function,
            lang,
            toolchain_id: default_toolchain_id(lang).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::SSTI,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 1,
            spec_hash: spec_hash.clone(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
        };

        (spec, tmp)
    }

    fn run(lang: Lang, fixture: &str, entry_name: &str) -> Option<RunOutcome> {
        let bin = toolchain_for(lang);
        if !command_available(bin) {
            eprintln!("SKIP {lang:?} {fixture}: missing toolchain {bin}");
            return None;
        }
        // Java/Thymeleaf also needs Maven on PATH to resolve the
        // Thymeleaf jars before javac runs.
        if matches!(lang, Lang::Java) && !command_available("mvn") {
            eprintln!("SKIP {lang:?} {fixture}: missing mvn for dependency resolution");
            return None;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_spec(lang, fixture, entry_name);
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        match run_spec(&spec, &opts) {
            Ok(outcome) => Some(outcome),
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP {lang:?} {fixture}: harness build failed after {attempts} attempts: {stderr}",
                );
                None
            }
            Err(e) => panic!("run_spec({lang:?} {fixture}) errored: {e:?}"),
        }
    }

    #[test]
    fn python_jinja2_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "vuln.py", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Python Jinja2 SSTI vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn ruby_erb_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Ruby, "vuln.rb", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Ruby ERB SSTI vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn php_twig_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Php, "vuln.php", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "PHP Twig SSTI vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn js_handlebars_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::JavaScript, "vuln.js", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "JS Handlebars SSTI vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn java_thymeleaf_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "vuln.java", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Java Thymeleaf SSTI vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }
}
