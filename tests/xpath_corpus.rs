//! Phase 07 (Track J.5) — XPATH_INJECTION corpus acceptance.
//!
//! Asserts the new cap end-to-end: corpus slices register per-language
//! vuln/benign pairs for Java / Python / PHP / JavaScript, the
//! lang-aware resolver pairs them inside the correct slice, the
//! per-language harness emitters splice in the synthetic XPath
//! evaluator + nodes-returned probe + sink-hit sentinel, the
//! framework adapters fire on the canonical sink call, the renamed
//! `QueryResultCountGreaterThan` predicate evaluates both `Xpath`
//! and `Ldap` probe kinds, and the in-workdir `xpath_corpus.xml`
//! carries the three canonical `<user>` records.
//!
//! `cargo nextest run --features dynamic --test xpath_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::corpus::{
    audit_marker_collisions, benign_payload_for_lang, payloads_for_lang,
    resolve_benign_control_lang, Oracle,
};
use nyx_scanner::dynamic::framework::registry::adapters_for;
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::oracle::{
    oracle_fired, ProbePredicate, SignalSet,
};
use nyx_scanner::dynamic::probe::{ProbeKind, ProbeWitness, SinkProbe};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use nyx_scanner::dynamic::stubs::xpath_document::{
    XPATH_CORPUS_FILENAME, XPATH_CORPUS_NODE_COUNT, XPATH_CORPUS_XML,
};
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;
use std::time::Duration;

const LANGS: &[Lang] = &[Lang::Java, Lang::Python, Lang::Php, Lang::JavaScript];

fn make_spec(lang: Lang, entry_file: &str, entry_name: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase07test0001".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id: "phase07".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::XPATH_INJECTION,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase07test0001".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
        java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
    }
}

#[test]
fn corpus_registers_xpath_for_every_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::XPATH_INJECTION, *lang);
        assert!(!slice.is_empty(), "XPATH_INJECTION has no payloads for {lang:?}");
        let has_vuln = slice.iter().any(|p| !p.is_benign);
        let has_benign = slice.iter().any(|p| p.is_benign);
        assert!(has_vuln, "{lang:?} XPath missing vuln payload");
        assert!(has_benign, "{lang:?} XPath missing benign control");
    }
}

#[test]
fn xpath_unsupported_caps_unchanged_for_other_langs() {
    for lang in [
        Lang::Rust,
        Lang::C,
        Lang::Cpp,
        Lang::Ruby,
        Lang::Go,
        Lang::TypeScript,
    ] {
        assert!(
            payloads_for_lang(Cap::XPATH_INJECTION, lang).is_empty(),
            "unexpected XPATH_INJECTION payloads for {lang:?}",
        );
    }
}

#[test]
fn benign_control_resolves_within_lang_slice() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::XPATH_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let resolved =
            resolve_benign_control_lang(vuln, Cap::XPATH_INJECTION, *lang).expect("paired control");
        assert!(resolved.is_benign);
        let direct = benign_payload_for_lang(Cap::XPATH_INJECTION, *lang).unwrap();
        assert_eq!(direct.label, resolved.label);
    }
}

#[test]
fn payload_oracle_carries_query_result_count_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::XPATH_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(
                    predicates.iter().any(|p| matches!(
                        p,
                        ProbePredicate::QueryResultCountGreaterThan { n: 1 }
                    )),
                    "{lang:?} vuln payload missing QueryResultCountGreaterThan {{ n: 1 }}",
                );
            }
            other => panic!("expected SinkProbe oracle for {lang:?}, got {other:?}"),
        }
    }
}

#[test]
fn vuln_payload_bytes_contain_quote_or_breakout() {
    // Vuln payload carries `' or '1'='1` quote-breakout; benign
    // control carries no XPath metacharacters.
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::XPATH_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let benign = slice.iter().find(|p| p.is_benign).unwrap();
        let vuln_text = std::str::from_utf8(vuln.bytes).unwrap();
        let benign_text = std::str::from_utf8(benign.bytes).unwrap();
        assert!(
            vuln_text.contains("' or '") && vuln_text.contains("'='"),
            "{lang:?} vuln payload must carry a `' or '` tautology breakout",
        );
        assert!(
            !benign_text.contains("'") && !benign_text.contains("="),
            "{lang:?} benign control must not carry XPath metacharacters",
        );
    }
}

#[test]
fn marker_collisions_clean_with_phase_07_additions() {
    assert!(audit_marker_collisions().is_empty());
}

#[test]
fn probe_kind_xpath_serdes() {
    let original = ProbeKind::Xpath { nodes_returned: 3 };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("Xpath"));
    assert!(json.contains("nodes_returned"));
    let parsed: ProbeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn query_result_count_predicate_fires_on_xpath_probe() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "xpath.select".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase07".into(),
        kind: ProbeKind::Xpath { nodes_returned: 3 },
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
fn query_result_count_predicate_clear_when_count_is_one() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "xpath.select".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase07".into(),
        kind: ProbeKind::Xpath { nodes_returned: 1 },
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
fn query_result_count_predicate_also_matches_ldap_probe() {
    // Phase 06 → Phase 07 rename: the renamed predicate must still
    // satisfy LDAP probes (`ProbeKind::Ldap.entries_returned > n`).
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::QueryResultCountGreaterThan { n: 1 }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "ldap.search_s".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase07".into(),
        kind: ProbeKind::Ldap { entries_returned: 3 },
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
    let _ = SignalSet::empty();
}

#[test]
fn lang_emitter_dispatches_to_xpath_harness() {
    // Per-lang `sink_callee_marker` pins which evaluator-construction
    // string the harness names in its probe record.
    for (lang, entry_file, entry_name, sink_callee_marker) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/xpath_injection/java/Vuln.java",
            "run",
            "javax.xml.xpath.XPath.evaluate",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/xpath_injection/python/vuln.py",
            "run",
            "lxml.etree.xpath",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/xpath_injection/php/vuln.php",
            "run",
            "DOMXPath::query",
        ),
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/xpath_injection/js/vuln.js",
            "run",
            "xpath.select",
        ),
    ] {
        let spec = make_spec(lang, entry_file, entry_name);
        let harness = lang::emit(&spec)
            .unwrap_or_else(|e| panic!("emit failed for {lang:?}: {e:?}"));
        assert!(
            harness.source.contains("nodes_returned"),
            "{lang:?} xpath harness must carry the nodes_returned probe field",
        );
        assert!(
            harness.source.contains(sink_callee_marker),
            "{lang:?} xpath harness must name {sink_callee_marker:?} as the sink callee",
        );
        assert!(
            harness.source.contains("__NYX_SINK_HIT__"),
            "{lang:?} xpath harness must emit the sink-hit sentinel",
        );
        assert!(
            harness.source.contains("//user[@name="),
            "{lang:?} xpath harness must build a `//user[@name=…]` selector from NYX_PAYLOAD",
        );
        assert!(
            harness
                .extra_files
                .iter()
                .any(|(p, c)| p == XPATH_CORPUS_FILENAME && c == XPATH_CORPUS_XML),
            "{lang:?} xpath harness must stage the canonical xpath_corpus.xml",
        );
    }
}

#[test]
fn framework_adapters_detect_xpath_sink() {
    // Each lang registers its J.5 XPath-evaluator adapter; detect_binding
    // routes through the registry and stamps an EntryKind::Function
    // binding when the fixture contains the canonical sink call.
    for (lang, fixture, sink_callee) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/xpath_injection/java/Vuln.java",
            "evaluate",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/xpath_injection/python/vuln.py",
            "xpath",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/xpath_injection/php/vuln.php",
            "query",
        ),
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/xpath_injection/js/vuln.js",
            "select",
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
            .unwrap_or_else(|| panic!("{lang:?} adapter must detect the XPath fixture"));
        assert_eq!(b.kind, EntryKind::Function);
        assert!(!b.adapter.is_empty());
    }
}

fn ts_language_for(lang: Lang) -> tree_sitter::Language {
    match lang {
        Lang::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Lang::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Lang::Php => tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
        Lang::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        other => panic!("unsupported test lang {other:?}"),
    }
}

fn slug(lang: Lang) -> &'static str {
    match lang {
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Php => "php",
        Lang::JavaScript => "javascript",
        _ => "other",
    }
}

#[test]
fn staged_corpus_carries_three_users() {
    assert_eq!(XPATH_CORPUS_NODE_COUNT, 3);
    for needle in ["alice", "bob", "carol"] {
        assert!(
            XPATH_CORPUS_XML.contains(needle),
            "staged xpath_corpus.xml must include canonical user {needle}",
        );
    }
}

// ── End-to-end Phase 07 acceptance via run_spec ───────────────────────────────
//
// Mirrors the `e2e_phase_06` block in `ldap_corpus.rs`.  Drives
// `run_spec` directly on a `Cap::XPATH_INJECTION` spec per language
// and asserts the polarity via the `ProbeKind::Xpath { nodes_returned > 1 }`
// probe and the `__NYX_SINK_HIT__` sentinel.  The synthetic harness
// inlines the XPath evaluator over the staged document, so the
// verdict path is deterministic without spawning a real XPath
// engine (`stubs_required: vec![]`).
//
// JavaScript is skipped: the synthetic harness's `require('xpath')`
// import resolves only when the workdir has the package installed.

mod e2e_phase_07 {
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::dynamic::runner::{run_spec, RunError, RunOutcome};
    use nyx_scanner::dynamic::sandbox::{SandboxBackend, SandboxOptions};
    use nyx_scanner::dynamic::spec::{
        default_toolchain_id, EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy,
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
            Lang::Java => "java",
            Lang::Python => "python3",
            Lang::Php => "php",
            _ => unreachable!("e2e_phase_07 covers Java/Python/PHP"),
        }
    }

    fn lang_subdir(lang: Lang) -> &'static str {
        match lang {
            Lang::Java => "java",
            Lang::Python => "python",
            Lang::Php => "php",
            _ => unreachable!(),
        }
    }

    fn build_spec(lang: Lang, fixture: &str, entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/xpath_injection")
            .join(lang_subdir(lang))
            .join(fixture);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase07-e2e-xpath|");
        digest.update(lang_subdir(lang).as_bytes());
        digest.update(b"|");
        digest.update(fixture.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        if matches!(lang, Lang::Java) {
            let workdir = std::path::PathBuf::from("/tmp/nyx-harness").join(&spec_hash);
            let _ = std::fs::remove_dir_all(&workdir);
        }

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: entry_name.to_owned(),
            entry_kind: EntryKind::Function,
            lang,
            toolchain_id: default_toolchain_id(lang).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::XPATH_INJECTION,
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
    fn java_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "Vuln.java", "run") else { return };
        assert!(
            outcome.triggered_by.is_some(),
            "Java XPath vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "vuln.py", "run") else { return };
        assert!(
            outcome.triggered_by.is_some(),
            "Python XPath vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn php_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Php, "vuln.php", "run") else { return };
        assert!(
            outcome.triggered_by.is_some(),
            "PHP XPath vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }
}
