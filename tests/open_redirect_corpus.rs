//! Phase 09 (Track J.7) — OPEN_REDIRECT corpus acceptance.
//!
//! Asserts the new cap end-to-end: corpus slices register per-language
//! vuln/benign pairs for Java / Python / PHP / Ruby / JavaScript / Go /
//! Rust, the lang-aware resolver pairs them inside the correct slice,
//! the per-language harness emitters splice in the synthetic
//! `sendRedirect` / `redirect` shim + `Redirect` probe + sink-hit
//! sentinel, the framework adapters fire on the canonical redirect
//! call, and the `RedirectHostNotIn` predicate fires only on probes
//! whose `location` resolves off-origin against the allowlist.
//!
//! `cargo nextest run --features dynamic --test open_redirect_corpus`.

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

const LANGS: &[Lang] = &[
    Lang::Java,
    Lang::Python,
    Lang::Php,
    Lang::Ruby,
    Lang::JavaScript,
    Lang::Go,
    Lang::Rust,
];

fn make_spec(lang: Lang, entry_file: &str, entry_name: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase09test0001".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id: "phase09".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::OPEN_REDIRECT,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase09test0001".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
    }
}

#[test]
fn corpus_registers_open_redirect_for_every_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::OPEN_REDIRECT, *lang);
        assert!(
            !slice.is_empty(),
            "OPEN_REDIRECT has no payloads for {lang:?}"
        );
        let has_vuln = slice.iter().any(|p| !p.is_benign);
        let has_benign = slice.iter().any(|p| p.is_benign);
        assert!(has_vuln, "{lang:?} OPEN_REDIRECT missing vuln payload");
        assert!(
            has_benign,
            "{lang:?} OPEN_REDIRECT missing benign control"
        );
    }
}

#[test]
fn open_redirect_unsupported_caps_unchanged_for_other_langs() {
    for lang in [Lang::C, Lang::Cpp, Lang::TypeScript] {
        assert!(
            payloads_for_lang(Cap::OPEN_REDIRECT, lang).is_empty(),
            "unexpected OPEN_REDIRECT payloads for {lang:?}",
        );
    }
}

#[test]
fn benign_control_resolves_within_lang_slice() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::OPEN_REDIRECT, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let resolved = resolve_benign_control_lang(vuln, Cap::OPEN_REDIRECT, *lang)
            .expect("paired control");
        assert!(resolved.is_benign);
        let direct = benign_payload_for_lang(Cap::OPEN_REDIRECT, *lang).unwrap();
        assert_eq!(direct.label, resolved.label);
    }
}

#[test]
fn payload_oracle_carries_redirect_host_not_in_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::OPEN_REDIRECT, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(
                    predicates.iter().any(|p| matches!(
                        p,
                        ProbePredicate::RedirectHostNotIn { .. }
                    )),
                    "{lang:?} vuln payload missing RedirectHostNotIn predicate",
                );
            }
            other => panic!("expected SinkProbe oracle for {lang:?}, got {other:?}"),
        }
    }
}

#[test]
fn vuln_payload_bytes_carry_off_origin_url_benign_bytes_do_not() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::OPEN_REDIRECT, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let benign = slice.iter().find(|p| p.is_benign).unwrap();
        let vuln_text = std::str::from_utf8(vuln.bytes).unwrap();
        let benign_text = std::str::from_utf8(benign.bytes).unwrap();
        assert!(
            vuln_text.contains("attacker.test"),
            "{lang:?} vuln payload must carry the off-origin attacker host",
        );
        assert!(
            !benign_text.contains("://"),
            "{lang:?} benign control must be a same-origin relative path",
        );
        assert!(
            benign_text.starts_with('/'),
            "{lang:?} benign control must be an absolute same-origin path",
        );
    }
}

#[test]
fn marker_collisions_clean_with_phase_09_additions() {
    assert!(audit_marker_collisions().is_empty());
}

#[test]
fn probe_kind_redirect_serdes() {
    let original = ProbeKind::Redirect {
        location: "https://attacker.test/".into(),
        request_host: "example.com".into(),
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("Redirect"));
    assert!(json.contains("location"));
    assert!(json.contains("request_host"));
    let parsed: ProbeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn redirect_host_not_in_fires_on_off_origin_location() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::RedirectHostNotIn {
            allowlist: &["example.com"],
        }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "HttpServletResponse.sendRedirect".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase09".into(),
        kind: ProbeKind::Redirect {
            location: "https://attacker.test/".into(),
            request_host: "example.com".into(),
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
fn redirect_host_not_in_clear_on_same_origin_path() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::RedirectHostNotIn {
            allowlist: &["example.com"],
        }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "HttpServletResponse.sendRedirect".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase09".into(),
        kind: ProbeKind::Redirect {
            location: "/dashboard".into(),
            request_host: "example.com".into(),
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
    assert!(!oracle_fired(&oracle, &outcome, &probes));
}

#[test]
fn lang_emitter_dispatches_to_open_redirect_harness() {
    // Per-lang `sink_callee_marker` pins which redirect entry point
    // the harness names in its probe record.
    for (lang, entry_file, entry_name, sink_callee_marker) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/open_redirect/java/Vuln.java",
            "run",
            "HttpServletResponse.sendRedirect",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/open_redirect/python/vuln.py",
            "run",
            "flask.redirect",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/open_redirect/php/vuln.php",
            "run",
            "Response::redirect",
        ),
        (
            Lang::Ruby,
            "tests/dynamic_fixtures/open_redirect/ruby/vuln.rb",
            "run",
            "Rack::Response#redirect",
        ),
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/open_redirect/js/vuln.js",
            "run",
            "res.redirect",
        ),
        (
            Lang::Go,
            "tests/dynamic_fixtures/open_redirect/go/vuln.go",
            "Run",
            "gin.Context.Redirect",
        ),
        (
            Lang::Rust,
            "tests/dynamic_fixtures/open_redirect/rust/vuln.rs",
            "run",
            "Redirect::to",
        ),
    ] {
        let spec = make_spec(lang, entry_file, entry_name);
        let harness = lang::emit(&spec)
            .unwrap_or_else(|e| panic!("emit failed for {lang:?}: {e:?}"));
        assert!(
            harness.source.contains("Redirect"),
            "{lang:?} redirect harness must carry the Redirect probe kind",
        );
        assert!(
            harness.source.contains(sink_callee_marker),
            "{lang:?} redirect harness must name {sink_callee_marker:?} as the sink callee",
        );
        assert!(
            harness.source.contains("__NYX_SINK_HIT__"),
            "{lang:?} redirect harness must emit the sink-hit sentinel",
        );
        assert!(
            harness.source.contains("request_host"),
            "{lang:?} redirect harness must carry the request_host field",
        );
    }
}

#[test]
fn framework_adapters_detect_redirect_sink() {
    // Each lang registers its J.7 redirect adapter; detect_binding
    // routes through the registry and stamps an
    // `EntryKind::Function` binding when the fixture contains the
    // canonical redirect call.
    for (lang, fixture, sink_callee) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/open_redirect/java/Vuln.java",
            "sendRedirect",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/open_redirect/python/vuln.py",
            "redirect",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/open_redirect/php/vuln.php",
            "RedirectResponse",
        ),
        (
            Lang::Ruby,
            "tests/dynamic_fixtures/open_redirect/ruby/vuln.rb",
            "redirect",
        ),
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/open_redirect/js/vuln.js",
            "redirect",
        ),
        (
            Lang::Go,
            "tests/dynamic_fixtures/open_redirect/go/vuln.go",
            "Redirect",
        ),
        (
            Lang::Rust,
            "tests/dynamic_fixtures/open_redirect/rust/vuln.rs",
            "to",
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
            .unwrap_or_else(|| panic!("{lang:?} adapter must detect the redirect fixture"));
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
        Lang::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        Lang::Go => tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
        Lang::Rust => tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
        other => panic!("unsupported test lang {other:?}"),
    }
}

fn slug(lang: Lang) -> &'static str {
    match lang {
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Php => "php",
        Lang::Ruby => "ruby",
        Lang::JavaScript => "javascript",
        Lang::Go => "go",
        Lang::Rust => "rust",
        _ => "other",
    }
}
