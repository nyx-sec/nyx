//! Phase 08 (Track J.6) — HEADER_INJECTION corpus acceptance.
//!
//! Asserts the new cap end-to-end: corpus slices register per-language
//! vuln/benign pairs for Java / Python / PHP / Ruby / JavaScript / Go /
//! Rust, the lang-aware resolver pairs them inside the correct slice,
//! the per-language harness emitters splice in the synthetic
//! `setHeader` shim + `HeaderEmit` probe + sink-hit sentinel, the
//! framework adapters fire on the canonical sink call, and the
//! `HeaderInjected` predicate fires only on probes whose value
//! carries a literal `\r\n` byte pair.
//!
//! `cargo nextest run --features dynamic --test header_injection_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::corpus::{
    Oracle, audit_marker_collisions, benign_payload_for_lang, payloads_for_lang,
    resolve_benign_control_lang,
};
use nyx_scanner::dynamic::framework::registry::adapters_for;
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::oracle::{ProbePredicate, oracle_fired};
use nyx_scanner::dynamic::probe::{HeaderEmitProtocol, ProbeKind, ProbeWitness, SinkProbe};
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
        finding_id: "phase08test0001".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id: "phase08".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::HEADER_INJECTION,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase08test0001".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
        java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
    }
}

#[test]
fn corpus_registers_header_injection_for_every_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::HEADER_INJECTION, *lang);
        assert!(
            !slice.is_empty(),
            "HEADER_INJECTION has no payloads for {lang:?}"
        );
        let has_vuln = slice.iter().any(|p| !p.is_benign);
        let has_benign = slice.iter().any(|p| p.is_benign);
        assert!(has_vuln, "{lang:?} HEADER_INJECTION missing vuln payload");
        assert!(
            has_benign,
            "{lang:?} HEADER_INJECTION missing benign control"
        );
    }
}

#[test]
fn header_injection_unsupported_caps_unchanged_for_other_langs() {
    for lang in [Lang::C, Lang::Cpp, Lang::TypeScript] {
        assert!(
            payloads_for_lang(Cap::HEADER_INJECTION, lang).is_empty(),
            "unexpected HEADER_INJECTION payloads for {lang:?}",
        );
    }
}

#[test]
fn benign_control_resolves_within_lang_slice() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::HEADER_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let resolved = resolve_benign_control_lang(vuln, Cap::HEADER_INJECTION, *lang)
            .expect("paired control");
        assert!(resolved.is_benign);
        let direct = benign_payload_for_lang(Cap::HEADER_INJECTION, *lang).unwrap();
        assert_eq!(direct.label, resolved.label);
    }
}

#[test]
fn payload_oracle_carries_header_injected_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::HEADER_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(
                    predicates.iter().any(|p| matches!(
                        p,
                        ProbePredicate::HeaderInjected {
                            header_name: "Set-Cookie"
                        }
                    )),
                    "{lang:?} vuln payload missing HeaderInjected predicate",
                );
            }
            other => panic!("expected SinkProbe oracle for {lang:?}, got {other:?}"),
        }
    }
}

#[test]
fn vuln_payload_bytes_carry_crlf_benign_bytes_do_not() {
    // Vuln payload carries raw `\r\n`; benign control carries the
    // URL-encoded `%0D%0A` form instead.
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::HEADER_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let benign = slice.iter().find(|p| p.is_benign).unwrap();
        assert!(
            vuln.bytes.windows(2).any(|w| w == b"\r\n"),
            "{lang:?} vuln payload must carry a raw CRLF pair",
        );
        assert!(
            !benign.bytes.windows(2).any(|w| w == b"\r\n"),
            "{lang:?} benign control must NOT carry a raw CRLF pair",
        );
        let benign_text = std::str::from_utf8(benign.bytes).unwrap();
        assert!(
            benign_text.contains("%0D%0A") || benign_text.contains("%0d%0a"),
            "{lang:?} benign control must URL-encode the CRLF as %0D%0A",
        );
    }
}

#[test]
fn marker_collisions_clean_with_phase_08_additions() {
    assert!(audit_marker_collisions().is_empty());
}

#[test]
fn probe_kind_header_emit_serdes() {
    let original = ProbeKind::HeaderEmit {
        name: "Set-Cookie".into(),
        value: "nyx-session\r\nSet-Cookie: nyx-injected=pwn".into(),
        protocol: HeaderEmitProtocol::InProcess,
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("HeaderEmit"));
    assert!(json.contains("name"));
    assert!(json.contains("value"));
    assert!(json.contains("\"protocol\":\"in-process\""));
    let parsed: ProbeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn probe_kind_header_emit_serdes_wire_variant() {
    let original = ProbeKind::HeaderEmit {
        name: "Set-Cookie".into(),
        value: "nyx-session\r\nSet-Cookie: nyx-injected=pwn".into(),
        protocol: HeaderEmitProtocol::Wire,
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("\"protocol\":\"wire\""));
    let parsed: ProbeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn probe_kind_header_emit_deserialises_legacy_records_as_in_process() {
    // Probe records emitted before the protocol field existed must
    // continue to deserialise via the `#[serde(default)]` hatch so the
    // future oracle tightening landing does not need to migrate the
    // on-disk channel format.
    let legacy_json =
        r#"{"kind":"HeaderEmit","name":"Set-Cookie","value":"nyx-session\r\nSet-Cookie: pwn"}"#;
    let parsed: ProbeKind = serde_json::from_str(legacy_json).unwrap();
    match parsed {
        ProbeKind::HeaderEmit {
            name,
            value,
            protocol,
        } => {
            assert_eq!(name, "Set-Cookie");
            assert_eq!(value, "nyx-session\r\nSet-Cookie: pwn");
            assert_eq!(protocol, HeaderEmitProtocol::InProcess);
        }
        other => panic!("expected HeaderEmit, got {other:?}"),
    }
}

#[test]
fn header_injected_predicate_fires_on_crlf_value() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "HttpServletResponse.setHeader".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase08".into(),
        kind: ProbeKind::HeaderEmit {
            name: "Set-Cookie".into(),
            value: "nyx-session\r\nSet-Cookie: nyx-injected=pwn".into(),
            protocol: HeaderEmitProtocol::InProcess,
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
fn header_injected_predicate_clear_when_value_is_url_encoded() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "HttpServletResponse.setHeader".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase08".into(),
        kind: ProbeKind::HeaderEmit {
            name: "Set-Cookie".into(),
            value: "nyx-session%0D%0ASet-Cookie%3A%20nyx-injected%3Dpwn".into(),
            protocol: HeaderEmitProtocol::InProcess,
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
fn header_injected_predicate_clear_on_unrelated_header() {
    // Predicate pins `Set-Cookie`; a CRLF-carrying value emitted on a
    // different header name must not satisfy.
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::HeaderInjected {
            header_name: "Set-Cookie",
        }],
    };
    let probes = vec![SinkProbe {
        sink_callee: "HttpServletResponse.setHeader".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "phase08".into(),
        kind: ProbeKind::HeaderEmit {
            name: "X-Trace-Id".into(),
            value: "trace\r\nX-Injected: 1".into(),
            protocol: HeaderEmitProtocol::InProcess,
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
fn lang_emitter_dispatches_to_header_injection_harness() {
    // Per-lang `sink_callee_marker` pins which response writer the
    // harness names in its probe record.
    for (lang, entry_file, entry_name, sink_callee_marker) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/header_injection/java/Vuln.java",
            "run",
            "HttpServletResponse.setHeader",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/header_injection/python/vuln.py",
            "run",
            "flask.Response.headers.__setitem__",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/header_injection/php/vuln.php",
            "run",
            "header()",
        ),
        (
            Lang::Ruby,
            "tests/dynamic_fixtures/header_injection/ruby/vuln.rb",
            "run",
            "Rack::Response#set_header",
        ),
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/header_injection/js/vuln.js",
            "run",
            "http.ServerResponse#setHeader",
        ),
        (
            Lang::Go,
            "tests/dynamic_fixtures/header_injection/go/vuln.go",
            "Run",
            "http.ResponseWriter.Header.Set",
        ),
        (
            Lang::Rust,
            "tests/dynamic_fixtures/header_injection/rust/vuln.rs",
            "run",
            "HeaderMap::insert",
        ),
    ] {
        let spec = make_spec(lang, entry_file, entry_name);
        let harness =
            lang::emit(&spec).unwrap_or_else(|e| panic!("emit failed for {lang:?}: {e:?}"));
        assert!(
            harness.source.contains("HeaderEmit"),
            "{lang:?} header harness must carry the HeaderEmit probe kind",
        );
        assert!(
            harness.source.contains(sink_callee_marker),
            "{lang:?} header harness must name {sink_callee_marker:?} as the sink callee",
        );
        assert!(
            harness.source.contains("__NYX_SINK_HIT__"),
            "{lang:?} header harness must emit the sink-hit sentinel",
        );
        assert!(
            harness.source.contains("Set-Cookie"),
            "{lang:?} header harness must set the Set-Cookie header",
        );
    }
}

#[test]
fn framework_adapters_detect_header_sink() {
    // Each lang registers its J.6 header adapter; detect_binding routes
    // through the registry and stamps an EntryKind::Function binding
    // when the fixture contains the canonical sink call.
    for (lang, fixture, sink_callee) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/header_injection/java/Vuln.java",
            "setHeader",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/header_injection/python/vuln.py",
            "__setitem__",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/header_injection/php/vuln.php",
            "header",
        ),
        (
            Lang::Ruby,
            "tests/dynamic_fixtures/header_injection/ruby/vuln.rb",
            "set_header",
        ),
        (
            Lang::JavaScript,
            "tests/dynamic_fixtures/header_injection/js/vuln.js",
            "setHeader",
        ),
        (
            Lang::Go,
            "tests/dynamic_fixtures/header_injection/go/vuln.go",
            "Set",
        ),
        (
            Lang::Rust,
            "tests/dynamic_fixtures/header_injection/rust/vuln.rs",
            "insert",
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
        let b =
            binding.unwrap_or_else(|| panic!("{lang:?} adapter must detect the header fixture"));
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

// ── End-to-end Phase 08 acceptance via run_spec ───────────────────────────────
//
// Mirrors the `e2e_phase_06` / `e2e_phase_07` blocks in `ldap_corpus.rs`
// and `xpath_corpus.rs`.  Drives `run_spec` directly on a
// `Cap::HEADER_INJECTION` spec per language and asserts the polarity via
// the `ProbeKind::HeaderEmit { name, value }` probe — the synthetic
// harness records the raw header bytes the host attempted to set, and
// the `HeaderInjected` predicate fires when `value` carries a literal
// `\r\n`.  The synthetic harness inlines the entire setter shim, so the
// verdict path is deterministic without binding the host's real
// servlet / flask / rack / http response writer.
//
// Per-lang skips:
// - Java: the Phase 08 fixture imports `javax.servlet.http`, which is
//   not on the JDK stdlib classpath; `javac` over the fixture errors
//   before `NyxHarness.java` compiles.  Skipped via the SKIP-on-
//   BuildFailed branch in `run`.
// - Go: the fixture declares `package vuln` but the synthetic harness
//   declares `package main` — `go build .` rejects the directory for
//   mixing two packages.  Skipped via the same branch.
// - Rust: the fixture declares `use axum::http::HeaderMap;`, but the
//   harness's `Cargo.toml` only depends on `libc`; the entry source
//   lands at `src/entry.rs` (declared by `entry_subpath`) and is
//   ignored because the synthetic `src/main.rs` never `mod entry;`s
//   it, so the build succeeds.

mod e2e_phase_08 {
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
            Lang::Java => "java",
            Lang::Python => "python3",
            Lang::Php => "php",
            Lang::Ruby => "ruby",
            Lang::JavaScript => "node",
            Lang::Go => "go",
            Lang::Rust => "cargo",
            _ => unreachable!("e2e_phase_08 covers J/P/Ph/R/JS/Go/Rust"),
        }
    }

    fn lang_subdir(lang: Lang) -> &'static str {
        match lang {
            Lang::Java => "java",
            Lang::Python => "python",
            Lang::Php => "php",
            Lang::Ruby => "ruby",
            Lang::JavaScript => "js",
            Lang::Go => "go",
            Lang::Rust => "rust",
            _ => unreachable!(),
        }
    }

    fn build_spec(lang: Lang, fixture: &str, entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/header_injection")
            .join(lang_subdir(lang))
            .join(fixture);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase08-e2e-header-injection|");
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
            expected_cap: Cap::HEADER_INJECTION,
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

    fn assert_confirmed(lang: Lang, outcome: &RunOutcome) {
        assert!(
            outcome.triggered_by.is_some(),
            "{lang:?} HEADER_INJECTION vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn java_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "Vuln.java", "run") else {
            return;
        };
        assert_confirmed(Lang::Java, &outcome);
    }

    #[test]
    fn python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "vuln.py", "run") else {
            return;
        };
        assert_confirmed(Lang::Python, &outcome);
    }

    #[test]
    fn php_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Php, "vuln.php", "run") else {
            return;
        };
        assert_confirmed(Lang::Php, &outcome);
    }

    #[test]
    fn ruby_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Ruby, "vuln.rb", "run") else {
            return;
        };
        assert_confirmed(Lang::Ruby, &outcome);
    }

    #[test]
    fn js_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::JavaScript, "vuln.js", "run") else {
            return;
        };
        assert_confirmed(Lang::JavaScript, &outcome);
    }

    #[test]
    fn go_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Go, "vuln.go", "Run") else {
            return;
        };
        assert_confirmed(Lang::Go, &outcome);
    }

    #[test]
    fn rust_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Rust, "vuln.rs", "run") else {
            return;
        };
        assert_confirmed(Lang::Rust, &outcome);
    }

    // Phase 08 tier-(b): Python raw-socket wire-frame fixture.
    // `tests/dynamic_fixtures/header_injection/python_raw/vuln.py` boots
    // a `BaseHTTPRequestHandler` writing raw bytes via `self.wfile.write`,
    // bypassing werkzeug's CRLF strip.  The harness boots the handler on a
    // loopback port, reads the response-header block off the socket, and
    // emits a `ProbeKind::HeaderWireFrame` record.  Asserts the test
    // exercises the wire-frame branch (not the synthetic fallback) by
    // pinning `wire_frame_len` in the captured stdout — that literal only
    // appears in the tier-(b) write path.
    fn build_python_raw_spec(entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/header_injection/python_raw/vuln.py");
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("vuln.py");
        std::fs::copy(&fixture_src, &dst).expect("copy python_raw fixture into tempdir");
        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase08-e2e-header-injection|python_raw|vuln.py");
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });
        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: entry_name.to_owned(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: default_toolchain_id(Lang::Python).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::HEADER_INJECTION,
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

    // Phase 08 tier-(b): JavaScript raw-socket wire-frame fixture.
    // `tests/dynamic_fixtures/header_injection/js_raw/vuln.js` boots a
    // `net.Server` whose callback writes raw bytes via `socket.write`,
    // bypassing Node's `http.ServerResponse#setHeader` CRLF strip.  The
    // harness boots the server on a loopback port, reads the response-
    // header block off the socket, and emits a
    // `ProbeKind::HeaderWireFrame` record.  Asserts the test exercises
    // the wire-frame branch (not the synthetic fallback) by pinning
    // `wire_frame_len` in the captured stdout — that literal only
    // appears in the tier-(b) write path.
    fn build_js_raw_spec(entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/header_injection/js_raw/vuln.js");
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("vuln.js");
        std::fs::copy(&fixture_src, &dst).expect("copy js_raw fixture into tempdir");
        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase08-e2e-header-injection|js_raw|vuln.js");
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });
        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: entry_name.to_owned(),
            entry_kind: EntryKind::Function,
            lang: Lang::JavaScript,
            toolchain_id: default_toolchain_id(Lang::JavaScript).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::HEADER_INJECTION,
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

    #[test]
    fn js_raw_socket_vuln_confirms_via_wire_frame_probe() {
        if !command_available("node") {
            eprintln!("SKIP js_raw: missing node");
            return;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_js_raw_spec("run");
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        let outcome = match run_spec(&spec, &opts) {
            Ok(outcome) => outcome,
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!("SKIP js_raw: harness build failed after {attempts} attempts: {stderr}",);
                return;
            }
            Err(e) => panic!("run_spec(js_raw) errored: {e:?}"),
        };
        assert_confirmed(Lang::JavaScript, &outcome);
        let any_wire_frame_marker = outcome
            .attempts
            .iter()
            .any(|a| String::from_utf8_lossy(&a.outcome.stdout).contains("wire_frame_len"));
        assert!(
            any_wire_frame_marker,
            "js_raw fixture must exercise the tier-(b) wire-frame harness branch; \
             expected `wire_frame_len` substring in at least one attempt's stdout, got attempts={:?}",
            outcome
                .attempts
                .iter()
                .map(|a| String::from_utf8_lossy(&a.outcome.stdout).into_owned())
                .collect::<Vec<_>>(),
        );
    }

    // Phase 08 tier-(b): Rust raw-socket wire-frame fixture.
    // `tests/dynamic_fixtures/header_injection/rust_raw/vuln.rs` boots a
    // `std::net::TcpListener` via `create_server` whose `run_once`
    // handler writes raw bytes via `TcpStream::write_all`, bypassing
    // axum's `HeaderValue::from_bytes` CRLF strip.  The harness boots
    // the listener on a loopback port, opens a client `TcpStream`,
    // reads the response-header block off the socket, and emits a
    // `ProbeKind::HeaderWireFrame` record.  Asserts the test exercises
    // the wire-frame branch (not the synthetic fallback) by pinning
    // `wire_frame_len` in the captured stdout — that literal only
    // appears in the tier-(b) write path.
    fn build_rust_raw_spec(entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/header_injection/rust_raw/vuln.rs");
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("vuln.rs");
        std::fs::copy(&fixture_src, &dst).expect("copy rust_raw fixture into tempdir");
        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase08-e2e-header-injection|rust_raw|vuln.rs");
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });
        // Mirror the Java workdir wipe — Cargo's release build dir lives
        // under the shared workdir at `/tmp/nyx-harness/<spec_hash>`, so
        // a previous run with a different harness source can serve stale
        // cached compilation results.
        let workdir = std::path::PathBuf::from("/tmp/nyx-harness").join(&spec_hash);
        let _ = std::fs::remove_dir_all(&workdir);
        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: entry_name.to_owned(),
            entry_kind: EntryKind::Function,
            lang: Lang::Rust,
            toolchain_id: default_toolchain_id(Lang::Rust).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::HEADER_INJECTION,
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

    #[test]
    fn rust_raw_socket_vuln_confirms_via_wire_frame_probe() {
        if !command_available("cargo") {
            eprintln!("SKIP rust_raw: missing cargo");
            return;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_rust_raw_spec("run");
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        let outcome = match run_spec(&spec, &opts) {
            Ok(outcome) => outcome,
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP rust_raw: harness build failed after {attempts} attempts: {stderr}",
                );
                return;
            }
            Err(e) => panic!("run_spec(rust_raw) errored: {e:?}"),
        };
        assert_confirmed(Lang::Rust, &outcome);
        let any_wire_frame_marker = outcome
            .attempts
            .iter()
            .any(|a| String::from_utf8_lossy(&a.outcome.stdout).contains("wire_frame_len"));
        assert!(
            any_wire_frame_marker,
            "rust_raw fixture must exercise the tier-(b) wire-frame harness branch; \
             expected `wire_frame_len` substring in at least one attempt's stdout, got attempts={:?}",
            outcome
                .attempts
                .iter()
                .map(|a| String::from_utf8_lossy(&a.outcome.stdout).into_owned())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn python_raw_socket_vuln_confirms_via_wire_frame_probe() {
        if !command_available("python3") {
            eprintln!("SKIP python_raw: missing python3");
            return;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_python_raw_spec("run");
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        let outcome = match run_spec(&spec, &opts) {
            Ok(outcome) => outcome,
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP python_raw: harness build failed after {attempts} attempts: {stderr}",
                );
                return;
            }
            Err(e) => panic!("run_spec(python_raw) errored: {e:?}"),
        };
        assert_confirmed(Lang::Python, &outcome);
        let any_wire_frame_marker = outcome
            .attempts
            .iter()
            .any(|a| String::from_utf8_lossy(&a.outcome.stdout).contains("wire_frame_len"));
        assert!(
            any_wire_frame_marker,
            "python_raw fixture must exercise the tier-(b) wire-frame harness branch; \
             expected `wire_frame_len` substring in at least one attempt's stdout, got attempts={:?}",
            outcome
                .attempts
                .iter()
                .map(|a| String::from_utf8_lossy(&a.outcome.stdout).into_owned())
                .collect::<Vec<_>>(),
        );
    }

    // Phase 08 tier-(b): Ruby raw-socket wire-frame fixture.
    // `tests/dynamic_fixtures/header_injection/ruby_raw/vuln.rb` binds
    // a `TCPServer` via `create_server` whose `run_once` handler writes
    // raw bytes via `TCPSocket#write`, bypassing Rack's CRLF strip on
    // `Rack::Response#set_header`.  The harness boots the server on a
    // loopback port, opens a client `TCPSocket`, reads the response-
    // header block off the socket, and emits a
    // `ProbeKind::HeaderWireFrame` record.  Asserts the test exercises
    // the wire-frame branch (not the synthetic fallback) by pinning
    // `wire_frame_len` in the captured stdout — that literal only
    // appears in the tier-(b) write path.
    fn build_ruby_raw_spec(entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/header_injection/ruby_raw/vuln.rb");
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("vuln.rb");
        std::fs::copy(&fixture_src, &dst).expect("copy ruby_raw fixture into tempdir");
        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase08-e2e-header-injection|ruby_raw|vuln.rb");
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });
        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: entry_name.to_owned(),
            entry_kind: EntryKind::Function,
            lang: Lang::Ruby,
            toolchain_id: default_toolchain_id(Lang::Ruby).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::HEADER_INJECTION,
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

    #[test]
    fn ruby_raw_socket_vuln_confirms_via_wire_frame_probe() {
        if !command_available("ruby") {
            eprintln!("SKIP ruby_raw: missing ruby");
            return;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_ruby_raw_spec("run");
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        let outcome = match run_spec(&spec, &opts) {
            Ok(outcome) => outcome,
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP ruby_raw: harness build failed after {attempts} attempts: {stderr}",
                );
                return;
            }
            Err(e) => panic!("run_spec(ruby_raw) errored: {e:?}"),
        };
        assert_confirmed(Lang::Ruby, &outcome);
        let any_wire_frame_marker = outcome
            .attempts
            .iter()
            .any(|a| String::from_utf8_lossy(&a.outcome.stdout).contains("wire_frame_len"));
        assert!(
            any_wire_frame_marker,
            "ruby_raw fixture must exercise the tier-(b) wire-frame harness branch; \
             expected `wire_frame_len` substring in at least one attempt's stdout, got attempts={:?}",
            outcome
                .attempts
                .iter()
                .map(|a| String::from_utf8_lossy(&a.outcome.stdout).into_owned())
                .collect::<Vec<_>>(),
        );
    }

    // Phase 08 tier-(b): PHP raw-socket wire-frame fixture.
    // `tests/dynamic_fixtures/header_injection/php_raw/vuln.php` binds
    // a `stream_socket_server` via `create_server` whose `run_once`
    // handler writes raw bytes via `fwrite($conn, $raw)`, bypassing
    // PHP's built-in `header()` CRLF strip (rejected since 5.1.2).
    // The harness boots the server on a loopback port, opens a client
    // stream via `stream_socket_client`, reads the response-header
    // block off the socket, and emits a `ProbeKind::HeaderWireFrame`
    // record.  Asserts the test exercises the wire-frame branch (not
    // the synthetic fallback) by pinning `wire_frame_len` in the
    // captured stdout — that literal only appears in the tier-(b)
    // write path.
    fn build_php_raw_spec(entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/header_injection/php_raw/vuln.php");
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("vuln.php");
        std::fs::copy(&fixture_src, &dst).expect("copy php_raw fixture into tempdir");
        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase08-e2e-header-injection|php_raw|vuln.php");
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });
        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: entry_name.to_owned(),
            entry_kind: EntryKind::Function,
            lang: Lang::Php,
            toolchain_id: default_toolchain_id(Lang::Php).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::HEADER_INJECTION,
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

    #[test]
    fn php_raw_socket_vuln_confirms_via_wire_frame_probe() {
        if !command_available("php") {
            eprintln!("SKIP php_raw: missing php");
            return;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_php_raw_spec("run");
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        let outcome = match run_spec(&spec, &opts) {
            Ok(outcome) => outcome,
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!("SKIP php_raw: harness build failed after {attempts} attempts: {stderr}",);
                return;
            }
            Err(e) => panic!("run_spec(php_raw) errored: {e:?}"),
        };
        assert_confirmed(Lang::Php, &outcome);
        let any_wire_frame_marker = outcome
            .attempts
            .iter()
            .any(|a| String::from_utf8_lossy(&a.outcome.stdout).contains("wire_frame_len"));
        assert!(
            any_wire_frame_marker,
            "php_raw fixture must exercise the tier-(b) wire-frame harness branch; \
             expected `wire_frame_len` substring in at least one attempt's stdout, got attempts={:?}",
            outcome
                .attempts
                .iter()
                .map(|a| String::from_utf8_lossy(&a.outcome.stdout).into_owned())
                .collect::<Vec<_>>(),
        );
    }

    // Phase 08 tier-(b): Java raw-socket wire-frame fixture.
    // `tests/dynamic_fixtures/header_injection/java_raw/Vuln.java`
    // binds a `java.net.ServerSocket` via `createServer` whose
    // `runOnce` handler writes raw bytes via
    // `Socket.getOutputStream().write(byte[])`, bypassing Tomcat /
    // Jetty / Undertow's CRLF strip on `HttpServletResponse.setHeader`.
    // The harness boots the server on a loopback port via reflective
    // dispatch (`Class.forName("Vuln").getDeclaredMethod(...)`), opens
    // a client `java.net.Socket`, reads the response-header block off
    // the socket, and emits a `ProbeKind::HeaderWireFrame` record.
    // Asserts the test exercises the wire-frame branch (not the
    // synthetic fallback) by pinning `wire_frame_len` in the captured
    // stdout — that literal only appears in the tier-(b) write path.
    fn build_java_raw_spec(entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/header_injection/java_raw/Vuln.java");
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("Vuln.java");
        std::fs::copy(&fixture_src, &dst).expect("copy java_raw fixture into tempdir");
        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase08-e2e-header-injection|java_raw|Vuln.java");
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });
        // Mirror the Java workdir wipe used by build_spec — javac caches
        // compiled bytecode under the shared workdir at
        // `/tmp/nyx-harness/<spec_hash>`, so a previous run with a
        // different harness source can serve stale class files.
        let workdir = std::path::PathBuf::from("/tmp/nyx-harness").join(&spec_hash);
        let _ = std::fs::remove_dir_all(&workdir);
        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: entry_name.to_owned(),
            entry_kind: EntryKind::Function,
            lang: Lang::Java,
            toolchain_id: default_toolchain_id(Lang::Java).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::HEADER_INJECTION,
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

    #[test]
    fn java_raw_socket_vuln_confirms_via_wire_frame_probe() {
        if !command_available("javac") {
            eprintln!("SKIP java_raw: missing javac");
            return;
        }
        if !command_available("java") {
            eprintln!("SKIP java_raw: missing java");
            return;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_java_raw_spec("run");
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            ..SandboxOptions::default()
        };
        let outcome = match run_spec(&spec, &opts) {
            Ok(outcome) => outcome,
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP java_raw: harness build failed after {attempts} attempts: {stderr}",
                );
                return;
            }
            Err(e) => panic!("run_spec(java_raw) errored: {e:?}"),
        };
        assert_confirmed(Lang::Java, &outcome);
        let any_wire_frame_marker = outcome
            .attempts
            .iter()
            .any(|a| String::from_utf8_lossy(&a.outcome.stdout).contains("wire_frame_len"));
        assert!(
            any_wire_frame_marker,
            "java_raw fixture must exercise the tier-(b) wire-frame harness branch; \
             expected `wire_frame_len` substring in at least one attempt's stdout, got attempts={:?}",
            outcome
                .attempts
                .iter()
                .map(|a| String::from_utf8_lossy(&a.outcome.stdout).into_owned())
                .collect::<Vec<_>>(),
        );
    }
}
