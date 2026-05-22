//! Phase 06 (Track J.4) — LDAP_INJECTION corpus acceptance.
//!
//! Asserts the new cap end-to-end: corpus slices register per-language
//! vuln/benign pairs for Java / Python / PHP, the lang-aware resolver
//! pairs them inside the correct slice, the per-language harness
//! emitters splice in the synthetic LDAP filter evaluator + entries-
//! returned probe + sink-hit sentinel, the framework adapters fire on
//! the canonical sink call, and the in-sandbox LDAP server stub
//! returns three entries for the malicious filter / one entry for the
//! benign control.
//!
//! `cargo nextest run --features dynamic --test ldap_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::corpus::{
    Oracle, audit_marker_collisions, benign_payload_for_lang, payloads_for_lang,
    resolve_benign_control_lang,
};
use nyx_scanner::dynamic::framework::registry::adapters_for;
use nyx_scanner::dynamic::lang;
use nyx_scanner::dynamic::oracle::ProbePredicate;
use nyx_scanner::dynamic::probe::ProbeKind;
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use nyx_scanner::dynamic::stubs::ldap_server::LdapStub;
use nyx_scanner::dynamic::stubs::{StubKind, StubProvider};
use nyx_scanner::labels::Cap;
use nyx_scanner::summary::FuncSummary;
use nyx_scanner::symbol::Lang;

const LANGS: &[Lang] = &[Lang::Java, Lang::Python, Lang::Php];

fn make_spec(lang: Lang, entry_file: &str, entry_name: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "phase06test0001".into(),
        entry_file: entry_file.into(),
        entry_name: entry_name.into(),
        entry_kind: EntryKind::Function,
        lang,
        toolchain_id: "phase06".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::LDAP_INJECTION,
        constraint_hints: vec![],
        sink_file: entry_file.into(),
        sink_line: 1,
        spec_hash: "phase06test0001".into(),
        derivation: nyx_scanner::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
        java_toolchain: nyx_scanner::dynamic::spec::JavaToolchain::default(),
    }
}

#[test]
fn corpus_registers_ldap_for_every_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::LDAP_INJECTION, *lang);
        assert!(
            !slice.is_empty(),
            "LDAP_INJECTION has no payloads for {lang:?}"
        );
        let has_vuln = slice.iter().any(|p| !p.is_benign);
        let has_benign = slice.iter().any(|p| p.is_benign);
        assert!(has_vuln, "{lang:?} LDAP missing vuln payload");
        assert!(has_benign, "{lang:?} LDAP missing benign control");
    }
}

#[test]
fn ldap_unsupported_caps_unchanged_for_other_langs() {
    for lang in [
        Lang::Rust,
        Lang::C,
        Lang::Cpp,
        Lang::Ruby,
        Lang::Go,
        Lang::JavaScript,
        Lang::TypeScript,
    ] {
        assert!(
            payloads_for_lang(Cap::LDAP_INJECTION, lang).is_empty(),
            "unexpected LDAP_INJECTION payloads for {lang:?}",
        );
    }
}

#[test]
fn benign_control_resolves_within_lang_slice() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::LDAP_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let resolved =
            resolve_benign_control_lang(vuln, Cap::LDAP_INJECTION, *lang).expect("paired control");
        assert!(resolved.is_benign);
        let direct = benign_payload_for_lang(Cap::LDAP_INJECTION, *lang).unwrap();
        assert_eq!(direct.label, resolved.label);
    }
}

#[test]
fn payload_oracle_carries_ldap_result_count_predicate() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::LDAP_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(
                    predicates
                        .iter()
                        .any(|p| matches!(p, ProbePredicate::QueryResultCountGreaterThan { n: 1 })),
                    "{lang:?} vuln payload missing QueryResultCountGreaterThan {{ n: 1 }}",
                );
            }
            other => panic!("expected SinkProbe oracle for {lang:?}, got {other:?}"),
        }
    }
}

#[test]
fn vuln_payload_bytes_contain_filter_breakout() {
    // The whole differential rule rests on the vuln payload carrying
    // a `*)(uid=*`-style filter breakout and the benign control NOT
    // carrying one — pin both invariants so a future corpus tweak
    // does not silently break the oracle.
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::LDAP_INJECTION, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).unwrap();
        let benign = slice.iter().find(|p| p.is_benign).unwrap();
        let vuln_text = std::str::from_utf8(vuln.bytes).unwrap();
        let benign_text = std::str::from_utf8(benign.bytes).unwrap();
        assert!(
            vuln_text.contains("*") && vuln_text.contains(")"),
            "{lang:?} vuln payload must carry a wildcard + paren breakout",
        );
        assert!(
            !benign_text.contains("*") && !benign_text.contains(")"),
            "{lang:?} benign control must not carry filter metacharacters",
        );
    }
}

#[test]
fn marker_collisions_clean_with_phase_06_additions() {
    assert!(audit_marker_collisions().is_empty());
}

#[test]
fn probe_kind_ldap_serdes() {
    let original = ProbeKind::Ldap {
        entries_returned: 3,
    };
    let json = serde_json::to_string(&original).unwrap();
    assert!(json.contains("Ldap"));
    assert!(json.contains("entries_returned"));
    let parsed: ProbeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn lang_emitter_dispatches_to_ldap_harness() {
    // Per-lang `sink_callee_marker` pins which client-construction
    // string the harness names in its probe record — the
    // `LdapTemplate.search` / `ldap.search_s` / `ldap_search`
    // boundary the brief calls out.
    for (lang, entry_file, entry_name, sink_callee_marker) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/ldap_injection/java/Vuln.java",
            "run",
            "LdapTemplate.search",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/ldap_injection/python/vuln.py",
            "run",
            "ldap.search_s",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/ldap_injection/php/vuln.php",
            "run",
            "ldap_search",
        ),
    ] {
        let spec = make_spec(lang, entry_file, entry_name);
        let harness =
            lang::emit(&spec).unwrap_or_else(|e| panic!("emit failed for {lang:?}: {e:?}"));
        assert!(
            harness.source.contains("entries_returned"),
            "{lang:?} ldap harness must carry the entries_returned probe field",
        );
        assert!(
            harness.source.contains(sink_callee_marker),
            "{lang:?} ldap harness must name {sink_callee_marker:?} as the sink callee",
        );
        assert!(
            harness.source.contains("__NYX_SINK_HIT__"),
            "{lang:?} ldap harness must emit the sink-hit sentinel",
        );
        assert!(
            harness.source.contains("uid="),
            "{lang:?} ldap harness must build a `(uid=…)` filter from NYX_PAYLOAD",
        );
    }
}

#[test]
fn framework_adapters_detect_ldap_sink() {
    // Each lang registers its J.4 LDAP-search adapter; detect_binding
    // routes through the registry and stamps an EntryKind::Function
    // binding when the fixture contains the canonical sink call.
    for (lang, fixture, sink_callee) in [
        (
            Lang::Java,
            "tests/dynamic_fixtures/ldap_injection/java/Vuln.java",
            "search",
        ),
        (
            Lang::Python,
            "tests/dynamic_fixtures/ldap_injection/python/vuln.py",
            "search_s",
        ),
        (
            Lang::Php,
            "tests/dynamic_fixtures/ldap_injection/php/vuln.php",
            "ldap_search",
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
        let b = binding.unwrap_or_else(|| panic!("{lang:?} adapter must detect the LDAP fixture"));
        assert_eq!(b.kind, EntryKind::Function);
        assert!(!b.adapter.is_empty());
    }
}

fn ts_language_for(lang: Lang) -> tree_sitter::Language {
    match lang {
        Lang::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Lang::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Lang::Php => tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
        other => panic!("unsupported test lang {other:?}"),
    }
}

fn slug(lang: Lang) -> &'static str {
    match lang {
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Php => "php",
        _ => "other",
    }
}

#[test]
fn stub_ldap_server_returns_three_for_wildcard_filter() {
    // The acceptance bullet states: stub LDAP server returns > 1
    // entry on the malicious filter, exactly 1 on the benign filter.
    // Pin both directions against the actual stub.
    let stub = LdapStub::start().expect("ldap stub starts");
    let mal = LdapStub::evaluate("(|(uid=alice)(uid=*))");
    let benign = LdapStub::evaluate("(uid=alice)");
    assert!(
        mal.len() > 1,
        "malicious filter must match > 1 entry, got {mal:?}"
    );
    assert_eq!(benign.len(), 1, "benign filter must match exactly 1 entry");
    assert_eq!(stub.kind(), StubKind::Ldap);
}

#[test]
fn stub_kind_for_cap_routes_ldap_injection() {
    let kinds = StubKind::for_cap(Cap::LDAP_INJECTION);
    assert!(kinds.contains(&StubKind::Ldap));
}

// ── End-to-end Phase 06 acceptance via run_spec ───────────────────────────────
//
// Mirrors the `e2e_phase_05` block in `xxe_corpus.rs`.  Drives
// `run_spec` directly on a `Cap::LDAP_INJECTION` spec per language and
// asserts the polarity via the `ProbeKind::Ldap { entries_returned > 1 }`
// probe and the `__NYX_SINK_HIT__` sentinel.  The synthetic harness
// mirrors the in-sandbox LDAP server stub's RFC-4515 subset locally,
// so the verdict path is deterministic even when the stub itself is
// not spawned (`stubs_required: vec![]`).

mod e2e_phase_06 {
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
            _ => unreachable!("e2e_phase_06 covers Java/Python/PHP"),
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
            .join("tests/dynamic_fixtures/ldap_injection")
            .join(lang_subdir(lang))
            .join(fixture);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase06-e2e-ldap|");
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
            expected_cap: Cap::LDAP_INJECTION,
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
        let Some(outcome) = run(Lang::Java, "Vuln.java", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Java LDAP vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "vuln.py", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Python LDAP vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn php_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Php, "vuln.php", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "PHP LDAP vuln must Confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    // ── Tier (a): socket-route exercise ──────────────────────────────
    //
    // When `NYX_LDAP_ENDPOINT` is injected into the sandbox env the
    // per-language harness must route its `(uid=…)` search through the
    // in-sandbox LDAP stub over the documented `SEARCH <filter>\n` /
    // `COUNT <n>\n…` wire protocol instead of evaluating the filter
    // in-process.  The fallback inline matcher stays in place so a
    // call site that runs without the stub still produces a verdict;
    // this test pins the socket-route path itself.
    use nyx_scanner::dynamic::stubs::StubProvider;
    use nyx_scanner::dynamic::stubs::ldap_server::LdapStub;

    fn run_with_ldap_stub(
        lang: Lang,
        fixture: &str,
        entry_name: &str,
    ) -> Option<(RunOutcome, Vec<nyx_scanner::dynamic::stubs::StubEvent>)> {
        let bin = toolchain_for(lang);
        if !command_available(bin) {
            eprintln!("SKIP {lang:?} {fixture}: missing toolchain {bin}");
            return None;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let stub = LdapStub::start().expect("ldap stub starts");
        let endpoint = stub.endpoint();
        let (mut spec, _tmp) = build_spec(lang, fixture, entry_name);
        spec.stubs_required = vec![nyx_scanner::dynamic::stubs::StubKind::Ldap];
        let opts = SandboxOptions {
            backend: SandboxBackend::Process,
            extra_env: vec![(
                nyx_scanner::dynamic::stubs::ldap_server::LDAP_ENDPOINT_ENV_VAR.to_owned(),
                endpoint,
            )],
            ..SandboxOptions::default()
        };
        let outcome = match run_spec(&spec, &opts) {
            Ok(o) => o,
            Err(RunError::BuildFailed { stderr, attempts }) => {
                eprintln!(
                    "SKIP {lang:?} {fixture}: harness build failed after {attempts} attempts: {stderr}",
                );
                return None;
            }
            Err(e) => panic!("run_spec({lang:?} {fixture}) errored: {e:?}"),
        };
        let events = stub.drain_events();
        Some((outcome, events))
    }

    #[test]
    fn java_vuln_routes_searches_through_stub() {
        let Some((outcome, events)) = run_with_ldap_stub(Lang::Java, "Vuln.java", "run") else {
            return;
        };
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
        assert!(
            !events.is_empty(),
            "Java harness must route SEARCH through stub; got no events",
        );
        assert!(
            events.iter().any(|e| e.summary.starts_with("SEARCH (uid=")),
            "Java harness stub events must carry a `(uid=…)` filter; got {events:?}",
        );
        // The Java emitter dispatches via `javax.naming.directory.InitialDirContext`,
        // so the stub's BER handler must record `protocol=ldapv3` on at
        // least one event — pins the tier-(b) wire format and prevents a
        // regression that silently falls back to the plaintext path.
        assert!(
            events
                .iter()
                .any(|e| e.detail.get("protocol").map(String::as_str) == Some("ldapv3")),
            "Java harness must exercise the LDAPv3 BER path; got {events:?}",
        );
    }

    #[test]
    fn python_vuln_routes_searches_through_stub() {
        let Some((outcome, events)) = run_with_ldap_stub(Lang::Python, "vuln.py", "run") else {
            return;
        };
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
        assert!(
            !events.is_empty(),
            "Python harness must route SEARCH through stub; got no events",
        );
        assert!(
            events.iter().any(|e| e.summary.starts_with("SEARCH (uid=")),
            "Python harness stub events must carry a `(uid=…)` filter; got {events:?}",
        );
        // The Python emitter now dispatches via a pure-stdlib LDAPv3 BER
        // client, so the stub's BER handler must record `protocol=ldapv3`
        // on at least one event — pins the tier-(b) wire format and
        // prevents a regression that silently falls back to the plaintext
        // path.
        assert!(
            events
                .iter()
                .any(|e| e.detail.get("protocol").map(String::as_str) == Some("ldapv3")),
            "Python harness must exercise the LDAPv3 BER path; got {events:?}",
        );
    }

    #[test]
    fn php_vuln_routes_searches_through_stub() {
        let Some((outcome, events)) = run_with_ldap_stub(Lang::Php, "vuln.php", "run") else {
            return;
        };
        let diff = outcome
            .differential
            .as_ref()
            .expect("Confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
        assert!(
            !events.is_empty(),
            "PHP harness must route SEARCH through stub; got no events",
        );
        assert!(
            events.iter().any(|e| e.summary.starts_with("SEARCH (uid=")),
            "PHP harness stub events must carry a `(uid=…)` filter; got {events:?}",
        );
        // The PHP emitter now dispatches via a core-PHP LDAPv3 BER client
        // (no `ext-ldap` dep), so the stub's BER handler must record
        // `protocol=ldapv3` on at least one event — pins the tier-(b) wire
        // format and prevents a regression that silently falls back to the
        // plaintext path.
        assert!(
            events
                .iter()
                .any(|e| e.detail.get("protocol").map(String::as_str) == Some("ldapv3")),
            "PHP harness must exercise the LDAPv3 BER path; got {events:?}",
        );
    }
}
