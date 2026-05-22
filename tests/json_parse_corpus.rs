//! Phase 11 (Track J.9) — `Cap::JSON_PARSE` corpus acceptance.
//!
//! Asserts the corpus + oracle layer for the pollution oracle that
//! reuses the Phase 10 prototype canary across the three languages
//! whose JSON parsers have a published pollution surface: JavaScript,
//! Python, Ruby.  Per-lang harness dispatchers are deferred — see
//! `.pitboss/play/deferred.md`.
//!
//! `cargo nextest run --features dynamic --test json_parse_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::corpus::{payloads_for_lang, resolve_benign_control_lang};
use nyx_scanner::dynamic::oracle::{Oracle, ProbePredicate, oracle_fired};
use nyx_scanner::dynamic::probe::{ProbeKind, ProbeWitness, SinkProbe};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;
use std::time::Duration;

const LANGS: &[Lang] = &[
    Lang::JavaScript,
    Lang::Python,
    Lang::Ruby,
    Lang::Php,
    Lang::Go,
    Lang::Rust,
    Lang::Java,
];

/// Subset of [`LANGS`] whose JSON parser has a prototype-pollution
/// surface — JS / Python / Ruby ship object-property merging idioms
/// downstream of `JSON.parse` / `json.loads`.  PHP / Go / Rust have no
/// equivalent surface so the canary predicate is intentionally absent
/// from their corpus slice.
const CANARY_LANGS: &[Lang] = &[Lang::JavaScript, Lang::Python, Lang::Ruby];

fn outcome() -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(0),
        stdout: vec![],
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: false,
        duration: Duration::from_millis(1),
        hardening_outcome: None,
    }
}

fn canary_probe(property: &str) -> SinkProbe {
    SinkProbe {
        sink_callee: "__nyx_pp_canary_set".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "json-parse-test".into(),
        kind: ProbeKind::PrototypePollution {
            property: property.into(),
            value: "pwned".into(),
        },
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn corpus_registers_json_parse_for_each_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::JSON_PARSE, *lang);
        assert!(!slice.is_empty(), "JSON_PARSE missing for {lang:?}");
        assert!(slice.iter().any(|p| !p.is_benign));
        assert!(slice.iter().any(|p| p.is_benign));
    }
}

#[test]
fn json_parse_pairs_benign_per_lang_via_canary_predicate() {
    for lang in CANARY_LANGS {
        let slice = payloads_for_lang(Cap::JSON_PARSE, *lang);
        let vuln = slice
            .iter()
            .find(|p| {
                !p.is_benign
                    && matches!(
                        p.oracle,
                        Oracle::SinkProbe {
                            predicates,
                            ..
                        } if predicates.iter().any(|q| matches!(
                            q,
                            ProbePredicate::PrototypeCanaryTouched {
                                canary: "__nyx_canary"
                            }
                        ))
                    )
            })
            .expect("vuln canary payload");
        let resolved = resolve_benign_control_lang(vuln, Cap::JSON_PARSE, *lang)
            .expect("benign control resolves");
        assert!(resolved.is_benign);
    }
}

#[test]
fn json_parse_depth_bomb_pairs_benign_per_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::JSON_PARSE, *lang);
        let vuln = slice
            .iter()
            .find(|p| {
                !p.is_benign
                    && matches!(
                        p.oracle,
                        Oracle::SinkProbe {
                            predicates,
                            ..
                        } if predicates.iter().any(|q| matches!(
                            q,
                            ProbePredicate::JsonParseExcessiveDepth { max_depth: 64 }
                        ))
                    )
            })
            .unwrap_or_else(|| panic!("{lang:?} JSON_PARSE slice must carry a depth-bomb vuln"));
        let resolved = resolve_benign_control_lang(vuln, Cap::JSON_PARSE, *lang)
            .expect("depth-bomb benign control resolves");
        assert!(resolved.is_benign);
    }
}

#[test]
fn canary_predicate_fires_only_on_canary_property() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::PrototypeCanaryTouched {
            canary: "__nyx_canary",
        }],
    };
    assert!(oracle_fired(
        &oracle,
        &outcome(),
        &[canary_probe("__nyx_canary")]
    ));
    assert!(!oracle_fired(
        &oracle,
        &outcome(),
        &[canary_probe("__data__")]
    ));
    assert!(!oracle_fired(&oracle, &outcome(), &[]));
}

// Runs the depth-bomb fixture through the dynamic runner. The same fixture
// handles the vulnerable and benign payloads; the payload tag picks the branch.
mod e2e_json_parse_depth {
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

    fn build_spec(lang: Lang, fixture: &str, entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/json_parse_depth")
            .join(match lang {
                Lang::Python => "python",
                Lang::JavaScript => "javascript",
                Lang::Ruby => "ruby",
                Lang::Php => "php",
                Lang::Go => "go",
                Lang::Rust => "rust",
                Lang::Java => "java",
                _ => unreachable!("JSON_PARSE depth e2e covers JS / Python / Ruby / PHP / Go / Rust / Java only"),
            })
            .join(fixture);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"e2e-json-parse|");
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
            expected_cap: Cap::JSON_PARSE,
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
        let required = match lang {
            Lang::Python => "python3",
            Lang::JavaScript => "node",
            Lang::Ruby => "ruby",
            Lang::Php => "php",
            Lang::Go => "go",
            Lang::Rust => "cargo",
            Lang::Java => "javac",
            _ => unreachable!("JSON_PARSE depth e2e covers JS / Python / Ruby / PHP / Go / Rust / Java only"),
        };
        if !command_available(required) {
            eprintln!("SKIP {lang:?} {fixture}: missing toolchain {required}");
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
            "{lang:?} JSON_PARSE depth bomb must confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "vuln.py", "run") else {
            return;
        };
        assert_confirmed(Lang::Python, &outcome);
    }

    #[test]
    fn javascript_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::JavaScript, "vuln.js", "run") else {
            return;
        };
        assert_confirmed(Lang::JavaScript, &outcome);
    }

    #[test]
    fn ruby_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Ruby, "vuln.rb", "run") else {
            return;
        };
        assert_confirmed(Lang::Ruby, &outcome);
    }

    #[test]
    fn php_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Php, "vuln.php", "run") else {
            return;
        };
        assert_confirmed(Lang::Php, &outcome);
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

    #[test]
    fn java_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "Vuln.java", "run") else {
            return;
        };
        assert_confirmed(Lang::Java, &outcome);
    }
}

#[test]
fn json_parse_unsupported_for_other_langs() {
    for lang in [Lang::C, Lang::Cpp, Lang::TypeScript] {
        assert!(
            payloads_for_lang(Cap::JSON_PARSE, lang).is_empty(),
            "JSON_PARSE has unexpected payloads for {lang:?}",
        );
    }
}
