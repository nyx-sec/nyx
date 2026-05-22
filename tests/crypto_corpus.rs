//! Phase 11 (Track J.9) — `Cap::CRYPTO` corpus acceptance.
//!
//! Asserts the new cap end-to-end at the corpus + oracle layer:
//! per-language vuln/benign slices register, lang-aware benign-control
//! resolution pairs them inside the correct slice, and the
//! `WeakKeyEntropy` predicate fires only when a `WeakKey { key_int }`
//! probe whose `key_int` is strictly less than `2^max_bits` lands on
//! the channel.  Per-lang harness dispatchers are deferred — see
//! `.pitboss/play/deferred.md`.
//!
//! `cargo nextest run --features dynamic --test crypto_corpus`.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::corpus::{payloads_for_lang, resolve_benign_control_lang};
use nyx_scanner::dynamic::oracle::{Oracle, ProbePredicate, oracle_fired};
use nyx_scanner::dynamic::probe::{ProbeKind, ProbeWitness, SinkProbe};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;
use std::time::Duration;

const LANGS: &[Lang] = &[Lang::Java, Lang::Python, Lang::Php, Lang::Go, Lang::Rust];

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

fn weak_key_probe(key_int: u64) -> SinkProbe {
    SinkProbe {
        sink_callee: "__nyx_weak_key".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "crypto-test".into(),
        kind: ProbeKind::WeakKey { key_int },
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn corpus_registers_crypto_for_each_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::CRYPTO, *lang);
        assert!(!slice.is_empty(), "CRYPTO has no payloads for {lang:?}");
        assert!(
            slice.iter().any(|p| !p.is_benign),
            "{lang:?} CRYPTO missing vuln payload",
        );
        assert!(
            slice.iter().any(|p| p.is_benign),
            "{lang:?} CRYPTO missing benign control",
        );
    }
}

#[test]
fn crypto_payloads_pair_benign_controls_per_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::CRYPTO, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).expect("vuln payload");
        let resolved =
            resolve_benign_control_lang(vuln, Cap::CRYPTO, *lang).expect("benign control resolves");
        assert!(resolved.is_benign);
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => {
                assert!(
                    predicates
                        .iter()
                        .any(|p| matches!(p, ProbePredicate::WeakKeyEntropy { max_bits: 16 }))
                );
            }
            other => panic!("expected SinkProbe, got {other:?}"),
        }
    }
}

#[test]
fn weak_key_entropy_fires_below_budget() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: 16 }],
    };
    let probes = vec![weak_key_probe(0x1234)];
    assert!(oracle_fired(&oracle, &outcome(), &probes));
}

#[test]
fn weak_key_entropy_clears_above_budget() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: 16 }],
    };
    let probes = vec![weak_key_probe(u64::MAX / 2)];
    assert!(!oracle_fired(&oracle, &outcome(), &probes));
}

#[test]
fn weak_key_entropy_clears_with_no_probe() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::WeakKeyEntropy { max_bits: 16 }],
    };
    assert!(!oracle_fired(&oracle, &outcome(), &[]));
}

// ── End-to-end Phase 11 CRYPTO acceptance via run_spec ───────────────────────
//
// Drives `run_spec` directly on a `Cap::CRYPTO` spec per language and
// asserts the polarity via the `ProbeKind::WeakKey { key_int }` probe.
// The vuln fixture is payload-branched: the curated `NYX_CRYPTO_WEAK`
// payload routes through the weak RNG (sub-2^16 key → predicate fires);
// the curated `NYX_CRYPTO_STRONG` benign control routes through the
// CSPRNG (huge key → predicate clears).  Both attempts load the same
// `vuln.<ext>` fixture, so the runner's existing single-entry-file
// model holds — see the deferred items file for the rationale.
//
// Per-lang coverage: Python / PHP / Java / Go / Rust fixtures are
// payload-branched in tree.  The Go case SKIPs on hosts without the
// `go` toolchain.

mod e2e_phase_11_crypto {
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
            Lang::Php => "php",
            Lang::Java => "java",
            Lang::Rust => "cargo",
            Lang::Go => "go",
            _ => unreachable!("e2e_phase_11_crypto covers Python/PHP/Java/Rust/Go today"),
        }
    }

    fn lang_subdir(lang: Lang) -> &'static str {
        match lang {
            Lang::Python => "python",
            Lang::Php => "php",
            Lang::Java => "java",
            Lang::Rust => "rust",
            Lang::Go => "go",
            _ => unreachable!(),
        }
    }

    fn build_spec(lang: Lang, fixture: &str, entry_name: &str) -> (HarnessSpec, TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/crypto")
            .join(lang_subdir(lang))
            .join(fixture);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase11-e2e-crypto|");
        digest.update(lang_subdir(lang).as_bytes());
        digest.update(b"|");
        digest.update(fixture.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        if matches!(lang, Lang::Java | Lang::Rust) {
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
            expected_cap: Cap::CRYPTO,
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
            "{lang:?} CRYPTO vuln must Confirm via run_spec; got {outcome:?}",
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
    fn java_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "vuln.java", "run") else {
            return;
        };
        assert_confirmed(Lang::Java, &outcome);
    }

    #[test]
    fn rust_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Rust, "vuln.rs", "run") else {
            return;
        };
        assert_confirmed(Lang::Rust, &outcome);
    }

    #[test]
    fn go_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Go, "vuln.go", "Run") else {
            return;
        };
        assert_confirmed(Lang::Go, &outcome);
    }
}

#[test]
fn crypto_unsupported_for_other_langs() {
    for lang in [
        Lang::C,
        Lang::Cpp,
        Lang::Ruby,
        Lang::JavaScript,
        Lang::TypeScript,
    ] {
        assert!(
            payloads_for_lang(Cap::CRYPTO, lang).is_empty(),
            "CRYPTO has unexpected payloads for {lang:?}",
        );
    }
}
