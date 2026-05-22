//! Phase 11 (Track J.9) — `Cap::UNAUTHORIZED_ID` corpus acceptance.
//!
//! Asserts the corpus + IDOR oracle for all seven backend-capable
//! languages.  The vuln payload supplies an `owner_id` belonging to
//! another user; the
//! [`nyx_scanner::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
//! predicate fires when `caller_id != owner_id`.  Per-lang harness
//! dispatchers are deferred — see `.pitboss/play/deferred.md`.
//!
//! `cargo nextest run --features dynamic --test unauthorized_id_corpus`.

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
    Lang::Python,
    Lang::Ruby,
    Lang::Java,
    Lang::Php,
    Lang::JavaScript,
    Lang::Go,
    Lang::Rust,
];

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

fn idor_probe(caller: &str, owner: &str) -> SinkProbe {
    SinkProbe {
        sink_callee: "__nyx_idor_lookup".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "idor-test".into(),
        kind: ProbeKind::IdorAccess {
            caller_id: caller.into(),
            owner_id: owner.into(),
        },
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn corpus_registers_unauthorized_id_for_each_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::UNAUTHORIZED_ID, *lang);
        assert!(!slice.is_empty(), "UNAUTHORIZED_ID missing for {lang:?}");
        assert!(slice.iter().any(|p| !p.is_benign));
        assert!(slice.iter().any(|p| p.is_benign));
    }
}

#[test]
fn idor_payloads_pair_benign_per_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::UNAUTHORIZED_ID, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).expect("vuln");
        let resolved = resolve_benign_control_lang(vuln, Cap::UNAUTHORIZED_ID, *lang)
            .expect("benign control resolves");
        assert!(resolved.is_benign);
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => assert!(
                predicates
                    .iter()
                    .any(|p| matches!(p, ProbePredicate::IdorBoundaryCrossed))
            ),
            other => panic!("expected SinkProbe, got {other:?}"),
        }
    }
}

#[test]
fn idor_predicate_fires_on_boundary_crossing() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::IdorBoundaryCrossed],
    };
    assert!(oracle_fired(
        &oracle,
        &outcome(),
        &[idor_probe("alice", "bob")]
    ));
    assert!(!oracle_fired(
        &oracle,
        &outcome(),
        &[idor_probe("alice", "alice")]
    ));
    assert!(!oracle_fired(&oracle, &outcome(), &[]));
}

/// Drives the per-language UNAUTHORIZED_ID fixtures through `run_spec`
/// and asserts the vuln payload Confirms while the benign control does
/// not.  Each fixture pair shares a single entry function (`run`); the
/// harness emitter resolves the payload-vs-record boundary via the
/// hard-coded `caller_id = "alice"` it embeds in the probe shim.
mod e2e_unauthorized_id {
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
            .join("tests/dynamic_fixtures/unauthorized_id")
            .join(match lang {
                Lang::Python => "python",
                _ => unreachable!("UNAUTHORIZED_ID e2e currently covers Python only"),
            })
            .join(fixture);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"e2e-unauthorized-id|");
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
            expected_cap: Cap::UNAUTHORIZED_ID,
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
            _ => unreachable!("UNAUTHORIZED_ID e2e currently covers Python only"),
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

    /// The runner draws the curated payload pair (vuln "bob" + benign "alice")
    /// from `payloads_for_lang(Cap::UNAUTHORIZED_ID, Lang::Python)`.  Pointed at
    /// the vuln fixture:
    ///
    /// * `bob` → fixture returns bob's record → probe(caller=alice, owner=bob)
    ///   → `IdorBoundaryCrossed` fires.
    /// * `alice` → fixture returns alice's record → probe(caller=alice,
    ///   owner=alice) → predicate clears.
    ///
    /// The vuln-vs-benign differential lands at `Confirmed`.
    #[test]
    fn python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "vuln.py", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Python UNAUTHORIZED_ID vuln must confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    /// Pointed at the benign fixture:
    ///
    /// * `bob` → fixture rejects (returns None) → no probe.
    /// * `alice` → fixture returns alice's record → probe(alice, alice) →
    ///   predicate clears.
    ///
    /// Neither payload fires the predicate; the differential lands at
    /// `NotConfirmed`.
    #[test]
    fn python_benign_does_not_confirm_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "benign.py", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "Python UNAUTHORIZED_ID benign control must not confirm via run_spec; got {outcome:?}",
        );
    }
}
