//! Phase 11 (Track J.9) — `Cap::DATA_EXFIL` corpus acceptance.
//!
//! Asserts the corpus + outbound-network oracle for all seven
//! backend-capable languages.  The vuln payload supplies an
//! attacker-controlled host (`attacker.test`); the
//! [`nyx_scanner::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
//! predicate fires when the captured `host` falls outside the
//! loopback allowlist (`&["127.0.0.1", "localhost"]`).  Per-lang
//! harness dispatchers are deferred — see
//! `.pitboss/play/deferred.md`.
//!
//! `cargo nextest run --features dynamic --test data_exfil_corpus`.

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

const ALLOWLIST: &[&str] = &["127.0.0.1", "localhost"];

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

fn outbound_probe(host: &str) -> SinkProbe {
    SinkProbe {
        sink_callee: "__nyx_mock_http".into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "data-exfil-test".into(),
        kind: ProbeKind::OutboundNetwork { host: host.into() },
        witness: ProbeWitness::empty(),
    }
}

#[test]
fn corpus_registers_data_exfil_for_each_supported_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::DATA_EXFIL, *lang);
        assert!(!slice.is_empty(), "DATA_EXFIL missing for {lang:?}");
        assert!(slice.iter().any(|p| !p.is_benign));
        assert!(slice.iter().any(|p| p.is_benign));
    }
}

#[test]
fn data_exfil_payloads_pair_benign_per_lang() {
    for lang in LANGS {
        let slice = payloads_for_lang(Cap::DATA_EXFIL, *lang);
        let vuln = slice.iter().find(|p| !p.is_benign).expect("vuln");
        let resolved = resolve_benign_control_lang(vuln, Cap::DATA_EXFIL, *lang)
            .expect("benign control resolves");
        assert!(resolved.is_benign);
        match &vuln.oracle {
            Oracle::SinkProbe { predicates } => assert!(
                predicates
                    .iter()
                    .any(|p| matches!(p, ProbePredicate::OutboundHostNotIn { .. }))
            ),
            other => panic!("expected SinkProbe, got {other:?}"),
        }
    }
}

#[test]
fn outbound_predicate_fires_off_allowlist() {
    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::OutboundHostNotIn {
            allowlist: ALLOWLIST,
        }],
    };
    assert!(oracle_fired(
        &oracle,
        &outcome(),
        &[outbound_probe("attacker.test")]
    ));
    assert!(!oracle_fired(
        &oracle,
        &outcome(),
        &[outbound_probe("127.0.0.1")]
    ));
    assert!(!oracle_fired(
        &oracle,
        &outcome(),
        &[outbound_probe("Localhost")]
    ));
    assert!(!oracle_fired(&oracle, &outcome(), &[]));
}

/// Drives the per-language DATA_EXFIL fixtures through `run_spec` and
/// asserts the vuln payload Confirms while the benign control does not.
/// Both fixtures share a single entry function (`run`) and the harness
/// monkey-patches `urllib.request.urlopen` so no real network egress
/// happens — the probe captures the parsed host before the request is
/// short-circuited.
mod e2e_data_exfil {
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
            .join("tests/dynamic_fixtures/data_exfil")
            .join(match lang {
                Lang::Python => "python",
                Lang::Ruby => "ruby",
                Lang::JavaScript => "js",
                Lang::Java => "java",
                Lang::Php => "php",
                _ => unreachable!(
                    "DATA_EXFIL e2e currently covers Python + Ruby + JavaScript + Java + Php"
                ),
            })
            .join(fixture);
        let tmp = TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(fixture);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture into tempdir");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"e2e-data-exfil|");
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
            expected_cap: Cap::DATA_EXFIL,
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
            Lang::Ruby => "ruby",
            Lang::JavaScript => "node",
            Lang::Java => "javac",
            Lang::Php => "php",
            _ => unreachable!(
                "DATA_EXFIL e2e currently covers Python + Ruby + JavaScript + Java + Php"
            ),
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

    /// Pointed at the vuln fixture:
    ///
    /// * `attacker.test` → fixture sends to `attacker.test` → probe captures
    ///   `host = "attacker.test"` → `OutboundHostNotIn` fires.
    /// * `127.0.0.1` → fixture sends to loopback → probe captures
    ///   `host = "127.0.0.1"` → predicate clears (loopback in allowlist).
    ///
    /// Differential lands at `Confirmed`.
    #[test]
    fn python_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "vuln.py", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Python DATA_EXFIL vuln must confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    /// Pointed at the benign fixture (which rejects non-allowlist hosts
    /// before calling urlopen):
    ///
    /// * `attacker.test` → fixture rejects → no urlopen → no probe.
    /// * `127.0.0.1` → fixture sends to loopback → probe(host = "127.0.0.1")
    ///   → predicate clears.
    ///
    /// Neither payload fires; differential lands at `NotConfirmed`.
    #[test]
    fn python_benign_does_not_confirm_via_run_spec() {
        let Some(outcome) = run(Lang::Python, "benign.py", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "Python DATA_EXFIL benign control must not confirm via run_spec; got {outcome:?}",
        );
    }

    /// Ruby pair, same shape as Python: the vuln fixture always calls
    /// `Net::HTTP.get(uri)` and the harness's open-class shim records
    /// the URI host; the benign fixture early-returns when the host
    /// argument is not in `ALLOWLIST` so no `Net::HTTP.get` call is
    /// made for the attacker payload.  Skips when `ruby` is not on
    /// PATH.
    #[test]
    fn ruby_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Ruby, "vuln.rb", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Ruby DATA_EXFIL vuln must confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn ruby_benign_does_not_confirm_via_run_spec() {
        let Some(outcome) = run(Lang::Ruby, "benign.rb", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "Ruby DATA_EXFIL benign control must not confirm via run_spec; got {outcome:?}",
        );
    }

    /// JavaScript pair, same shape as Python + Ruby: the vuln fixture's
    /// `http.request({ host, ... })` hits the harness's `http.request`
    /// shim and the captured `host` flips `OutboundHostNotIn` for the
    /// attacker payload.  The benign fixture's `ALLOWLIST.has(host)`
    /// guard short-circuits before the request call for non-loopback
    /// hosts so no probe fires.  Skips when `node` is not on PATH.
    #[test]
    fn javascript_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::JavaScript, "vuln.js", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "JavaScript DATA_EXFIL vuln must confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn javascript_benign_does_not_confirm_via_run_spec() {
        let Some(outcome) = run(Lang::JavaScript, "benign.js", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "JavaScript DATA_EXFIL benign control must not confirm via run_spec; got {outcome:?}",
        );
    }

    /// Java pair, same shape as Python + Ruby + JavaScript.  The vuln
    /// fixture calls `NyxMockHttp.get("http://" + host + "/exfil?...")`;
    /// the harness-supplied `NyxMockHttp.captureHost` parses the URL
    /// host into `CAPTURED_HOSTS`; the harness drains the list after
    /// the entry returns and emits one `ProbeKind::OutboundNetwork` per
    /// host.  `OutboundHostNotIn` fires for the attacker payload.  The
    /// benign fixture's `ALLOWLIST.contains(host)` guard short-circuits
    /// before reaching `NyxMockHttp.get` for non-loopback payloads, so
    /// `CAPTURED_HOSTS` stays empty and no probe fires.  Skips when
    /// `javac` is not on PATH.
    #[test]
    fn java_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "Vuln.java", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "Java DATA_EXFIL vuln must confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn java_benign_does_not_confirm_via_run_spec() {
        let Some(outcome) = run(Lang::Java, "Benign.java", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "Java DATA_EXFIL benign control must not confirm via run_spec; got {outcome:?}",
        );
    }

    /// PHP pair, same shape as Python + Ruby + JavaScript + Java.  The
    /// vuln fixture calls `@file_get_contents("http://" . $host . "/...")`;
    /// the harness installs a stream-wrapper override for the `http`
    /// scheme that parses the URL host via `parse_url(PHP_URL_HOST)`,
    /// emits a `ProbeKind::OutboundNetwork`, and returns an empty
    /// stream.  `OutboundHostNotIn` fires for the attacker payload.
    /// The benign fixture's `in_array($host, ALLOWLIST)` guard
    /// short-circuits before `file_get_contents` for non-loopback
    /// payloads, so no probe fires.  Skips when `php` is not on PATH.
    #[test]
    fn php_vuln_confirms_via_run_spec() {
        let Some(outcome) = run(Lang::Php, "vuln.php", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_some(),
            "PHP DATA_EXFIL vuln must confirm via run_spec; got {outcome:?}",
        );
        let diff = outcome
            .differential
            .as_ref()
            .expect("confirmed run must carry a DifferentialOutcome");
        assert_eq!(diff.verdict, DifferentialVerdict::Confirmed);
    }

    #[test]
    fn php_benign_does_not_confirm_via_run_spec() {
        let Some(outcome) = run(Lang::Php, "benign.php", "run") else {
            return;
        };
        assert!(
            outcome.triggered_by.is_none(),
            "PHP DATA_EXFIL benign control must not confirm via run_spec; got {outcome:?}",
        );
    }
}
