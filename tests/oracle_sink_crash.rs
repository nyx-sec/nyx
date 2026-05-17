//! Phase 08 — Track C.4 + C.5 acceptance tests.
//!
//! The runner-side path is exercised in isolation by the
//! `oracle_differential` tests; here we lock down the synthetic side of
//! Phase 08 — that a sink-site crash probe confirms via
//! [`Oracle::SinkCrash`], that an outside-sink process abort *does not*
//! confirm, and that witness construction stays bounded.
//!
//! Acceptance bullets (`plan.md` phase 08):
//!
//! - (a) sink-site crash → `Confirmed`
//! - (b) crash outside sink → `Inconclusive(UnrelatedCrash)`
//! - (c) bounded witness capture for known payloads
//!
//! End-to-end fixtures at the bottom of this file drive the full
//! [`run_spec`] pipeline against compiled C harnesses, locking in that
//! the `__nyx_install_crash_guard` ordering inside the emitted `main.c`
//! routes setup-fault and sink-fault crashes to the right verdicts.

#![cfg(feature = "dynamic")]

mod common;

use nyx_scanner::dynamic::oracle::{
    oracle_fired, probe_crash_signal, Oracle, Signal, SignalSet,
};
use nyx_scanner::dynamic::policy;
use nyx_scanner::dynamic::probe::{
    ProbeArg, ProbeChannel, ProbeKind, ProbeWitness, SinkProbe,
};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::evidence::InconclusiveReason;
use std::time::Duration;
use tempfile::TempDir;

fn crashed_outcome() -> SandboxOutcome {
    // Process-level abort: no exit code, no timeout.
    SandboxOutcome {
        exit_code: None,
        stdout: vec![],
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: false,
        duration: Duration::from_millis(1),
        hardening_outcome: None,
    }
}

fn clean_outcome() -> SandboxOutcome {
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

fn crash_probe(callee: &str, signal: Signal, witness: ProbeWitness) -> SinkProbe {
    SinkProbe {
        sink_callee: callee.into(),
        args: vec![],
        captured_at_ns: 1,
        payload_id: "crash-test".into(),
        kind: ProbeKind::Crash { signal },
        witness,
    }
}

// ── (a) Sink-site crash → Confirmed ──────────────────────────────────────────

#[test]
fn case_a_sink_site_crash_confirms() {
    // Simulates the per-language signal handler: harness aborted, but
    // before re-raising it wrote a Crash probe to the channel.
    let dir = TempDir::new().unwrap();
    let channel = ProbeChannel::for_workdir(dir.path()).unwrap();
    let witness = ProbeWitness::from_inputs(
        vec![("PATH".to_owned(), "/bin".to_owned())],
        "/tmp/run",
        b"<? system($_GET[x]); ?>",
        "system",
        vec!["<? system($_GET[x]); ?>".to_owned()],
    );
    channel
        .write(&crash_probe("system", Signal::Sigsegv, witness))
        .unwrap();

    let probes = channel.drain();
    assert_eq!(probes.len(), 1);

    let oracle = Oracle::SinkCrash {
        signals: SignalSet::from_slice(&[Signal::Sigsegv]),
    };
    assert!(
        oracle_fired(&oracle, &crashed_outcome(), &probes),
        "sink-site Crash probe with matching signal must fire SinkCrash oracle"
    );

    // Helper accessor exposes the signal so the runner can distinguish
    // "matching probe present" from "process crashed only".
    assert_eq!(probe_crash_signal(&probes[0]), Some(Signal::Sigsegv));
}

// ── (b) Crash outside sink → Inconclusive(UnrelatedCrash) ────────────────────

#[test]
fn case_b_outside_sink_crash_does_not_fire_and_is_unrelated() {
    // The harness was instrumented with Oracle::SinkCrash but the
    // process aborted in setup code (e.g. abort() in module init)
    // before the sink ran — no Crash probe was written.
    let dir = TempDir::new().unwrap();
    let channel = ProbeChannel::for_workdir(dir.path()).unwrap();
    let probes = channel.drain();
    assert!(probes.is_empty(), "no probe written from outside-sink abort");

    let oracle = Oracle::SinkCrash {
        signals: SignalSet::all(),
    };
    assert!(
        !oracle_fired(&oracle, &crashed_outcome(), &probes),
        "process crash without a sink-site probe must NOT fire SinkCrash"
    );

    // The verifier's runner-side condition that promotes this case to
    // `Inconclusive(UnrelatedCrash)` is: SinkCrash oracle + crashed
    // outcome + no probe with a crash signal.  Lock the predicate
    // here so the runner's wiring in src/dynamic/runner.rs stays in
    // sync with what the test labels expect.
    let process_crashed =
        crashed_outcome().exit_code.is_none() && !crashed_outcome().timed_out;
    let has_sink_crash_probe = probes.iter().any(|p| probe_crash_signal(p).is_some());
    let is_sink_crash_oracle = matches!(oracle, Oracle::SinkCrash { .. });
    assert!(is_sink_crash_oracle && process_crashed && !has_sink_crash_probe);

    // The verdict mapping itself is constructed by the verifier; reference
    // the variant so a rename keeps this test honest.
    let _reason = InconclusiveReason::UnrelatedCrash;
}

#[test]
fn case_b_clean_exit_does_not_fire_sink_crash() {
    // Sanity: a clean run with no probe is also not Confirmed (and not
    // UnrelatedCrash either, since the process did not crash).
    let oracle = Oracle::SinkCrash {
        signals: SignalSet::all(),
    };
    assert!(!oracle_fired(&oracle, &clean_outcome(), &[]));
}

// ── (c) Bounded witness capture ─────────────────────────────────────────────

#[test]
fn case_c_witness_capture_is_bounded_and_scrubbed() {
    // Construct a witness from intentionally oversized + credential-tainted
    // inputs to lock the policy contract: payload truncated at 16 KiB and
    // denied env keys redacted.
    let huge_payload = vec![0x41u8; policy::PAYLOAD_CAPTURE_LIMIT_BYTES * 4];
    let env = vec![
        ("PATH".to_owned(), "/usr/bin".to_owned()),
        ("AWS_SECRET_ACCESS_KEY".to_owned(), "AKIAEXAMPLE".to_owned()),
        ("GITHUB_TOKEN".to_owned(), "ghs_fake".to_owned()),
        ("HOME".to_owned(), "/home/x".to_owned()),
    ];
    let witness = ProbeWitness::from_inputs(
        env,
        "/tmp/nyx-run-1",
        &huge_payload,
        "exec",
        vec!["arg0".to_owned(), "arg1".to_owned()],
    );

    assert_eq!(
        witness.payload_bytes.len(),
        policy::PAYLOAD_CAPTURE_LIMIT_BYTES,
        "payload must be truncated to the 16 KiB cap"
    );
    assert!(
        witness.payload_bytes.iter().all(|b| *b == 0x41),
        "head-truncation keeps prefix bytes"
    );

    // PATH / HOME unchanged.
    assert_eq!(
        witness.env_snapshot.get("PATH").map(String::as_str),
        Some("/usr/bin"),
    );
    assert_eq!(
        witness.env_snapshot.get("HOME").map(String::as_str),
        Some("/home/x"),
    );

    // Credential-shaped keys redacted.
    assert_eq!(
        witness
            .env_snapshot
            .get("AWS_SECRET_ACCESS_KEY")
            .map(String::as_str),
        Some(policy::REDACTED_VALUE),
    );
    assert_eq!(
        witness.env_snapshot.get("GITHUB_TOKEN").map(String::as_str),
        Some(policy::REDACTED_VALUE),
    );

    assert_eq!(witness.cwd, "/tmp/nyx-run-1");
    assert_eq!(witness.callee, "exec");
    assert_eq!(witness.args_repr, vec!["arg0".to_owned(), "arg1".to_owned()]);
}

#[test]
fn case_c_witness_round_trips_through_probe_channel() {
    // The witness must survive serde round-trip so downstream repro
    // tools see what the harness captured.
    let dir = TempDir::new().unwrap();
    let channel = ProbeChannel::for_workdir(dir.path()).unwrap();
    let witness = ProbeWitness::from_inputs(
        vec![
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            ("API_KEY".to_owned(), "live".to_owned()),
        ],
        "/tmp/run",
        b"; rm -rf /",
        "system",
        vec!["; rm -rf /".to_owned()],
    );
    let probe = SinkProbe {
        sink_callee: "system".into(),
        args: vec![ProbeArg::String("; rm -rf /".into())],
        captured_at_ns: 42,
        payload_id: "phase08-c".into(),
        kind: ProbeKind::Crash {
            signal: Signal::Sigabrt,
        },
        witness,
    };
    channel.write(&probe).unwrap();

    let drained = channel.drain();
    assert_eq!(drained.len(), 1);
    let p = &drained[0];
    assert!(matches!(
        p.kind,
        ProbeKind::Crash {
            signal: Signal::Sigabrt
        }
    ));
    assert_eq!(p.witness.cwd, "/tmp/run");
    assert_eq!(
        p.witness.env_snapshot.get("API_KEY").map(String::as_str),
        Some(policy::REDACTED_VALUE),
    );
    assert_eq!(
        p.witness.env_snapshot.get("PATH").map(String::as_str),
        Some("/usr/bin"),
    );
    assert_eq!(p.witness.payload_bytes, b"; rm -rf /".to_vec());
}

#[test]
fn signal_wire_format_accepts_canonical_and_short_aliases() {
    // The per-language shims write SIGSEGV / SIGABRT / etc. as the
    // signal value; downstream JSON consumers and the host-side oracle
    // both need to deserialise the same wire format.
    let canonical =
        serde_json::from_str::<Signal>("\"SIGSEGV\"").expect("canonical SIG name");
    assert_eq!(canonical, Signal::Sigsegv);
    let short = serde_json::from_str::<Signal>("\"SEGV\"").expect("short alias");
    assert_eq!(short, Signal::Sigsegv);
    let title =
        serde_json::from_str::<Signal>("\"Sigsegv\"").expect("derive-default alias");
    assert_eq!(title, Signal::Sigsegv);
}

#[test]
fn signal_set_const_construction_is_order_independent() {
    const A: SignalSet = SignalSet::from_slice(&[Signal::Sigsegv, Signal::Sigabrt]);
    const B: SignalSet = SignalSet::from_slice(&[Signal::Sigabrt, Signal::Sigsegv]);
    assert!(A.contains(Signal::Sigsegv));
    assert!(A.contains(Signal::Sigabrt));
    assert!(B.contains(Signal::Sigsegv));
    assert!(B.contains(Signal::Sigabrt));
    assert!(!A.contains(Signal::Sigfpe));
}

// ── End-to-end Phase 08 acceptance via compiled C harnesses ───────────────────
//
// These tests drive the full `run_spec` pipeline against the FMT_STRING
// curated payload + paired benign control, against two purpose-built
// fixtures under `tests/dynamic_fixtures/c/free_fn/`.  Both pin the
// install ordering inside the emitted `main.c`:
//
//   nyx_payload()                       <- harness setup
//   __nyx_install_crash_guard(callee)   <- install
//   run(payload, len)                   <- entry
//
// `setup_fault.c` aborts in a global constructor (before `main` runs),
// so the handler never installs and `Oracle::SinkCrash` cannot fire —
// the verifier downgrades to `Inconclusive(UnrelatedCrash)`.
//
// `sink_fault.c` prints the in-harness sink-hit sentinel and then
// NULL-dereferences on the vuln payload only.  The handler is installed
// by the time the deref happens, a Crash probe lands in `NYX_PROBE_PATH`,
// and the differential rule (§4.1) confirms because the benign payload
// short-circuits without crashing.

mod e2e_phase_08 {
    use crate::common::fixture_harness::FIXTURE_LOCK;
    use nyx_scanner::dynamic::runner::{run_spec, RunOutcome};
    use nyx_scanner::dynamic::sandbox::SandboxOptions;
    use nyx_scanner::dynamic::spec::{
        default_toolchain_id, EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy,
    };
    use nyx_scanner::labels::Cap;
    use nyx_scanner::symbol::Lang;
    use std::path::PathBuf;

    fn cc_available() -> bool {
        let bin = std::env::var("NYX_CC_BIN").unwrap_or_else(|_| "cc".to_owned());
        std::process::Command::new(&bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Stage `tests/dynamic_fixtures/c/free_fn/<file>` into a fresh
    /// tempdir and synthesise a [`HarnessSpec`] pointing at the copy.
    /// Returns the spec plus the tempdir guard (caller drops it after
    /// `run_spec` completes so the workdir survives the test).
    fn build_spec(file: &str) -> (HarnessSpec, tempfile::TempDir) {
        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/c/free_fn")
            .join(file);
        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let dst = tmp.path().join(file);
        std::fs::copy(&fixture_src, &dst).expect("copy fixture");

        let entry_file = dst.to_string_lossy().into_owned();
        let mut digest = blake3::Hasher::new();
        digest.update(b"phase08-c-e2e|");
        digest.update(file.as_bytes());
        let spec_hash = format!("{:016x}", {
            let bytes = digest.finalize();
            u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
        });

        let spec = HarnessSpec {
            finding_id: spec_hash.clone(),
            entry_file: entry_file.clone(),
            entry_name: "run".to_owned(),
            entry_kind: EntryKind::Function,
            lang: Lang::C,
            toolchain_id: default_toolchain_id(Lang::C).into(),
            payload_slot: PayloadSlot::Param(0),
            expected_cap: Cap::FMT_STRING,
            constraint_hints: vec![],
            sink_file: entry_file,
            sink_line: 22,
            spec_hash: spec_hash.clone(),
            derivation: SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
        };

        (spec, tmp)
    }

    fn run(file: &str) -> Option<RunOutcome> {
        if !cc_available() {
            eprintln!("SKIP {file}: cc not available");
            return None;
        }
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (spec, _tmp) = build_spec(file);
        let opts = SandboxOptions::default();
        match run_spec(&spec, &opts) {
            Ok(outcome) => Some(outcome),
            Err(e) => panic!("run_spec({file}) errored: {e:?}"),
        }
    }

    #[test]
    fn setup_fault_routes_to_unrelated_crash() {
        let Some(outcome) = run("setup_fault.c") else { return };
        assert!(
            outcome.triggered_by.is_none(),
            "setup_fault must not Confirm — handler is never installed: {outcome:?}",
        );
        assert!(
            outcome.unrelated_crash,
            "setup_fault must set unrelated_crash so verifier downgrades to Inconclusive(UnrelatedCrash): {outcome:?}",
        );
        let any_attempt_crashed = outcome
            .attempts
            .iter()
            .any(|a| a.outcome.exit_code.is_none() && !a.outcome.timed_out);
        assert!(
            any_attempt_crashed,
            "setup_fault constructor must abort the process at least once across attempts",
        );
    }

    #[test]
    fn sink_fault_confirms_via_sink_crash_probe() {
        let Some(outcome) = run("sink_fault.c") else { return };
        assert!(
            outcome.triggered_by.is_some(),
            "sink_fault must Confirm via SinkCrash + differential: {outcome:?}",
        );
        let label = outcome
            .triggered_by
            .and_then(|i| outcome.attempts.get(i))
            .map(|a| a.payload_label);
        assert_eq!(
            label,
            Some("fmt-string-percent-n-crash"),
            "triggering payload must be the FMT_STRING vuln entry"
        );
        assert!(
            !outcome.unrelated_crash,
            "sink_fault attempt should NOT set unrelated_crash — probe was written: {outcome:?}",
        );
    }
}
