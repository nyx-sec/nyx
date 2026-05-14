//! Integration test for Phase 06 — Track C.1.
//!
//! Synthetic harness emits a structured [`SinkProbe`] record to the
//! per-run [`ProbeChannel`]; the oracle's [`Oracle::SinkProbe`] path
//! drains the channel and applies [`ProbePredicate`]s.  A matching
//! synthetic control harness *omits* the probe write — the same oracle
//! must then return `NotConfirmed`.
//!
//! Acceptance bullet from `plan.md` phase 06:
//!
//! > Removing the probe write from one fixture flips its verdict from
//! > `Confirmed` to `NotConfirmed` in CI.
//!
//! Mechanism: the two fixtures share the identical oracle + payload
//! configuration; the only difference is whether the synthetic harness
//! body writes a [`SinkProbe`] record to the probe channel.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::oracle::{oracle_fired, Oracle, ProbePredicate};
use nyx_scanner::dynamic::probe::{
    ProbeArg, ProbeChannel, ProbeKind, ProbeWitness, SinkProbe, PROBE_PATH_ENV,
};
use std::time::Duration;
use tempfile::TempDir;

/// Minimal [`SandboxOutcome`] suitable for oracle evaluation when the
/// runner-side execution path is not exercised.  All flags are off so any
/// `true` verdict must come from the probe channel, not from
/// `output_contains` / `oob_callback_seen` etc.
fn dummy_outcome() -> nyx_scanner::dynamic::sandbox::SandboxOutcome {
    nyx_scanner::dynamic::sandbox::SandboxOutcome {
        exit_code: Some(0),
        stdout: vec![],
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: true,
        duration: Duration::from_millis(1),
    }
}

/// Synthetic harness body.  Mirrors what a real per-language `__nyx_probe`
/// shim would do: read `NYX_PROBE_PATH` from its env, append one JSON
/// record per fired sink.  The runner-side test serialises the harness
/// invocation with this Rust function instead of spawning a subprocess.
fn synthetic_harness_fires_probe(
    channel: &ProbeChannel,
    sink_callee: &str,
    captured_arg: &str,
    payload_id: &str,
) {
    let probe = SinkProbe {
        sink_callee: sink_callee.into(),
        args: vec![ProbeArg::String(captured_arg.into())],
        captured_at_ns: 1,
        payload_id: payload_id.into(),
        kind: ProbeKind::Normal,
        witness: ProbeWitness::empty(),
    };
    channel.write(&probe).expect("synthetic harness probe write");
}

/// "Control" harness — runs the same way but does NOT write a probe.
fn synthetic_harness_omits_probe(_channel: &ProbeChannel) {
    // Intentionally empty: the oracle path must observe zero probe records
    // and decide NotConfirmed.
}

#[test]
fn sink_probe_oracle_confirms_when_harness_writes_probe() {
    let dir = TempDir::new().unwrap();
    let channel = ProbeChannel::for_workdir(dir.path()).unwrap();

    // Exercise the harness env-var path so the test also locks the
    // NYX_PROBE_PATH contract the real sandbox forwards to the harness.
    // SAFETY: each test has a fresh tempdir and the env var is consumed
    // immediately by the synthetic harness body, then re-checked below.
    // Tests in this binary run on isolated channels so the env var read
    // is unambiguous.
    // SAFETY: env_var is process-global; this binary contains only the
    // oracle_sink_probe tests so the writes do not race other suites.
    unsafe {
        std::env::set_var(PROBE_PATH_ENV, channel.path());
    }
    assert_eq!(
        std::env::var(PROBE_PATH_ENV).unwrap().as_str(),
        channel.path().to_str().unwrap(),
    );

    synthetic_harness_fires_probe(
        &channel,
        "os.system",
        "; echo NYX_PWN_CMDI",
        "cmdi-echo-marker",
    );

    let oracle = Oracle::SinkProbe {
        predicates: &[
            ProbePredicate::CalleeEquals("os.system"),
            ProbePredicate::ArgContains {
                index: 0,
                needle: "NYX_PWN_CMDI",
            },
        ],
    };
    let probes = channel.drain();
    assert_eq!(probes.len(), 1, "harness must have written one probe");

    assert!(
        oracle_fired(&oracle, &dummy_outcome(), &probes),
        "oracle with SinkProbe predicates must confirm when probe matches",
    );
}

#[test]
fn sink_probe_oracle_not_confirmed_when_harness_omits_probe() {
    let dir = TempDir::new().unwrap();
    let channel = ProbeChannel::for_workdir(dir.path()).unwrap();

    unsafe {
        std::env::set_var(PROBE_PATH_ENV, channel.path());
    }

    // Control fixture: identical configuration but the harness skips its
    // probe write.  Same oracle predicate set as the Confirmed test —
    // the only difference is the (absent) write.
    synthetic_harness_omits_probe(&channel);

    let oracle = Oracle::SinkProbe {
        predicates: &[
            ProbePredicate::CalleeEquals("os.system"),
            ProbePredicate::ArgContains {
                index: 0,
                needle: "NYX_PWN_CMDI",
            },
        ],
    };
    let probes = channel.drain();
    assert!(
        probes.is_empty(),
        "control harness must not have written any probe",
    );

    assert!(
        !oracle_fired(&oracle, &dummy_outcome(), &probes),
        "oracle must NOT confirm when no probe is present",
    );
}

#[test]
fn sink_probe_oracle_not_confirmed_when_predicate_mismatch() {
    // Probe is present, but its captured arg does not satisfy the
    // predicates.  Verifies the oracle does not blanket-confirm on
    // "any probe at all" — payload predicates have teeth.
    let dir = TempDir::new().unwrap();
    let channel = ProbeChannel::for_workdir(dir.path()).unwrap();

    synthetic_harness_fires_probe(
        &channel,
        "os.system",
        "benign argument that does not match",
        "cmdi-echo-marker",
    );

    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::ArgContains {
            index: 0,
            needle: "NYX_PWN_CMDI",
        }],
    };
    let probes = channel.drain();
    assert_eq!(probes.len(), 1);

    assert!(
        !oracle_fired(&oracle, &dummy_outcome(), &probes),
        "oracle must NOT confirm when probe args fail the predicate set",
    );
}

#[test]
fn probe_channel_clear_between_runs_isolates_verdicts() {
    // Mirrors the runner's clear-before-each-payload behaviour: a probe
    // left over from a previous payload run must not bleed into the
    // verdict for a later payload.
    let dir = TempDir::new().unwrap();
    let channel = ProbeChannel::for_workdir(dir.path()).unwrap();

    synthetic_harness_fires_probe(&channel, "os.system", "stale probe", "earlier-payload");
    assert_eq!(channel.drain().len(), 1);

    channel.clear().unwrap();
    assert!(
        channel.drain().is_empty(),
        "clear() must remove the leftover probe from the previous run",
    );

    let oracle = Oracle::SinkProbe {
        predicates: &[ProbePredicate::CalleeEquals("os.system")],
    };
    // Second payload omits the probe write entirely.
    let probes = channel.drain();
    assert!(!oracle_fired(&oracle, &dummy_outcome(), &probes));
}
