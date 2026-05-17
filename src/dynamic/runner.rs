//! Orchestration: spec -> harness -> sandbox -> oracle -> verdict.
//!
//! The runner is the only place that knows about all four submodules at once.
//! Everything below it (corpus, harness, sandbox) is independent; everything
//! above it ([`crate::dynamic::verify`]) just calls [`run_spec`] and turns
//! the result into a [`crate::dynamic::report::VerifyResult`].

use crate::dynamic::build_sandbox;
use crate::dynamic::corpus::{
    materialise_bytes, payloads_for, payloads_for_lang, resolve_benign_control,
    resolve_benign_control_lang, Payload,
};
use crate::dynamic::differential;
use crate::dynamic::harness::{self, HarnessError};
use crate::dynamic::oracle::{oracle_fired_with_stubs, probe_crash_signal, Oracle};
use crate::dynamic::probe::{ProbeChannel, SinkProbe};
use crate::dynamic::stubs::StubEvent;
use crate::dynamic::sandbox::{self, SandboxBackend, SandboxError, SandboxOptions, SandboxOutcome};
use crate::dynamic::spec::HarnessSpec;
use crate::dynamic::trace::{TraceStage, VerifyTrace};
use crate::evidence::{DifferentialOutcome, DifferentialVerdict};
use crate::symbol::Lang;
use std::sync::Arc;

/// Record a trace event on the caller's [`VerifyTrace`] handle if one
/// was attached to [`SandboxOptions::trace`].  No-op otherwise — keeps
/// every direct `crate::dynamic::sandbox::run` caller (tests, parity
/// fixtures) free of trace boilerplate.
fn trace_record(trace: Option<&Arc<VerifyTrace>>, stage: TraceStage, detail: Option<String>) {
    if let Some(t) = trace {
        t.record(stage, detail);
    }
}

/// Short, stable variant tag used in [`TraceStage::SandboxStarted`]
/// details so a trace line names the oracle without dumping the full
/// `Debug` repr (which includes payload-specific `predicates` slices).
#[allow(deprecated)]
fn oracle_short_name(oracle: &Oracle) -> &'static str {
    match oracle {
        Oracle::SinkProbe { .. } => "SinkProbe",
        Oracle::SinkCrash { .. } => "SinkCrash",
        Oracle::OutputContains(_) => "OutputContains",
        Oracle::Crash => "Crash",
        Oracle::OobCallback { .. } => "OobCallback",
        Oracle::FileEscape => "FileEscape",
        Oracle::ExitStatus(_) => "ExitStatus",
        Oracle::StubEvent { .. } => "StubEvent",
    }
}

/// Max harness-build attempts before giving up.
const MAX_BUILD_ATTEMPTS: u32 = 2;

#[derive(Debug)]
pub struct RunOutcome {
    pub spec: HarnessSpec,
    pub attempts: Vec<Attempt>,
    /// First attempt that fired the sink with `oracle_fired && sink_hit`.
    pub triggered_by: Option<usize>,
    /// Whether the oracle fired but the sink probe did not (oracle collision).
    pub oracle_collision: bool,
    /// Number of build attempts consumed.
    pub build_attempts: u32,
    /// Harness sources for repro artifacts.
    pub harness_source: String,
    pub entry_source: String,
    /// Phase 07 differential-confirmation trace.  Carries the verdict +
    /// raw probe traces from both the vulnerable run and the paired
    /// benign-control run when one was executed.  `None` when no benign
    /// control was available (the runner sets [`Self::no_benign_control`]
    /// in that case) or when execution never reached the differential
    /// step.
    pub differential: Option<DifferentialOutcome>,
    /// `true` when a vuln payload tripped its oracle + sink-hit gate but
    /// the matching [`crate::dynamic::corpus::CuratedPayload::benign_control`]
    /// reference was `None` (or unresolved).  The verifier maps this to
    /// [`crate::evidence::InconclusiveReason::NoBenignControl`].
    pub no_benign_control: bool,
    /// Phase 08 §C.4: at least one payload's sandbox outcome reported a
    /// process-level crash (no exit code, no timeout) but no
    /// [`crate::dynamic::probe::ProbeKind::Crash`] record was drained
    /// from the channel.  The verifier maps this to
    /// [`crate::evidence::InconclusiveReason::UnrelatedCrash`] so a
    /// setup-code abort cannot impersonate a confirmed sink fire.
    pub unrelated_crash: bool,
}

#[derive(Debug)]
pub struct Attempt {
    pub payload_label: &'static str,
    pub outcome: SandboxOutcome,
    pub oracle_fired: bool,
    pub triggered: bool,
}

#[derive(Debug)]
pub enum RunError {
    NoPayloadsForCap,
    Harness(HarnessError),
    Sandbox(SandboxError),
    BuildFailed { stderr: String, attempts: u32 },
}

impl From<SandboxError> for RunError {
    fn from(e: SandboxError) -> Self {
        RunError::Sandbox(e)
    }
}

/// Build harness (with retry), run every payload, stop at first confirmed trigger.
///
/// "Confirmed trigger" = `oracle_fired && sink_hit` (§4.1).
///
/// If the oracle fires but the sink probe does not, sets `oracle_collision = true`
/// and continues (no `triggered_by` is set).
pub fn run_spec(spec: &HarnessSpec, opts: &SandboxOptions) -> Result<RunOutcome, RunError> {
    // Track J.0 deferred fix: prefer the lang-specific slice when
    // present so a payload registered for another language cannot leak
    // into the run.  Falls back to the lang-agnostic union shim only
    // when the per-language slice is empty, matching the pre-Phase-03
    // behaviour for caps that have not yet been carved by lang.  When
    // we use the union, benign-control resolution must also use the
    // union (otherwise we'd flip pre-existing fixtures to
    // `Inconclusive(NoBenignControl)`).
    let lang_slice = payloads_for_lang(spec.expected_cap, spec.lang);
    let used_lang_slice = !lang_slice.is_empty();
    let payloads = if used_lang_slice {
        lang_slice
    } else {
        payloads_for(spec.expected_cap)
    };
    if payloads.is_empty() {
        return Err(RunError::NoPayloadsForCap);
    }

    let trace_handle = opts.trace.as_ref().cloned();
    trace_record(
        trace_handle.as_ref(),
        TraceStage::BuildStarted,
        Some(format!("lang={:?} spec_hash={}", spec.lang, spec.spec_hash)),
    );

    // Build harness with retry.
    const BACKOFF: [u64; 1] = [1];
    let mut build_attempts = 0u32;
    let mut harness = loop {
        build_attempts += 1;
        match harness::build(spec) {
            Ok(h) => break h,
            Err(HarnessError::BuildFailed(msg)) if build_attempts < MAX_BUILD_ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_secs(
                    BACKOFF[(build_attempts as usize - 1).min(BACKOFF.len() - 1)],
                ));
                let _ = msg; // log would go here
            }
            Err(HarnessError::BuildFailed(msg)) => {
                return Err(RunError::BuildFailed {
                    stderr: msg,
                    attempts: build_attempts,
                });
            }
            Err(e) => return Err(RunError::Harness(e)),
        }
    };

    // Build-time isolation and dependency setup — dispatched by language.
    match spec.lang {
        Lang::Python => {
            // Prepare Python venv for dependency caching.
            // Errors propagate as RunError::BuildFailed or are swallowed for
            // non-fatal failures (Io / Unsupported), falling back to system python3.
            match build_sandbox::prepare_python(spec, &harness.workdir) {
                Ok(build_result) => {
                    if let Some(cmd0) = harness.command.first_mut() {
                        if cmd0 == "python3" || cmd0 == "python" {
                            let venv_python = build_result.venv_path.join("bin").join("python3");
                            if venv_python.exists() {
                                *cmd0 = venv_python.to_string_lossy().into_owned();
                            }
                        }
                    }
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(_) => {}
            }
        }
        Lang::Rust => {
            // Compile the harness binary with `cargo build --release`.
            match build_sandbox::prepare_rust(spec, &harness.workdir) {
                Ok(build_result) => {
                    // Update command to the compiled binary path.
                    let binary = build_result.venv_path.join("nyx_harness");
                    if binary.exists() {
                        harness.command = vec![binary.to_string_lossy().into_owned()];
                    } else {
                        // Fall back to binary inside the workdir.
                        let fallback = harness.workdir.join("target").join("release").join("nyx_harness");
                        if fallback.exists() {
                            harness.command = vec![fallback.to_string_lossy().into_owned()];
                        }
                    }
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed {
                        stderr,
                        attempts,
                    });
                }
                Err(_) => {
                    // Io: fall back to whatever command was set (will likely fail at exec).
                }
            }
        }
        Lang::JavaScript | Lang::TypeScript => {
            // npm install for dependency resolution (no deps in basic fixtures).
            match build_sandbox::prepare_node(spec, &harness.workdir) {
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                _ => {}
            }
        }
        Lang::Go => {
            // Compile the harness binary with `go build -o nyx_harness .`.
            match build_sandbox::prepare_go(spec, &harness.workdir) {
                Ok(build_result) => {
                    let binary = build_result.venv_path.join("nyx_harness");
                    if binary.exists() {
                        harness.command = vec![binary.to_string_lossy().into_owned()];
                    } else {
                        let fallback = harness.workdir.join("nyx_harness");
                        if fallback.exists() {
                            harness.command = vec![fallback.to_string_lossy().into_owned()];
                        }
                    }
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(_) => {}
            }
        }
        Lang::Java => {
            // Compile NyxHarness.java + Entry.java with javac.
            match build_sandbox::prepare_java(spec, &harness.workdir) {
                Ok(_) => {
                    // Update classpath to absolute workdir path for Docker compatibility.
                    harness.command = vec![
                        "java".to_owned(),
                        "-cp".to_owned(),
                        harness.workdir.to_string_lossy().into_owned(),
                        "NyxHarness".to_owned(),
                    ];
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(_) => {}
            }
        }
        Lang::Php => {
            // composer install if composer.json is present.
            match build_sandbox::prepare_php(spec, &harness.workdir) {
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                _ => {}
            }
        }
        Lang::C => {
            // Compile the harness binary with `cc -o nyx_harness main.c`.
            // Pass the sandbox profile so the build chooses `-static` when
            // the run will chroot into `harness.workdir` and the dynamic
            // loader would otherwise miss `/lib*`.
            match build_sandbox::prepare_c(spec, &harness.workdir, opts.process_hardening) {
                Ok(build_result) => {
                    let binary = build_result.venv_path.join("nyx_harness");
                    if binary.exists() {
                        harness.command = vec![binary.to_string_lossy().into_owned()];
                    } else {
                        let fallback = harness.workdir.join("nyx_harness");
                        if fallback.exists() {
                            harness.command = vec![fallback.to_string_lossy().into_owned()];
                        }
                    }
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(_) => {}
            }
        }
        Lang::Cpp => {
            // Compile the harness binary with `c++ -o nyx_harness main.cpp`.
            match build_sandbox::prepare_cpp(spec, &harness.workdir) {
                Ok(build_result) => {
                    let binary = build_result.venv_path.join("nyx_harness");
                    if binary.exists() {
                        harness.command = vec![binary.to_string_lossy().into_owned()];
                    } else {
                        let fallback = harness.workdir.join("nyx_harness");
                        if fallback.exists() {
                            harness.command = vec![fallback.to_string_lossy().into_owned()];
                        }
                    }
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(_) => {}
            }
        }
        _ => {
            // No build step for other languages.
        }
    }

    trace_record(
        trace_handle.as_ref(),
        TraceStage::BuildDone,
        Some(format!("attempts={build_attempts}")),
    );

    let harness_source = harness.source.clone();
    let entry_source = harness.entry_source.clone();

    // Provision a per-run [`ProbeChannel`] under the harness workdir when
    // the caller didn't pre-supply one (the public verifier path leaves
    // `probe_channel = None` so the runner owns lifetime).  Failure to
    // create the file is non-fatal: the legacy `Oracle::OutputContains`
    // oracle still works without a channel.
    let mut effective_opts = opts.clone();
    if effective_opts.probe_channel.is_none() {
        if let Ok(ch) = ProbeChannel::for_workdir(&harness.workdir) {
            effective_opts.probe_channel = Some(Arc::new(ch));
        }
    }
    let probe_channel: Option<Arc<ProbeChannel>> = effective_opts.probe_channel.clone();

    // Run only vuln (non-benign) payloads in the main loop.
    let vuln_payloads: Vec<&Payload> = payloads.iter().filter(|p| !p.is_benign).collect();

    let mut attempts = Vec::with_capacity(vuln_payloads.len());
    let mut triggered_by = None;
    let mut oracle_collision = false;
    let mut no_benign_control = false;
    let mut unrelated_crash = false;
    let mut differential_outcome: Option<DifferentialOutcome> = None;

    for (i, payload) in vuln_payloads.iter().enumerate() {
        // Materialise payload bytes (OOB nonce-slot payloads generate a URL).
        let (oob_nonce, effective_bytes) = if payload.oob_nonce_slot {
            if let Some(listener) = effective_opts.oob_listener() {
                let nonce = generate_nonce();
                let url = if uses_docker_backend(&effective_opts) {
                    listener.nonce_url_for_host("host-gateway", &nonce)
                } else {
                    listener.nonce_url(&nonce)
                };
                let bytes = url.into_bytes();
                (Some(nonce), bytes)
            } else {
                // No OOB listener configured — skip OOB payloads.
                continue;
            }
        } else {
            (None, payload.bytes.to_vec())
        };

        // Clear the probe channel before each payload so the oracle's
        // drained records belong unambiguously to this run.
        if let Some(ch) = &probe_channel {
            let _ = ch.clear();
        }

        trace_record(
            trace_handle.as_ref(),
            TraceStage::SandboxStarted,
            Some(format!(
                "attempt={i} payload={} oracle={}",
                payload.label,
                oracle_short_name(&payload.oracle)
            )),
        );

        let mut outcome = sandbox::run(&harness, &effective_bytes, &effective_opts)?;
        trace_record(
            trace_handle.as_ref(),
            TraceStage::OracleWait,
            Some(format!(
                "attempt={i} exit_code={:?} timed_out={}",
                outcome.exit_code, outcome.timed_out
            )),
        );

        // For OOB payloads, check the nonce listener and update the outcome flag.
        if let (Some(nonce), Some(listener)) = (&oob_nonce, effective_opts.oob_listener()) {
            // Poll until the nonce arrives or the budget expires. The sandbox run
            // already waited for process exit so the callback should arrive quickly;
            // 200 ms covers OS TCP delivery jitter without burning wall-clock at scale.
            if listener.wait_for_nonce(nonce, std::time::Duration::from_millis(200)) {
                outcome.oob_callback_seen = true;
            }
        }

        let vuln_probes: Vec<SinkProbe> = probe_channel
            .as_ref()
            .map(|ch| ch.drain())
            .unwrap_or_default();
        // Phase 10: drain boundary-stub events so the oracle can use
        // them (`Oracle::StubEvent`, `ProbePredicate::StubEventMatches`).
        let vuln_stub_events: Vec<StubEvent> = effective_opts
            .stub_harness
            .as_ref()
            .map(|h| h.drain_all())
            .unwrap_or_default();

        let vuln_fired = oracle_fired_with_stubs(
            &payload.oracle,
            &outcome,
            &vuln_probes,
            &vuln_stub_events,
        );
        let sink_hit = outcome.sink_hit;
        trace_record(
            trace_handle.as_ref(),
            TraceStage::OracleObserved,
            Some(format!(
                "attempt={i} fired={vuln_fired} sink_hit={sink_hit}"
            )),
        );

        // Phase 08 §C.4: a process-level crash with no matching sink-site
        // Crash probe is an "unrelated abort" (setup code, harness build,
        // library init).  Detect once per payload and surface via
        // `unrelated_crash` so the verifier downgrades from `Confirmed`
        // to `Inconclusive(UnrelatedCrash)`.  Only applies to
        // `Oracle::SinkCrash` payloads — other oracles handle crashes
        // through their own predicates.
        let process_crashed = outcome.exit_code.is_none() && !outcome.timed_out;
        let has_sink_crash_probe = vuln_probes.iter().any(|p| probe_crash_signal(p).is_some());
        if matches!(payload.oracle, Oracle::SinkCrash { .. })
            && process_crashed
            && !has_sink_crash_probe
        {
            unrelated_crash = true;
        }

        // Differential rule (Phase 07, §4.1).  Only when the vuln oracle
        // fired *and* the in-harness sink-hit sentinel was observed do we
        // consult the paired benign control.  Oracle-fires-without-sink
        // stays on the legacy `oracle_collision` path so the existing
        // `Inconclusive(OracleCollisionSuspected)` semantics survive.
        let triggered = if vuln_fired && sink_hit {
            // Match the resolution scope to the payload-slice scope so a
            // benign control declared in another language is still found
            // when this run was driven off the lang-agnostic union (see
            // `used_lang_slice` above).  When the run did use the
            // per-language slice, the lang-aware resolver keeps a
            // mismatched language from silently producing a Confirmed.
            let resolved = if used_lang_slice {
                resolve_benign_control_lang(payload, spec.expected_cap, spec.lang)
            } else {
                resolve_benign_control(payload, spec.expected_cap)
            };
            match resolved {
                None => {
                    no_benign_control = true;
                    false
                }
                Some(benign) => {
                    let benign_bytes = materialise_bytes(benign, None)
                        .map(|b| b.into_owned())
                        .unwrap_or_default();
                    if let Some(ch) = &probe_channel {
                        let _ = ch.clear();
                    }
                    let benign_outcome =
                        sandbox::run(&harness, &benign_bytes, &effective_opts)?;
                    let benign_probes: Vec<SinkProbe> = probe_channel
                        .as_ref()
                        .map(|ch| ch.drain())
                        .unwrap_or_default();
                    let benign_stub_events: Vec<StubEvent> = effective_opts
                        .stub_harness
                        .as_ref()
                        .map(|h| h.drain_all())
                        .unwrap_or_default();
                    let benign_fired = oracle_fired_with_stubs(
                        &benign.oracle,
                        &benign_outcome,
                        &benign_probes,
                        &benign_stub_events,
                    );
                    let outcome_record = differential::build_outcome(
                        payload.label,
                        vuln_fired,
                        &vuln_probes,
                        benign.label,
                        benign_fired,
                        &benign_probes,
                    );
                    let confirmed = outcome_record.verdict == DifferentialVerdict::Confirmed;
                    differential_outcome = Some(outcome_record);
                    confirmed
                }
            }
        } else if vuln_fired && !sink_hit {
            // Oracle fired but probe didn't — likely collision.
            oracle_collision = true;
            false
        } else {
            false
        };

        attempts.push(Attempt {
            payload_label: payload.label,
            outcome,
            oracle_fired: vuln_fired,
            triggered,
        });

        if triggered {
            triggered_by = Some(i);
            break;
        }
    }

    Ok(RunOutcome {
        spec: spec.clone(),
        attempts,
        triggered_by,
        oracle_collision,
        build_attempts,
        harness_source,
        entry_source,
        differential: differential_outcome,
        no_benign_control,
        unrelated_crash,
    })
}

/// Returns true when the active backend will use Docker for execution.
///
/// Used at URL-generation time so Docker runs embed `host-gateway` rather than
/// `127.0.0.1` (the container's loopback ≠ the host's loopback).
fn uses_docker_backend(opts: &SandboxOptions) -> bool {
    match opts.backend {
        SandboxBackend::Docker => true,
        SandboxBackend::Auto => sandbox::docker_available(),
        SandboxBackend::Process | SandboxBackend::Firecracker => false,
    }
}


/// Generate a random 16-character hex nonce for OOB callback tracking.
fn generate_nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Simple pseudo-random nonce: mix timestamp, thread ID, and a counter.
    // Good enough for deduplication; not cryptographically secure.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let cnt = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mixed = ts.wrapping_mul(0x517cc1b727220a95).wrapping_add(cnt);
    format!("{mixed:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_nonce_is_16_hex_chars() {
        let n = generate_nonce();
        assert_eq!(n.len(), 16);
        assert!(n.chars().all(|c| c.is_ascii_hexdigit()), "nonce must be hex: {n}");
    }

    #[test]
    fn generate_nonce_unique_per_call() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2, "consecutive nonces must differ");
    }
}
