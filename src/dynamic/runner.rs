//! Orchestration: spec -> harness -> sandbox -> oracle -> verdict.
//!
//! The runner is the only place that knows about all four submodules at once.
//! Everything below it (corpus, harness, sandbox) is independent; everything
//! above it ([`crate::dynamic::verify`]) just calls [`run_spec`] and turns
//! the result into a [`crate::dynamic::report::VerifyResult`].

use crate::dynamic::build_sandbox;
use crate::dynamic::corpus::{
    Payload, materialise_bytes, payloads_for, payloads_for_lang, resolve_benign_control,
    resolve_benign_control_lang,
};
use crate::dynamic::differential;
use crate::dynamic::harness::{self, HarnessError};
use crate::dynamic::middleware_demotion;
use crate::dynamic::oracle::{Canary, Oracle, oracle_fired_full, probe_crash_signal};
use crate::dynamic::probe::{ProbeChannel, SinkProbe};
use crate::dynamic::sandbox::{self, SandboxBackend, SandboxError, SandboxOptions, SandboxOutcome};
use crate::dynamic::spec::HarnessSpec;
use crate::dynamic::stubs::StubEvent;
use crate::dynamic::trace::{TraceStage, VerifyTrace};
use crate::evidence::{DifferentialOutcome, DifferentialVerdict};
use crate::labels::Cap;
use crate::symbol::Lang;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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

fn stage_native_harness_command(
    harness: &mut harness::BuiltHarness,
    build_root: &Path,
    fallback: PathBuf,
) {
    let cached = build_root.join("nyx_harness");
    let source = if cached.exists() {
        cached
    } else if fallback.exists() {
        fallback
    } else {
        return;
    };
    let run_path = harness.workdir.join("nyx_harness");
    if source != run_path {
        if let Some(parent) = run_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::copy(&source, &run_path).is_ok() {
            make_executable(&run_path);
            harness.command = vec![run_path.to_string_lossy().into_owned()];
            return;
        }
    }
    harness.command = vec![source.to_string_lossy().into_owned()];
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o700);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

#[derive(Debug)]
pub struct RunOutcome {
    pub spec: HarnessSpec,
    pub attempts: Vec<Attempt>,
    /// Index into [`Self::attempts`] of the attempt the confirm verdict is
    /// attributed to.  Set by the Phase 26 set aggregation when
    /// [`crate::dynamic::differential::evaluate_sets`] returns a
    /// Confirmed-class verdict (any vuln payload fired the oracle + sink
    /// while every paired benign control stayed clean), or when an
    /// OOB-nonce payload self-confirmed.  `None` otherwise.
    pub triggered_by: Option<usize>,
    /// Whether the oracle fired but the sink probe did not (oracle collision).
    pub oracle_collision: bool,
    /// Phase 26: a vuln payload's in-harness sink-reachability probe fired
    /// (`outcome.sink_hit`) but its oracle marker was never observed (no file
    /// write / no OOB callback / output lacked the proof token), *and* the
    /// paired benign control neither reached the sink nor fired its oracle.
    /// The benign-control differential is the discriminator: it proves the
    /// vuln input specifically drives the sink, ruling out safe code that
    /// merely reaches the sink (e.g. array-form `exec` with inert
    /// metacharacters, which the benign control also reaches).  The verifier
    /// maps this to [`crate::evidence::VerifyStatus::PartiallyConfirmed`]: the
    /// sink is reachable under the vuln input but the exploit chain did not
    /// complete.  Never set when a Confirmed-class verdict or a colliding
    /// differential was produced (those take precedence at the verify
    /// boundary).
    pub sink_reached_no_oracle: bool,
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
    /// Phase 11 (Track J.9): the requested cap is in the structural
    /// "no sound oracle" set
    /// ([`crate::dynamic::corpus::registry::CORPUS_SOUND_ORACLE_UNAVAILABLE`]).
    /// Surfaces as
    /// [`crate::evidence::UnsupportedReason::SoundOracleUnavailable`]
    /// at the verify boundary so unsupported-budget accounting
    /// distinguishes "no oracle exists" from "no payloads carved
    /// yet".
    SoundOracleUnavailable {
        cap: crate::labels::Cap,
        lang: Lang,
        hint: String,
    },
    Harness(HarnessError),
    Sandbox(SandboxError),
    BuildFailed {
        stderr: String,
        attempts: u32,
    },
}

struct HarnessWorkdirCleanup {
    path: PathBuf,
}

impl HarnessWorkdirCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for HarnessWorkdirCleanup {
    fn drop(&mut self) {
        if std::env::var_os("NYX_KEEP_HARNESS").is_some() {
            return;
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl From<SandboxError> for RunError {
    fn from(e: SandboxError) -> Self {
        RunError::Sandbox(e)
    }
}

/// Detect the conventional harness import-error signal: exit code 77 plus
/// the `NYX_IMPORT_ERROR:` marker on stderr.  Per-lang harness preambles in
/// `src/dynamic/lang/{js_shared,ruby,php}.rs` emit this when the fixture's
/// top-level `require` / `import` / `use` fails at runtime (missing npm,
/// gem, or composer dep; unparseable syntax).  Treated as a build failure
/// upstream so the SKIP-on-`BuildFailed` branch in e2e corpus tests catches
/// missing host deps instead of failing the assertion.
fn is_runtime_import_error(outcome: &sandbox::SandboxOutcome) -> bool {
    if outcome.exit_code != Some(77) {
        return false;
    }
    let needle = b"NYX_IMPORT_ERROR:";
    outcome.stderr.windows(needle.len()).any(|w| w == needle)
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
        // Phase 11 (Track J.9): route caps with no sound oracle to a
        // distinct error so the unsupported budget reflects
        // structural impossibility rather than a missing payload.
        if (spec.expected_cap.bits()
            & crate::dynamic::corpus::registry::CORPUS_SOUND_ORACLE_UNAVAILABLE)
            != 0
        {
            return Err(RunError::SoundOracleUnavailable {
                cap: spec.expected_cap,
                lang: spec.lang,
                hint: crate::dynamic::corpus::registry::sound_oracle_unavailable_hint(
                    spec.expected_cap,
                )
                .to_owned(),
            });
        }
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
    let _harness_workdir_cleanup = HarnessWorkdirCleanup::new(harness.workdir.clone());

    // Build-time isolation and dependency setup — dispatched by language.
    match spec.lang {
        Lang::Python => {
            // Prepare Python venv for dependency caching.
            // Errors propagate as RunError::BuildFailed or are swallowed for
            // non-fatal failures (Io / Unsupported), falling back to system python3.
            match build_sandbox::prepare_python(spec, &harness.workdir) {
                Ok(build_result) => {
                    if let Some(cmd0) = harness.command.first_mut()
                        && (cmd0 == "python3" || cmd0 == "python")
                    {
                        let venv_python = build_result.venv_path.join("bin").join("python3");
                        if venv_python.exists() {
                            *cmd0 = venv_python.to_string_lossy().into_owned();
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
                    let fallback = harness
                        .workdir
                        .join("target")
                        .join("release")
                        .join("nyx_harness");
                    stage_native_harness_command(&mut harness, &build_result.venv_path, fallback);
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(build_sandbox::BuildError::Io(e)) => {
                    return Err(RunError::BuildFailed {
                        stderr: format!("prepare rust build cache: {e}"),
                        attempts: 1,
                    });
                }
                Err(build_sandbox::BuildError::Unsupported) => {
                    return Err(RunError::BuildFailed {
                        stderr: "rust build preparation unsupported on this host".to_owned(),
                        attempts: 1,
                    });
                }
            }
        }
        Lang::JavaScript | Lang::TypeScript => {
            // npm install for dependency resolution (no deps in basic fixtures).
            if let Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) =
                build_sandbox::prepare_node(spec, &harness.workdir)
            {
                return Err(RunError::BuildFailed { stderr, attempts });
            }
        }
        Lang::Go => {
            // Compile the harness binary with `go build -o nyx_harness .`.
            match build_sandbox::prepare_go(spec, &harness.workdir) {
                Ok(build_result) => {
                    let fallback = harness.workdir.join("nyx_harness");
                    stage_native_harness_command(&mut harness, &build_result.venv_path, fallback);
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(build_sandbox::BuildError::Io(e)) => {
                    return Err(RunError::BuildFailed {
                        stderr: format!("prepare go build cache: {e}"),
                        attempts: 1,
                    });
                }
                Err(build_sandbox::BuildError::Unsupported) => {
                    return Err(RunError::BuildFailed {
                        stderr: "go build preparation unsupported on this host".to_owned(),
                        attempts: 1,
                    });
                }
            }
        }
        Lang::Java => {
            // Compile NyxHarness.java + Entry.java with javac.
            match build_sandbox::prepare_java(spec, &harness.workdir) {
                Ok(_) => {
                    // Update classpath to absolute workdir paths for Docker
                    // compatibility. Include Maven-staged jars too; framework
                    // harnesses compile with `lib/*` and need the same jars at
                    // runtime.
                    let workdir_cp = harness.workdir.to_string_lossy();
                    let lib_cp = harness.workdir.join("lib/*");
                    let cp = format!("{workdir_cp}:{}", lib_cp.to_string_lossy());
                    harness.command = vec![
                        "java".to_owned(),
                        // Bound the JVM's virtual-address footprint so it fits
                        // inside the sandbox RLIMIT_AS cap (the Linux process
                        // backend floors it at 4 GiB).  A default-ergonomics
                        // JVM on a high-RAM CI runner pre-reserves a heap sized
                        // to ~25% of host RAM plus a 1 GiB compressed-class
                        // space and a 240 MiB code cache, which lands right at
                        // the 4 GiB ceiling — leaving no headroom for the
                        // `fork`/`posix_spawn` a command-injection sink performs
                        // via `ProcessBuilder.start()`, so the spawn aborts with
                        // "Native memory allocation (malloc) failed to allocate
                        // N bytes".  These caps hold the whole reservation under
                        // ~700 MiB regardless of host RAM; a short-lived harness
                        // never needs more, and a responsive heap stays well
                        // clear of the cap so the spawn always succeeds.
                        "-XX:+UseSerialGC".to_owned(),
                        "-Xmx256m".to_owned(),
                        "-XX:CompressedClassSpaceSize=128m".to_owned(),
                        "-XX:ReservedCodeCacheSize=64m".to_owned(),
                        "-cp".to_owned(),
                        cp,
                        "NyxHarness".to_owned(),
                    ];
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(build_sandbox::BuildError::Io(e)) => {
                    return Err(RunError::BuildFailed {
                        stderr: format!("prepare java build cache: {e}"),
                        attempts: 1,
                    });
                }
                Err(build_sandbox::BuildError::Unsupported) => {
                    return Err(RunError::BuildFailed {
                        stderr: "java build preparation unsupported on this host".to_owned(),
                        attempts: 1,
                    });
                }
            }
        }
        Lang::Php => {
            // composer install if composer.json is present.
            if let Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) =
                build_sandbox::prepare_php(spec, &harness.workdir)
            {
                return Err(RunError::BuildFailed { stderr, attempts });
            }
        }
        Lang::Ruby => {
            // bundle install if Gemfile is present.
            match build_sandbox::prepare_ruby(spec, &harness.workdir) {
                Ok(_) => {}
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(build_sandbox::BuildError::Io(e)) => {
                    return Err(RunError::BuildFailed {
                        stderr: format!("prepare ruby build cache: {e}"),
                        attempts: 1,
                    });
                }
                Err(build_sandbox::BuildError::Unsupported) => {
                    return Err(RunError::BuildFailed {
                        stderr: "ruby build preparation unsupported on this host".to_owned(),
                        attempts: 1,
                    });
                }
            }
        }
        Lang::C => {
            // Compile the harness binary with `cc -o nyx_harness main.c`.
            // Pass the sandbox profile so the build chooses `-static` when
            // the run will chroot into `harness.workdir` and the dynamic
            // loader would otherwise miss `/lib*`.
            match build_sandbox::prepare_c(spec, &harness.workdir, opts.process_hardening) {
                Ok(build_result) => {
                    let fallback = harness.workdir.join("nyx_harness");
                    stage_native_harness_command(&mut harness, &build_result.venv_path, fallback);
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
                    let fallback = harness.workdir.join("nyx_harness");
                    stage_native_harness_command(&mut harness, &build_result.venv_path, fallback);
                }
                Err(build_sandbox::BuildError::BuildFailed { stderr, attempts }) => {
                    return Err(RunError::BuildFailed { stderr, attempts });
                }
                Err(_) => {}
            }
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
    if effective_opts.probe_channel.is_none()
        && let Ok(ch) = ProbeChannel::for_workdir(&harness.workdir)
    {
        effective_opts.probe_channel = Some(Arc::new(ch));
    }
    let probe_channel: Option<Arc<ProbeChannel>> = effective_opts.probe_channel.clone();

    // ── Phase 30 (Track N.0): per-spec verification canary ──────────────
    // Derive a cryptographically-random, per-`spec_hash` canary, hand it to
    // the harness via `NYX_CANARY` (the prototype-pollution setter trap and
    // any future per-spec sentinel read it from the environment), and thread
    // it into the oracle match below.  Each payload's bytes have the const
    // corpus's `Canary::PLACEHOLDER` token rewritten to this value, so the
    // harness trap, the polluted property name, and the oracle all agree on
    // a token unique to this finding — a stale probe from another run (or
    // ambient output mentioning the historical `__nyx_canary` sentinel) can
    // never satisfy this run's oracle.
    let run_canary = Canary::for_spec(&spec.spec_hash);
    effective_opts
        .extra_env
        .push(("NYX_CANARY".to_string(), run_canary.clone()));

    // Run only vuln (non-benign) payloads in the main loop.
    let vuln_payloads: Vec<&Payload> = payloads.iter().filter(|p| !p.is_benign).collect();

    let mut attempts = Vec::with_capacity(vuln_payloads.len());
    let mut triggered_by = None;
    let mut oracle_collision = false;
    let mut no_benign_control = false;
    let mut unrelated_crash = false;
    let mut differential_outcome: Option<DifferentialOutcome> = None;

    // Phase 26 set aggregation, phase A: per-vuln-payload run record.
    // Every vuln payload runs to completion (no early break) so the
    // differential rule can aggregate across the whole set — a single
    // benign control firing anywhere must be able to veto a `Confirmed`.
    struct VulnRun {
        /// Index into `vuln_payloads` (for benign-control resolution).
        payload_index: usize,
        /// Index into `attempts` (what `triggered_by` points at).
        attempt_index: usize,
        vuln_fired: bool,
        sink_hit: bool,
        oob_nonce_slot: bool,
        oob_callback_seen: bool,
        /// The harness reached only its SYNTHETIC fallback sink — the real
        /// guarded entry could not be driven (e.g. a top-level `$_GET` PHP
        /// script with no named entry fn, or a JS fixture whose response
        /// import failed), so the fixture's own guards never executed. Such a
        /// run must not terminally Confirm (that would claim exploitation of
        /// code whose guard was bypassed — the DVWA impossible.php /
        /// juiceshop prototype_pollution over-confirm class); it is routed to
        /// partial confirmation instead. Set when the harness emitted the
        /// `__NYX_SYNTHETIC_FALLBACK__` marker (PHP / JS synthetic branches).
        synthetic_fallback: bool,
        vuln_probes: Vec<SinkProbe>,
    }
    let mut vuln_runs: Vec<VulnRun> = Vec::with_capacity(vuln_payloads.len());

    // ── Phase A: run every vuln payload, record its firing signals ──────
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
        // Phase 30: rewrite the corpus canary placeholder to this run's
        // per-spec canary so the harness trap + oracle agree on it.
        let effective_bytes = substitute_canary_bytes(effective_bytes, &run_canary);

        // Clear the probe channel before each payload so the oracle's
        // drained records belong unambiguously to this run.
        if let Some(ch) = &probe_channel {
            let _ = ch.clear();
        }

        let attempt_index = attempts.len();
        trace_record(
            trace_handle.as_ref(),
            TraceStage::SandboxStarted,
            Some(format!(
                "attempt={attempt_index} payload={} oracle={}",
                payload.label,
                oracle_short_name(&payload.oracle)
            )),
        );

        let mut outcome = sandbox::run(&harness, &effective_bytes, &effective_opts)?;
        trace_record(
            trace_handle.as_ref(),
            TraceStage::OracleWait,
            Some(format!(
                "attempt={attempt_index} exit_code={:?} timed_out={}",
                outcome.exit_code, outcome.timed_out
            )),
        );

        // Harness runtime-load failure: the per-lang preamble at
        // `src/dynamic/lang/{js_shared,ruby,php}.rs` writes the marker
        // `NYX_IMPORT_ERROR:` to stderr and `exit(77)` when the fixture's
        // top-level imports fail (missing npm / gem / composer dep, syntax
        // the runtime can't parse, etc.).  Semantically this is a build
        // failure — the harness "linked" against deps that don't resolve at
        // run time — so route through `RunError::BuildFailed` to keep the
        // SKIP-on-BuildFailed branch in the e2e corpus tests honest.  Only
        // checked on the first actually-run payload because the missing dep
        // won't appear later in the run.
        if attempts.is_empty() && is_runtime_import_error(&outcome) {
            return Err(RunError::BuildFailed {
                stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
                attempts: build_attempts,
            });
        }

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

        let vuln_fired = oracle_fired_full(
            &payload.oracle,
            &outcome,
            &vuln_probes,
            &vuln_stub_events,
            Some(&run_canary),
        );
        let sink_hit = outcome.sink_hit;
        const SYNTHETIC_FALLBACK_SENTINEL: &[u8] = b"__NYX_SYNTHETIC_FALLBACK__";
        let synthetic_fallback = outcome
            .stdout
            .windows(SYNTHETIC_FALLBACK_SENTINEL.len())
            .any(|w| w == SYNTHETIC_FALLBACK_SENTINEL)
            || outcome
                .stderr
                .windows(SYNTHETIC_FALLBACK_SENTINEL.len())
                .any(|w| w == SYNTHETIC_FALLBACK_SENTINEL);
        trace_record(
            trace_handle.as_ref(),
            TraceStage::OracleObserved,
            Some(format!(
                "attempt={attempt_index} fired={vuln_fired} sink_hit={sink_hit} synthetic={synthetic_fallback}"
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

        // Legacy single-payload collision: oracle fired without the
        // in-harness sink-hit sentinel.  Phase 26 partial-confirmation is
        // deliberately NOT decided here: a vuln run that reaches the sink
        // without firing its oracle is ambiguous — it could be a real engine
        // gap (the vuln input drives the sink but the exploit chain could not
        // be observed) or merely safe code that happens to reach the sink
        // (e.g. array-form `exec` with inert metacharacters).  The call is
        // deferred to the differential check in Phase B, which compares the
        // benign control's sink reachability.
        if vuln_fired && !sink_hit {
            oracle_collision = true;
        }

        let oob_callback_seen = outcome.oob_callback_seen;
        attempts.push(Attempt {
            payload_label: payload.label,
            outcome,
            oracle_fired: vuln_fired,
            triggered: false,
        });
        vuln_runs.push(VulnRun {
            payload_index: i,
            attempt_index,
            vuln_fired,
            sink_hit,
            oob_nonce_slot: payload.oob_nonce_slot,
            oob_callback_seen,
            synthetic_fallback,
            vuln_probes,
        });
    }

    // ── Phase B: differential confirmation + partial-confirmation gate ──
    // Two candidate classes drive a paired benign-control run:
    //   • confirm candidate — vuln oracle fired *and* the in-harness sink-hit
    //     sentinel was observed.  Collected into the set aggregation (§4.1).
    //   • partial candidate — the sink-hit sentinel fired but the oracle did
    //     not.  The benign control's sink reachability decides whether this is
    //     a real engine gap (`PartiallyConfirmed`) or safe code that merely
    //     reaches the sink (`NotConfirmed`).
    // Oracle-fires-without-sink stays on the legacy `oracle_collision` path.
    let mut vuln_fires: Vec<bool> = Vec::new();
    let mut benign_fires: Vec<bool> = Vec::new();
    // (attempt_index, differential outcome) per confirm candidate.
    let mut candidates: Vec<(usize, DifferentialOutcome)> = Vec::new();
    // Phase 26: set when a partial candidate's vuln run reached the sink that
    // its benign control did *not* — a sink-reachability differential proving
    // the vuln input specifically drives the sink even though the exploit
    // chain could not be observed completing.
    let mut partial_signal = false;

    for vr in &vuln_runs {
        // Synthetic-fallback runs reached only the harness's synthetic sink —
        // the fixture's real guarded entry never executed — so the attacker
        // payload "reaching the sink" proves nothing about the guarded code.
        // Reaching the synthetic sink is at most a partial confirmation
        // (sink-reachable, exploit unproven). Routing it here (instead of the
        // confirm / OOB-self-confirm paths below) yields PartiallyConfirmed
        // rather than a false Confirmed, closing the guard-bypass over-confirm
        // class (DVWA header_injection/open_redirect on top-level $_GET
        // scripts; juiceshop prototype_pollution) without claiming the finding
        // is benign.
        if vr.synthetic_fallback && vr.sink_hit {
            partial_signal = true;
            continue;
        }
        let is_confirm_candidate = vr.vuln_fired && vr.sink_hit;
        let is_partial_candidate = vr.sink_hit && !vr.vuln_fired;
        if !is_confirm_candidate && !is_partial_candidate {
            continue;
        }
        // The partial signal is a single bool; once established, skip further
        // partial-only probing.  Confirm candidates always run — the set
        // aggregation needs every one.
        if is_partial_candidate && !is_confirm_candidate && partial_signal {
            continue;
        }
        let payload = vuln_payloads[vr.payload_index];
        // Match the resolution scope to the payload-slice scope so a benign
        // control declared in another language is still found when this run
        // was driven off the lang-agnostic union (see `used_lang_slice`).
        // When the run did use the per-language slice, the lang-aware
        // resolver keeps a mismatched language from producing a Confirmed.
        let resolved = if used_lang_slice {
            resolve_benign_control_lang(payload, spec.expected_cap, spec.lang)
        } else {
            resolve_benign_control(payload, spec.expected_cap)
        };
        match resolved {
            None => {
                // Phase 05 OOB closure: OOB-nonce payloads with
                // `benign_control = None` are structurally self-confirming
                // when the listener observed the callback.  A benign URL
                // cannot hit a per-finding nonce, so the OOB observation is
                // independent network-level evidence the sink fired.  Skip
                // the no-benign-control downgrade and emit
                // [`DifferentialVerdict::ConfirmedProvenOob`].
                if is_confirm_candidate && vr.oob_nonce_slot && vr.oob_callback_seen {
                    let mut outcome_record = differential::build_oob_self_confirmed_outcome(
                        payload.label,
                        &vr.vuln_probes,
                    );
                    middleware_demotion::apply_demotion(
                        &mut outcome_record,
                        spec.framework.as_ref(),
                        spec.lang,
                    );
                    // No paired benign control runs, so this candidate
                    // contributes only to the vuln side of the set.
                    vuln_fires.push(true);
                    candidates.push((vr.attempt_index, outcome_record));
                } else if is_confirm_candidate {
                    no_benign_control = true;
                }
                // A partial candidate without a benign control cannot rule out
                // "safe code that reaches the sink", so it raises no partial
                // signal and falls through to `NotConfirmed`.
            }
            Some(benign) => {
                let benign_bytes = substitute_canary_bytes(
                    materialise_bytes(benign, None)
                        .map(|b| b.into_owned())
                        .unwrap_or_default(),
                    &run_canary,
                );
                if let Some(ch) = &probe_channel {
                    let _ = ch.clear();
                }
                let benign_outcome = sandbox::run(&harness, &benign_bytes, &effective_opts)?;
                let benign_sink_hit = benign_outcome.sink_hit;
                let benign_probes: Vec<SinkProbe> = probe_channel
                    .as_ref()
                    .map(|ch| ch.drain())
                    .unwrap_or_default();
                let benign_stub_events: Vec<StubEvent> = effective_opts
                    .stub_harness
                    .as_ref()
                    .map(|h| h.drain_all())
                    .unwrap_or_default();
                let benign_fired = oracle_fired_full(
                    &benign.oracle,
                    &benign_outcome,
                    &benign_probes,
                    &benign_stub_events,
                    Some(&run_canary),
                );

                if is_confirm_candidate {
                    let mut outcome_record = differential::build_outcome(
                        payload.label,
                        vr.vuln_fired,
                        &vr.vuln_probes,
                        benign.label,
                        benign_fired,
                        &benign_probes,
                    );
                    // Phase 05 OOB closure: when an OOB-nonce payload also
                    // carries a paired benign control, promote `Confirmed` →
                    // `ConfirmedProvenOob` whenever the listener observed the
                    // per-finding nonce.  The upgrade preserves the differential
                    // trace (benign run still recorded) and surfaces the
                    // stronger network-level evidence to operators.
                    if outcome_record.verdict == DifferentialVerdict::Confirmed
                        && vr.oob_nonce_slot
                        && vr.oob_callback_seen
                    {
                        outcome_record.verdict = DifferentialVerdict::ConfirmedProvenOob;
                    }
                    middleware_demotion::apply_demotion(
                        &mut outcome_record,
                        spec.framework.as_ref(),
                        spec.lang,
                    );
                    vuln_fires.push(vr.vuln_fired);
                    benign_fires.push(benign_fired);
                    candidates.push((vr.attempt_index, outcome_record));
                } else {
                    // Partial candidate: the vuln run reached the sink without
                    // firing the oracle.  It is a real engine gap only when the
                    // benign control neither reached the sink nor fired its
                    // oracle — i.e. the vuln input specifically drives the sink.
                    // If the benign control also reaches the sink, the code path
                    // is shared and safe (e.g. array-form `exec`), so no partial
                    // signal is raised and the run stays `NotConfirmed`.
                    if !benign_sink_hit && !benign_fired {
                        partial_signal = true;
                    }
                }
            }
        }
    }

    // ── Phase 26 aggregation ────────────────────────────────────────────
    // `evaluate_sets` collapses the firing sets to a single verdict: any
    // vuln payload firing + no benign control firing → Confirmed; any
    // benign firing anywhere → OracleCollisionSuspected (global ambient-
    // noise veto).  A ConfirmedProvenOob candidate is terminal positive
    // evidence (a per-finding OOB nonce cannot be hit by ambient noise), so
    // it confirms even if some unrelated payload's benign tripped a noisy
    // oracle.
    if !candidates.is_empty() {
        let aggregate = differential::evaluate_sets(&vuln_fires, &benign_fires);
        let has_proven_oob = candidates
            .iter()
            .any(|(_, r)| r.verdict == DifferentialVerdict::ConfirmedProvenOob);
        let confirmed_class = has_proven_oob || matches!(aggregate, DifferentialVerdict::Confirmed);
        if confirmed_class {
            // Representative outcome: prefer the strongest (ProvenOob), else
            // the first candidate carrying a triggering verdict.  Iteration
            // follows payload order, so the choice is deterministic.
            let chosen = candidates
                .iter()
                .find(|(_, r)| r.verdict == DifferentialVerdict::ConfirmedProvenOob)
                .or_else(|| {
                    candidates
                        .iter()
                        .find(|(_, r)| middleware_demotion::is_triggering_verdict(r.verdict))
                })
                .cloned();
            if let Some((idx, record)) = chosen {
                attempts[idx].triggered = true;
                triggered_by = Some(idx);
                differential_outcome = Some(record);
            }
        } else {
            // Ambient-noise veto: at least one benign control fired and no
            // terminal OOB evidence exists.  Surface a colliding candidate
            // so the verifier downgrades to
            // `Inconclusive(OracleCollisionSuspected)`.
            differential_outcome = candidates
                .iter()
                .find(|(_, r)| r.verdict == DifferentialVerdict::OracleCollisionSuspected)
                .or_else(|| candidates.first())
                .map(|(_, r)| r.clone());
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
        sink_reached_no_oracle: partial_signal,
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

/// Rewrite every occurrence of [`Canary::PLACEHOLDER`] in `bytes` to the
/// per-spec `canary` (Phase 30 — Track N.0).
///
/// Const corpus payloads embed the placeholder token; the runner swaps in
/// the finding's per-spec canary before the harness runs so the polluted
/// property name matches the trap the harness installed from `NYX_CANARY`
/// and the oracle's per-spec match.  A cheap no-op for the vast majority of
/// payloads — those that never mention the placeholder return their input
/// buffer unchanged without reallocating.
fn substitute_canary_bytes(bytes: Vec<u8>, canary: &str) -> Vec<u8> {
    let needle = Canary::PLACEHOLDER.as_bytes();
    if needle.is_empty()
        || needle.len() > bytes.len()
        || !bytes.windows(needle.len()).any(|w| w == needle)
    {
        return bytes;
    }
    let repl = canary.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(needle) {
            out.extend_from_slice(repl);
            i += needle.len();
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
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

/// Per-lane bounded-channel capacity (Track P.0).
///
/// Small on purpose: lanes are backpressure-bounded so a fast feeder cannot
/// queue the whole batch ahead of a slow worker, but large enough that a
/// worker never starves waiting on the feeder for the next item.
const LANE_CHANNEL_CAP: usize = 4;

/// Cap-routed concurrency lanes for batched verification (Track P.0).
///
/// A single-queue verifier lets one slow `DESERIALIZE` harness (JVM spin-up,
/// gadget-chain payloads) head-of-line block a queue full of fast `SSRF`
/// findings. [`WorkerPool::run_in_lanes`] instead routes each finding to a
/// lane keyed by its capability: every cap drains its *own* set of bounded
/// channels with a per-cap worker budget from [`WorkerPool::lanes_for_cap`],
/// and all caps run concurrently, so a slow cap throttles only itself.
///
/// Results are returned in input order regardless of lane scheduling, so the
/// verdict sequence stays deterministic (the engine's determinism contract is
/// about verdicts, not wall-clock interleaving).
pub struct WorkerPool;

impl WorkerPool {
    /// Concurrency budget for `cap`'s lanes.
    ///
    /// Verification is dominated by per-harness subprocess wall-time, not CPU,
    /// so wide lanes for cheap independent caps (SSRF) pay off even past the
    /// core count, while expensive caps stay narrow so one harness can't
    /// monopolise the host. Expensive caps are checked first so a combined
    /// cap-set inherits the *narrower* lane.
    pub fn lanes_for_cap(cap: Cap) -> usize {
        if cap.contains(Cap::CRYPTO) {
            1
        } else if cap.contains(Cap::DESERIALIZE) || cap.contains(Cap::CODE_EXEC) {
            2
        } else if cap.contains(Cap::SSRF) {
            8
        } else {
            4
        }
    }

    /// Run `work(i, &items[i])` for every item, routed through per-cap lanes.
    ///
    /// `cap_of` extracts the routing capability for each item. Returns one
    /// output per input, in input order. Empty / single-item batches run
    /// inline (no threads) so trivial scans pay no concurrency overhead.
    ///
    /// `trace`, when present, receives a deterministic
    /// [`TraceStage::WorkerLaneAssigned`] event per item (recorded in a
    /// single-threaded pre-pass so the trace order does not depend on lane
    /// scheduling).
    pub fn run_in_lanes<I, O, C, W>(
        items: &[I],
        trace: Option<&Arc<VerifyTrace>>,
        cap_of: C,
        work: W,
    ) -> Vec<O>
    where
        I: Sync,
        O: Send,
        C: Fn(&I) -> Cap + Sync,
        W: Fn(usize, &I) -> O + Sync,
    {
        // Group item indices by cap (BTreeMap over the raw bits keeps both the
        // pre-pass trace and lane spawning in a stable, reproducible order).
        let mut groups: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for (i, item) in items.iter().enumerate() {
            groups.entry(cap_of(item).bits()).or_default().push(i);
        }

        // Deterministic lane-assignment trace, single-threaded.
        if trace.is_some() {
            for (bits, idxs) in &groups {
                let cap = Cap::from_bits_truncate(*bits);
                let lanes = Self::lanes_for_cap(cap).max(1);
                for (pos, _) in idxs.iter().enumerate() {
                    trace_record(
                        trace,
                        TraceStage::WorkerLaneAssigned,
                        Some(format!(
                            "cap={} lane={}",
                            crate::labels::cap_to_name(cap),
                            pos % lanes
                        )),
                    );
                }
            }
        }

        // Inline fast path: nothing to parallelise.
        if items.len() <= 1 {
            return items
                .iter()
                .enumerate()
                .map(|(i, it)| work(i, it))
                .collect();
        }

        let results: Vec<Mutex<Option<O>>> = (0..items.len()).map(|_| Mutex::new(None)).collect();

        std::thread::scope(|scope| {
            let results = &results;
            let work = &work;
            for (bits, idxs) in groups {
                let cap = Cap::from_bits_truncate(bits);
                let lanes = Self::lanes_for_cap(cap).max(1);

                // One bounded channel + one worker per lane.
                let mut senders = Vec::with_capacity(lanes);
                for _ in 0..lanes {
                    let (tx, rx) = crossbeam_channel::bounded::<usize>(LANE_CHANNEL_CAP);
                    senders.push(tx);
                    scope.spawn(move || {
                        while let Ok(idx) = rx.recv() {
                            let out = work(idx, &items[idx]);
                            if let Ok(mut slot) = results[idx].lock() {
                                *slot = Some(out);
                            }
                        }
                    });
                }

                // Dedicated feeder per cap so feeding one group never blocks
                // another group's workers from starting (cross-cap isolation).
                scope.spawn(move || {
                    for (pos, idx) in idxs.into_iter().enumerate() {
                        let lane = pos % lanes;
                        if senders[lane].send(idx).is_err() {
                            break;
                        }
                    }
                    // `senders` drops here → each lane's rx closes → worker exits.
                });
            }
        });

        results
            .into_iter()
            .map(|m| {
                m.into_inner()
                    .ok()
                    .flatten()
                    .expect("every lane worker writes its result slot")
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_nonce_is_16_hex_chars() {
        let n = generate_nonce();
        assert_eq!(n.len(), 16);
        assert!(
            n.chars().all(|c| c.is_ascii_hexdigit()),
            "nonce must be hex: {n}"
        );
    }

    #[test]
    fn generate_nonce_unique_per_call() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2, "consecutive nonces must differ");
    }

    fn outcome_with(exit_code: Option<i32>, stderr: &[u8]) -> sandbox::SandboxOutcome {
        sandbox::SandboxOutcome {
            exit_code,
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
            timed_out: false,
            oob_callback_seen: false,
            sink_hit: false,
            duration: std::time::Duration::ZERO,
            hardening_outcome: None,
        }
    }

    #[test]
    fn import_error_detects_exit_77_with_marker() {
        let outcome = outcome_with(
            Some(77),
            b"NYX_IMPORT_ERROR: Cannot find module 'express'\n",
        );
        assert!(is_runtime_import_error(&outcome));
    }

    #[test]
    fn import_error_ignores_clean_exit() {
        let outcome = outcome_with(Some(0), b"NYX_IMPORT_ERROR: bogus\n");
        assert!(!is_runtime_import_error(&outcome));
    }

    #[test]
    fn import_error_ignores_other_nonzero_exits() {
        let outcome = outcome_with(Some(1), b"some other crash\n");
        assert!(!is_runtime_import_error(&outcome));
    }

    #[test]
    fn import_error_ignores_exit_77_without_marker() {
        let outcome = outcome_with(Some(77), b"crash but no marker\n");
        assert!(!is_runtime_import_error(&outcome));
    }

    #[test]
    fn import_error_ignores_signal_no_exit_code() {
        let outcome = outcome_with(None, b"NYX_IMPORT_ERROR: spurious\n");
        assert!(!is_runtime_import_error(&outcome));
    }

    #[test]
    fn import_error_matches_marker_embedded_in_other_stderr() {
        let outcome = outcome_with(
            Some(77),
            b"some preamble\nNYX_IMPORT_ERROR: real failure\nmore noise\n",
        );
        assert!(is_runtime_import_error(&outcome));
    }

    #[test]
    fn lanes_for_cap_matches_table() {
        assert_eq!(WorkerPool::lanes_for_cap(Cap::SSRF), 8);
        assert_eq!(WorkerPool::lanes_for_cap(Cap::DESERIALIZE), 2);
        assert_eq!(WorkerPool::lanes_for_cap(Cap::CODE_EXEC), 2);
        assert_eq!(WorkerPool::lanes_for_cap(Cap::CRYPTO), 1);
        // Unlisted cap falls back to the default lane width.
        assert_eq!(WorkerPool::lanes_for_cap(Cap::SQL_QUERY), 4);
        // Expensive cap wins a combined cap-set (narrower lane).
        assert_eq!(WorkerPool::lanes_for_cap(Cap::SSRF | Cap::CRYPTO), 1);
    }

    #[test]
    fn run_in_lanes_preserves_input_order() {
        // Mixed caps across many items: results must come back indexed by
        // input position regardless of which lane finished first.
        let caps = [
            Cap::SSRF,
            Cap::DESERIALIZE,
            Cap::CRYPTO,
            Cap::SQL_QUERY,
            Cap::SSRF,
            Cap::CRYPTO,
        ];
        let items: Vec<(usize, Cap)> = caps.iter().copied().enumerate().collect();
        let out = WorkerPool::run_in_lanes(
            &items,
            None,
            |&(_, cap)| cap,
            |i, &(orig, _)| {
                assert_eq!(i, orig);
                orig * 10
            },
        );
        assert_eq!(out, vec![0, 10, 20, 30, 40, 50]);
    }

    #[test]
    fn run_in_lanes_runs_every_item_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let items: Vec<Cap> = (0..64)
            .map(|i| match i % 4 {
                0 => Cap::SSRF,
                1 => Cap::DESERIALIZE,
                2 => Cap::CRYPTO,
                _ => Cap::SQL_QUERY,
            })
            .collect();
        let calls = AtomicUsize::new(0);
        let out = WorkerPool::run_in_lanes(
            &items,
            None,
            |c| *c,
            |i, _| {
                calls.fetch_add(1, Ordering::Relaxed);
                i
            },
        );
        assert_eq!(calls.load(Ordering::Relaxed), 64);
        assert_eq!(out, (0..64).collect::<Vec<_>>());
    }

    #[test]
    fn run_in_lanes_emits_deterministic_lane_trace() {
        let items = [Cap::SSRF, Cap::CRYPTO, Cap::SSRF];
        let trace_a = Arc::new(VerifyTrace::new());
        let _ = WorkerPool::run_in_lanes(&items, Some(&trace_a), |c| *c, |i, _| i);
        let trace_b = Arc::new(VerifyTrace::new());
        let _ = WorkerPool::run_in_lanes(&items, Some(&trace_b), |c| *c, |i, _| i);

        let events_a = trace_a.events();
        // One WorkerLaneAssigned per item.
        assert_eq!(
            events_a
                .iter()
                .filter(|e| e.stage == TraceStage::WorkerLaneAssigned)
                .count(),
            3
        );
        // Deterministic across runs.
        assert_eq!(trace_a.to_jsonl(), trace_b.to_jsonl());
    }
}
