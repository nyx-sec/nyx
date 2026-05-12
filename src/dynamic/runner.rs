//! Orchestration: spec -> harness -> sandbox -> oracle -> verdict.
//!
//! The runner is the only place that knows about all four submodules at once.
//! Everything below it (corpus, harness, sandbox) is independent; everything
//! above it ([`crate::dynamic::verify`]) just calls [`run_spec`] and turns
//! the result into a [`crate::dynamic::report::VerifyResult`].

use crate::dynamic::build_sandbox;
use crate::dynamic::corpus::{benign_payload_for, materialise_bytes, payloads_for, Oracle, Payload};
use crate::dynamic::harness::{self, HarnessError};
use crate::dynamic::sandbox::{self, SandboxError, SandboxOptions, SandboxOutcome};
use crate::dynamic::spec::HarnessSpec;
use crate::symbol::Lang;

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
    let payloads = payloads_for(spec.expected_cap);
    if payloads.is_empty() {
        return Err(RunError::NoPayloadsForCap);
    }

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
        _ => {
            // No build step for other languages.
        }
    }

    let harness_source = harness.source.clone();
    let entry_source = harness.entry_source.clone();

    // Run only vuln (non-benign) payloads in the main loop.
    let vuln_payloads: Vec<&Payload> = payloads.iter().filter(|p| !p.is_benign).collect();
    let benign_payload = benign_payload_for(spec.expected_cap);

    let mut attempts = Vec::with_capacity(vuln_payloads.len());
    let mut triggered_by = None;
    let mut oracle_collision = false;

    for (i, payload) in vuln_payloads.iter().enumerate() {
        // Materialise payload bytes (OOB nonce-slot payloads generate a URL).
        let (oob_nonce, effective_bytes) = if payload.oob_nonce_slot {
            if let Some(ref listener) = opts.oob_listener {
                let nonce = generate_nonce();
                let url = listener.nonce_url(&nonce);
                let bytes = url.into_bytes();
                (Some(nonce), bytes)
            } else {
                // No OOB listener configured — skip OOB payloads.
                continue;
            }
        } else {
            (None, payload.bytes.to_vec())
        };

        let mut outcome = sandbox::run(&harness, &effective_bytes, opts)?;

        // For OOB payloads, check the nonce listener and update the outcome flag.
        if let (Some(nonce), Some(listener)) = (&oob_nonce, &opts.oob_listener) {
            // Give the harness a brief window to complete the callback before we check.
            // The sandbox run already waited for process exit, so the callback should
            // have arrived. A short sleep handles edge cases where the OS hasn't yet
            // delivered the TCP segment to the listener thread.
            std::thread::sleep(std::time::Duration::from_millis(50));
            if listener.was_nonce_hit(nonce) {
                outcome.oob_callback_seen = true;
            }
        }

        let fired = oracle_fired(&payload.oracle, &outcome);
        let sink_hit = outcome.sink_hit;

        let triggered = if fired && sink_hit {
            // Full confirmation: oracle + probe both fired.
            // Check differential: if benign payload also triggers oracle, downgrade.
            if let Some(benign) = benign_payload {
                let benign_bytes = materialise_bytes(benign, None)
                    .map(|b| b.into_owned())
                    .unwrap_or_default();
                let benign_outcome = sandbox::run(&harness, &benign_bytes, opts)?;
                let benign_fired = oracle_fired(&benign.oracle, &benign_outcome);
                !benign_fired
            } else {
                true
            }
        } else if fired && !sink_hit {
            // Oracle fired but probe didn't — likely collision.
            oracle_collision = true;
            false
        } else {
            false
        };

        attempts.push(Attempt {
            payload_label: payload.label,
            outcome,
            oracle_fired: fired,
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
    })
}

fn oracle_fired(oracle: &Oracle, outcome: &SandboxOutcome) -> bool {
    match oracle {
        Oracle::OutputContains(needle) => {
            let nb = needle.as_bytes();
            contains_subslice(&outcome.stdout, nb) || contains_subslice(&outcome.stderr, nb)
        }
        Oracle::Crash => matches!(outcome.exit_code, None) && !outcome.timed_out,
        Oracle::OobCallback { .. } => outcome.oob_callback_seen,
        Oracle::FileEscape => false,
        Oracle::ExitStatus(code) => outcome.exit_code == Some(*code),
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return needle.is_empty();
    }
    hay.windows(needle.len()).any(|w| w == needle)
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
    fn contains_subslice_empty_needle() {
        assert!(contains_subslice(b"hello", b""));
    }

    #[test]
    fn contains_subslice_finds_match() {
        assert!(contains_subslice(b"hello world", b"world"));
    }

    #[test]
    fn contains_subslice_no_match() {
        assert!(!contains_subslice(b"hello", b"xyz"));
    }

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
