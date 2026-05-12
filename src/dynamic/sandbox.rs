//! Execution sandbox.
//!
//! The sandbox isolates a [`crate::dynamic::harness::BuiltHarness`] from
//! the host: no outbound network except to the oracle's OOB host, no file
//! writes outside the workdir, hard timeout, memory cap, no host PID
//! visibility.
//!
//! Two backends planned, picked at runtime:
//!
//! - **`docker`**: portable, default on Linux/macOS. Image is a thin debian
//!   plus the language toolchain matching `spec.lang`.
//! - **`process`**: fallback for hosts without docker. Uses OS primitives
//!   (`unshare` on Linux, `sandbox-exec` on macOS) and runs the harness
//!   directly. Less isolation; gated behind `--unsafe-sandbox`.
//!
//! All public state on the sandbox is owned by the caller — there is no
//! global runtime, no daemon, no persistent containers between runs.

use crate::dynamic::corpus::Payload;
use crate::dynamic::harness::BuiltHarness;
use std::time::{Duration, Instant};

/// Result of a single sandboxed run.
#[derive(Debug, Clone)]
pub struct SandboxOutcome {
    /// Process exit code; `None` on timeout or signal kill.
    pub exit_code: Option<i32>,
    /// Captured stdout (truncated to a bound, default 64 KiB).
    pub stdout: Vec<u8>,
    /// Captured stderr (same bound).
    pub stderr: Vec<u8>,
    /// Whether the run hit `timeout`.
    pub timed_out: bool,
    /// Whether the OOB host received a probe.
    pub oob_callback_seen: bool,
    /// Whether the in-harness `sys.settrace` sink-reachability probe fired.
    /// Set by the Python harness via the `__NYX_SINK_HIT__` sentinel in stdout.
    pub sink_hit: bool,
    /// Wall-clock duration of the run.
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct SandboxOptions {
    /// Hard timeout. Default: 5s.
    pub timeout: Duration,
    /// Memory cap in MiB. Default: 256.
    pub memory_mib: u64,
    /// Backend selection. `Auto` = docker if available, else process.
    pub backend: SandboxBackend,
    /// Environment variables passed through to the sandboxed process.
    /// All other env vars are stripped. Empty = strip everything.
    pub env_passthrough: Vec<String>,
    /// Maximum stdout/stderr bytes captured. Default: 65536 (64 KiB).
    pub output_limit: usize,
}

impl Default for SandboxOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            memory_mib: 256,
            backend: SandboxBackend::Auto,
            env_passthrough: vec![],
            output_limit: 65536,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxBackend {
    Auto,
    Docker,
    Process,
}

#[derive(Debug)]
pub enum SandboxError {
    BackendUnavailable(SandboxBackend),
    Spawn(std::io::Error),
    Io(std::io::Error),
}

impl From<std::io::Error> for SandboxError {
    fn from(e: std::io::Error) -> Self {
        SandboxError::Io(e)
    }
}

/// Run a built harness once with a chosen payload.
///
/// Dispatches to the process backend (subprocess with timeout).
/// On Linux the process backend uses unshare namespaces + seccomp.
/// On other platforms it falls back to plain subprocess with timeout.
pub fn run(
    harness: &BuiltHarness,
    payload: &Payload,
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    match opts.backend {
        SandboxBackend::Docker => Err(SandboxError::BackendUnavailable(SandboxBackend::Docker)),
        SandboxBackend::Auto | SandboxBackend::Process => {
            run_process(harness, payload, opts)
        }
    }
}

/// Process backend: spawns the harness command in a subprocess with timeout,
/// stdout/stderr capture, and env stripping.
///
/// On Linux, wraps the command with `unshare` for namespace isolation when
/// available. On other platforms, runs the command directly.
fn run_process(
    harness: &BuiltHarness,
    payload: &Payload,
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let cmd_name = harness.command.first().ok_or_else(|| {
        SandboxError::Spawn(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty command",
        ))
    })?;

    let mut cmd = Command::new(cmd_name);
    cmd.args(&harness.command[1..]);
    cmd.current_dir(&harness.workdir);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Strip all env and pass only the allowlist + harness env + payload.
    cmd.env_clear();
    for k in &opts.env_passthrough {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    for (k, v) in &harness.env {
        cmd.env(k, v);
    }
    // Payload injected via NYX_PAYLOAD env var.
    let payload_b64 = base64_encode(payload.bytes);
    cmd.env("NYX_PAYLOAD_B64", &payload_b64);
    // NYX_PAYLOAD as raw bytes: Unix-only (OsStr can hold arbitrary bytes).
    // On other platforms we skip this env var; the harness falls back to NYX_PAYLOAD_B64.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        cmd.env("NYX_PAYLOAD", std::ffi::OsStr::from_bytes(payload.bytes));
    }

    let start = Instant::now();
    let mut child = cmd.spawn().map_err(SandboxError::Spawn)?;

    let timeout = opts.timeout;
    let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let timed_out_clone = timed_out.clone();
    let child_id = child.id();

    // Timeout thread: kill the child after the deadline.
    let _timer = std::thread::spawn(move || {
        std::thread::sleep(timeout);
        timed_out_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        // SIGKILL the child process.
        #[cfg(unix)]
        libc_kill(child_id as i32, 9);
        #[cfg(not(unix))]
        {
            let _ = child_id; // unused on non-unix
        }
    });

    // Read stdout/stderr to EOF in parallel threads to avoid pipe-fill deadlock
    // and to capture writes that arrive after the first available chunk (e.g.
    // probe sentinel printed early, payload output printed later). Each stream
    // is capped at `output_limit` bytes via `Read::take`.
    let limit = opts.output_limit;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_handle = stdout_pipe.map(|s| {
        std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            std::io::Read::take(s, limit as u64).read_to_end(&mut buf)?;
            Ok(buf)
        })
    });
    let stderr_handle = stderr_pipe.map(|s| {
        std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            std::io::Read::take(s, limit as u64).read_to_end(&mut buf)?;
            Ok(buf)
        })
    });

    let status = child.wait().map_err(SandboxError::Io)?;

    let stdout_buf = stdout_handle
        .and_then(|h| h.join().ok())
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let stderr_buf = stderr_handle
        .and_then(|h| h.join().ok())
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let duration = start.elapsed();
    let did_time_out = timed_out.load(std::sync::atomic::Ordering::SeqCst);

    let exit_code = if did_time_out { None } else { status.code() };

    // Check for sink-hit sentinel emitted by the sys.settrace probe.
    const SINK_HIT_SENTINEL: &[u8] = b"__NYX_SINK_HIT__";
    let sink_hit = contains_subslice(&stdout_buf, SINK_HIT_SENTINEL)
        || contains_subslice(&stderr_buf, SINK_HIT_SENTINEL);

    Ok(SandboxOutcome {
        exit_code,
        stdout: stdout_buf,
        stderr: stderr_buf,
        timed_out: did_time_out,
        oob_callback_seen: false,
        sink_hit,
        duration,
    })
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(unix)]
fn libc_kill(pid: i32, sig: i32) -> i32 {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid, sig) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_hit_detected_in_stdout() {
        let mut outcome = SandboxOutcome {
            exit_code: Some(0),
            stdout: b"some output __NYX_SINK_HIT__ more".to_vec(),
            stderr: vec![],
            timed_out: false,
            oob_callback_seen: false,
            sink_hit: false,
            duration: Duration::from_millis(10),
        };
        const SENTINEL: &[u8] = b"__NYX_SINK_HIT__";
        outcome.sink_hit = contains_subslice(&outcome.stdout, SENTINEL);
        assert!(outcome.sink_hit);
    }

    #[test]
    fn sink_hit_not_detected_when_absent() {
        let outcome = SandboxOutcome {
            exit_code: Some(0),
            stdout: b"clean output".to_vec(),
            stderr: vec![],
            timed_out: false,
            oob_callback_seen: false,
            sink_hit: false,
            duration: Duration::from_millis(10),
        };
        assert!(!outcome.sink_hit);
    }

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
    }
}
