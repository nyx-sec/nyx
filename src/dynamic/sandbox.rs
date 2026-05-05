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
use std::time::Duration;

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
}

impl Default for SandboxOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            memory_mib: 256,
            backend: SandboxBackend::Auto,
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
/// Stub: dispatches to one of the backend submodules
/// (`sandbox/docker.rs`, `sandbox/process.rs`) once those land.
pub fn run(
    _harness: &BuiltHarness,
    _payload: &Payload,
    _opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    Err(SandboxError::BackendUnavailable(SandboxBackend::Auto))
}
