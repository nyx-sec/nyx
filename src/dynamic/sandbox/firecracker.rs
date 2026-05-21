//! Phase 20 (Track E.4) — Firecracker microVM backend skeleton.
//!
//! This module is compiled in only when the `firecracker` Cargo feature is
//! enabled.  Today it carries no live VM logic — the goal of Phase 20 is to
//! freeze the public surface that the verifier and the rest of the sandbox
//! dispatcher in [`super`] talk to, so that Phase 21 can fill in the boot
//! path (jailer arg shaping, vsock relay for the probe channel, snapshot
//! restore, …) without churning the call sites again.
//!
//! What the skeleton guarantees:
//!
//! 1. [`run`] probes the host for a `firecracker` binary on `PATH` (with the
//!    `NYX_FIRECRACKER_BIN` override for tests) and returns
//!    [`SandboxError::BackendUnavailable`] when it is missing.  No partially-
//!    initialised VM state is created.
//! 2. When the binary is present, the function still returns
//!    `BackendUnavailable` for now — Phase 21 will replace the stub with the
//!    live jailer wrap.  The variant is the only one the verifier needs to
//!    branch on, so it can downgrade `Cap::FILE_IO` / `Cap::CODE_EXEC`
//!    verdicts to [`crate::evidence::InconclusiveReason::BackendInsufficient`]
//!    consistently across hosts that do and do not have firecracker
//!    available.
//! 3. The probe is cached behind a `OnceLock` so repeated calls into [`run`]
//!    do not re-`stat` the binary every time.  Tests that swap
//!    `NYX_FIRECRACKER_BIN` between scenarios bypass the cache via the
//!    uncached [`is_firecracker_reachable`] helper.

use std::sync::OnceLock;

use crate::dynamic::harness::BuiltHarness;

use super::{SandboxBackend, SandboxError, SandboxOptions, SandboxOutcome};

/// Env var override for the firecracker binary path.  Used by tests + dev
/// hosts where firecracker is staged in a non-`PATH` location.
const FIRECRACKER_BIN_ENV: &str = "NYX_FIRECRACKER_BIN";

/// Default binary name when no override is set.
const FIRECRACKER_BIN_DEFAULT: &str = "firecracker";

/// Cached probe result.  `Some(true)` = binary reachable, `Some(false)` =
/// probe ran and failed, `None` = never probed.
static FIRECRACKER_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Returns `true` if a `firecracker` binary is reachable on this host.
///
/// Result is cached after the first call.  Tests that mutate
/// `NYX_FIRECRACKER_BIN` between assertions should call
/// [`is_firecracker_reachable`] instead so they observe the new value.
pub fn firecracker_available() -> bool {
    *FIRECRACKER_AVAILABLE.get_or_init(is_firecracker_reachable)
}

/// Uncached binary-availability probe.  Walks the host `PATH` looking for
/// the resolved binary name and returns `true` when it is a regular file.
pub fn is_firecracker_reachable() -> bool {
    let name = firecracker_bin();
    if std::path::Path::new(&name).is_absolute() {
        return std::path::Path::new(&name).is_file();
    }
    super::find_in_host_path(&name).is_some()
}

fn firecracker_bin() -> String {
    std::env::var(FIRECRACKER_BIN_ENV).unwrap_or_else(|_| FIRECRACKER_BIN_DEFAULT.to_owned())
}

/// Run a harness inside a Firecracker microVM.
///
/// Phase 20: returns [`SandboxError::BackendUnavailable`] in every case.
/// The unused-variable shape is kept so that adding the live boot path in
/// Phase 21 is a single-function diff that does not change the call sites
/// in [`super::run`].
pub fn run(
    _harness: &BuiltHarness,
    _payload_bytes: &[u8],
    _opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    if !firecracker_available() {
        return Err(SandboxError::BackendUnavailable(
            SandboxBackend::Firecracker,
        ));
    }
    // Binary present but no VM logic yet.  Surface BackendUnavailable
    // explicitly so callers do not mistakenly think the run succeeded.
    Err(SandboxError::BackendUnavailable(
        SandboxBackend::Firecracker,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_returns_backend_unavailable() {
        // Force the probe to a path that cannot exist.  The OnceLock means
        // we have to drive `is_firecracker_reachable` directly instead of
        // relying on `firecracker_available()` — another test in the same
        // binary may have warmed the cache.
        let saved = std::env::var(FIRECRACKER_BIN_ENV).ok();
        unsafe { std::env::set_var(FIRECRACKER_BIN_ENV, "/nyx/does-not-exist/firecracker") };
        assert!(!is_firecracker_reachable());
        if let Some(v) = saved {
            unsafe { std::env::set_var(FIRECRACKER_BIN_ENV, v) };
        } else {
            unsafe { std::env::remove_var(FIRECRACKER_BIN_ENV) };
        }
    }

    #[test]
    fn run_returns_backend_unavailable_under_phase_20_stub() {
        // The skeleton never returns Ok regardless of whether the binary
        // is present — Phase 21 owns the live path.
        let harness = BuiltHarness {
            workdir: std::path::PathBuf::from("/tmp"),
            command: vec!["true".into()],
            env: vec![],
            source: String::new(),
            entry_source: String::new(),
        };
        let opts = SandboxOptions {
            backend: SandboxBackend::Firecracker,
            ..SandboxOptions::default()
        };
        let result = run(&harness, b"", &opts);
        assert!(matches!(
            result,
            Err(SandboxError::BackendUnavailable(
                SandboxBackend::Firecracker
            ))
        ));
    }
}
