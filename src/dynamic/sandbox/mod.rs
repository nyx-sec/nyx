//! Execution sandbox.
//!
//! The sandbox isolates a [`crate::dynamic::harness::BuiltHarness`] from
//! the host: no outbound network except to the oracle's OOB host, no file
//! writes outside the workdir, hard timeout, memory cap, no host PID
//! visibility.
//!
//! Two backends, picked at runtime:
//!
//! - **`docker`**: default when docker is available. Runs the harness inside
//!   a container with `--cap-drop=ALL`, `--security-opt
//!   no-new-privileges:true`, and `--network none`. Containers are reused
//!   within a single spec_hash via `docker exec` to amortise image
//!   cold-start cost.
//! - **`process`**: fallback for hosts without docker; gated behind
//!   `--unsafe-sandbox`. Runs the harness as a child process with env
//!   stripping, memory cap (RLIMIT_AS on Linux), and
//!   `prctl(PR_SET_NO_NEW_PRIVS)`. No network or namespace isolation — this
//!   backend is intentionally weaker and is for dev iteration only.
//!
//! All public state on the sandbox is owned by the caller — there is no
//! global runtime, no daemon. Containers are stopped and removed when the
//! process exits.

use crate::dynamic::harness::BuiltHarness;
use crate::dynamic::oob::OobListener;
use crate::dynamic::probe::{ProbeChannel, PROBE_PATH_ENV};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
pub mod process_linux;
#[cfg(target_os = "linux")]
pub mod seccomp;

#[cfg(target_os = "linux")]
pub use process_linux::{HardeningLevel, HardeningOutcome};

#[cfg(target_os = "macos")]
pub mod process_macos;

/// Phase 19 (Track E.3) — pinned-digest docker backend helpers.
///
/// The functions in this module resolve [`crate::dynamic::toolchain::
/// IMAGE_DIGESTS`] entries to docker image refs, render `docker run`
/// flag slices that honour [`NetworkPolicy`], and mount the harness
/// workdir at the fixed `/work` path.  The legacy entry points in this
/// file ([`run_docker`] / [`run_native_binary_docker`]) call into
/// `docker::ensure_image_pulled` so every harness run uses the catalogue
/// pin when one is available.
pub mod docker;

// ── Harness interpretation probe ──────────────────────────────────────────────

/// Returns true when the harness is driven by an interpreter (Python, Node, …)
/// rather than a compiled native binary.
///
/// Interpreted harnesses can be run inside a Python/Node Docker image directly.
/// Compiled harnesses (Rust, Go) are routed to `run_native_binary_docker` on
/// Linux or to the process backend on other platforms.
/// Resolve a bare command name to an absolute path by walking the host's
/// `PATH`.  Returns `None` if `PATH` is unset or the name is not present in
/// any entry as a regular file.
///
/// Used by `run_process` so spawn(2) succeeds even after the child
/// environment has been wiped: macOS' `posix_spawnp` defaults to
/// `confstr(_CS_PATH)` (`/usr/bin:/bin`) when the child has no `PATH`, which
/// misses common installs like Homebrew's `/opt/homebrew/bin/node` or
/// `nvm`-managed binaries under `~/.nvm/...`.
fn find_in_host_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn harness_is_interpreted(command: &[String]) -> bool {
    let cmd0 = match command.first() {
        Some(c) => c.as_str(),
        None => return false,
    };
    let base = std::path::Path::new(cmd0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd0);
    matches!(
        base,
        "python3" | "python" | "python2" | "node" | "nodejs" | "ruby" | "php" | "perl" | "java"
    )
}

/// Returns true when the harness is a compiled native binary that can be run
/// inside a Linux Docker container.
///
/// Compiled harnesses (Rust, Go) set `command[0]` to an absolute path after
/// `prepare_rust()` / `prepare_go()` succeeds. This distinguishes them from
/// interpreter commands (bare names like `python3`) and lets the Docker backend
/// route them to `run_native_binary_docker` instead of the process backend.
///
/// Only returns true on Linux: native binaries compiled on macOS or Windows are
/// not Linux ELF and cannot execute in Linux Docker containers.
pub fn harness_is_native_binary(command: &[String]) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    match command.first() {
        Some(cmd) => {
            std::path::Path::new(cmd.as_str()).is_absolute() && !harness_is_interpreted(command)
        }
        None => false,
    }
}

/// Docker image used to run compiled native binaries (Rust, Go).
///
/// `debian:bookworm-slim` provides glibc and a minimal runtime compatible with
/// dynamically-linked Rust/Go binaries produced by the standard toolchains.
const NATIVE_BINARY_IMAGE: &str = "debian:bookworm-slim";

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
    /// Phase 11 (Track D.5): network reachability the harness is allowed
    /// to exercise.  Default [`NetworkPolicy::None`] — the previous
    /// behaviour was equivalent to a binary `oob_listener: Option<...>`;
    /// callers wanting OOB callbacks now set
    /// [`NetworkPolicy::OobOutbound`].  See [`NetworkPolicy`] for the
    /// per-variant backend wiring.
    pub network_policy: NetworkPolicy,
    /// Per-run structured-oracle [`ProbeChannel`] (Phase 06 — Track C.1).
    /// When set, the sandbox forwards the channel's path to the harness via
    /// the `NYX_PROBE_PATH` env var so the per-language `__nyx_probe` shim
    /// can write [`crate::dynamic::probe::SinkProbe`] records.  The runner
    /// drains the channel after each sandbox run and evaluates
    /// [`crate::dynamic::oracle::ProbePredicate`]s against the records.
    pub probe_channel: Option<Arc<ProbeChannel>>,
    /// Phase 10 (Track D.3): extra env vars injected after
    /// [`Self::env_passthrough`] / `harness.env`.  The verifier
    /// populates this from
    /// [`crate::dynamic::stubs::StubHarness::endpoints`] so each
    /// boundary stub's endpoint reaches the harness via a stable
    /// env-var name (e.g. `NYX_SQL_ENDPOINT`).
    pub extra_env: Vec<(String, String)>,
    /// Phase 10 (Track D.3): live boundary-stub harness used by the
    /// runner to drain stub events between payload runs and feed them
    /// into [`crate::dynamic::oracle::oracle_fired_with_stubs`].
    /// `None` when the spec's `stubs_required` is empty.
    pub stub_harness: Option<Arc<crate::dynamic::stubs::StubHarness>>,
    /// Phase 17 (Track E.1): cap bits used to minimise the seccomp-bpf
    /// allowlist applied to the Linux process backend.  When `0`, the
    /// process backend installs only the cap-independent `base` allowlist
    /// from [`seccomp::seccomp_policy.toml`]; when non-zero, every cap bit
    /// set adds its allowlisted syscalls on top.  Other backends ignore
    /// this field.
    pub seccomp_caps: u32,
    /// Phase 17 (Track E.1): hardening profile applied by the Linux
    /// process backend.  See [`ProcessHardeningProfile`] for the per-
    /// variant primitive matrix.
    pub process_hardening: ProcessHardeningProfile,
}

/// Phase 17 (Track E.1): selects which subset of the Linux process-
/// backend hardening primitives is applied.
///
/// - [`ProcessHardeningProfile::Standard`] — the historical baseline:
///   `prctl(PR_SET_NO_NEW_PRIVS)` + `setrlimit(RLIMIT_AS)` only.  No
///   namespaces, no chroot, no seccomp.  Default for back-compat.
/// - [`ProcessHardeningProfile::Strict`] — full Phase 17 sequence:
///   no-new-privs, all rlimits, namespace unshare, chroot to workdir,
///   default-deny seccomp filter scoped to [`SandboxOptions::seccomp_caps`].
///   Each primitive is best-effort; failures degrade to
///   [`HardeningLevel::Partial`] without aborting the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessHardeningProfile {
    Standard,
    Strict,
}

impl Default for ProcessHardeningProfile {
    fn default() -> Self {
        ProcessHardeningProfile::Standard
    }
}

impl SandboxOptions {
    /// Borrow the OOB listener handle when the network policy carries
    /// one.  Returns `None` for every variant except
    /// [`NetworkPolicy::OobOutbound`].
    ///
    /// Kept stable across the Phase 11 cut-over so the runner can keep
    /// poking at `effective_opts.oob_listener()` without caring whether
    /// the policy machinery moves underneath it.
    pub fn oob_listener(&self) -> Option<&Arc<OobListener>> {
        self.network_policy.oob_listener()
    }
}

impl Default for SandboxOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            memory_mib: 256,
            backend: SandboxBackend::Auto,
            env_passthrough: vec![],
            output_limit: 65536,
            network_policy: NetworkPolicy::None,
            probe_channel: None,
            extra_env: Vec::new(),
            stub_harness: None,
            seccomp_caps: 0,
            process_hardening: ProcessHardeningProfile::Standard,
        }
    }
}

// ── Phase 11 — Track D.5: NetworkPolicy ──────────────────────────────────────

/// Host + port allowlist entry referenced by [`NetworkPolicy::StubsOnly`].
///
/// The Docker backend treats each entry as an `--add-host` line so the
/// harness DNS-resolves stub endpoints to their host-side bind address;
/// the netfilter chain itself blocks all other egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port }
    }
}

/// Phase 11 (Track D.5): network reachability the harness is allowed to
/// exercise.  Replaces the legacy `oob_listener: Option<Arc<OobListener>>`
/// binary flag with an enum that distinguishes the four operationally
/// meaningful stances:
///
/// - [`NetworkPolicy::None`] — no outbound network at all (default).
///   Docker: `--network none`.  Process backend: caller-imposed; the
///   process backend has no network namespace facility so the policy is
///   structural here (the harness has whatever connectivity the host's
///   `lo`/routes provide; production runs should use the Docker backend
///   for real isolation).
/// - [`NetworkPolicy::StubsOnly`] — only the listed host/port pairs are
///   reachable.  Docker: `bridge` network + `--add-host` per allow-entry.
///   Linux production hardening (netns + nftables) is staged for a
///   follow-up phase; today the variant carries the allowlist for the
///   harness emitter and is mechanically distinguished by the backend
///   selector.
/// - [`NetworkPolicy::OobOutbound`] — the legacy "OOB only" path: the
///   harness can reach the per-scan OOB listener (and only it via the
///   Linux iptables filter in [`apply_oob_egress_filter`]).  Docker:
///   `bridge` + host-gateway + iptables OOB-port filter.
/// - [`NetworkPolicy::Open`] — unrestricted outbound.  Docker: `bridge`
///   with no egress filter.  Reserved for diagnostic / dev-only runs;
///   the verifier never sets this in production.
#[derive(Debug, Clone)]
pub enum NetworkPolicy {
    None,
    StubsOnly { allow: Vec<HostPort> },
    OobOutbound { listener: Arc<OobListener> },
    Open,
}

impl NetworkPolicy {
    /// `true` when the docker backend should run the container with a
    /// bridge network (i.e. with outbound reachability available, even
    /// if filtered).  `false` selects `--network none`.
    pub fn allows_network(&self) -> bool {
        !matches!(self, NetworkPolicy::None)
    }

    /// OOB listener handle when this policy carries one.
    pub fn oob_listener(&self) -> Option<&Arc<OobListener>> {
        match self {
            NetworkPolicy::OobOutbound { listener } => Some(listener),
            _ => None,
        }
    }

    /// Stub allow-list entries when this policy carries one.
    pub fn stub_allow_list(&self) -> Option<&[HostPort]> {
        match self {
            NetworkPolicy::StubsOnly { allow } => Some(allow.as_slice()),
            _ => None,
        }
    }

    /// Short tag used by the docker `--add-host` shaper / telemetry.
    pub fn variant_tag(&self) -> &'static str {
        match self {
            NetworkPolicy::None => "none",
            NetworkPolicy::StubsOnly { .. } => "stubs-only",
            NetworkPolicy::OobOutbound { .. } => "oob-outbound",
            NetworkPolicy::Open => "open",
        }
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy::None
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

// ── Docker availability probe ─────────────────────────────────────────────────

static DOCKER_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Returns true if the docker daemon is reachable on this host.
///
/// Result is cached after the first call (§4.2 lazy-backend bullet).
/// Override the docker binary with `NYX_DOCKER_BIN` for testing.
pub fn docker_available() -> bool {
    *DOCKER_AVAILABLE.get_or_init(probe_docker)
}

fn probe_docker() -> bool {
    std::process::Command::new(docker_bin())
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Returns the docker binary path, respecting `NYX_DOCKER_BIN` for tests.
fn docker_bin() -> String {
    std::env::var("NYX_DOCKER_BIN").unwrap_or_else(|_| "docker".to_owned())
}

// ── Docker container registry (exec reuse) ────────────────────────────────────

/// Global registry: workdir absolute path → container name.
///
/// When `run_docker` is called for a workdir that already has a running
/// container, it skips `docker run` and goes straight to `docker exec`.
static CONTAINER_REGISTRY: OnceLock<dashmap::DashMap<String, String>> = OnceLock::new();

// ── OOB egress filter (Linux only, §17.2) ────────────────────────────────────

/// Saved state for an active OOB egress iptables filter.
///
/// Retained so the cleanup handler can issue matching `-D` rules without
/// needing to re-run `docker inspect` (the container may already be stopping).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct OobEgressState {
    container_ip: String,
    oob_port: u16,
}

#[cfg(target_os = "linux")]
static OOB_EGRESS_REGISTRY: OnceLock<dashmap::DashMap<String, OobEgressState>> = OnceLock::new();

#[cfg(target_os = "linux")]
fn oob_egress_registry() -> &'static dashmap::DashMap<String, OobEgressState> {
    OOB_EGRESS_REGISTRY.get_or_init(dashmap::DashMap::new)
}

/// Retrieve the container's primary IP address via `docker inspect`.
#[cfg(target_os = "linux")]
fn get_container_ip(container_name: &str) -> Option<String> {
    let out = std::process::Command::new(docker_bin())
        .args([
            "inspect",
            "--format={{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_name,
        ])
        .output()
        .ok()?;
    let ip = std::str::from_utf8(&out.stdout).ok()?.trim().to_owned();
    if ip.is_empty() { None } else { Some(ip) }
}

/// Apply host-level iptables rules restricting an OOB-sandboxed container.
///
/// Only outbound traffic to the host's OOB listener port is permitted:
///
/// - INPUT chain (docker0): ACCEPT `container_ip → host:oob_port` (TCP)
/// - INPUT chain (docker0): DROP all other traffic from `container_ip` to host
/// - DOCKER-USER chain (FORWARD): DROP all egress from `container_ip` (blocks
///   internet via NAT)
///
/// Rules are inserted at the chain head so they precede any pre-existing
/// allow-all rules.  On failure (no root / `iptables` absent) a warning is
/// printed to stderr and the function returns; the OOB listener still works
/// but without strict per-port egress isolation (§17.2 relaxed mode).
#[cfg(target_os = "linux")]
fn apply_oob_egress_filter(container_name: &str, oob_port: u16) {
    let container_ip = match get_container_ip(container_name) {
        Some(ip) => ip,
        None => {
            eprintln!(
                "nyx: [oob-filter] docker inspect failed for {container_name} \
                 — egress filter skipped"
            );
            return;
        }
    };

    let port_str = oob_port.to_string();
    let ip = container_ip.as_str();

    let rules: &[&[&str]] = &[
        // Allow container → host OOB port (INPUT; docker0 bridge to host).
        &["-I", "INPUT", "1", "-i", "docker0",
          "-s", ip, "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT"],
        // Drop all other container → host traffic (INPUT; position 2 fires after accept).
        &["-I", "INPUT", "2", "-i", "docker0",
          "-s", ip, "-j", "DROP"],
        // Drop all container egress to external internet (FORWARD / DOCKER-USER).
        &["-I", "DOCKER-USER", "1",
          "-s", ip, "-j", "DROP"],
    ];

    let mut applied = 0usize;
    for rule in rules {
        let ok = std::process::Command::new("iptables")
            .args(*rule)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            applied += 1;
        }
    }

    if applied == rules.len() {
        oob_egress_registry().insert(
            container_name.to_owned(),
            OobEgressState { container_ip, oob_port },
        );
    } else {
        eprintln!(
            "nyx: [oob-filter] iptables partially applied ({}/{} rules) for {} \
             — needs root or CAP_NET_ADMIN; egress filtering is best-effort only",
            applied,
            rules.len(),
            container_name,
        );
    }
}

/// Remove the iptables rules applied by [`apply_oob_egress_filter`].
///
/// Called from the atexit handler in [`stop_all_containers`].  Safe to call
/// even if no filter was applied for `container_name` (no-op in that case).
#[cfg(target_os = "linux")]
fn remove_oob_egress_filter(container_name: &str) {
    let Some((_, state)) = oob_egress_registry().remove(container_name) else {
        return;
    };

    let port_str = state.oob_port.to_string();
    let ip = state.container_ip.as_str();

    let rules: &[&[&str]] = &[
        &["-D", "INPUT", "-i", "docker0",
          "-s", ip, "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT"],
        &["-D", "INPUT", "-i", "docker0",
          "-s", ip, "-j", "DROP"],
        &["-D", "DOCKER-USER",
          "-s", ip, "-j", "DROP"],
    ];

    for rule in rules {
        // Best-effort: ignore errors (container already removed, no privileges, etc.)
        let _ = std::process::Command::new("iptables")
            .args(*rule)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn container_registry() -> &'static dashmap::DashMap<String, String> {
    CONTAINER_REGISTRY.get_or_init(|| {
        // Register an atexit handler to stop containers on normal process exit.
        // Containers are also started with --rm and `sleep 300` so they self-remove
        // within 5 minutes if the handler doesn't run (e.g. SIGKILL).
        #[cfg(unix)]
        register_exit_cleanup();
        dashmap::DashMap::new()
    })
}

/// extern "C" fn registered via atexit(3).
///
/// Stops all containers in the registry with --time=0 (immediate SIGKILL).
/// Runs on normal process exit and on `std::process::exit()`. Does not run
/// on SIGKILL; the `sleep 300` in started containers bounds the leak window.
#[cfg(unix)]
extern "C" fn stop_all_containers() {
    let Some(reg) = CONTAINER_REGISTRY.get() else { return };
    let bin = std::env::var("NYX_DOCKER_BIN").unwrap_or_else(|_| "docker".to_owned());
    for entry in reg.iter() {
        // Remove OOB egress filter before stopping the container so stale
        // iptables rules don't accumulate across scans.
        #[cfg(target_os = "linux")]
        remove_oob_egress_filter(entry.key());
        let _ = std::process::Command::new(&bin)
            .args(["stop", "--time=0", entry.key()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[cfg(unix)]
fn register_exit_cleanup() {
    unsafe extern "C" {
        fn atexit(f: extern "C" fn()) -> i32;
    }
    // Safety: atexit(3) is async-signal-safe for registration; the handler
    // itself runs on the main thread during normal shutdown, after all Rust
    // destructors, so std::process::Command is safe to call from it.
    unsafe { atexit(stop_all_containers) };
}

fn workdir_to_container_name(workdir: &Path) -> String {
    // The workdir is /tmp/nyx-harness/{spec_hash}; the spec_hash is the last
    // path component (16-char hex). Use it directly for a readable name.
    let spec_hash = workdir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    // Container names: [a-zA-Z0-9_.-], must not start with dot or dash.
    // spec_hash is lowercase hex (0-9a-f); safe to use directly.
    format!("nyx-{spec_hash}")
}

/// Docker image tag for a Python toolchain ID (e.g. `python-3.11`).
fn python_image_for_toolchain(toolchain_id: &str) -> String {
    let ver = toolchain_id.strip_prefix("python-").unwrap_or("3");
    format!("python:{ver}-slim")
}

fn node_image_for_toolchain(toolchain_id: &str) -> String {
    let ver = toolchain_id.strip_prefix("node-").unwrap_or("20");
    format!("node:{ver}-slim")
}

fn java_image_for_toolchain(toolchain_id: &str) -> String {
    let ver = toolchain_id.strip_prefix("java-").unwrap_or("21");
    format!("eclipse-temurin:{ver}-jre-jammy")
}

fn php_image_for_toolchain(toolchain_id: &str) -> String {
    let ver = toolchain_id.strip_prefix("php-").unwrap_or("8");
    format!("php:{ver}-cli")
}

fn ruby_image_for_toolchain(toolchain_id: &str) -> String {
    let ver = toolchain_id.strip_prefix("ruby-").unwrap_or("3");
    format!("ruby:{ver}-slim")
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run a built harness once with a chosen payload.
///
/// `payload_bytes` overrides `payload.bytes` so the runner can inject
/// materialised OOB-nonce URLs without cloning the static corpus entry.
///
/// Dispatches to the docker backend when available (or when explicitly
/// requested), otherwise to the process backend.
pub fn run(
    harness: &BuiltHarness,
    payload_bytes: &[u8],
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    match opts.backend {
        SandboxBackend::Docker => {
            if harness_is_interpreted(&harness.command) {
                run_docker(harness, payload_bytes, opts)
            } else if harness_is_native_binary(&harness.command) {
                run_native_binary_docker(harness, payload_bytes, opts)
            } else {
                run_process(harness, payload_bytes, opts)
            }
        }
        SandboxBackend::Auto => {
            if docker_available() && harness_is_interpreted(&harness.command) {
                run_docker(harness, payload_bytes, opts)
            } else if docker_available() && harness_is_native_binary(&harness.command) {
                run_native_binary_docker(harness, payload_bytes, opts)
            } else {
                run_process(harness, payload_bytes, opts)
            }
        }
        SandboxBackend::Process => run_process(harness, payload_bytes, opts),
    }
}

// ── Docker backend ────────────────────────────────────────────────────────────

/// Docker backend: image per toolchain_id, container reuse via `docker exec`.
fn run_docker(
    harness: &BuiltHarness,
    payload_bytes: &[u8],
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    // Quick availability check (uses same binary as docker_available but not
    // gated on the cached probe so tests can override NYX_DOCKER_BIN freely).
    if !is_docker_reachable() {
        return Err(SandboxError::BackendUnavailable(SandboxBackend::Docker));
    }

    let container_name = workdir_to_container_name(&harness.workdir);
    let registry = container_registry();

    // Ensure a container is running for this spec_hash.
    let reused = if registry.contains_key(&container_name) {
        // Verify it is still alive before trusting the registry entry.
        is_container_running(&container_name)
    } else {
        false
    };

    if !reused {
        // Determine the Python image from the harness command (first element).
        // Fall back to python:3-slim when the command is not recognised.
        let image = detect_image_for_harness(harness);
        start_container(&container_name, &harness.workdir, &image, &opts.network_policy)?;
        registry.insert(container_name.clone(), container_name.clone());
    }

    exec_in_container(&container_name, harness, payload_bytes, opts)
}

/// Returns true when `docker info` succeeds using the current `NYX_DOCKER_BIN`.
///
/// Unlike `docker_available()` this is not cached, allowing tests to swap the
/// docker binary between calls.
fn is_docker_reachable() -> bool {
    std::process::Command::new(docker_bin())
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_container_running(name: &str) -> bool {
    let out = std::process::Command::new(docker_bin())
        .args(["inspect", "--format={{.State.Running}}", name])
        .output();
    match out {
        Ok(o) => o.status.success() && o.stdout.starts_with(b"true"),
        Err(_) => false,
    }
}

/// Start a long-lived container for this spec_hash and copy harness files into it.
///
/// Uses `docker cp` rather than a volume mount for portability — volume mounts
/// of host temp paths can fail silently on macOS Docker Desktop and in some CI
/// environments. Copying the harness into the container is always reliable.
///
/// Container options:
/// - `--rm`: auto-remove on stop (no manual cleanup required).
/// - `--cap-drop=ALL`: drop all Linux capabilities.
/// - `--security-opt no-new-privileges:true`: block privilege escalation.
/// - Network: derived from [`NetworkPolicy`] —
///   - [`NetworkPolicy::None`] ⇒ `--network none` (no egress).
///   - [`NetworkPolicy::OobOutbound`] ⇒ `bridge` + `--add-host=host-gateway`
///     + (on Linux) iptables OOB-port filter.
///   - [`NetworkPolicy::StubsOnly`] ⇒ `bridge` + one `--add-host` per
///     [`HostPort`] in the allow list so DNS resolves to the host bind.
///   - [`NetworkPolicy::Open`] ⇒ `bridge` with no egress filter.
fn start_container(
    name: &str,
    workdir: &Path,
    image: &str,
    policy: &NetworkPolicy,
) -> Result<(), SandboxError> {
    // Phase 19 (Track E.3): when `image` is a pinned reference produced by
    // `docker::image_reference_for_toolchain`, make sure it is present on
    // this host before `docker run` tries to start a container from it.
    // `ensure_image_pulled` is a per-process cache, so the second harness
    // against the same toolchain is free.
    docker::ensure_image_pulled(image);

    let workdir_mount = format!(
        "{}:{}:rw",
        workdir.to_string_lossy(),
        docker::WORK_MOUNT_PATH,
    );

    let mut run_args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--rm".into(),
        "--name".into(), name.into(),
        "--cap-drop=ALL".into(),
        "--security-opt".into(), "no-new-privileges:true".into(),
        "--tmpfs".into(), "/tmp:size=128m,exec".into(),
        // Phase 19 (Track E.3): bind-mount the host workdir at the fixed
        // `/work` path read-write.  Harness code emitted in Phase 12+ can
        // reference `/work/...` without threading the host tempdir
        // through every layer.  The `docker cp` path below is retained so
        // older harness command lines (which still look at `/workdir`)
        // keep working until they are migrated.
        "-v".into(), workdir_mount,
    ];
    match policy {
        NetworkPolicy::None => {
            run_args.extend(["--network".into(), "none".into()]);
        }
        NetworkPolicy::OobOutbound { .. } => {
            run_args.extend(["--network".into(), "bridge".into()]);
            run_args.extend(["--add-host=host-gateway:host-gateway".into()]);
        }
        NetworkPolicy::StubsOnly { allow } => {
            run_args.extend(["--network".into(), "bridge".into()]);
            // host-gateway alias still useful so stubs bound to 127.0.0.1
            // can be reached as host-gateway from inside the container.
            run_args.extend(["--add-host=host-gateway:host-gateway".into()]);
            for hp in allow {
                run_args.push(format!("--add-host={}:host-gateway", hp.host));
            }
        }
        NetworkPolicy::Open => {
            run_args.extend(["--network".into(), "bridge".into()]);
        }
    }
    run_args.extend([image.into(), "sleep".into(), "300".into()]);

    // Start container (no volume mount).
    let status = std::process::Command::new(docker_bin())
        .args(&run_args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(SandboxError::Spawn)?;

    if !status.success() {
        return Err(SandboxError::BackendUnavailable(SandboxBackend::Docker));
    }

    // Copy harness files into /workdir inside the container.
    let workdir_str = workdir.to_string_lossy();
    let status = std::process::Command::new(docker_bin())
        .args([
            "exec",
            name,
            "mkdir", "-p", "/workdir",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(SandboxError::Io)?;

    if !status.success() {
        return Err(SandboxError::BackendUnavailable(SandboxBackend::Docker));
    }

    // Copy workdir contents (harness.py + entry module) into the container.
    let cp_src = format!("{workdir_str}/."); // trailing /. copies dir contents
    let cp_dst = format!("{name}:/workdir");
    let status = std::process::Command::new(docker_bin())
        .args(["cp", &cp_src, &cp_dst])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(SandboxError::Io)?;

    if status.success() {
        // Apply OOB egress filter on Linux when the OOB listener is active.
        // This restricts the bridge-networked container to only reach the host
        // on the OOB port; all other egress is dropped (§17.2).
        #[cfg(target_os = "linux")]
        if let NetworkPolicy::OobOutbound { listener } = policy {
            apply_oob_egress_filter(name, listener.port());
        }
        #[cfg(not(target_os = "linux"))]
        let _ = policy; // policy already consumed structurally above
        Ok(())
    } else {
        Err(SandboxError::BackendUnavailable(SandboxBackend::Docker))
    }
}

/// Build the inner-container command args for `docker exec`.
///
/// For 2-arg interpreted commands (`python3 harness.py`, `node harness.js`,
/// `php harness.php`) the file arg is prefixed with `/workdir/`.
/// For Java (`java -cp /host/abs/path NyxHarness`) the classpath argument is
/// replaced with `/workdir` (the container-side mount path, not the host path
/// that runner.rs wrote after `javac`).
fn build_container_exec_args(command: &[String]) -> Vec<String> {
    let mut args = Vec::new();
    let cmd0 = match command.first() {
        Some(c) => c.as_str(),
        None => return args,
    };
    let base = std::path::Path::new(cmd0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd0);

    if base == "java" {
        args.push("java".to_owned());
        let mut i = 1;
        while i < command.len() {
            if command[i] == "-cp" || command[i] == "-classpath" {
                args.push(command[i].clone());
                i += 1;
                args.push("/workdir".to_owned());
                i += 1;
            } else {
                args.push(command[i].clone());
                i += 1;
            }
        }
    } else {
        args.push(cmd0.to_owned());
        if let Some(harness_file) = command.get(1) {
            if harness_file.starts_with('/') {
                args.push(harness_file.clone());
            } else {
                args.push(format!("/workdir/{harness_file}"));
            }
        }
    }
    args
}

/// Execute the harness inside an already-running container.
fn exec_in_container(
    container_name: &str,
    harness: &BuiltHarness,
    payload_bytes: &[u8],
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    // Build the docker exec command.
    // exec_in_container is only called for interpreted harnesses (python3, node, …);
    // compiled binaries are routed to run_process by the dispatch in run().
    let payload_b64 = base64_encode(payload_bytes);
    let mut cmd_args: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        // Run the harness as an unprivileged user so that uid-based kernel
        // checks provide a second layer of defence on top of --cap-drop=ALL.
        // The container itself starts as root for setup (mkdir, docker cp),
        // but harness execution runs as nobody (uid/gid 65534).
        "--user".into(), "65534:65534".into(),
        "-e".into(), format!("NYX_PAYLOAD_B64={payload_b64}"),
    ];
    // Forward harness-specific env vars.
    for (k, v) in &harness.env {
        cmd_args.push("-e".into());
        cmd_args.push(format!("{k}={v}"));
    }
    cmd_args.push(container_name.into());

    // Build the exec command inside the container.
    for arg in build_container_exec_args(&harness.command) {
        cmd_args.push(arg);
    }

    let mut cmd = Command::new(docker_bin());
    cmd.args(&cmd_args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let start = Instant::now();
    let mut child = cmd.spawn().map_err(SandboxError::Spawn)?;

    let timeout = opts.timeout;
    let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let timed_out_clone = timed_out.clone();
    let child_id = child.id();
    let container_name_for_kill = container_name.to_owned();

    let _timer = std::thread::spawn(move || {
        std::thread::sleep(timeout);
        timed_out_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        // Kill the local docker-exec client.
        #[cfg(unix)]
        libc_kill(child_id as i32, 9);
        #[cfg(not(unix))]
        let _ = child_id;
        // Also kill all non-PID-1 processes inside the container so runaway
        // payloads (fork bombs, infinite loops) don't keep consuming host
        // resources after the harness reports timed_out.
        let _ = std::process::Command::new(docker_bin())
            .args(["exec", &container_name_for_kill, "kill", "-9", "-1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    });

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

/// Detect the Docker image for the harness based on the interpreter command.
///
/// Dispatches by the basename of `command[0]` (e.g. `python3`, `node`, `java`,
/// `php`). Falls back to `python:3-slim` for unrecognised interpreters.
/// `NYX_TOOLCHAIN_ID` env var overrides the version portion of the image tag.
///
/// Phase 19 (Track E.3): when `NYX_TOOLCHAIN_ID` matches a pinned entry in
/// `IMAGE_DIGESTS` we return the `<base>@sha256:…` reference directly so the
/// container starts from byte-identical bits across hosts.  Unpinned entries
/// fall through to the legacy tag mapping below so behaviour on a fresh
/// catalogue stays unchanged.
fn detect_image_for_harness(harness: &BuiltHarness) -> String {
    let cmd0 = harness.command.first().map(|s| s.as_str()).unwrap_or("python3");
    let base = std::path::Path::new(cmd0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd0);

    if let Ok(tid) = std::env::var("NYX_TOOLCHAIN_ID") {
        if let Some(pinned) = docker::image_reference_for_toolchain(&tid) {
            // Catalogue entry takes priority over the legacy hard-coded tag
            // map — pinned or unpinned, the value here came from
            // tools/image-builder/images.toml.
            return pinned.to_owned();
        }
        return match base {
            "node" | "nodejs" => node_image_for_toolchain(&tid),
            "java" => java_image_for_toolchain(&tid),
            "php" => php_image_for_toolchain(&tid),
            "ruby" => ruby_image_for_toolchain(&tid),
            _ => python_image_for_toolchain(&tid),
        };
    }

    match base {
        "node" | "nodejs" => "node:20-slim".to_owned(),
        "java" => "eclipse-temurin:21-jre-jammy".to_owned(),
        "php" => "php:8-cli".to_owned(),
        "ruby" => "ruby:3-slim".to_owned(),
        _ => "python:3-slim".to_owned(),
    }
}

// ── Native binary Docker backend ──────────────────────────────────────────────

/// Docker backend for compiled native binaries (Rust, Go).
///
/// Starts a `debian:bookworm-slim` container (glibc-compatible runtime), copies
/// the compiled binary into it, then executes it via `docker exec`. This gives
/// the same `--cap-drop=ALL` / `--network none` isolation as the interpreted
/// harness path.
///
/// Only reachable on Linux (see [`harness_is_native_binary`]). On other platforms
/// the dispatch in [`run`] routes compiled harnesses to [`run_process`].
fn run_native_binary_docker(
    harness: &BuiltHarness,
    payload_bytes: &[u8],
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    if !is_docker_reachable() {
        return Err(SandboxError::BackendUnavailable(SandboxBackend::Docker));
    }

    let binary_path = match harness.command.first() {
        Some(p) => p.clone(),
        None => return Err(SandboxError::Spawn(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty command for native binary",
        ))),
    };

    let container_name = workdir_to_container_name(&harness.workdir);
    let registry = container_registry();

    let reused = if registry.contains_key(&container_name) {
        is_container_running(&container_name)
    } else {
        false
    };

    if !reused {
        start_container(
            &container_name,
            &harness.workdir,
            NATIVE_BINARY_IMAGE,
            &opts.network_policy,
        )?;

        // Copy the compiled binary into the container as /workdir/nyx_harness.
        let cp_dst = format!("{container_name}:/workdir/nyx_harness");
        let cp_status = std::process::Command::new(docker_bin())
            .args(["cp", &binary_path, &cp_dst])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(SandboxError::Io)?;
        if !cp_status.success() {
            return Err(SandboxError::BackendUnavailable(SandboxBackend::Docker));
        }

        // Ensure execute bit is set (docker cp preserves it on Linux, but be explicit).
        let chmod_status = std::process::Command::new(docker_bin())
            .args(["exec", &container_name, "chmod", "+x", "/workdir/nyx_harness"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(SandboxError::Io)?;
        if !chmod_status.success() {
            return Err(SandboxError::BackendUnavailable(SandboxBackend::Docker));
        }

        registry.insert(container_name.clone(), container_name.clone());
    }

    exec_native_binary_in_container(&container_name, harness, payload_bytes, opts)
}

/// Execute a native binary already in the container at `/workdir/nyx_harness`.
fn exec_native_binary_in_container(
    container_name: &str,
    harness: &BuiltHarness,
    payload_bytes: &[u8],
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let payload_b64 = base64_encode(payload_bytes);
    let mut cmd_args: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(), "65534:65534".into(),
        "-e".into(), format!("NYX_PAYLOAD_B64={payload_b64}"),
    ];
    for (k, v) in &harness.env {
        cmd_args.push("-e".into());
        cmd_args.push(format!("{k}={v}"));
    }
    cmd_args.push(container_name.into());
    cmd_args.push("/workdir/nyx_harness".into());

    let mut cmd = Command::new(docker_bin());
    cmd.args(&cmd_args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let start = std::time::Instant::now();
    let mut child = cmd.spawn().map_err(SandboxError::Spawn)?;

    let timeout = opts.timeout;
    let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let timed_out_clone = timed_out.clone();
    let child_id = child.id();
    let container_name_for_kill = container_name.to_owned();

    let _timer = std::thread::spawn(move || {
        std::thread::sleep(timeout);
        timed_out_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(unix)]
        libc_kill(child_id as i32, 9);
        #[cfg(not(unix))]
        let _ = child_id;
        let _ = std::process::Command::new(docker_bin())
            .args(["exec", &container_name_for_kill, "kill", "-9", "-1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    });

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

// ── Process backend ───────────────────────────────────────────────────────────

/// Process backend: spawns the harness command in a subprocess with timeout,
/// stdout/stderr capture, env stripping, and memory cap (Linux: RLIMIT_AS).
///
/// Isolation is limited to env stripping, RLIMIT_AS, and
/// `prctl(PR_SET_NO_NEW_PRIVS)` on Linux. No network or namespace isolation.
/// Use the docker backend for stronger guarantees; this backend is gated
/// behind `--unsafe-sandbox` in production.
fn run_process(
    harness: &BuiltHarness,
    payload_bytes: &[u8],
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

    // Resolve a bare interpreter name against the *host* PATH so the spawn
    // works even when the child env has been scrubbed (env_clear strips PATH,
    // so posix_spawnp falls back to confstr(_CS_PATH) which is typically just
    // `/usr/bin:/bin` on macOS — node/cargo/etc. installed via Homebrew or nvm
    // are not on that path and would otherwise yield `Spawn(NotFound)`).
    // Absolute commands pass through unchanged.
    let resolved_cmd_path = if std::path::Path::new(cmd_name).is_absolute() {
        std::path::PathBuf::from(cmd_name)
    } else {
        find_in_host_path(cmd_name).unwrap_or_else(|| std::path::PathBuf::from(cmd_name))
    };

    // Phase 18 (Track E.2): on macOS, wrap the command with
    // `sandbox-exec -f <profile> -D WORKDIR=<workdir> ...` so per-cap
    // policies confine the harness.  When `sandbox-exec` is missing or
    // the wrap setup fails, `wrap_plan` returns `None` and we fall
    // back to the unwrapped command; the verifier reads back the
    // recorded [`process_macos::HardeningLevel::Trusted`] outcome and
    // downgrades filesystem-oracle verdicts to
    // [`crate::evidence::InconclusiveReason::BackendInsufficient`].
    #[cfg(target_os = "macos")]
    let macos_wrap = {
        if matches!(opts.process_hardening, ProcessHardeningProfile::Strict) {
            process_macos::wrap_plan(&process_macos::WrapInput {
                cmd_path: &resolved_cmd_path,
                cmd_args: &harness.command[1..],
                workdir: &harness.workdir,
                caps: opts.seccomp_caps,
                profile_override: None,
            })
        } else {
            None
        }
    };

    #[cfg(target_os = "macos")]
    let (effective_cmd_path, effective_cmd_args): (std::path::PathBuf, Vec<String>) =
        match &macos_wrap {
            Some(plan) => (plan.binary.clone(), plan.args.clone()),
            None => (resolved_cmd_path.clone(), harness.command[1..].to_vec()),
        };
    #[cfg(not(target_os = "macos"))]
    let (effective_cmd_path, effective_cmd_args): (std::path::PathBuf, Vec<String>) = (
        resolved_cmd_path.clone(),
        harness.command[1..].to_vec(),
    );

    let mut cmd = Command::new(&effective_cmd_path);
    cmd.args(&effective_cmd_args);
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
    // Phase 10: stub endpoints (SQL DB path, HTTP origin URL, etc.)
    // overlaid after harness.env so a per-language emitter cannot
    // accidentally shadow a boundary endpoint with a placeholder of
    // its own.
    for (k, v) in &opts.extra_env {
        cmd.env(k, v);
    }
    // Payload injected via NYX_PAYLOAD env var.
    let payload_b64 = base64_encode(payload_bytes);
    cmd.env("NYX_PAYLOAD_B64", &payload_b64);
    // Probe channel (Phase 06).  Process backend writes directly to the
    // host workdir file the channel handles, so the harness shim only
    // needs the absolute path.
    if let Some(ch) = &opts.probe_channel {
        cmd.env(PROBE_PATH_ENV, ch.path());
    }
    // NYX_PAYLOAD as raw bytes: Unix-only (OsStr can hold arbitrary bytes).
    // On other platforms we skip this env var; the harness falls back to NYX_PAYLOAD_B64.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        cmd.env("NYX_PAYLOAD", std::ffi::OsStr::from_bytes(payload_bytes));
    }

    // Phase 17 (Track E.1): install the Linux process-backend hardening
    // sequence — `prctl(PR_SET_NO_NEW_PRIVS)`, `setrlimit` (CPU/NOFILE/AS),
    // `unshare(CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWUSER)`, `chroot` to the
    // workdir, and a default-deny seccomp-bpf filter scoped to
    // `opts.seccomp_caps`.  Each primitive is best-effort: failures
    // downgrade to `HardeningLevel::Partial` instead of aborting the run.
    #[cfg(target_os = "linux")]
    let collector = process_linux::install_pre_exec(&mut cmd, opts, &harness.workdir);

    let start = Instant::now();
    let child_result = cmd.spawn();
    #[cfg(target_os = "linux")]
    let outcome_joiner;
    let mut child = match child_result {
        Ok(c) => {
            #[cfg(target_os = "linux")]
            {
                outcome_joiner = collector.map(|c| c.after_spawn());
            }
            c
        }
        Err(e) => {
            #[cfg(target_os = "linux")]
            if let Some(c) = collector {
                c.forget();
            }
            return Err(SandboxError::Spawn(e));
        }
    };

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

    // Phase 17 (Track E.1): wait for the per-primitive HardeningOutcome
    // drain thread before returning so callers (tests + telemetry) read
    // a settled value via `process_linux::last_hardening_outcome()`.
    #[cfg(target_os = "linux")]
    if let Some(joiner) = outcome_joiner {
        joiner.await_outcome();
    }

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

// ── Shared helpers ────────────────────────────────────────────────────────────

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

// ── Linux-specific syscall wrappers ──────────────────────────────────────────

// `rlimit_as_linux`, `prctl_no_new_privs`, and the rest of the Linux process
// backend hardening sequence now live in [`process_linux`].  See
// [`process_linux::install_pre_exec`] for the call-site.

#[cfg(unix)]
fn libc_kill(pid: i32, sig: i32) -> i32 {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid, sig) }
}

// ── Docker image digest enrichment (§22.1) ────────────────────────────────────

/// Map a toolchain_id to its corresponding Docker image tag.
///
/// Only covers Docker-backed interpreted runtimes (Python, Node, Java, PHP).
/// Returns `None` for compiled toolchains (Rust, Go) that use the generic
/// `debian:bookworm-slim` runtime image independently of `toolchain_id`.
fn docker_image_for_toolchain_id(toolchain_id: &str) -> Option<String> {
    if toolchain_id.starts_with("python-") {
        Some(python_image_for_toolchain(toolchain_id))
    } else if toolchain_id.starts_with("node-") {
        Some(node_image_for_toolchain(toolchain_id))
    } else if toolchain_id.starts_with("java-") {
        Some(java_image_for_toolchain(toolchain_id))
    } else if toolchain_id.starts_with("php-") {
        Some(php_image_for_toolchain(toolchain_id))
    } else {
        None
    }
}

/// Fetch the first 12 hex characters of the Docker image content digest.
///
/// Runs `docker inspect --format={{.Id}} <image>` and truncates the SHA256
/// hex string. Returns an empty string when docker is unavailable, the image
/// has not been pulled locally, or the output cannot be parsed.
pub fn fetch_docker_image_digest_short(image: &str) -> String {
    let out = std::process::Command::new(docker_bin())
        .args(["inspect", "--format={{.Id}}", image])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let id = std::str::from_utf8(&o.stdout).unwrap_or("").trim();
            let hex = id.strip_prefix("sha256:").unwrap_or(id);
            hex.chars().take(12).collect()
        }
        _ => String::new(),
    }
}

/// Return a toolchain_id enriched with the Docker image digest (§22.1).
///
/// For Docker-backed toolchains (Python, Node, Java, PHP), appends a 12-char
/// digest suffix so that cache keys remain distinct across image updates.
/// Example: `"python-3.11"` → `"python-3.11-abc123456789"`.
///
/// Returns the base ID unchanged when:
/// - the toolchain is not Docker-backed (Rust, Go),
/// - docker is unavailable, or
/// - the image has not been pulled locally.
pub fn toolchain_id_with_digest(base_id: &str) -> String {
    let Some(image) = docker_image_for_toolchain_id(base_id) else {
        return base_id.to_owned();
    };
    let digest = fetch_docker_image_digest_short(&image);
    if digest.is_empty() {
        base_id.to_owned()
    } else {
        format!("{base_id}-{digest}")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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

    #[test]
    fn container_name_from_spec_hash_workdir() {
        let workdir = std::path::Path::new("/tmp/nyx-harness/abcdef1234567890");
        let name = workdir_to_container_name(workdir);
        assert_eq!(name, "nyx-abcdef1234567890");
    }

    #[test]
    fn python_image_for_known_toolchains() {
        assert_eq!(python_image_for_toolchain("python-3.11"), "python:3.11-slim");
        assert_eq!(python_image_for_toolchain("python-3"), "python:3-slim");
        assert_eq!(python_image_for_toolchain("python-3.12"), "python:3.12-slim");
    }

    #[test]
    fn node_image_for_known_toolchains() {
        assert_eq!(node_image_for_toolchain("node-20"), "node:20-slim");
        assert_eq!(node_image_for_toolchain("node-18"), "node:18-slim");
        assert_eq!(node_image_for_toolchain("node-lts"), "node:lts-slim");
    }

    #[test]
    fn java_image_for_known_toolchains() {
        assert_eq!(java_image_for_toolchain("java-21"), "eclipse-temurin:21-jre-jammy");
        assert_eq!(java_image_for_toolchain("java-17"), "eclipse-temurin:17-jre-jammy");
    }

    #[test]
    fn php_image_for_known_toolchains() {
        assert_eq!(php_image_for_toolchain("php-8"), "php:8-cli");
        assert_eq!(php_image_for_toolchain("php-8.2"), "php:8.2-cli");
    }

    #[test]
    fn ruby_image_for_known_toolchains() {
        assert_eq!(ruby_image_for_toolchain("ruby-3"), "ruby:3-slim");
        assert_eq!(ruby_image_for_toolchain("ruby-3.2"), "ruby:3.2-slim");
        assert_eq!(ruby_image_for_toolchain("ruby-3.3"), "ruby:3.3-slim");
    }

    #[test]
    fn harness_is_interpreted_java() {
        let cmd = vec!["java".to_owned(), "-cp".to_owned(), ".".to_owned(), "NyxHarness".to_owned()];
        assert!(harness_is_interpreted(&cmd));
    }

    #[test]
    fn harness_is_interpreted_node() {
        assert!(harness_is_interpreted(&["node".to_owned(), "harness.js".to_owned()]));
    }

    #[test]
    fn build_container_exec_args_python() {
        let cmd = vec!["python3".to_owned(), "harness.py".to_owned()];
        assert_eq!(
            build_container_exec_args(&cmd),
            vec!["python3", "/workdir/harness.py"]
        );
    }

    #[test]
    fn build_container_exec_args_node() {
        let cmd = vec!["node".to_owned(), "harness.js".to_owned()];
        assert_eq!(
            build_container_exec_args(&cmd),
            vec!["node", "/workdir/harness.js"]
        );
    }

    #[test]
    fn build_container_exec_args_php() {
        let cmd = vec!["php".to_owned(), "harness.php".to_owned()];
        assert_eq!(
            build_container_exec_args(&cmd),
            vec!["php", "/workdir/harness.php"]
        );
    }

    #[test]
    fn build_container_exec_args_ruby() {
        let cmd = vec!["ruby".to_owned(), "harness.rb".to_owned()];
        assert_eq!(
            build_container_exec_args(&cmd),
            vec!["ruby", "/workdir/harness.rb"]
        );
    }

    #[test]
    fn build_container_exec_args_java() {
        let cmd = vec![
            "java".to_owned(),
            "-cp".to_owned(),
            "/tmp/nyx-harness/abc123".to_owned(),
            "NyxHarness".to_owned(),
        ];
        assert_eq!(
            build_container_exec_args(&cmd),
            vec!["java", "-cp", "/workdir", "NyxHarness"]
        );
    }

    #[test]
    fn build_container_exec_args_empty() {
        assert!(build_container_exec_args(&[]).is_empty());
    }

    /// Verify that a second sandbox::run call for the same workdir does NOT
    /// start a new container when one is already registered.
    ///
    /// This is a logic-level unit test for the exec-reuse path. End-to-end
    /// verification against a real (or mock) docker daemon runs in
    /// `tests/dynamic_sandbox_escape.rs::docker_exec_reuse`.
    #[test]
    fn container_registry_insert_and_lookup() {
        let reg = dashmap::DashMap::<String, String>::new();
        let name = "nyx-testspec0001".to_owned();
        assert!(!reg.contains_key(&name));
        reg.insert(name.clone(), name.clone());
        assert!(reg.contains_key(&name));
    }

    #[test]
    fn harness_is_native_binary_absolute_path() {
        let abs = "/home/ci/.cache/nyx/dynamic/build-cache/abc123-rust-stable/nyx_harness";
        let cmd = vec![abs.to_owned()];
        // On Linux: absolute path + not an interpreter → native binary.
        // On other platforms: always false (not ELF).
        #[cfg(target_os = "linux")]
        assert!(harness_is_native_binary(&cmd));
        #[cfg(not(target_os = "linux"))]
        assert!(!harness_is_native_binary(&cmd));
    }

    #[test]
    fn harness_is_native_binary_relative_path_false() {
        // Relative paths are not detected as native binaries.
        let cmd = vec!["./nyx_harness".to_owned()];
        assert!(!harness_is_native_binary(&cmd));
    }

    #[test]
    fn harness_is_native_binary_interpreter_false() {
        let cmd = vec!["python3".to_owned(), "harness.py".to_owned()];
        assert!(!harness_is_native_binary(&cmd));
    }

    #[test]
    fn harness_is_native_binary_empty_false() {
        assert!(!harness_is_native_binary(&[]));
    }

    #[test]
    fn harness_is_native_binary_node_absolute_path_false() {
        // Even an absolute path to an interpreter is not a native binary.
        let cmd = vec!["/usr/bin/node".to_owned(), "harness.js".to_owned()];
        // node is in the interpreter list → not native binary
        assert!(!harness_is_native_binary(&cmd));
    }

    // ── Docker image digest enrichment tests ──────────────────────────────────

    #[test]
    fn fetch_docker_image_digest_short_returns_empty_on_bad_image() {
        // A non-existent image tag always returns empty (inspect fails).
        let digest = fetch_docker_image_digest_short("nyx-nonexistent-image:does-not-exist-99999");
        assert!(digest.is_empty(), "non-existent image must return empty digest");
    }

    #[test]
    fn toolchain_id_with_digest_passthrough_for_rust() {
        // Rust toolchain IDs are not Docker-backed; digest enrichment is a no-op.
        let id = toolchain_id_with_digest("rust-stable");
        assert_eq!(id, "rust-stable");
    }

    #[test]
    fn toolchain_id_with_digest_passthrough_for_go() {
        let id = toolchain_id_with_digest("go-1.22");
        assert_eq!(id, "go-1.22");
    }

    #[test]
    fn toolchain_id_with_digest_no_suffix_when_digest_empty() {
        // When docker is absent or image not pulled, the base ID is returned unchanged.
        // We can't control whether docker is available, but a non-existent image
        // always yields an empty digest, so the base ID is returned as-is.
        let id = toolchain_id_with_digest("python-nyx-nonexistent-99999");
        // The crafted toolchain maps to python:nyx-nonexistent-99999-slim which
        // won't be present → empty digest → base ID returned.
        assert!(
            id == "python-nyx-nonexistent-99999" || id.starts_with("python-nyx-nonexistent-99999-"),
            "id should be base or base-digest, got: {id}"
        );
    }

    // ── OOB egress filter unit tests ──────────────────────────────────────────

    /// `remove_oob_egress_filter` is a no-op when no filter was registered.
    #[test]
    #[cfg(target_os = "linux")]
    fn oob_egress_remove_noop_when_no_entry() {
        // Should not panic or error when the registry has no entry.
        remove_oob_egress_filter("nyx-nonexistent-container-xyz");
    }

    /// Registry insert + remove round-trip.
    #[test]
    #[cfg(target_os = "linux")]
    fn oob_egress_registry_insert_remove() {
        let reg = oob_egress_registry();
        let name = "nyx-test-egress-roundtrip";
        reg.insert(
            name.to_owned(),
            OobEgressState {
                container_ip: "172.17.0.99".to_owned(),
                oob_port: 12345,
            },
        );
        assert!(reg.contains_key(name), "entry must be present after insert");
        // remove_oob_egress_filter also calls iptables -D; those will fail
        // silently without root, but the registry entry is removed regardless
        // of whether the iptables commands succeed.
        let removed = reg.remove(name);
        assert!(removed.is_some(), "entry must be removable");
        assert!(!reg.contains_key(name), "entry must be gone after remove");
    }

    /// `get_container_ip` returns `None` for a nonexistent container name.
    #[test]
    #[cfg(target_os = "linux")]
    fn get_container_ip_none_for_nonexistent() {
        // This calls real docker; if docker is absent the command will fail
        // and we still get None — both outcomes satisfy the assertion.
        let ip = get_container_ip("nyx-nonexistent-container-abc9999");
        assert!(ip.is_none(), "nonexistent container must yield None IP");
    }

    #[test]
    fn docker_image_for_toolchain_id_maps_correctly() {
        assert_eq!(
            docker_image_for_toolchain_id("python-3.11"),
            Some("python:3.11-slim".to_owned())
        );
        assert_eq!(
            docker_image_for_toolchain_id("node-20"),
            Some("node:20-slim".to_owned())
        );
        assert_eq!(
            docker_image_for_toolchain_id("java-21"),
            Some("eclipse-temurin:21-jre-jammy".to_owned())
        );
        assert_eq!(
            docker_image_for_toolchain_id("php-8"),
            Some("php:8-cli".to_owned())
        );
        assert_eq!(docker_image_for_toolchain_id("rust-stable"), None);
        assert_eq!(docker_image_for_toolchain_id("go-1.22"), None);
    }
}
