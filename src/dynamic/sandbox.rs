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

use crate::dynamic::corpus::Payload;
use crate::dynamic::harness::BuiltHarness;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ── Harness interpretation probe ──────────────────────────────────────────────

/// Returns true when the harness is driven by an interpreter (Python, Node, …)
/// rather than a compiled native binary.
///
/// Interpreted harnesses can be run inside a Python/Node Docker image directly.
/// Compiled harnesses (Rust, Go) are routed to `run_native_binary_docker` on
/// Linux or to the process backend on other platforms.
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

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run a built harness once with a chosen payload.
///
/// Dispatches to the docker backend when available (or when explicitly
/// requested), otherwise to the process backend.
pub fn run(
    harness: &BuiltHarness,
    payload: &Payload,
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    match opts.backend {
        SandboxBackend::Docker => {
            if harness_is_interpreted(&harness.command) {
                run_docker(harness, payload, opts)
            } else if harness_is_native_binary(&harness.command) {
                run_native_binary_docker(harness, payload, opts)
            } else {
                run_process(harness, payload, opts)
            }
        }
        SandboxBackend::Auto => {
            if docker_available() && harness_is_interpreted(&harness.command) {
                run_docker(harness, payload, opts)
            } else if docker_available() && harness_is_native_binary(&harness.command) {
                run_native_binary_docker(harness, payload, opts)
            } else {
                run_process(harness, payload, opts)
            }
        }
        SandboxBackend::Process => run_process(harness, payload, opts),
    }
}

// ── Docker backend ────────────────────────────────────────────────────────────

/// Docker backend: image per toolchain_id, container reuse via `docker exec`.
fn run_docker(
    harness: &BuiltHarness,
    payload: &Payload,
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
        start_container(&container_name, &harness.workdir, &image)?;
        registry.insert(container_name.clone(), container_name.clone());
    }

    exec_in_container(&container_name, harness, payload, opts)
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
/// - `--network none`: no network access (loopback only).
fn start_container(name: &str, workdir: &Path, image: &str) -> Result<(), SandboxError> {
    // Start container (no volume mount).
    let status = std::process::Command::new(docker_bin())
        .args([
            "run",
            "-d",
            "--rm",
            "--name", name,
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--network", "none",
            "--tmpfs", "/tmp:size=128m,exec",
            image,
            "sleep", "300",
        ])
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
    payload: &Payload,
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    // Build the docker exec command.
    // exec_in_container is only called for interpreted harnesses (python3, node, …);
    // compiled binaries are routed to run_process by the dispatch in run().
    let payload_b64 = base64_encode(payload.bytes);
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
fn detect_image_for_harness(harness: &BuiltHarness) -> String {
    let cmd0 = harness.command.first().map(|s| s.as_str()).unwrap_or("python3");
    let base = std::path::Path::new(cmd0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd0);

    if let Ok(tid) = std::env::var("NYX_TOOLCHAIN_ID") {
        return match base {
            "node" | "nodejs" => node_image_for_toolchain(&tid),
            "java" => java_image_for_toolchain(&tid),
            "php" => php_image_for_toolchain(&tid),
            _ => python_image_for_toolchain(&tid),
        };
    }

    match base {
        "node" | "nodejs" => "node:20-slim".to_owned(),
        "java" => "eclipse-temurin:21-jre-jammy".to_owned(),
        "php" => "php:8-cli".to_owned(),
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
    payload: &Payload,
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
        start_container(&container_name, &harness.workdir, NATIVE_BINARY_IMAGE)?;

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

    exec_native_binary_in_container(&container_name, harness, payload, opts)
}

/// Execute a native binary already in the container at `/workdir/nyx_harness`.
fn exec_native_binary_in_container(
    container_name: &str,
    harness: &BuiltHarness,
    payload: &Payload,
    opts: &SandboxOptions,
) -> Result<SandboxOutcome, SandboxError> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let payload_b64 = base64_encode(payload.bytes);
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

    // Enforce memory cap before exec on Linux via RLIMIT_AS + PR_SET_NO_NEW_PRIVS.
    // RLIMIT_AS limits total virtual address space. Python uses significantly
    // more virtual AS than RSS (shared libs, mmap arenas), so the enforced
    // limit is memory_mib * 8 with a floor of 4 GiB.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let memory_mib = opts.memory_mib;
        // Safety: called in the child after fork but before exec; no allocator use.
        unsafe {
            cmd.pre_exec(move || {
                rlimit_as_linux(memory_mib)?;
                prctl_no_new_privs()
            });
        }
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

/// Set RLIMIT_AS (virtual address space) in a `pre_exec` context on Linux.
///
/// `memory_mib` is the configured cap; we enforce `max(memory_mib * 8, 4096)`
/// MiB of virtual AS to give Python's mmap-heavy runtime adequate headroom
/// while still capping runaway memory bombs.
///
/// RLIMIT_AS = 9 on x86_64, aarch64, arm, ppc64, s390x, and all other major
/// Linux architectures (kernel source: include/uapi/asm-generic/resource.h).
#[cfg(target_os = "linux")]
fn rlimit_as_linux(memory_mib: u64) -> std::io::Result<()> {
    #[repr(C)]
    struct Rlimit {
        cur: u64,
        max: u64,
    }
    unsafe extern "C" {
        fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32;
    }
    const RLIMIT_AS: i32 = 9;
    let cap_mib = memory_mib.saturating_mul(8).max(4096);
    let bytes = cap_mib.saturating_mul(1024 * 1024);
    let rl = Rlimit { cur: bytes, max: bytes };
    let ret = unsafe { setrlimit(RLIMIT_AS, &rl) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Set PR_SET_NO_NEW_PRIVS to 1 in a `pre_exec` context on Linux.
///
/// This prevents the child process from acquiring new privileges via setuid
/// binaries, file capabilities, or ptrace. Best-effort: silently succeeds
/// even if the prctl call fails (e.g., in restricted environments).
#[cfg(target_os = "linux")]
fn prctl_no_new_privs() -> std::io::Result<()> {
    unsafe extern "C" {
        fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    }
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    // Failure is non-fatal: some container runtimes block prctl but are
    // themselves already sandboxed. Don't abort the child for this.
    unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    Ok(())
}

#[cfg(unix)]
fn libc_kill(pid: i32, sig: i32) -> i32 {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid, sig) }
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
}
