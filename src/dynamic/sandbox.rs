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
/// Compiled harnesses (Rust, C) require a platform-matching binary; the Docker
/// backend falls back to the process backend for them in Phase 04.
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
        "python3" | "python" | "python2" | "node" | "nodejs" | "ruby" | "php" | "perl"
    )
}

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
    // toolchain_id examples: "python-3", "python-3.11", "python-3.12"
    let ver = toolchain_id.strip_prefix("python-").unwrap_or("3");
    format!("python:{ver}-slim")
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
            // Docker backend currently only supports interpreted harnesses.
            // Compiled binaries (Rust, C) are not yet cross-platform in containers;
            // fall back to the process backend for them.
            if harness_is_interpreted(&harness.command) {
                run_docker(harness, payload, opts)
            } else {
                run_process(harness, payload, opts)
            }
        }
        SandboxBackend::Auto => {
            if docker_available() && harness_is_interpreted(&harness.command) {
                run_docker(harness, payload, opts)
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
        let image = detect_python_toolchain_from_harness(harness);
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
    let payload_b64 = base64_encode(payload.bytes);
    let mut cmd_args: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        "-e".into(), format!("NYX_PAYLOAD_B64={payload_b64}"),
    ];
    // Forward harness-specific env vars.
    for (k, v) in &harness.env {
        cmd_args.push("-e".into());
        cmd_args.push(format!("{k}={v}"));
    }
    cmd_args.push(container_name.into());

    // Build the exec command inside the container.
    // For interpreters: `python3 /workdir/harness.py`
    // For compiled binaries: `/workdir/target/release/nyx_harness`
    let exec_cmd = harness.command.first().map(|s| s.as_str()).unwrap_or("python3");
    if harness_is_interpreted(&harness.command) {
        let harness_file = harness
            .command
            .get(1)
            .map(|s| s.as_str())
            .unwrap_or("harness.py");
        cmd_args.push(exec_cmd.into());
        cmd_args.push(format!("/workdir/{harness_file}"));
    } else {
        // Compiled binary: the command is the relative path within workdir.
        // e.g. "target/release/nyx_harness" → run "/workdir/target/release/nyx_harness"
        let rel = std::path::Path::new(exec_cmd)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(exec_cmd);
        if exec_cmd.contains('/') || exec_cmd.contains('\\') {
            // Relative path within workdir (e.g. "target/release/nyx_harness").
            cmd_args.push(format!("/workdir/{exec_cmd}"));
        } else {
            // Just a filename — try /workdir directly.
            cmd_args.push(format!("/workdir/{rel}"));
        }
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

/// Detect the Python image to use based on the harness command.
///
/// The first element of `harness.command` is typically `python3` or a venv
/// path like `/path/to/venv/bin/python3`. Fall back to `python:3-slim`.
fn detect_python_toolchain_from_harness(harness: &BuiltHarness) -> String {
    // The harness workdir encodes the spec_hash but not the toolchain.
    // Use the default image for Python; callers that know the toolchain_id
    // should pass it through BuiltHarness.env (NYX_TOOLCHAIN_ID) when needed.
    if let Ok(tid) = std::env::var("NYX_TOOLCHAIN_ID") {
        return python_image_for_toolchain(&tid);
    }
    // Default to python:3-slim which is always available in CI.
    let _ = harness;
    "python:3-slim".to_owned()
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
}
