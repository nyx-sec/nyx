//! Phase 17 (Track E.1) — Linux process backend hardening.
//!
//! Owns the `pre_exec` sequence applied to every harness child started by
//! [`super::run_process`] on Linux:
//!
//! 1. `prctl(PR_SET_NO_NEW_PRIVS)` — block setuid / file-cap escalation.
//! 2. `setrlimit(RLIMIT_CPU)` — cap CPU time so a runaway payload exits.
//! 3. `setrlimit(RLIMIT_NOFILE)` — cap open fds; the harness receives only
//!    a small number of stdio + probe fds from the parent.
//! 4. `setrlimit(RLIMIT_AS)` — cap virtual address space; multiplied by 8
//!    with a 4 GiB floor so interpreted runtimes still start.
//! 5. `unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS)` — drop the
//!    host PID, mount, and user namespace views.
//! 6. `chroot(workdir)` + `chdir("/")` — isolate filesystem reach to the
//!    harness workdir; payloads that try to read `/etc/passwd` see the
//!    harness root, not the host one.
//! 7. seccomp-bpf default-deny filter scoped to the cap bits the spec
//!    actually exercises (see [`super::seccomp`]).
//!
//! Each primitive is best-effort: failures are recorded into the per-
//! child [`HardeningOutcome`] file the parent reads back after exec, so
//! the verifier can downgrade to [`HardeningLevel::Partial`] without
//! aborting the harness run.
//!
//! The pre_exec callback runs in the child between fork(2) and execve(2)
//! — no Rust allocator use, no heap-borrowing closures.  Anything the
//! parent needs to know is shipped through an `O_CLOEXEC` pipe the
//! parent owns the read end of: the child writes one [`HardeningOutcome`]
//! record into it, execve(2) drops the write end, and the parent's
//! drain thread sees EOF and records the outcome.

use crate::dynamic::sandbox::seccomp;
use crate::dynamic::sandbox::seccomp::bpf::SockFilter;
use crate::dynamic::sandbox::{ProcessHardeningProfile, SandboxOptions};
use std::io::Read;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

// ── HardeningLevel reporting ─────────────────────────────────────────────────

/// Coarse summary of which Phase 17 primitives applied successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningLevel {
    /// Standard profile selected — only no-new-privs + RLIMIT_AS were
    /// installed (no Phase 17 hardening attempted).
    Baseline,
    /// All requested primitives applied successfully.
    Full,
    /// At least one primitive failed (typically because the process is
    /// already inside a sandbox that disallows e.g. `unshare`).
    Partial,
    /// Every primitive failed; the harness ran with no Phase 17
    /// hardening at all.
    None,
}

/// Per-primitive outcome captured by the child and read back by the
/// parent after `wait`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningOutcome {
    pub no_new_privs: PrimitiveStatus,
    pub rlimit_cpu: PrimitiveStatus,
    pub rlimit_nofile: PrimitiveStatus,
    pub rlimit_as: PrimitiveStatus,
    pub unshare: PrimitiveStatus,
    pub chroot: PrimitiveStatus,
    pub seccomp: PrimitiveStatus,
    pub profile: ProcessHardeningProfileTag,
}

impl Default for HardeningOutcome {
    fn default() -> Self {
        Self {
            no_new_privs: PrimitiveStatus::Skipped,
            rlimit_cpu: PrimitiveStatus::Skipped,
            rlimit_nofile: PrimitiveStatus::Skipped,
            rlimit_as: PrimitiveStatus::Skipped,
            unshare: PrimitiveStatus::Skipped,
            chroot: PrimitiveStatus::Skipped,
            seccomp: PrimitiveStatus::Skipped,
            profile: ProcessHardeningProfileTag::Standard,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PrimitiveStatus {
    /// Primitive was not requested by the active profile.
    #[default]
    Skipped,
    /// Primitive applied successfully.
    Applied,
    /// Primitive call returned an error; raw errno is captured below.
    Failed(i32),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProcessHardeningProfileTag {
    #[default]
    Standard,
    Strict,
}

impl HardeningOutcome {
    /// Coarse summary used for the `HardeningLevel` column.
    pub fn level(&self) -> HardeningLevel {
        if matches!(self.profile, ProcessHardeningProfileTag::Standard) {
            return HardeningLevel::Baseline;
        }
        let primitives = [
            self.no_new_privs,
            self.rlimit_cpu,
            self.rlimit_nofile,
            self.rlimit_as,
            self.unshare,
            self.chroot,
            self.seccomp,
        ];
        let applied = primitives.iter().filter(|s| matches!(s, PrimitiveStatus::Applied)).count();
        let failed = primitives.iter().filter(|s| matches!(s, PrimitiveStatus::Failed(_))).count();
        match (applied, failed) {
            (_, 0) => HardeningLevel::Full,
            (0, _) => HardeningLevel::None,
            _ => HardeningLevel::Partial,
        }
    }
}

// ── Last outcome registry (read back by tests + telemetry) ───────────────────

static LAST_OUTCOME: OnceLock<Mutex<Option<HardeningOutcome>>> = OnceLock::new();

fn outcome_cell() -> &'static Mutex<Option<HardeningOutcome>> {
    LAST_OUTCOME.get_or_init(|| Mutex::new(None))
}

fn record_outcome(outcome: HardeningOutcome) {
    if let Ok(mut g) = outcome_cell().lock() {
        *g = Some(outcome);
    }
}

/// Snapshot of the most-recent hardening outcome.  Returns `None` until
/// at least one [`install_pre_exec`] child has been spawned and waited
/// on.  Tests + telemetry read this after `wait_for_outcome` to get the
/// per-primitive status table.
pub fn last_hardening_outcome() -> Option<HardeningOutcome> {
    outcome_cell().lock().ok().and_then(|g| *g)
}

/// Reset the last-outcome slot.  Tests use this between cases so a stale
/// value from a prior spawn cannot leak into the assertion under test.
pub fn reset_last_hardening_outcome() {
    if let Ok(mut g) = outcome_cell().lock() {
        *g = None;
    }
}

// ── Status pipe between parent and child ─────────────────────────────────────

struct StatusPipe {
    write_fd: RawFd,
    read_fd: RawFd,
}

impl StatusPipe {
    fn new() -> std::io::Result<Self> {
        unsafe extern "C" {
            fn pipe2(pipefd: *mut i32, flags: i32) -> i32;
        }
        const O_CLOEXEC: i32 = 0o2_000_000;
        let mut fds = [-1_i32; 2];
        let ret = unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { write_fd: fds[1], read_fd: fds[0] })
    }
}

fn close_fd(fd: RawFd) {
    unsafe extern "C" {
        fn close(fd: i32) -> i32;
    }
    unsafe { close(fd) };
}

/// Drain `read_fd` into a `HardeningOutcome`.  Wire format is the
/// 15-byte fixed-width record produced by [`encode_outcome`].
fn drain_outcome(read_fd: RawFd) -> Option<HardeningOutcome> {
    let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let mut buf = Vec::with_capacity(64);
    if file.read_to_end(&mut buf).is_err() {
        return None;
    }
    decode_outcome(&buf)
}

const OUTCOME_LEN: usize = 1 + 7 * 2;

/// Decode a 15-byte hardening outcome record:
///   `[profile_tag, no_new_privs_tag, no_new_privs_errno_lo,
///     rlimit_cpu_tag, rlimit_cpu_errno_lo, ..., seccomp_tag, seccomp_errno_lo]`
/// All errnos are clamped to the low byte for the wire (true value is
/// recovered post-hoc from `errno`-symbolic context if needed).
fn decode_outcome(buf: &[u8]) -> Option<HardeningOutcome> {
    if buf.len() < OUTCOME_LEN {
        return None;
    }
    let profile = match buf[0] {
        1 => ProcessHardeningProfileTag::Strict,
        _ => ProcessHardeningProfileTag::Standard,
    };
    let mut idx = 1;
    let mut next = || -> PrimitiveStatus {
        let tag = buf[idx];
        let errno = buf[idx + 1] as i32;
        idx += 2;
        match tag {
            0 => PrimitiveStatus::Skipped,
            1 => PrimitiveStatus::Applied,
            _ => PrimitiveStatus::Failed(if errno == 0 { -1 } else { errno }),
        }
    };
    let no_new_privs = next();
    let rlimit_cpu = next();
    let rlimit_nofile = next();
    let rlimit_as = next();
    let unshare = next();
    let chroot = next();
    let seccomp = next();
    Some(HardeningOutcome {
        no_new_privs,
        rlimit_cpu,
        rlimit_nofile,
        rlimit_as,
        unshare,
        chroot,
        seccomp,
        profile,
    })
}

fn encode_outcome(out: &HardeningOutcome) -> [u8; OUTCOME_LEN] {
    let mut buf = [0_u8; OUTCOME_LEN];
    buf[0] = match out.profile {
        ProcessHardeningProfileTag::Standard => 0,
        ProcessHardeningProfileTag::Strict => 1,
    };
    let mut idx = 1;
    for status in [
        out.no_new_privs,
        out.rlimit_cpu,
        out.rlimit_nofile,
        out.rlimit_as,
        out.unshare,
        out.chroot,
        out.seccomp,
    ] {
        let (tag, errno) = match status {
            PrimitiveStatus::Skipped => (0_u8, 0_u8),
            PrimitiveStatus::Applied => (1_u8, 0_u8),
            PrimitiveStatus::Failed(e) => (2_u8, (e.unsigned_abs() & 0xff) as u8),
        };
        buf[idx] = tag;
        buf[idx + 1] = errno;
        idx += 2;
    }
    buf
}

// ── Primitive wrappers (called from the child's pre_exec) ────────────────────

const RLIMIT_CPU: i32 = 0;
const RLIMIT_NOFILE: i32 = 7;
const RLIMIT_AS: i32 = 9;

const PR_SET_NO_NEW_PRIVS: i32 = 38;

const CLONE_NEWNS: i32 = 0x0002_0000;
const CLONE_NEWUSER: i32 = 0x1000_0000;
const CLONE_NEWPID: i32 = 0x2000_0000;

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

unsafe extern "C" {
    fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32;
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    fn unshare(flags: i32) -> i32;
    fn chroot(path: *const i8) -> i32;
    fn chdir(path: *const i8) -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn __errno_location() -> *mut i32;
}

fn last_errno() -> i32 {
    unsafe { *__errno_location() }
}

fn apply_rlimit(resource: i32, bytes: u64) -> PrimitiveStatus {
    let rl = Rlimit { cur: bytes, max: bytes };
    let ret = unsafe { setrlimit(resource, &rl) };
    if ret == 0 {
        PrimitiveStatus::Applied
    } else {
        PrimitiveStatus::Failed(last_errno())
    }
}

fn apply_no_new_privs() -> PrimitiveStatus {
    let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret == 0 {
        PrimitiveStatus::Applied
    } else {
        PrimitiveStatus::Failed(last_errno())
    }
}

fn apply_unshare() -> PrimitiveStatus {
    // CLONE_NEWUSER must come first on most modern kernels so the
    // unprivileged caller can map uid/gid; CLONE_NEWPID + CLONE_NEWNS
    // then succeed because the new user namespace owns them.
    let flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS;
    let ret = unsafe { unshare(flags) };
    if ret == 0 {
        PrimitiveStatus::Applied
    } else {
        PrimitiveStatus::Failed(last_errno())
    }
}

fn apply_chroot(workdir: &[u8]) -> PrimitiveStatus {
    // `workdir` is NUL-terminated by `canonicalize_workdir` so we can
    // hand the bytes straight to `chroot(2)` without allocating in
    // pre_exec.
    let ret = unsafe { chroot(workdir.as_ptr() as *const i8) };
    if ret != 0 {
        return PrimitiveStatus::Failed(last_errno());
    }
    let root = b"/\0";
    let ret = unsafe { chdir(root.as_ptr() as *const i8) };
    if ret != 0 {
        return PrimitiveStatus::Failed(last_errno());
    }
    PrimitiveStatus::Applied
}

/// Install a pre-compiled seccomp BPF filter on the calling thread.
///
/// `program` is a heap-allocated BPF instruction array compiled in the
/// parent (`build_plan`) and shared via `Arc` so the child does not have
/// to allocate during pre_exec.
fn apply_seccomp(program: &[SockFilter]) -> PrimitiveStatus {
    match seccomp::install_compiled_filter(program) {
        Ok(()) => PrimitiveStatus::Applied,
        Err(e) => PrimitiveStatus::Failed(e.raw_os_error().unwrap_or(-1)),
    }
}

// ── Pre-exec installer ───────────────────────────────────────────────────────

#[derive(Clone)]
struct PreExecPlan {
    rlimit_cpu_seconds: u64,
    rlimit_nofile: u64,
    rlimit_as_bytes: u64,
    workdir_nul: Vec<u8>,
    /// Pre-compiled BPF program for the requested cap-bits.  Built in
    /// the parent so the child's pre_exec callback never touches the
    /// allocator.
    seccomp_program: Arc<Vec<SockFilter>>,
    profile: ProcessHardeningProfileTag,
}

/// Returned by [`install_pre_exec`].  The caller MUST invoke either
/// [`OutcomeCollector::after_spawn`] or [`OutcomeCollector::forget`]
/// after `cmd.spawn()` returns — the parent's write-fd has to close so
/// the read end sees EOF and the drain thread terminates.
pub struct OutcomeCollector {
    write_fd: RawFd,
    read_fd: RawFd,
}

/// Background-drain handle returned by [`OutcomeCollector::after_spawn`].
/// `run_process` awaits this after `child.wait()` so the outcome is
/// guaranteed to be in the registry before the function returns; tests
/// that bypass `run_process` can call [`OutcomeJoiner::await_outcome`]
/// themselves.
pub struct OutcomeJoiner {
    handle: Option<std::thread::JoinHandle<()>>,
}

impl OutcomeJoiner {
    /// Block until the drain thread finishes recording the outcome.
    pub fn await_outcome(mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for OutcomeJoiner {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl OutcomeCollector {
    /// Call after `cmd.spawn()` returns `Ok`.  Closes the parent's copy
    /// of the write fd so the kernel ref-count drops to whatever the
    /// child is still holding; once execve(2) closes the child's
    /// O_CLOEXEC copy too, the read end sees EOF and the drain thread
    /// records the outcome via [`record_outcome`].  Returns a join
    /// handle the caller can await to know the outcome is settled.
    pub fn after_spawn(self) -> OutcomeJoiner {
        close_fd(self.write_fd);
        let read_fd = self.read_fd;
        let handle = std::thread::spawn(move || {
            if let Some(outcome) = drain_outcome(read_fd) {
                record_outcome(outcome);
            }
        });
        OutcomeJoiner { handle: Some(handle) }
    }

    /// Call when `cmd.spawn()` failed.  Closes both ends so neither fd
    /// leaks; no outcome is recorded.
    pub fn forget(self) {
        close_fd(self.write_fd);
        close_fd(self.read_fd);
    }
}

/// Install the Phase 17 hardening sequence on `cmd`.
///
/// Returns `Some(collector)` when the status pipe was successfully
/// created; the caller must invoke
/// [`OutcomeCollector::after_spawn`] after a successful `cmd.spawn()`.
/// Returns `None` when pipe creation itself failed (rare:
/// `EMFILE`/`ENFILE`).  In that case the pre_exec hook is still
/// installed — the child still gets the full hardening sequence — but
/// the per-primitive outcome cannot be reported back to the parent.
pub fn install_pre_exec(
    cmd: &mut Command,
    opts: &SandboxOptions,
    workdir: &Path,
) -> Option<OutcomeCollector> {
    let plan = build_plan(opts, workdir);

    let pipe = StatusPipe::new().ok();
    let write_fd = pipe.as_ref().map(|p| p.write_fd).unwrap_or(-1);
    let read_fd = pipe.as_ref().map(|p| p.read_fd);
    let plan_for_child = plan.clone();

    // Safety: pre_exec runs after fork(2) and before execve(2).  We must
    // not allocate, take any locks, or call into the Rust runtime.  The
    // captured `plan_for_child` is moved in; reading its already-allocated
    // fields is safe because no allocator call is needed.
    unsafe {
        cmd.pre_exec(move || {
            let outcome = run_pre_exec_in_child(&plan_for_child);
            if write_fd >= 0 {
                let bytes = encode_outcome(&outcome);
                let _ = write(write_fd, bytes.as_ptr(), bytes.len());
                // execve(2) closes write_fd via O_CLOEXEC; no manual
                // close needed here.
            }
            Ok(())
        });
    }
    read_fd.map(|read_fd| OutcomeCollector { write_fd, read_fd })
}

fn run_pre_exec_in_child(plan: &PreExecPlan) -> HardeningOutcome {
    let mut outcome = HardeningOutcome::default();
    outcome.profile = plan.profile;

    // ── Always-on: PR_SET_NO_NEW_PRIVS + RLIMIT_AS ───────────────────────
    outcome.no_new_privs = apply_no_new_privs();
    outcome.rlimit_as = apply_rlimit(RLIMIT_AS, plan.rlimit_as_bytes);

    if matches!(plan.profile, ProcessHardeningProfileTag::Standard) {
        return outcome;
    }

    // ── Strict profile: rlimits, unshare, chroot, seccomp ────────────────
    outcome.rlimit_cpu = apply_rlimit(RLIMIT_CPU, plan.rlimit_cpu_seconds);
    outcome.rlimit_nofile = apply_rlimit(RLIMIT_NOFILE, plan.rlimit_nofile);
    outcome.unshare = apply_unshare();
    outcome.chroot = apply_chroot(&plan.workdir_nul);
    // seccomp is applied last so the filter does not block any of the
    // earlier syscalls (setrlimit, prctl, unshare, chroot, chdir).
    outcome.seccomp = apply_seccomp(plan.seccomp_program.as_slice());

    outcome
}

fn build_plan(opts: &SandboxOptions, workdir: &Path) -> PreExecPlan {
    let memory_mib = opts.memory_mib;
    let cap_mib = memory_mib.saturating_mul(8).max(4096);
    let rlimit_as_bytes = cap_mib.saturating_mul(1024 * 1024);

    let timeout_secs = opts.timeout.as_secs().max(1);
    let rlimit_cpu_seconds = timeout_secs.saturating_mul(2).max(2);

    let workdir_nul = canonicalize_workdir(workdir);

    // Pre-compile the BPF program in the parent so the pre_exec
    // callback (which must not allocate) can hand it straight to
    // `prctl(PR_SET_SECCOMP)`.
    let nrs = seccomp::allowed_syscall_numbers(opts.seccomp_caps);
    let program = seccomp::bpf::compile(&nrs, seccomp::syscalls::AUDIT_ARCH);

    PreExecPlan {
        rlimit_cpu_seconds,
        rlimit_nofile: 256,
        rlimit_as_bytes,
        workdir_nul,
        seccomp_program: Arc::new(program),
        profile: match opts.process_hardening {
            ProcessHardeningProfile::Standard => ProcessHardeningProfileTag::Standard,
            ProcessHardeningProfile::Strict => ProcessHardeningProfileTag::Strict,
        },
    }
}

fn canonicalize_workdir(workdir: &Path) -> Vec<u8> {
    let canonical: PathBuf = std::fs::canonicalize(workdir).unwrap_or_else(|_| workdir.to_path_buf());
    let mut bytes = canonical.into_os_string().into_encoded_bytes();
    if !bytes.ends_with(&[0]) {
        bytes.push(0);
    }
    bytes
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_codec_round_trip_strict_full() {
        let out = HardeningOutcome {
            no_new_privs: PrimitiveStatus::Applied,
            rlimit_cpu: PrimitiveStatus::Applied,
            rlimit_nofile: PrimitiveStatus::Applied,
            rlimit_as: PrimitiveStatus::Applied,
            unshare: PrimitiveStatus::Applied,
            chroot: PrimitiveStatus::Applied,
            seccomp: PrimitiveStatus::Applied,
            profile: ProcessHardeningProfileTag::Strict,
        };
        let bytes = encode_outcome(&out);
        let decoded = decode_outcome(&bytes).expect("decode");
        assert_eq!(decoded, out);
        assert_eq!(decoded.level(), HardeningLevel::Full);
    }

    #[test]
    fn outcome_codec_round_trip_partial() {
        let out = HardeningOutcome {
            no_new_privs: PrimitiveStatus::Applied,
            rlimit_cpu: PrimitiveStatus::Applied,
            rlimit_nofile: PrimitiveStatus::Failed(13),
            rlimit_as: PrimitiveStatus::Applied,
            unshare: PrimitiveStatus::Failed(1),
            chroot: PrimitiveStatus::Failed(13),
            seccomp: PrimitiveStatus::Applied,
            profile: ProcessHardeningProfileTag::Strict,
        };
        let bytes = encode_outcome(&out);
        let decoded = decode_outcome(&bytes).expect("decode");
        assert_eq!(decoded, out);
        assert_eq!(decoded.level(), HardeningLevel::Partial);
    }

    #[test]
    fn standard_profile_reports_baseline_level() {
        let out = HardeningOutcome {
            no_new_privs: PrimitiveStatus::Applied,
            rlimit_as: PrimitiveStatus::Applied,
            profile: ProcessHardeningProfileTag::Standard,
            ..HardeningOutcome::default()
        };
        assert_eq!(out.level(), HardeningLevel::Baseline);
    }

    #[test]
    fn build_plan_pads_workdir_with_nul() {
        let opts = SandboxOptions::default();
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        assert!(plan.workdir_nul.ends_with(&[0]));
        assert_eq!(plan.profile, ProcessHardeningProfileTag::Standard);
    }

    #[test]
    fn build_plan_strict_compiles_seccomp_program() {
        let opts = SandboxOptions {
            seccomp_caps: 0xff,
            process_hardening: ProcessHardeningProfile::Strict,
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        // The arch check + ld nr + KILL + ALLOW alone are 5 instructions;
        // the BASE allowlist adds dozens more.
        assert!(plan.seccomp_program.len() > 5, "BPF program too small: {}", plan.seccomp_program.len());
        assert_eq!(plan.profile, ProcessHardeningProfileTag::Strict);
    }

    #[test]
    fn rlimit_as_bytes_floors_at_4_gib() {
        let opts = SandboxOptions { memory_mib: 1, ..SandboxOptions::default() };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        assert_eq!(plan.rlimit_as_bytes, 4096_u64 * 1024 * 1024);
    }

    #[test]
    fn rlimit_as_bytes_scales_with_memory_mib() {
        let opts = SandboxOptions { memory_mib: 1024, ..SandboxOptions::default() };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        // 1024 MiB * 8 = 8192 MiB
        assert_eq!(plan.rlimit_as_bytes, 8192_u64 * 1024 * 1024);
    }

    #[test]
    fn truncated_buffer_decodes_to_none() {
        assert!(decode_outcome(&[]).is_none());
        assert!(decode_outcome(&[0_u8; OUTCOME_LEN - 1]).is_none());
    }

    #[test]
    fn record_and_reset_round_trip() {
        let original = last_hardening_outcome();
        let probe = HardeningOutcome {
            no_new_privs: PrimitiveStatus::Applied,
            profile: ProcessHardeningProfileTag::Strict,
            ..HardeningOutcome::default()
        };
        record_outcome(probe);
        assert_eq!(last_hardening_outcome(), Some(probe));
        reset_last_hardening_outcome();
        assert!(last_hardening_outcome().is_none());
        if let Some(prev) = original {
            record_outcome(prev);
        }
    }
}
