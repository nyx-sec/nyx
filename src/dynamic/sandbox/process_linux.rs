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

#![warn(clippy::undocumented_unsafe_blocks)]

use crate::dynamic::sandbox::seccomp;
use crate::dynamic::sandbox::seccomp::bpf::SockFilter;
use crate::dynamic::sandbox::{AblationMask, ProcessHardeningProfile, SandboxOptions};
use std::io::Read;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

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
        let applied = primitives
            .iter()
            .filter(|s| matches!(s, PrimitiveStatus::Applied))
            .count();
        let failed = primitives
            .iter()
            .filter(|s| matches!(s, PrimitiveStatus::Failed(_)))
            .count();
        match (applied, failed) {
            (_, 0) => HardeningLevel::Full,
            (0, _) => HardeningLevel::None,
            _ => HardeningLevel::Partial,
        }
    }
}

// ── Status pipe between parent and child ─────────────────────────────────────

struct StatusPipe {
    write_fd: RawFd,
    read_fd: RawFd,
}

impl StatusPipe {
    fn new() -> std::io::Result<Self> {
        // SAFETY: declares the libc `pipe2(2)` ABI; the signature matches <unistd.h>.
        unsafe extern "C" {
            fn pipe2(pipefd: *mut i32, flags: i32) -> i32;
        }
        const O_CLOEXEC: i32 = 0o2_000_000;
        let mut fds = [-1_i32; 2];
        // SAFETY: `fds` is a valid 2-element array the kernel writes into; `pipe2`
        // reads no caller memory beyond that pointer. Return value checked below.
        let ret = unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            write_fd: fds[1],
            read_fd: fds[0],
        })
    }
}

fn close_fd(fd: RawFd) {
    // SAFETY: declares the libc `close(2)` ABI; signature matches <unistd.h>.
    unsafe extern "C" {
        fn close(fd: i32) -> i32;
    }
    // SAFETY: `fd` is an owned raw fd closed exactly once; the return value is
    // intentionally ignored (best-effort close).
    unsafe { close(fd) };
}

/// Drain `read_fd` into a `HardeningOutcome`.  Wire format is the
/// 15-byte fixed-width record produced by [`encode_outcome`].
fn drain_outcome(read_fd: RawFd) -> Option<HardeningOutcome> {
    // SAFETY: `read_fd` is an owned raw fd (the pipe read end) used nowhere else;
    // `File` takes sole ownership and closes it on drop.
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

// `mount(2)` flag bits used by the bind-mount path.  Constants match
// `<sys/mount.h>` on glibc / musl; kept inline so pre_exec does not need
// a libc-bindings crate.
const MS_RDONLY: u64 = 0x0000_0001;
const MS_REMOUNT: u64 = 0x0000_0020;
const MS_BIND: u64 = 0x0000_1000;

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

// SAFETY: declares the libc syscall-wrapper ABI (setrlimit/prctl/unshare/chroot/
// chdir/mount/write/__errno_location); signatures match the glibc/musl headers.
unsafe extern "C" {
    fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32;
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    fn unshare(flags: i32) -> i32;
    fn chroot(path: *const i8) -> i32;
    fn chdir(path: *const i8) -> i32;
    fn mount(
        source: *const i8,
        target: *const i8,
        fstype: *const i8,
        flags: u64,
        data: *const core::ffi::c_void,
    ) -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn __errno_location() -> *mut i32;
}

fn last_errno() -> i32 {
    // SAFETY: `__errno_location` returns a valid pointer to the calling thread's
    // errno; dereferencing it right after a failed syscall is the standard idiom.
    unsafe { *__errno_location() }
}

fn apply_rlimit(resource: i32, bytes: u64) -> PrimitiveStatus {
    let rl = Rlimit {
        cur: bytes,
        max: bytes,
    };
    // SAFETY: `&rl` points to a valid `Rlimit` for the duration of the call;
    // `setrlimit` only reads it and returns a status checked below.
    let ret = unsafe { setrlimit(resource, &rl) };
    if ret == 0 {
        PrimitiveStatus::Applied
    } else {
        PrimitiveStatus::Failed(last_errno())
    }
}

fn apply_no_new_privs() -> PrimitiveStatus {
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, ..)` takes only scalar args and touches
    // no caller memory; the return value is checked below.
    let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret == 0 {
        PrimitiveStatus::Applied
    } else {
        PrimitiveStatus::Failed(last_errno())
    }
}

fn apply_unshare_with_flags(flags: i32) -> PrimitiveStatus {
    // CLONE_NEWUSER must come first on most modern kernels so the
    // unprivileged caller can map uid/gid; CLONE_NEWPID + CLONE_NEWNS
    // then succeed because the new user namespace owns them.  Phase 20
    // ablation drops individual flags via `AblationMask::no_userns` /
    // `no_pidns` so the escape-fixture matrix can prove the namespace
    // primitive carries its weight.
    // SAFETY: `unshare` takes a scalar flag set and touches no caller memory;
    // the return value is checked below.
    let ret = unsafe { unshare(flags) };
    if ret == 0 {
        PrimitiveStatus::Applied
    } else {
        PrimitiveStatus::Failed(last_errno())
    }
}

/// Compose the `unshare(2)` flag set for a given ablation mask.  The
/// production path passes `None` and gets the full
/// `CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS` set.  Tests pass `Some`
/// to drop individual namespaces and assert the escape fixture flips.
fn unshare_flags_for_ablation(mask: Option<AblationMask>) -> i32 {
    let m = mask.unwrap_or_default();
    let mut flags = CLONE_NEWNS;
    if !m.no_userns {
        flags |= CLONE_NEWUSER;
    }
    if !m.no_pidns {
        flags |= CLONE_NEWPID;
    }
    flags
}

fn apply_chroot(workdir: &[u8]) -> PrimitiveStatus {
    // `workdir` is NUL-terminated by `canonicalize_workdir` so we can
    // hand the bytes straight to `chroot(2)` without allocating in
    // pre_exec.
    // SAFETY: `workdir` is NUL-terminated by `canonicalize_workdir`, so the
    // pointer references a valid C string for the duration of the call.
    let ret = unsafe { chroot(workdir.as_ptr() as *const i8) };
    if ret != 0 {
        return PrimitiveStatus::Failed(last_errno());
    }
    let root = b"/\0";
    // SAFETY: `root` is a NUL-terminated byte literal, a valid C string.
    let ret = unsafe { chdir(root.as_ptr() as *const i8) };
    if ret != 0 {
        return PrimitiveStatus::Failed(last_errno());
    }
    PrimitiveStatus::Applied
}

/// One read-only bind-mount the child applies after `unshare(CLONE_NEWNS)`
/// and before `chroot(2)`.  Both fields are NUL-terminated by
/// [`canonicalize_bind_mount`] so the pre_exec callback can hand the
/// bytes straight to `mount(2)` without allocating.
#[derive(Clone, Debug)]
struct BindMount {
    source_nul: Vec<u8>,
    dest_nul: Vec<u8>,
}

/// Apply each bind-mount in `mounts`: first `mount(... MS_BIND ...)` to
/// graft the host path into the workdir, then a second `mount(... MS_REMOUNT
/// | MS_BIND | MS_RDONLY ...)` to flip the new mount read-only.  Both
/// calls are best-effort — a failure surfaces only via the post-chroot
/// behaviour (the interpreter cannot resolve its `ld.so`) rather than
/// the [`HardeningOutcome`] wire record, so callers that care about the
/// bind-mount succeeding gate on whether the harness produced output.
///
/// Called in pre_exec after [`apply_unshare_with_flags`] and before
/// [`apply_chroot`] so the new mount namespace is private to the child +
/// grandchildren and the workdir is still reachable at its host-side absolute
/// path.
fn apply_bind_mounts(mounts: &[BindMount]) {
    let none = b"none\0";
    for m in mounts {
        // SAFETY: `source_nul`/`dest_nul` are NUL-terminated by
        // `canonicalize_bind_mount` and `none` is a NUL-terminated literal, so
        // every pointer references a valid C string for the duration of the call.
        let r = unsafe {
            mount(
                m.source_nul.as_ptr() as *const i8,
                m.dest_nul.as_ptr() as *const i8,
                none.as_ptr() as *const i8,
                MS_BIND,
                std::ptr::null(),
            )
        };
        if r != 0 {
            continue;
        }
        // SAFETY: `dest_nul` is NUL-terminated; the remaining pointers are null,
        // which `mount(2)` accepts for a remount. Best-effort: result ignored.
        unsafe {
            mount(
                std::ptr::null(),
                m.dest_nul.as_ptr() as *const i8,
                std::ptr::null(),
                MS_REMOUNT | MS_BIND | MS_RDONLY,
                std::ptr::null(),
            )
        };
    }
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
    /// Read-only bind-mounts the child applies after `unshare(CLONE_NEWNS)`
    /// and before `chroot(2)`.  Empty when
    /// [`SandboxOptions::bind_mount_host_libs`] is false, the active
    /// profile is `Standard` (no namespace to bind into), or the active
    /// ablation mask sets `no_chroot` (no `chroot(2)` means the bind
    /// mounts would just orphan-mount inside the workdir).
    bind_mounts: Vec<BindMount>,
    /// `unshare(2)` flag bits the child requests.  Computed from
    /// [`unshare_flags_for_ablation`] so the Phase 20 ablation harness
    /// can drop `CLONE_NEWUSER` / `CLONE_NEWPID` individually without
    /// the test re-implementing the bit math.
    unshare_flags: i32,
    /// `Some` when the active mask is non-default; consulted in
    /// [`run_pre_exec_in_child`] to skip individual primitives.  `None`
    /// in production so the hot path is unaffected.
    ablation: Option<AblationMask>,
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
/// `run_process` awaits this after `child.wait()`, receiving the per-
/// primitive [`HardeningOutcome`] the drain thread parsed off the
/// status pipe.  Each spawn gets its own joiner, so the outcome flows
/// back to exactly the caller that spawned it — no process-global
/// singleton, no race when `verify_finding` runs under
/// `rayon::par_iter`.
pub struct OutcomeJoiner {
    handle: Option<std::thread::JoinHandle<Option<HardeningOutcome>>>,
}

impl OutcomeJoiner {
    /// Block until the drain thread finishes, returning the per-
    /// primitive outcome it parsed.  `None` when the status pipe was
    /// drained but the wire record was truncated (rare: child died
    /// before `pre_exec` could write).
    pub fn await_outcome(mut self) -> Option<HardeningOutcome> {
        self.handle.take().and_then(|h| h.join().ok().flatten())
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
    /// parses the outcome off the pipe and ships it back via the
    /// returned [`OutcomeJoiner`].
    pub fn after_spawn(self) -> OutcomeJoiner {
        close_fd(self.write_fd);
        let read_fd = self.read_fd;
        let handle = std::thread::spawn(move || drain_outcome(read_fd));
        OutcomeJoiner {
            handle: Some(handle),
        }
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

    // SAFETY: pre_exec runs after fork(2) and before execve(2).  We must
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
    let ablation = plan.ablation.unwrap_or_default();

    // ── Always-on: PR_SET_NO_NEW_PRIVS + RLIMIT_AS ───────────────────────
    outcome.no_new_privs = if ablation.no_no_new_privs {
        PrimitiveStatus::Skipped
    } else {
        apply_no_new_privs()
    };
    outcome.rlimit_as = apply_rlimit(RLIMIT_AS, plan.rlimit_as_bytes);

    if matches!(plan.profile, ProcessHardeningProfileTag::Standard) {
        return outcome;
    }

    // ── Strict profile: rlimits, unshare, chroot, seccomp ────────────────
    outcome.rlimit_cpu = apply_rlimit(RLIMIT_CPU, plan.rlimit_cpu_seconds);
    outcome.rlimit_nofile = apply_rlimit(RLIMIT_NOFILE, plan.rlimit_nofile);
    // `unshare(2)` always runs even under ablation because the BindMount
    // step needs `CLONE_NEWNS` to land in a private mount namespace;
    // userns/pidns are dropped via the flag mask in `build_plan`.
    outcome.unshare = apply_unshare_with_flags(plan.unshare_flags);
    // Bind-mount host library paths into the workdir after unshare (so
    // the new mount namespace catches them) and before chroot (so the
    // bind sources are still reachable at their absolute host paths).
    // No-op when `bind_mounts` is empty.
    apply_bind_mounts(&plan.bind_mounts);
    outcome.chroot = if ablation.no_chroot {
        PrimitiveStatus::Skipped
    } else {
        apply_chroot(&plan.workdir_nul)
    };
    // seccomp is applied last so the filter does not block any of the
    // earlier syscalls (setrlimit, prctl, unshare, chroot, chdir, mount).
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
    // `prctl(PR_SET_SECCOMP)`.  Ablation extras add the socket / setuid
    // syscall families back to the allowlist so escape fixtures can
    // prove that the corresponding seccomp slice carries its weight.
    let ablation = opts.ablation;
    let extras: Vec<&'static str> = ablation_extras(ablation);
    let nrs =
        seccomp::allowed_syscall_numbers_with_extras(opts.seccomp_caps, extras.iter().copied());
    let program = seccomp::bpf::compile(&nrs, seccomp::syscalls::AUDIT_ARCH);

    let profile = match opts.process_hardening {
        ProcessHardeningProfile::Standard => ProcessHardeningProfileTag::Standard,
        ProcessHardeningProfile::Strict => ProcessHardeningProfileTag::Strict,
    };

    let mask = ablation.unwrap_or_default();
    // Bind-mounts are only useful when the child will chroot, i.e. under
    // the Strict profile.  Computing them under Standard would create
    // empty dest dirs in the workdir for no reason.  Skipping the
    // chroot via ablation drops the bind-mounts too — leaving them on
    // would mount over the host directly inside the unshared mount
    // namespace, which is not what the ablation harness wants.
    let bind_mounts = if opts.bind_mount_host_libs
        && matches!(profile, ProcessHardeningProfileTag::Strict)
        && !mask.no_chroot
    {
        compute_host_lib_bind_mounts(workdir)
    } else {
        Vec::new()
    };

    PreExecPlan {
        rlimit_cpu_seconds,
        rlimit_nofile: 256,
        rlimit_as_bytes,
        workdir_nul,
        seccomp_program: Arc::new(program),
        profile,
        bind_mounts,
        unshare_flags: unshare_flags_for_ablation(ablation),
        ablation,
    }
}

/// Collect the syscall-name extras a Phase 20 ablation mask requires.
/// Returns an empty Vec when the mask is `None` or default; otherwise
/// folds `ABLATION_SOCKET_FAMILY` / `ABLATION_SETUID_FAMILY` from
/// [`crate::dynamic::sandbox::seccomp`] into the allowlist seed.
fn ablation_extras(mask: Option<AblationMask>) -> Vec<&'static str> {
    let m = match mask {
        Some(m) => m,
        None => return Vec::new(),
    };
    let mut out: Vec<&'static str> = Vec::new();
    if m.no_seccomp_socket {
        out.extend_from_slice(seccomp::ABLATION_SOCKET_FAMILY);
    }
    if m.no_seccomp_setuid {
        out.extend_from_slice(seccomp::ABLATION_SETUID_FAMILY);
    }
    out
}

/// Build the bind-mount list for the dynamic-loader paths an interpreted
/// harness needs to find shared libraries from inside the chroot.  Each
/// entry is `(host_source, workdir_dest)` where `host_source` is a real
/// host path that exists and `workdir_dest` is a freshly-created mount
/// point inside the harness workdir.
///
/// Skips any candidate whose host source does not exist (e.g. `/lib64`
/// on a multi-arch Debian box that puts everything under `/lib/x86_64-linux-gnu`).
/// Also skips any candidate whose dest directory creation fails — the
/// mount would not have a target to attach to anyway.
fn compute_host_lib_bind_mounts(workdir: &Path) -> Vec<BindMount> {
    // The candidate set covers the dynamic-loader resolution path on
    // every mainstream glibc distro:
    //   * /lib            — ld-linux.so on multilib-i386 systems, and the
    //                       traditional location on musl-based distros.
    //   * /lib64          — ld-linux-x86-64.so.2 on glibc x86_64 systems.
    //   * /usr/lib        — the bulk of shared libraries on modern distros
    //                       after the `/usr` merge.
    //   * /usr/bin        — interpreter binaries (python3, node, java)
    //                       resolved via PATH=/usr/bin after chroot.
    const CANDIDATES: &[(&str, &str)] = &[
        ("/lib", "lib"),
        ("/lib64", "lib64"),
        ("/usr/lib", "usr/lib"),
        ("/usr/bin", "usr/bin"),
    ];
    let mut out = Vec::with_capacity(CANDIDATES.len());
    for (host, rel) in CANDIDATES {
        if !Path::new(host).exists() {
            continue;
        }
        let dest = workdir.join(rel);
        if std::fs::create_dir_all(&dest).is_err() {
            continue;
        }
        let dest_canonical = std::fs::canonicalize(&dest).unwrap_or(dest);
        out.push(BindMount {
            source_nul: nul_terminate(host.as_bytes()),
            dest_nul: nul_terminate(dest_canonical.to_string_lossy().as_bytes()),
        });
    }
    out
}

fn nul_terminate(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(0);
    v
}

fn canonicalize_workdir(workdir: &Path) -> Vec<u8> {
    let canonical: PathBuf =
        std::fs::canonicalize(workdir).unwrap_or_else(|_| workdir.to_path_buf());
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
        assert!(
            plan.seccomp_program.len() > 5,
            "BPF program too small: {}",
            plan.seccomp_program.len()
        );
        assert_eq!(plan.profile, ProcessHardeningProfileTag::Strict);
    }

    #[test]
    fn rlimit_as_bytes_floors_at_4_gib() {
        let opts = SandboxOptions {
            memory_mib: 1,
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        assert_eq!(plan.rlimit_as_bytes, 4096_u64 * 1024 * 1024);
    }

    #[test]
    fn rlimit_as_bytes_scales_with_memory_mib() {
        let opts = SandboxOptions {
            memory_mib: 1024,
            ..SandboxOptions::default()
        };
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
    fn build_plan_without_bind_mount_flag_yields_empty_list() {
        let opts = SandboxOptions {
            process_hardening: ProcessHardeningProfile::Strict,
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        assert!(
            plan.bind_mounts.is_empty(),
            "bind_mounts should stay empty when bind_mount_host_libs=false",
        );
    }

    #[test]
    fn build_plan_standard_profile_skips_bind_mounts_even_when_flag_set() {
        // Standard profile does not chroot, so bind-mounting host libs
        // would just create dead dirs in the workdir for no reason.
        let opts = SandboxOptions {
            bind_mount_host_libs: true,
            process_hardening: ProcessHardeningProfile::Standard,
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        assert!(plan.bind_mounts.is_empty());
    }

    #[test]
    fn build_plan_strict_with_bind_mount_flag_pre_creates_dest_dirs() {
        // /usr/lib exists on every mainstream Linux distro, so at least
        // one bind-mount entry should land.  The dest must be a real
        // directory by the time build_plan returns — pre_exec cannot
        // mkdir during the no-allocate window.
        let workdir = tempfile::TempDir::new().expect("tempdir");
        let opts = SandboxOptions {
            bind_mount_host_libs: true,
            process_hardening: ProcessHardeningProfile::Strict,
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, workdir.path());

        // Every entry's source must be NUL-terminated for the `mount(2)`
        // call, and every dest must exist on disk.
        for m in &plan.bind_mounts {
            assert!(
                m.source_nul.ends_with(&[0]),
                "source path must be NUL-terminated"
            );
            assert!(
                m.dest_nul.ends_with(&[0]),
                "dest path must be NUL-terminated"
            );
            let dest_str = std::str::from_utf8(&m.dest_nul[..m.dest_nul.len() - 1])
                .expect("dest path must be valid UTF-8");
            assert!(
                std::path::Path::new(dest_str).is_dir(),
                "dest dir must be pre-created by build_plan: {dest_str}",
            );
        }
        // The candidate set has four entries; on a working Linux host at
        // least `/usr/lib` and `/usr/bin` exist, so we expect ≥ 2 entries.
        // We do not assert the exact count to stay portable across multi-
        // arch (`/lib64`-less) and musl distros.
        assert!(
            plan.bind_mounts.len() >= 2,
            "expected ≥ 2 bind-mount entries on a Linux host; got {}",
            plan.bind_mounts.len(),
        );
    }

    #[test]
    fn nul_terminate_appends_zero_byte_once() {
        assert_eq!(nul_terminate(b""), b"\0");
        assert_eq!(nul_terminate(b"/lib"), b"/lib\0");
        // Idempotency property does NOT hold — caller must not double-terminate.
        let twice = nul_terminate(b"/lib\0");
        assert_eq!(twice, b"/lib\0\0");
    }

    // ── Phase 20 ablation harness ────────────────────────────────────────────

    #[test]
    fn ablation_default_mask_matches_full_strict_flags() {
        // The production path (`opts.ablation == None`) must request the
        // full namespace set so non-ablation runs do not regress.
        assert_eq!(
            unshare_flags_for_ablation(None),
            CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS,
        );
        // A non-None but default-valued mask must behave identically:
        // the integration test layer can construct an empty mask as a
        // sentinel without losing any production primitive.
        assert_eq!(
            unshare_flags_for_ablation(Some(AblationMask::default())),
            CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS,
        );
    }

    #[test]
    fn ablation_no_userns_drops_clone_newuser_flag() {
        let flags = unshare_flags_for_ablation(Some(AblationMask {
            no_userns: true,
            ..AblationMask::default()
        }));
        assert_eq!(flags & CLONE_NEWUSER, 0, "CLONE_NEWUSER must be dropped");
        assert_eq!(
            flags & CLONE_NEWPID,
            CLONE_NEWPID,
            "CLONE_NEWPID must persist"
        );
        assert_eq!(
            flags & CLONE_NEWNS,
            CLONE_NEWNS,
            "CLONE_NEWNS must persist (bind-mount target)"
        );
    }

    #[test]
    fn ablation_no_pidns_drops_clone_newpid_flag() {
        let flags = unshare_flags_for_ablation(Some(AblationMask {
            no_pidns: true,
            ..AblationMask::default()
        }));
        assert_eq!(flags & CLONE_NEWPID, 0, "CLONE_NEWPID must be dropped");
        assert_eq!(
            flags & CLONE_NEWUSER,
            CLONE_NEWUSER,
            "CLONE_NEWUSER must persist"
        );
    }

    #[test]
    fn ablation_no_userns_and_no_pidns_keeps_only_newns() {
        // Even with both namespace ablations set, CLONE_NEWNS must
        // remain so the bind-mount step has a private mount namespace
        // to land in.  Dropping NEWNS too would mount host libs into
        // the live host namespace — a serious test-side foot-gun.
        let flags = unshare_flags_for_ablation(Some(AblationMask {
            no_userns: true,
            no_pidns: true,
            ..AblationMask::default()
        }));
        assert_eq!(flags, CLONE_NEWNS);
    }

    #[test]
    fn ablation_no_chroot_drops_bind_mounts_from_plan() {
        // bind_mount_host_libs requested, Strict profile selected — yet
        // the ablated chroot means we should not pre-create bind dirs in
        // the workdir.  Doing so would leak mount points to the host.
        let workdir = tempfile::TempDir::new().expect("tempdir");
        let opts = SandboxOptions {
            bind_mount_host_libs: true,
            process_hardening: ProcessHardeningProfile::Strict,
            ablation: Some(AblationMask {
                no_chroot: true,
                ..AblationMask::default()
            }),
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, workdir.path());
        assert!(
            plan.bind_mounts.is_empty(),
            "no_chroot ablation must zero out bind_mounts; got {} entries",
            plan.bind_mounts.len(),
        );
    }

    #[test]
    fn ablation_no_chroot_plan_carries_mask_through_to_pre_exec() {
        // Verify the mask survives `build_plan` so the pre_exec callback
        // can inspect it.  The pre_exec sequence itself is hard to drive
        // without an actual fork; the wire-level "Skipped" outcome
        // assertion lives in `run_pre_exec_outcome_with_no_chroot_mask`.
        let opts = SandboxOptions {
            process_hardening: ProcessHardeningProfile::Strict,
            ablation: Some(AblationMask {
                no_chroot: true,
                no_no_new_privs: true,
                ..AblationMask::default()
            }),
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        let mask = plan.ablation.expect("plan must carry the mask");
        assert!(mask.no_chroot);
        assert!(mask.no_no_new_privs);
    }

    #[test]
    fn ablation_extras_default_is_empty() {
        assert!(ablation_extras(None).is_empty());
        assert!(ablation_extras(Some(AblationMask::default())).is_empty());
    }

    #[test]
    fn ablation_no_seccomp_socket_extends_allowlist_with_socket_family() {
        let extras = ablation_extras(Some(AblationMask {
            no_seccomp_socket: true,
            ..AblationMask::default()
        }));
        for needle in ["socket", "bind", "connect", "accept"] {
            assert!(
                extras.contains(&needle),
                "no_seccomp_socket extras must include {needle}, got {extras:?}",
            );
        }
        for forbidden in ["setuid", "setgid"] {
            assert!(
                !extras.contains(&forbidden),
                "no_seccomp_socket extras must not leak setuid family",
            );
        }
    }

    #[test]
    fn ablation_no_seccomp_setuid_extends_allowlist_with_setuid_family() {
        let extras = ablation_extras(Some(AblationMask {
            no_seccomp_setuid: true,
            ..AblationMask::default()
        }));
        for needle in ["setuid", "setgid", "setreuid", "setresuid"] {
            assert!(
                extras.contains(&needle),
                "no_seccomp_setuid extras must include {needle}, got {extras:?}",
            );
        }
        for forbidden in ["socket", "bind"] {
            assert!(
                !extras.contains(&forbidden),
                "no_seccomp_setuid extras must not leak socket family",
            );
        }
    }

    #[test]
    fn ablation_no_seccomp_socket_bpf_includes_socket_syscall() {
        // Verify the extension reaches the compiled BPF program, not
        // just the name list.  socket() lives in the SSRF cap allowlist
        // today; without that cap bit set, the production path filters
        // it.  Ablation must add it back via the extras seed.
        let opts = SandboxOptions {
            seccomp_caps: 0,
            process_hardening: ProcessHardeningProfile::Strict,
            ablation: Some(AblationMask {
                no_seccomp_socket: true,
                ..AblationMask::default()
            }),
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        let socket_nr =
            seccomp::syscalls::syscall_number("socket").expect("socket in per-arch syscall map");
        // BPF compile emits one JEQ per allowed syscall (+ a fixed arch
        // prelude + a default-deny tail), so encoding socket as a JEQ
        // instruction's k-field is the load-bearing signal.
        let program = plan.seccomp_program.as_slice();
        let landed = program.iter().any(|insn| insn.k == socket_nr);
        assert!(
            landed,
            "BPF program must include socket={} after no_seccomp_socket ablation",
            socket_nr,
        );
    }

    #[test]
    fn ablation_no_seccomp_setuid_bpf_includes_setuid_syscall() {
        let opts = SandboxOptions {
            seccomp_caps: 0,
            process_hardening: ProcessHardeningProfile::Strict,
            ablation: Some(AblationMask {
                no_seccomp_setuid: true,
                ..AblationMask::default()
            }),
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        let setuid_nr =
            seccomp::syscalls::syscall_number("setuid").expect("setuid in per-arch syscall map");
        let program = plan.seccomp_program.as_slice();
        let landed = program.iter().any(|insn| insn.k == setuid_nr);
        assert!(
            landed,
            "BPF program must include setuid={} after no_seccomp_setuid ablation",
            setuid_nr,
        );
    }

    #[test]
    fn ablation_off_keeps_socket_filtered_when_cap_unset() {
        // Sanity: without the no_seccomp_socket toggle, socket() must
        // NOT land in the program when no cap requests it.  This is the
        // tripwire for an accidental "ablation extras always added"
        // regression.
        let opts = SandboxOptions {
            seccomp_caps: 0,
            process_hardening: ProcessHardeningProfile::Strict,
            ablation: None,
            ..SandboxOptions::default()
        };
        let plan = build_plan(&opts, std::path::Path::new("/tmp"));
        let socket_nr =
            seccomp::syscalls::syscall_number("socket").expect("socket in per-arch syscall map");
        let landed = plan.seccomp_program.iter().any(|insn| insn.k == socket_nr);
        assert!(
            !landed,
            "production path must filter socket() when no cap requests it",
        );
    }

    #[test]
    fn run_pre_exec_outcome_with_no_chroot_mask_skips_chroot_status() {
        // Drive `run_pre_exec_in_child` directly so we exercise the
        // ablation-aware status assignment without actually fork+exec.
        // The pre_exec sequence is allocator-free but ordinary Rust on
        // the parent thread — its only side effect under test is the
        // returned HardeningOutcome record, which is what tabulators
        // and ablation assertions consume.
        let plan = PreExecPlan {
            rlimit_cpu_seconds: 1,
            rlimit_nofile: 256,
            rlimit_as_bytes: 4096_u64 * 1024 * 1024,
            workdir_nul: b"/tmp\0".to_vec(),
            seccomp_program: Arc::new(Vec::new()),
            profile: ProcessHardeningProfileTag::Strict,
            bind_mounts: Vec::new(),
            unshare_flags: 0,
            ablation: Some(AblationMask {
                no_chroot: true,
                no_no_new_privs: true,
                ..AblationMask::default()
            }),
        };
        let outcome = run_pre_exec_in_child(&plan);
        assert!(
            matches!(outcome.chroot, PrimitiveStatus::Skipped),
            "no_chroot mask must yield Skipped, got {:?}",
            outcome.chroot,
        );
        assert!(
            matches!(outcome.no_new_privs, PrimitiveStatus::Skipped),
            "no_no_new_privs mask must yield Skipped, got {:?}",
            outcome.no_new_privs,
        );
    }
}
