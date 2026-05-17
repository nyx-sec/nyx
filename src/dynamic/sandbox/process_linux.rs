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
        let applied = primitives.iter().filter(|s| matches!(s, PrimitiveStatus::Applied)).count();
        let failed = primitives.iter().filter(|s| matches!(s, PrimitiveStatus::Failed(_))).count();
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
        data: *const i8,
    ) -> i32;
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
/// Called in pre_exec between [`apply_unshare`] and [`apply_chroot`] so
/// the new mount namespace is private to the child + grandchildren and
/// the workdir is still reachable at its host-side absolute path.
fn apply_bind_mounts(mounts: &[BindMount]) {
    let none = b"none\0";
    for m in mounts {
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
    /// [`SandboxOptions::bind_mount_host_libs`] is false or the active
    /// profile is `Standard` (no namespace to bind into).
    bind_mounts: Vec<BindMount>,
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
    // Bind-mount host library paths into the workdir after unshare (so
    // the new mount namespace catches them) and before chroot (so the
    // bind sources are still reachable at their absolute host paths).
    // No-op when `bind_mounts` is empty.
    apply_bind_mounts(&plan.bind_mounts);
    outcome.chroot = apply_chroot(&plan.workdir_nul);
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
    // `prctl(PR_SET_SECCOMP)`.
    let nrs = seccomp::allowed_syscall_numbers(opts.seccomp_caps);
    let program = seccomp::bpf::compile(&nrs, seccomp::syscalls::AUDIT_ARCH);

    let profile = match opts.process_hardening {
        ProcessHardeningProfile::Standard => ProcessHardeningProfileTag::Standard,
        ProcessHardeningProfile::Strict => ProcessHardeningProfileTag::Strict,
    };

    // Bind-mounts are only useful when the child will chroot, i.e. under
    // the Strict profile.  Computing them under Standard would create
    // empty dest dirs in the workdir for no reason.
    let bind_mounts = if opts.bind_mount_host_libs
        && matches!(profile, ProcessHardeningProfileTag::Strict)
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
    }
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
            assert!(m.source_nul.ends_with(&[0]), "source path must be NUL-terminated");
            assert!(m.dest_nul.ends_with(&[0]), "dest path must be NUL-terminated");
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

}
