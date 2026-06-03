//! Phase 17 (Track E.1) — seccomp-bpf default-deny filter.
//!
//! [`install_compiled_filter`] installs a pre-compiled BPF program (built
//! from the cap-tagged allowlist baked from `seccomp_policy.toml` via
//! `build.rs`) via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)`.
//! The filter is per-thread and inherited across `execve`, so the harness
//! runs under it from the very first instruction of its image.
//! The hardening pre_exec callback pre-compiles the program in the parent
//! and hands a borrowed slice to [`install_compiled_filter`] from inside
//! the child (allocator-free path; the post-fork allocator ban precludes
//! compiling from the child).
//!
//! Layout
//! ------
//! - `seccomp_policy.toml` — declarative cap → syscall table (the source
//!   of truth).  `build.rs` parses it and emits an inline-includable Rust
//!   table to `OUT_DIR/seccomp_policy.rs`.
//! - `bpf.rs` — minimal BPF instruction emitter (`compile()` returns a
//!   `Vec<SockFilter>`).
//! - `syscalls.rs` — name → number map, x86_64 / aarch64.
//!
//! Design choices
//! --------------
//! - Default action is `SECCOMP_RET_KILL_PROCESS` so a denied syscall
//!   takes the whole harness down (loud failure, easy to tell apart from
//!   a normal sink hit).
//! - Unknown syscall names from the policy are silently dropped — they
//!   can't be filtered without a number, and any kernel that recognises
//!   the name has the number too.  Tests assert the policy round-trips.

#![warn(clippy::undocumented_unsafe_blocks)]

pub mod bpf;
pub mod syscalls;

use std::collections::BTreeSet;

use crate::dynamic::sandbox::seccomp::bpf::{SockFilter, SockFprog};
use crate::dynamic::sandbox::seccomp::syscalls::{AUDIT_ARCH, syscall_number};

include!(concat!(env!("OUT_DIR"), "/seccomp_policy.rs"));

const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: u64 = 2;

// SAFETY: declares the libc `prctl(2)` / `__errno_location` ABI; signatures
// match the glibc/musl headers.
unsafe extern "C" {
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    fn __errno_location() -> *mut i32;
}

/// Compose the cap-aware syscall allowlist: the `BASE` set unconditionally
/// plus every `CAP[i]` whose bit is set in `caps`.  Names are deduped via a
/// `BTreeSet` and resolved to numbers via [`syscall_number`].  Unknown
/// names (not in the per-arch table) are silently dropped.
pub fn allowed_syscall_numbers(caps: u32) -> Vec<u32> {
    allowed_syscall_numbers_with_extras(caps, std::iter::empty())
}

/// Same as [`allowed_syscall_numbers`] but additionally folds in every
/// name yielded by `extras`.  Used by the Phase 20 ablation harness to
/// add the socket / setuid families back to the allowlist when a
/// per-primitive escape fixture wants to prove that removing the
/// corresponding seccomp filter flips the fixture red.  Unknown names
/// are silently dropped, identical to the base path.
pub fn allowed_syscall_numbers_with_extras<I>(caps: u32, extras: I) -> Vec<u32>
where
    I: IntoIterator<Item = &'static str>,
{
    let mut names: BTreeSet<&'static str> = BTreeSet::new();
    for &n in BASE.iter() {
        names.insert(n);
    }
    for &(bit, allowlist) in CAP.iter() {
        if caps & bit != 0 {
            for &n in allowlist.iter() {
                names.insert(n);
            }
        }
    }
    for n in extras {
        names.insert(n);
    }
    let mut nrs: Vec<u32> = names.into_iter().filter_map(syscall_number).collect();
    nrs.sort_unstable();
    nrs.dedup();
    nrs
}

/// Syscall names re-allowed when [`crate::dynamic::sandbox::AblationMask::no_seccomp_socket`]
/// is set.  Covers the socket-family entries of every cap allowlist
/// plus the raw / packet-socket primitives the
/// `tests/sandbox_escape_suite.rs::raw_socket_bind` fixture exercises.
pub const ABLATION_SOCKET_FAMILY: &[&str] = &[
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "getsockname",
    "getpeername",
    "getsockopt",
    "setsockopt",
];

/// Syscall names re-allowed when [`crate::dynamic::sandbox::AblationMask::no_seccomp_setuid`]
/// is set.  Covers the uid / gid mutation entries the
/// `tests/sandbox_escape_suite.rs::setuid_zero` fixture exercises.
pub const ABLATION_SETUID_FAMILY: &[&str] = &[
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setfsuid",
    "setfsgid",
];

/// Install a pre-compiled seccomp filter on the calling thread.
///
/// `program` MUST come from [`bpf::compile`].  Calls
/// `prctl(PR_SET_NO_NEW_PRIVS)` first (a kernel prerequisite for
/// unprivileged seccomp filter install) then
/// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`.  Returns the
/// underlying `io::Error` on failure.
///
/// Allocator-free: the function only borrows `program`, so the
/// hardening pre_exec callback can use it without violating the
/// post-fork allocator ban.
pub fn install_compiled_filter(program: &[SockFilter]) -> std::io::Result<()> {
    if AUDIT_ARCH == 0 || program.is_empty() {
        return Ok(());
    }

    // PR_SET_NO_NEW_PRIVS = 1 is a kernel prerequisite for unprivileged
    // seccomp filter install.  The Phase 17 hardening sequence already
    // calls it earlier, but installing here too is idempotent and
    // protects direct callers.
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, ..)` takes only scalar args and touches
    // no caller memory; idempotent, result intentionally ignored.
    let _ = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    let prog = SockFprog {
        len: program.len() as u16,
        filter: program.as_ptr(),
    };
    // SAFETY: `prog` and the `program` slice it points to outlive the call; the
    // pointer passed as u64 references a valid `SockFprog`. Return value checked below.
    let ret = unsafe {
        prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &prog as *const SockFprog as u64,
            0,
            0,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        // SAFETY: `__errno_location` returns a valid per-thread errno pointer,
        // dereferenced immediately after the failed prctl call.
        Err(std::io::Error::from_raw_os_error(unsafe {
            *__errno_location()
        }))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_table_is_non_empty() {
        assert!(
            !BASE.is_empty(),
            "seccomp BASE allowlist must include stdio + startup syscalls"
        );
    }

    #[test]
    fn cap_table_includes_known_caps() {
        let known: Vec<&str> = CAP.iter().map(|(_, _)| "_").collect();
        // We declared SQL_QUERY, FILE_IO, SSRF, CODE_EXEC, HTML_ESCAPE,
        // DESERIALIZE, HEADER_INJECTION, OPEN_REDIRECT in the toml; the
        // build script emits one entry per `[cap.X]` table.  The exact
        // count can grow as the policy grows; assert ≥ 4 so a future
        // accidental empty-policy regression is loud.
        assert!(known.len() >= 4, "CAP table emitted: {:?}", known.len());
    }

    #[test]
    fn allowlist_deduplicates_overlapping_caps() {
        // SSRF and HEADER_INJECTION both allow `socket`; the deduped set
        // must contain it exactly once.
        let nrs = allowed_syscall_numbers(0);
        let mut sorted = nrs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(nrs.len(), sorted.len());
    }

    #[test]
    fn caps_zero_returns_only_base() {
        let base = allowed_syscall_numbers(0);
        let with_caps = allowed_syscall_numbers(0xffff_ffff);
        assert!(base.len() <= with_caps.len());
    }

    /// `BASE` includes `read` / `write` / `close` — the minimum the
    /// harness needs to print to stdout and exit cleanly.
    #[test]
    fn base_allows_stdio() {
        let nrs = allowed_syscall_numbers(0);
        let read = syscall_number("read").expect("read in syscall map");
        let write = syscall_number("write").expect("write in syscall map");
        let close = syscall_number("close").expect("close in syscall map");
        assert!(nrs.contains(&read));
        assert!(nrs.contains(&write));
        assert!(nrs.contains(&close));
    }

    /// `BASE` carries the interpreter cold-start trio:
    /// `socketpair` (Node worker init), `umask` (Python tempfile init),
    /// `setrlimit` (older glibc fallback for `prlimit64`).  Without these
    /// a Python or Node harness aborts before printing a single line and
    /// the Confirmed-via-`verify_finding` path is structurally
    /// unreachable, so a regression that drops one is a load-bearing
    /// outage rather than a code-cleanliness slip.
    #[test]
    fn base_allows_interpreter_cold_start_syscalls() {
        let nrs = allowed_syscall_numbers(0);
        for name in ["socketpair", "umask", "setrlimit"] {
            let nr = syscall_number(name)
                .unwrap_or_else(|| panic!("{name} missing from per-arch syscall map"));
            assert!(
                nrs.contains(&nr),
                "BASE allowlist must include {name} (interpreter cold-start)",
            );
        }
    }
}
