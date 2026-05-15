//! Hand-rolled BPF program emitter for seccomp filters.
//!
//! BPF instruction format from `<linux/filter.h>`:
//!
//! ```text
//!   struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }
//! ```
//!
//! Only the ops Nyx needs to implement an AUDIT_ARCH check + per-syscall
//! allowlist are defined.  The output array is fed straight into
//! `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)`.

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

// BPF opcode constants — see `linux/bpf_common.h`.
pub const BPF_LD: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_K: u16 = 0x00;
pub const BPF_RET: u16 = 0x06;

// seccomp action constants — see `linux/seccomp.h`.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL: u32 = 0x0000_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

// Offsets into `struct seccomp_data` from `linux/seccomp.h`:
//   nr (s32) at offset 0
//   arch (u32) at offset 4
pub const SECCOMP_DATA_NR: u32 = 0;
pub const SECCOMP_DATA_ARCH: u32 = 4;

/// Emit a BPF program implementing:
///
/// 1. Load `arch` from `seccomp_data`; if it does not match
///    `audit_arch`, kill the process.
/// 2. Load `nr` from `seccomp_data`.
/// 3. For each `allowed_nr` in the table, jump to the ALLOW return.
/// 4. Default: return KILL_PROCESS (or KILL on older kernels).
///
/// The instruction count is `5 + allowed_nrs.len()` (plus one for the
/// final ALLOW return).  Linux caps seccomp programs at 4096
/// instructions; the realistic cap-per-finding allowlist is well under
/// 100.
pub fn compile(allowed_nrs: &[u32], audit_arch: u32) -> Vec<SockFilter> {
    let mut program: Vec<SockFilter> = Vec::with_capacity(allowed_nrs.len() + 8);

    // (0) ld [arch]
    program.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH,
    });
    // (1) jeq audit_arch ? next : KILL
    //     KILL is at the very end; computed below after we know the size.
    let arch_check_idx = program.len();
    program.push(SockFilter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 0, k: audit_arch });

    // (2) ld [nr]
    program.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR,
    });

    // (3..N) per-syscall jeq nr ? ALLOW : next
    //     ALLOW is two instructions before KILL (we lay out:
    //       ... checks ...
    //       ret KILL
    //       ret ALLOW
    //     ).  Each jeq jumps `(N - i - 1) + 1` (over the remaining checks
    //     plus the KILL ret) to land on the ALLOW ret.  Computed below.
    let first_check_idx = program.len();
    for &nr in allowed_nrs {
        program.push(SockFilter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 0, jf: 0, k: nr });
    }

    // (KILL) ret KILL_PROCESS
    let kill_idx = program.len();
    program.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    // (ALLOW) ret ALLOW
    let allow_idx = program.len();
    program.push(SockFilter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });

    // Patch arch check: jt=0 (next on match), jf=N (KILL on mismatch).
    let arch_jf = (kill_idx - arch_check_idx - 1) as u8;
    program[arch_check_idx].jf = arch_jf;

    // Patch each per-syscall jeq: jt = jump to ALLOW, jf = fall through.
    for (i, nr_idx) in (first_check_idx..first_check_idx + allowed_nrs.len()).enumerate() {
        let _ = i;
        let jt = (allow_idx - nr_idx - 1) as u8;
        program[nr_idx].jt = jt;
    }

    program
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_emits_arch_check_and_kill() {
        let prog = compile(&[], 0xc000_003e);
        // ld arch, jeq audit_arch, ld nr, ret KILL, ret ALLOW
        assert_eq!(prog.len(), 5);
        assert_eq!(prog[0].k, SECCOMP_DATA_ARCH);
        assert_eq!(prog[1].k, 0xc000_003e);
        assert_eq!(prog[2].k, SECCOMP_DATA_NR);
        assert_eq!(prog[3].k, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(prog[4].k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn single_syscall_allows_its_nr() {
        let prog = compile(&[42], 0xc000_003e);
        // ld arch, jeq audit_arch, ld nr, jeq 42, ret KILL, ret ALLOW
        assert_eq!(prog.len(), 6);
        let jeq = prog[3];
        assert_eq!(jeq.code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(jeq.k, 42);
        // jt jumps over the KILL ret (1 inst) to land on ALLOW
        assert_eq!(jeq.jt, 1);
        assert_eq!(prog[4].k, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(prog[5].k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn multi_syscall_jt_offsets_chain_to_allow() {
        let prog = compile(&[1, 2, 3], 0xc000_003e);
        // ld arch, jeq audit_arch, ld nr, jeq 1, jeq 2, jeq 3, KILL, ALLOW
        assert_eq!(prog.len(), 8);
        // jeq 1 at idx 3 → ALLOW at idx 7 → jt=7-3-1=3
        assert_eq!(prog[3].jt, 3);
        // jeq 2 at idx 4 → jt=7-4-1=2
        assert_eq!(prog[4].jt, 2);
        // jeq 3 at idx 5 → jt=7-5-1=1
        assert_eq!(prog[5].jt, 1);
    }

    #[test]
    fn arch_mismatch_jumps_to_kill() {
        let prog = compile(&[1, 2], 0xc000_003e);
        // ld arch (0), jeq arch (1), ld nr (2), jeq 1 (3), jeq 2 (4), KILL (5), ALLOW (6)
        // arch jeq jf must point to KILL → jf=5-1-1=3
        assert_eq!(prog[1].jf, 3);
        assert_eq!(prog[5].k, SECCOMP_RET_KILL_PROCESS);
    }
}
