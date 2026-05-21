//! Phase 17 (Track E.1) — Linux process backend hardening acceptance tests.
//!
//! Each primitive in the Phase 17 sequence is exercised against a
//! statically-linked C probe (`tests/dynamic_fixtures/hardening/probe.c`)
//! that prints its own `/proc/self` view to stdout.  The Rust test reads
//! stdout back and asserts on the expected line per primitive.
//!
//! The probe is built once per test run via `cc -static -O2`.  Hosts
//! without `cc` or without a static-link-capable libc skip with an
//! `eprintln!` rather than failing — the suite's authoritative gate is
//! the Linux CI matrix row that has both.
//!
//! Run with:
//!   `cargo nextest run --features dynamic --test sandbox_hardening_linux`

#[cfg(all(feature = "dynamic", target_os = "linux"))]
mod hardening_tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;
    use std::time::Duration;

    use nyx_scanner::dynamic::harness::BuiltHarness;
    use nyx_scanner::dynamic::sandbox::process_linux::{HardeningLevel, PrimitiveStatus};
    use nyx_scanner::dynamic::sandbox::seccomp;
    use nyx_scanner::dynamic::sandbox::{
        self, HardeningRecord, ProcessHardeningProfile, SandboxBackend, SandboxOptions,
    };

    fn linux_outcome(
        out: &sandbox::SandboxOutcome,
    ) -> Option<nyx_scanner::dynamic::sandbox::process_linux::HardeningOutcome> {
        match out.hardening_outcome.as_ref()? {
            HardeningRecord::Linux(o) => Some(*o),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    // ── Probe build ───────────────────────────────────────────────────────────

    /// Path to the freshly-built probe binary, shared across every test.
    static PROBE_BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();

    fn probe_path() -> Option<&'static Path> {
        PROBE_BINARY.get_or_init(|| build_probe_once()).as_deref()
    }

    fn build_probe_once() -> Option<PathBuf> {
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/hardening/probe.c");
        let out_dir = std::env::temp_dir().join("nyx-hardening-probe");
        let _ = std::fs::create_dir_all(&out_dir);
        let out_bin = out_dir.join("probe");

        // Try a static link first (works under glibc-dev with libc.a, or
        // musl-cross).  Fall back to dynamic if that fails — the probe
        // still functions before chroot but the chroot test will skip.
        let static_status = Command::new(&cc)
            .args(["-static", "-O2", "-o"])
            .arg(&out_bin)
            .arg(&src)
            .status();
        if matches!(&static_status, Ok(s) if s.success()) {
            return Some(out_bin);
        }

        let dyn_status = Command::new(&cc)
            .args(["-O2", "-o"])
            .arg(&out_bin)
            .arg(&src)
            .status();
        if matches!(&dyn_status, Ok(s) if s.success()) {
            // Mark via env so the chroot test can branch.
            unsafe { std::env::set_var("NYX_PROBE_DYNAMIC", "1") };
            return Some(out_bin);
        }

        eprintln!(
            "SKIP: could not build hardening probe with {cc:?} (static={static_status:?}, \
             dyn={dyn_status:?})"
        );
        None
    }

    fn probe_is_static() -> bool {
        std::env::var_os("NYX_PROBE_DYNAMIC").is_none()
    }

    // ── Sandbox helpers ───────────────────────────────────────────────────────

    fn strict_opts() -> SandboxOptions {
        SandboxOptions {
            timeout: Duration::from_secs(10),
            memory_mib: 256,
            backend: SandboxBackend::Process,
            output_limit: 65536,
            process_hardening: ProcessHardeningProfile::Strict,
            // Keep seccomp_caps = 0 so only the BASE allowlist applies:
            // the probe needs `read`, `write`, `openat`, `readlink`, etc.,
            // all of which are in the base set.
            seccomp_caps: 0,
            ..SandboxOptions::default()
        }
    }

    fn standard_opts() -> SandboxOptions {
        SandboxOptions {
            timeout: Duration::from_secs(10),
            memory_mib: 256,
            backend: SandboxBackend::Process,
            output_limit: 65536,
            process_hardening: ProcessHardeningProfile::Standard,
            ..SandboxOptions::default()
        }
    }

    fn build_harness_with_probe(workdir: &Path, args: &[&str]) -> BuiltHarness {
        // Stage the probe inside the workdir so `chroot(workdir)` doesn't
        // leave the binary unreachable mid-exec.
        let probe_src = probe_path().expect("probe must be built").to_path_buf();
        let probe_dst = workdir.join("probe");
        std::fs::copy(&probe_src, &probe_dst).expect("copy probe into workdir");
        // Ensure it's executable (cc preserves +x but be explicit).
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&probe_dst).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&probe_dst, perms).unwrap();

        let mut command: Vec<String> = vec![probe_dst.to_string_lossy().into_owned()];
        for a in args {
            command.push((*a).to_string());
        }

        BuiltHarness {
            workdir: workdir.to_path_buf(),
            command,
            env: vec![],
            source: String::new(),
            entry_source: String::new(),
        }
    }

    fn workdir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("temp dir")
    }

    fn stdout_string(out: &sandbox::SandboxOutcome) -> String {
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn assert_line(stdout: &str, prefix: &str) {
        assert!(
            stdout.lines().any(|l| l.starts_with(prefix)),
            "expected stdout to contain a line starting with {prefix:?}; full stdout:\n{stdout}"
        );
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Sanity gate: the probe must build and run on a Confirmed
    /// (exit-zero) baseline.  All other tests presume this passes.
    #[test]
    fn probe_runs_under_strict_profile() {
        let Some(_) = probe_path() else { return };
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        eprintln!("probe stdout under strict:\n{stdout}");
        // Probe always prints a `__NYX_PROBE_DONE__` sentinel after the
        // primitive lines; absence means the binary died before reaching
        // the end (e.g. seccomp killed it).  A clean Confirmed run prints
        // it.
        assert_line(&stdout, "__NYX_PROBE_DONE__");
    }

    #[test]
    fn no_new_privs_set_under_strict() {
        let Some(_) = probe_path() else { return };
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        // /proc/self/status's `NoNewPrivs:` line is `1` after PR_SET_NO_NEW_PRIVS.
        assert!(
            stdout.contains("NoNewPrivs:\t1"),
            "expected NoNewPrivs:1 line; full stdout:\n{stdout}"
        );
    }

    #[test]
    fn rlimit_cpu_capped_under_strict() {
        let Some(_) = probe_path() else { return };
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        // RLIMIT_CPU is set to timeout * 2 = 20 seconds in strict_opts.
        // Under Standard the value would be RLIM_INFINITY.
        assert_line(&stdout, "rlimit_cpu:");
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("rlimit_cpu:") {
                let (cur, _) = rest.split_once('/').expect("rlimit_cpu format");
                let cur: u64 = cur.parse().expect("numeric rlimit");
                assert!(cur <= 30, "RLIMIT_CPU not capped: {cur}");
                return;
            }
        }
        panic!("rlimit_cpu line missing from stdout:\n{stdout}");
    }

    #[test]
    fn rlimit_nofile_capped_under_strict() {
        let Some(_) = probe_path() else { return };
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("rlimit_nofile:") {
                let (cur, _) = rest.split_once('/').expect("rlimit_nofile format");
                let cur: u64 = cur.parse().expect("numeric rlimit");
                assert!(cur <= 256, "RLIMIT_NOFILE not capped: {cur}");
                return;
            }
        }
        panic!("rlimit_nofile line missing from stdout:\n{stdout}");
    }

    #[test]
    fn rlimit_as_capped_under_strict() {
        let Some(_) = probe_path() else { return };
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("rlimit_as:") {
                let (cur, _) = rest.split_once('/').expect("rlimit_as format");
                let cur: u64 = cur.parse().expect("numeric rlimit");
                // memory_mib=256 → cap = max(256*8, 4096) MiB = 4 GiB
                let four_gib = 4_u64 * 1024 * 1024 * 1024;
                assert_eq!(cur, four_gib, "RLIMIT_AS not 4 GiB: {cur}");
                return;
            }
        }
        panic!("rlimit_as line missing from stdout:\n{stdout}");
    }

    /// `unshare(CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNS)` is best-effort.
    /// On hosts that allow unprivileged user namespaces the probe's
    /// `/proc/self/ns/user` inode differs from the parent's; on locked-
    /// down hosts (sysctl `kernel.unprivileged_userns_clone=0`) the
    /// outcome decays to `Partial` instead of failing the run.
    #[test]
    fn unshare_namespaces_when_kernel_allows() {
        let Some(_) = probe_path() else { return };
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        let outcome = linux_outcome(&result).expect("hardening outcome recorded");

        // Parent's user-ns inode for comparison.
        let parent_user_ns =
            std::fs::read_link("/proc/self/ns/user").map(|p| p.to_string_lossy().into_owned());

        match outcome.unshare {
            PrimitiveStatus::Applied => {
                let probe_user_ns_line = stdout
                    .lines()
                    .find(|l| l.starts_with("ns_user:"))
                    .expect("ns_user: line in stdout");
                if let Ok(parent) = parent_user_ns {
                    assert!(
                        !probe_user_ns_line.contains(parent.as_str()),
                        "child user ns identical to parent — unshare reported Applied but ns inode unchanged"
                    );
                }
            }
            PrimitiveStatus::Failed(errno) => {
                eprintln!(
                    "unshare returned errno={errno} (likely unprivileged_userns_clone=0); \
                     accepting Partial level"
                );
                assert!(matches!(
                    outcome.level(),
                    HardeningLevel::Partial | HardeningLevel::None
                ));
            }
            PrimitiveStatus::Skipped => panic!("unshare must not be Skipped under Strict profile"),
        }
    }

    /// `chroot` should make the host's `/etc/passwd` unreachable from
    /// inside the harness.  Under the Strict profile and a static probe
    /// the file open returns ENOENT and the probe prints
    /// `chroot:blocked`.
    #[test]
    fn chroot_blocks_etc_passwd() {
        let Some(_) = probe_path() else { return };
        if !probe_is_static() {
            eprintln!(
                "SKIP: probe is dynamically linked — chroot would block its loader before main()"
            );
            return;
        }
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        let outcome = linux_outcome(&result).expect("hardening outcome recorded");

        match outcome.chroot {
            PrimitiveStatus::Applied => {
                assert!(
                    stdout.contains("chroot:blocked"),
                    "chroot reported Applied but /etc/passwd was readable; full stdout:\n{stdout}"
                );
            }
            PrimitiveStatus::Failed(errno) => {
                // Common failure: EPERM when the kernel blocks chroot
                // for unprivileged callers without CAP_SYS_CHROOT, or
                // EINVAL when the workdir doesn't satisfy the
                // canonicalisation precondition.  Accept Partial.
                eprintln!("chroot returned errno={errno}; recorded as Partial");
                assert_ne!(outcome.level(), HardeningLevel::Full);
            }
            PrimitiveStatus::Skipped => panic!("chroot must not be Skipped under Strict profile"),
        }
    }

    /// Path-traversal acceptance case from the phase deliverables.
    /// Drives the probe with `traverse` so it tries to open
    /// `/etc/passwd`; the binary exits non-zero on chroot success
    /// (mapped to `NotConfirmed` by the runner's exit-code rule) and
    /// prints `chroot blocked` for the test to assert on.
    #[test]
    fn path_traversal_returns_not_confirmed_when_chroot_holds() {
        let Some(_) = probe_path() else { return };
        if !probe_is_static() {
            eprintln!("SKIP: probe is dynamically linked — chroot test requires static link");
            return;
        }
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &["traverse"]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        let outcome = linux_outcome(&result).expect("hardening outcome recorded");

        if matches!(outcome.chroot, PrimitiveStatus::Applied) {
            // NotConfirmed shape: the verifier maps a non-zero exit + no
            // sink-hit sentinel to NotConfirmed.  We assert the two
            // structural pieces here directly.
            assert_eq!(
                result.exit_code,
                Some(7),
                "probe exit code mismatch — full stdout:\n{stdout}"
            );
            assert!(
                !result.sink_hit,
                "sink hit should be absent on a traversal-blocked run"
            );
            assert!(
                stdout.contains("chroot blocked")
                    || stdout.contains("chroot:blocked")
                    || stdout.contains("traverse:blocked"),
                "expected `chroot blocked` marker in probe stdout; got:\n{stdout}"
            );
        } else {
            eprintln!(
                "SKIP: chroot did not apply (status={:?}); cannot assert traversal blocked",
                outcome.chroot,
            );
        }
    }

    /// seccomp filter installs cleanly under the Strict profile and the
    /// probe survives long enough to print its sentinel.  /proc/self/
    /// status's `Seccomp:` line transitions from `0` (disabled) to `2`
    /// (filter mode) when the prctl call succeeds.
    #[test]
    fn seccomp_filter_installed_under_strict() {
        let Some(_) = probe_path() else { return };
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = strict_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        let outcome = linux_outcome(&result).expect("hardening outcome recorded");

        match outcome.seccomp {
            PrimitiveStatus::Applied => {
                assert!(
                    stdout.contains("Seccomp:\t2"),
                    "Seccomp:2 missing — filter not active in /proc/self/status; stdout:\n{stdout}"
                );
            }
            PrimitiveStatus::Failed(errno) => {
                eprintln!(
                    "SKIP: seccomp prctl returned errno={errno} (typical when running under \
                     a sandbox that already locked the syscall down); accepting Partial level"
                );
                assert_ne!(outcome.level(), HardeningLevel::Full);
            }
            PrimitiveStatus::Skipped => panic!("seccomp must not be Skipped under Strict profile"),
        }
    }

    /// Standard profile keeps the historical baseline: PR_SET_NO_NEW_PRIVS
    /// and RLIMIT_AS only.  /etc/passwd should still be readable
    /// (no chroot) and the seccomp counter stays at 0.
    #[test]
    fn standard_profile_skips_chroot_and_seccomp() {
        let Some(_) = probe_path() else { return };
        let tmp = workdir();
        let harness = build_harness_with_probe(tmp.path(), &[]);
        let opts = standard_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        let outcome = linux_outcome(&result).expect("hardening outcome recorded");

        assert_eq!(outcome.level(), HardeningLevel::Baseline);
        assert!(matches!(outcome.no_new_privs, PrimitiveStatus::Applied));
        assert!(matches!(outcome.rlimit_as, PrimitiveStatus::Applied));
        // None of the strict-only primitives should have been attempted.
        assert!(matches!(outcome.chroot, PrimitiveStatus::Skipped));
        assert!(matches!(outcome.seccomp, PrimitiveStatus::Skipped));
        assert!(matches!(outcome.unshare, PrimitiveStatus::Skipped));

        // Baseline: /etc/passwd should still be open-able from the host.
        // The probe prints either `chroot:blocked` (if outside the
        // sandbox restricted further) or `chroot:escaped`.  We don't
        // require either: the assertion here is purely on the recorded
        // hardening outcome.
        let _ = stdout;
        let _ = result.exit_code;
    }

    /// Phase 17 acceptance (e): Strict-profile run of a C `Cap::CODE_EXEC`
    /// fixture confirms AND stamps `VerifyResult::hardening_outcome` with
    /// the `linux-process` backend tag, mirroring the macOS counterpart at
    /// `tests/sandbox_hardening_macos.rs::verify_finding_under_strict_stamps_hardening_outcome`.
    /// Drives the full `verify_finding` pipeline (spec derivation → build →
    /// run → projection) so the typed-parameter wiring from
    /// `runner.rs::ensure_build` through `prepare_c(spec, workdir, profile)`
    /// gets exercised end-to-end: the Strict profile forces `cc -static`,
    /// which keeps the chrooted harness reachable after `chroot(workdir)`
    /// strips the host's `/lib*`.
    ///
    /// Skips when (a) `cc` is missing, (b) `cc -static` can't link
    /// against libc.a (no `libc6-dev` or `musl-cross`), or (c) seccomp
    /// is unavailable.  The Linux CI matrix row in `.github/workflows/dynamic.yml`
    /// installs `libc6-dev` (line 67) so the static link succeeds there;
    /// hosts without it skip with an eprintln rather than failing.
    #[test]
    fn verify_finding_under_strict_stamps_hardening_outcome() {
        use std::path::PathBuf;

        if std::process::Command::new(
            std::env::var("NYX_CC_BIN").unwrap_or_else(|_| "cc".to_owned()),
        )
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
        {
            eprintln!("SKIP: cc missing — cannot build C harness for strict-profile run");
            return;
        }

        // Pre-flight: confirm `cc -static` actually links.  Without libc.a
        // the build sandbox falls back to dynamic and chroot kills the
        // harness before main(), which would surface as a spurious
        // `NotConfirmed` rather than the wiring failure we'd want to flag.
        let probe_tmp = tempfile::TempDir::new().expect("probe tempdir");
        let probe_src = probe_tmp.path().join("nyx_static_probe.c");
        std::fs::write(&probe_src, "int main(void) { return 0; }\n")
            .expect("write static probe source");
        let probe_bin = probe_tmp.path().join("nyx_static_probe");
        let static_ok = std::process::Command::new(
            std::env::var("NYX_CC_BIN").unwrap_or_else(|_| "cc".to_owned()),
        )
        .args(["-static", "-O0", "-o"])
        .arg(&probe_bin)
        .arg(&probe_src)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
        if !static_ok {
            eprintln!(
                "SKIP: `cc -static` cannot link — install `libc6-dev` (Debian/Ubuntu) \
                 or `musl-cross` to exercise the chroot-bound static binary path"
            );
            return;
        }

        use nyx_scanner::commands::scan::Diag;
        use nyx_scanner::dynamic::verify::{VerifyOptions, verify_finding};
        use nyx_scanner::evidence::{Confidence, Evidence, FlowStep, FlowStepKind, VerifyStatus};
        use nyx_scanner::labels::Cap;
        use nyx_scanner::patterns::{FindingCategory, Severity};
        use nyx_scanner::utils::config::Config;

        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/c/free_fn/vuln.c");

        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("vuln.c");
        std::fs::copy(&fixture_src, &dst).expect("stage fixture into tempdir");

        unsafe {
            std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
            std::env::set_var(
                "NYX_TELEMETRY_PATH",
                tmp.path().join("events.jsonl").to_str().unwrap(),
            );
            // Clear any prior fallback marker so the assertion below
            // distinguishes a fresh fallback from a stale one set by an
            // earlier test in the same process.
            std::env::remove_var("NYX_BUILD_STATIC_FALLBACK");
        }

        let path_str = dst.to_string_lossy().into_owned();
        let evidence = Evidence {
            flow_steps: vec![
                FlowStep {
                    step: 1,
                    kind: FlowStepKind::Source,
                    file: path_str.clone(),
                    line: 10,
                    col: 0,
                    snippet: None,
                    variable: Some("payload".into()),
                    callee: None,
                    function: Some("run".into()),
                    is_cross_file: false,
                },
                FlowStep {
                    step: 2,
                    kind: FlowStepKind::Sink,
                    file: path_str.clone(),
                    line: 16,
                    col: 4,
                    snippet: None,
                    variable: None,
                    callee: Some("system".into()),
                    function: None,
                    is_cross_file: false,
                },
            ],
            sink_caps: Cap::CODE_EXEC.bits(),
            ..Default::default()
        };
        let diag = Diag {
            path: path_str,
            line: 16,
            col: 0,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: Some(Confidence::High),
            evidence: Some(evidence),
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: vec![],
            stable_hash: 0,
        };

        let mut config = Config::default();
        config.scanner.harden_profile = "strict".to_owned();
        // Pin the process backend: `Auto` would route to docker when
        // reachable, and docker ignores `process_hardening`, masking the
        // wiring this test is asserting.
        config.scanner.verify_backend = "process".to_owned();
        let opts = VerifyOptions::from_config(&config);
        let result = verify_finding(&diag, &opts);

        let fallback = std::env::var_os("NYX_BUILD_STATIC_FALLBACK").is_some();
        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
            std::env::remove_var("NYX_BUILD_STATIC_FALLBACK");
        }

        if fallback {
            eprintln!(
                "SKIP: prepare_c fell back to dynamic link mid-run \
                 (libc.a vanished between pre-flight and build); \
                 chroot would defeat the harness before main()"
            );
            return;
        }

        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "free_fn/vuln.c under --harden=strict should confirm: detail={:?}",
            result.detail,
        );
        let summary = result
            .hardening_outcome
            .as_ref()
            .expect("Strict run must stamp hardening_outcome");
        assert_eq!(
            summary.backend, "linux-process",
            "Linux host should produce a linux-process backend stamp",
        );
        assert_eq!(
            summary.profile, "strict",
            "Strict profile tag must round-trip through summarize_hardening",
        );
        assert!(
            !summary.primitives.is_empty(),
            "Linux backend records one entry per primitive (no_new_privs, rlimit_*, \
             unshare, chroot, seccomp); got: {:?}",
            summary.primitives,
        );
        assert!(
            summary
                .primitives
                .iter()
                .any(|p| p.name == "no_new_privs" && p.status == "applied"),
            "no_new_privs must apply under Strict — primitives: {:?}",
            summary.primitives,
        );
    }

    /// Phase 17 follow-up: interpreter-language harnesses survive the
    /// Strict chroot because `VerifyOptions::from_config` flips
    /// `bind_mount_host_libs = true` for any interpreted-lang spec
    /// (Python / JS / TS / Java / Ruby / PHP).  Drives the full
    /// `verify_finding` pipeline against
    /// `tests/dynamic_fixtures/python/cmdi_positive.py` under
    /// `harden_profile = "strict"` + `verify_backend = "process"` and
    /// asserts the python3 harness produced non-empty stdout — proof
    /// that `ld.so` + `libpython` resolved from the bind-mounted host
    /// directories inside the workdir-chroot.
    ///
    /// Skips when (a) `/usr/bin/python3` is missing on the host or
    /// (b) the per-cap macOS `.sb` path is reached (this test is
    /// `target_os = "linux"`-gated at the module level so case (b) is
    /// a compile-time skip on macOS, but the python3 pre-flight still
    /// covers Linux hosts without a system python).
    ///
    /// Mirrors the macOS counterpart at
    /// `tests/determinism_audit.rs::confirmed_run_is_byte_identical_across_runs`
    /// (same fixture, same Cap::CODE_EXEC payload, same flow_steps
    /// shape) so the only behavioural delta between hosts is the
    /// chroot + bind-mount layer this test gates.
    #[test]
    fn interpreter_strict_run_chroot_bind_mounts_work() {
        use std::path::PathBuf;

        if std::process::Command::new("/usr/bin/python3")
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!(
                "SKIP: /usr/bin/python3 missing — cannot drive the python harness through \
                 the Strict chroot.  Install python3 (Debian/Ubuntu: `apt install python3`)."
            );
            return;
        }

        use nyx_scanner::commands::scan::Diag;
        use nyx_scanner::dynamic::verify::{VerifyOptions, verify_finding};
        use nyx_scanner::evidence::{Confidence, Evidence, FlowStep, FlowStepKind, VerifyStatus};
        use nyx_scanner::labels::Cap;
        use nyx_scanner::patterns::{FindingCategory, Severity};
        use nyx_scanner::utils::config::Config;

        let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/python/cmdi_positive.py");

        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let dst = tmp.path().join("cmdi_positive.py");
        std::fs::copy(&fixture_src, &dst).expect("stage fixture into tempdir");

        unsafe {
            std::env::set_var("NYX_REPRO_BASE", tmp.path().join("repro").to_str().unwrap());
            std::env::set_var(
                "NYX_TELEMETRY_PATH",
                tmp.path().join("events.jsonl").to_str().unwrap(),
            );
        }

        let path_str = dst.to_string_lossy().into_owned();
        let evidence = Evidence {
            flow_steps: vec![
                FlowStep {
                    step: 1,
                    kind: FlowStepKind::Source,
                    file: path_str.clone(),
                    line: 9,
                    col: 0,
                    snippet: None,
                    variable: Some("host".into()),
                    callee: None,
                    function: Some("run_ping".into()),
                    is_cross_file: false,
                },
                FlowStep {
                    step: 2,
                    kind: FlowStepKind::Sink,
                    file: path_str.clone(),
                    line: 11,
                    col: 4,
                    snippet: None,
                    variable: None,
                    callee: Some("subprocess.run".into()),
                    function: None,
                    is_cross_file: false,
                },
            ],
            sink_caps: Cap::CODE_EXEC.bits(),
            ..Default::default()
        };
        let diag = Diag {
            path: path_str,
            line: 11,
            col: 0,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: Some(Confidence::High),
            evidence: Some(evidence),
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: vec![],
            stable_hash: 0,
        };

        let mut config = Config::default();
        config.scanner.harden_profile = "strict".to_owned();
        config.scanner.verify_backend = "process".to_owned();
        let opts = VerifyOptions::from_config(&config);

        // Sanity-check the wiring before driving the verifier: the
        // `from_config` predicate must have flipped on the
        // bind-mount opt-in for this Python diag because Strict +
        // Python is the exact case `lang_needs_host_libs` was added
        // for.  Note: `from_config` itself does not see the diag,
        // so the flag is actually set inside `verify_finding`'s
        // per-finding clone — what we assert here is only that
        // Strict survived the from_config round-trip.  If this
        // assertion ever flips, the verifier's per-finding wiring
        // has regressed.
        assert!(
            matches!(
                opts.sandbox.process_hardening,
                ProcessHardeningProfile::Strict,
            ),
            "harden_profile=strict must engage ProcessHardeningProfile::Strict so \
             the per-finding clone in `verify_finding` can layer bind-mounts on top",
        );

        let result = verify_finding(&diag, &opts);

        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }

        // The Strict chroot only survives if `mount(2)` actually
        // bind-mounted the host's libpython + ld.so inside the
        // workdir.  A failed bind-mount surfaces as a python3 cold-
        // start crash before `subprocess.run` ever fires, which the
        // oracle reports as `NotConfirmed`.
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "cmdi_positive.py under --harden=strict must Confirm: \
             interpreter cold-start should succeed via bind-mounted /lib + /usr/lib + \
             /usr/bin (detail={:?})",
            result.detail,
        );
        let summary = result
            .hardening_outcome
            .as_ref()
            .expect("Strict run must stamp hardening_outcome");
        assert_eq!(
            summary.backend, "linux-process",
            "Linux host should produce a linux-process backend stamp",
        );
        assert_eq!(
            summary.profile, "strict",
            "Strict profile tag must round-trip through summarize_hardening",
        );
        assert!(
            !summary.primitives.is_empty(),
            "Linux backend records one entry per primitive; got: {:?}",
            summary.primitives,
        );
        assert!(
            summary
                .primitives
                .iter()
                .any(|p| p.name == "chroot" && p.status == "applied"),
            "chroot primitive must apply under Strict — bind-mounts only matter \
             when chroot is active.  primitives: {:?}",
            summary.primitives,
        );
    }

    /// Seccomp policy synthesised from `seccomp_policy.toml` includes
    /// the syscalls required for the probe to reach `__NYX_PROBE_DONE__`
    /// (read, write, openat, readlinkat, fcntl, exit_group, …).  This
    /// tests the codegen path without touching the kernel.
    #[test]
    fn seccomp_policy_includes_essential_syscalls() {
        let nrs = seccomp::allowed_syscall_numbers(0);
        for essential in &["read", "write", "close", "openat", "exit_group", "fstat"] {
            let nr = seccomp::syscalls::syscall_number(essential)
                .unwrap_or_else(|| panic!("syscall {essential} missing from per-arch table"));
            assert!(
                nrs.contains(&nr),
                "BASE seccomp allowlist missing essential syscall {essential} (nr={nr})"
            );
        }
    }
}

// Non-Linux placeholder so `cargo nextest run --test sandbox_hardening_linux`
// doesn't fail with "no tests to run" on macOS / Windows CI rows.  The real
// suite gates every test on `target_os = "linux"`.
#[cfg(not(all(feature = "dynamic", target_os = "linux")))]
mod non_linux_placeholder {
    #[test]
    fn linux_only_suite_skipped_on_this_target() {
        eprintln!(
            "SKIP: tests/sandbox_hardening_linux.rs requires `--features dynamic` and \
             target_os = linux"
        );
    }
}
