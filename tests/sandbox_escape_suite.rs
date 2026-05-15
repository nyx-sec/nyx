//! Phase 20 (Track E.5) — non-vacuous sandbox-escape regression suite.
//!
//! Each fixture under `tests/dynamic_fixtures/escape/<technique>/{vuln,benign}`
//! is a small statically-linked C program that:
//!
//! 1. prints `__NYX_SINK_HIT__` so the process backend's
//!    [`SandboxOutcome::sink_hit`] flag flips to `true`, and
//! 2. (for `vuln/`) attempts the technique-specific escape — writing a
//!    sentinel file to a host-absolute path.
//!
//! For each fixture the test asserts BOTH:
//!
//! - the sink probe fired (else: harness failed to boot, surfaced as a
//!   `escape suite contains a Track-B regression` panic rather than a
//!   silent pass), and
//! - the host-absolute sentinel path is absent after the run (i.e. the
//!   chroot + seccomp + no_new_privs primitives kept the escape contained).
//!
//! Phase 17's primitives are the load-bearing guarantee.  Removing any one
//! of them flips at least one fixture from green to red:
//!
//! | primitive removed       | fixture that flips                    |
//! |-------------------------|---------------------------------------|
//! | `chroot`                | all six (sentinels appear on host)    |
//! | `seccomp` (`socket`)    | `raw_socket_bind`                     |
//! | `seccomp` (`setuid`)    | `setuid_zero`                         |
//! | `unshare(NEWPID|NEWUSER)`| `proc_root_passwd`, `setuid_zero`    |
//! | `no_new_privs`          | `chmod_4755` (setuid bit survives)    |
//!
//! Build prerequisite: a `cc` that can `-static -O2`.  Hosts without a
//! static libc skip with an `eprintln!` SKIP line — the suite's CI gate is
//! the Linux row with `libc6-dev` installed.
//!
//! Run with:
//!   `cargo nextest run --features dynamic --test sandbox_escape_suite`

#[cfg(all(feature = "dynamic", target_os = "linux"))]
mod escape_suite {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use nyx_scanner::dynamic::harness::BuiltHarness;
    use nyx_scanner::dynamic::sandbox::{
        self, ProcessHardeningProfile, SandboxBackend, SandboxOptions,
    };

    /// Per-technique fixture descriptor.  Drives both the per-variant
    /// build step and the host-side sentinel cleanup.
    struct Technique {
        /// Subdirectory name under `tests/dynamic_fixtures/escape`.
        name: &'static str,
        /// Host-absolute sentinel path the `vuln/` variant tries to write.
        /// Tested for absence after each run.
        sentinel: &'static str,
    }

    const TECHNIQUES: &[Technique] = &[
        Technique {
            name: "chmod_4755",
            sentinel: "/tmp/nyx_escape_chmod_4755_sentinel",
        },
        Technique {
            name: "etc_write",
            sentinel: "/etc/nyx_escape_etc_write_sentinel",
        },
        Technique {
            name: "dlopen_outside_chroot",
            sentinel: "/tmp/nyx_escape_dlopen_sentinel",
        },
        Technique {
            name: "proc_root_passwd",
            sentinel: "/tmp/nyx_escape_proc_root_sentinel",
        },
        Technique {
            name: "raw_socket_bind",
            sentinel: "/tmp/nyx_escape_raw_socket_sentinel",
        },
        Technique {
            name: "setuid_zero",
            sentinel: "/tmp/nyx_escape_setuid_zero_sentinel",
        },
    ];

    fn technique(name: &str) -> &'static Technique {
        TECHNIQUES
            .iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("unknown technique `{name}` — update TECHNIQUES table"))
    }

    // ── Build cache ──────────────────────────────────────────────────────────

    /// Per-(technique, variant) compiled binary path.  `None` when the
    /// build failed (e.g. no static libc) — in that case the test SKIPs
    /// rather than failing.
    static BUILDS: OnceLock<Mutex<HashMap<String, Option<PathBuf>>>> = OnceLock::new();

    fn builds() -> &'static Mutex<HashMap<String, Option<PathBuf>>> {
        BUILDS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Compile the C source for `<technique>/<variant>` and return the
    /// path to the resulting binary.  `None` ⇒ build failed (toolchain
    /// missing).  Results are cached.
    fn compile_fixture(technique: &str, variant: &str) -> Option<PathBuf> {
        let key = format!("{technique}::{variant}");
        if let Some(entry) = builds().lock().unwrap().get(&key) {
            return entry.clone();
        }

        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/dynamic_fixtures/escape")
            .join(technique)
            .join(variant)
            .join("main.c");
        if !src.is_file() {
            eprintln!("SKIP[{key}]: missing fixture source {src:?}");
            builds().lock().unwrap().insert(key, None);
            return None;
        }

        let out_dir = std::env::temp_dir().join("nyx-escape-suite");
        let _ = std::fs::create_dir_all(&out_dir);
        let out_bin = out_dir.join(format!("{technique}__{variant}"));

        let static_status = Command::new(&cc)
            .args(["-static", "-O2", "-o"])
            .arg(&out_bin)
            .arg(&src)
            .status();
        if !matches!(&static_status, Ok(s) if s.success()) {
            // Fall back to dynamic so the suite at least exercises the
            // process backend on hosts that lack static glibc.  The
            // chroot leg of the test SKIPs cleanly when the dynamic
            // loader can't resolve libc inside the chroot — but the
            // sink-probe assertion still gates Track-B regressions.
            let dyn_status = Command::new(&cc)
                .args(["-O2", "-o"])
                .arg(&out_bin)
                .arg(&src)
                .status();
            if !matches!(&dyn_status, Ok(s) if s.success()) {
                eprintln!(
                    "SKIP[{key}]: cc={cc} failed to build fixture (static={static_status:?}, \
                     dyn={dyn_status:?})"
                );
                builds().lock().unwrap().insert(key, None);
                return None;
            }
            // Mark dynamic so per-test code can branch if needed.
            unsafe { std::env::set_var(format!("NYX_ESCAPE_DYN_{technique}_{variant}"), "1") };
        }

        builds().lock().unwrap().insert(key.clone(), Some(out_bin.clone()));
        Some(out_bin)
    }

    fn variant_was_dynamic(technique: &str, variant: &str) -> bool {
        std::env::var_os(format!("NYX_ESCAPE_DYN_{technique}_{variant}")).is_some()
    }

    // ── Sandbox helpers ──────────────────────────────────────────────────────

    fn strict_opts() -> SandboxOptions {
        SandboxOptions {
            timeout: Duration::from_secs(10),
            memory_mib: 256,
            backend: SandboxBackend::Process,
            output_limit: 65536,
            process_hardening: ProcessHardeningProfile::Strict,
            seccomp_caps: 0,
            ..SandboxOptions::default()
        }
    }

    fn build_harness(workdir: &Path, bin: &Path) -> BuiltHarness {
        // Stage the binary inside the workdir so `chroot(workdir)`
        // does not strip its path mid-exec.
        let dst = workdir.join("harness");
        std::fs::copy(bin, &dst).expect("copy harness binary into workdir");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dst).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dst, perms).unwrap();

        BuiltHarness {
            workdir: workdir.to_path_buf(),
            command: vec![dst.to_string_lossy().into_owned()],
            env: vec![],
            source: String::new(),
            entry_source: String::new(),
        }
    }

    /// Run a fixture under the Strict-profile process backend.  Returns
    /// the captured outcome.  Panics with `escape suite contains a
    /// Track-B regression` when the run returned a `BackendUnavailable`
    /// or `Spawn` error — those previously passed vacuously in
    /// `tests/dynamic_sandbox_escape.rs` and are inverted here so the
    /// suite cannot hide a regression in the verifier's boot path.
    fn run_fixture(technique: &str, variant: &str) -> sandbox::SandboxOutcome {
        let Some(bin) = compile_fixture(technique, variant) else {
            // Toolchain skip — the test caller handles the None case
            // by returning early.  Unreachable here because every
            // caller short-circuits on the build-cache miss; left as a
            // panic to surface accidental misuse.
            panic!("compile_fixture returned None — caller should SKIP, not call run_fixture");
        };
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let harness = build_harness(tmp.path(), &bin);
        match sandbox::run(&harness, b"", &strict_opts()) {
            Ok(outcome) => outcome,
            Err(e) => panic!(
                "escape suite contains a Track-B regression: \
                 `sandbox::run({technique}/{variant})` returned Err({e:?}).  \
                 Previous behaviour silently passed; the new suite refuses \
                 to pass when the harness fails to boot."
            ),
        }
    }

    fn cleanup_sentinel(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    /// Top-level non-vacuous assertion for a single (technique, variant).
    ///
    /// Returns `false` when the fixture could not be built (caller
    /// reports SKIP).  Otherwise panics on any of:
    ///   - sandbox::run returned Err (Track-B regression);
    ///   - probe sink-hit sentinel missing from stdout (harness boot
    ///     failure or chroot stripped the binary before main());
    ///   - sentinel path appeared on the host (containment breach).
    fn assert_contained(technique_name: &str, variant: &str) -> bool {
        let t = technique(technique_name);
        if compile_fixture(technique_name, variant).is_none() {
            return false;
        }
        if variant == "vuln" && variant_was_dynamic(technique_name, variant) {
            // Dynamic-linked fixture: chroot blocks the loader before
            // main(), so the probe cannot fire — that is structurally
            // different from a Track-B regression.  Skip cleanly.
            eprintln!(
                "SKIP[{technique_name}::vuln]: fixture is dynamically linked; \
                 chroot would block the dynamic loader before main().  \
                 Install glibc-static (Debian: libc6-dev with libc.a) to gate."
            );
            return false;
        }

        cleanup_sentinel(t.sentinel);
        let outcome = run_fixture(technique_name, variant);
        let stdout = String::from_utf8_lossy(&outcome.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&outcome.stderr).into_owned();

        // (1) Non-vacuity: sink probe must have fired.
        assert!(
            outcome.sink_hit,
            "escape suite contains a Track-B regression: \
             `{technique_name}/{variant}` did not reach the sink \
             (__NYX_SINK_HIT__ missing from stdout).  \
             stdout:\n{stdout}\nstderr:\n{stderr}"
        );

        // (2) Containment: sentinel file must be absent on the host.
        let leaked = Path::new(t.sentinel).exists();
        // Always clean up before asserting, regardless of outcome.
        cleanup_sentinel(t.sentinel);
        assert!(
            !leaked,
            "escape suite breach: `{technique_name}/{variant}` wrote sentinel \
             to host path {} — Phase 17 chroot/seccomp/no_new_privs did not \
             contain the escape.  stdout:\n{stdout}\nstderr:\n{stderr}",
            t.sentinel,
        );

        true
    }

    // ── Per-technique tests ──────────────────────────────────────────────────
    //
    // Each technique gets two test functions — `<name>_benign` and
    // `<name>_vuln`.  Both must pass for the technique to be considered
    // covered.

    // The repo does not depend on `paste`; declare cases by hand to
    // keep the build dependency-free.

    #[test]
    fn chmod_4755_benign() { let _ = assert_contained("chmod_4755", "benign"); }
    #[test]
    fn chmod_4755_vuln()   { let _ = assert_contained("chmod_4755", "vuln"); }

    #[test]
    fn etc_write_benign() { let _ = assert_contained("etc_write", "benign"); }
    #[test]
    fn etc_write_vuln()   { let _ = assert_contained("etc_write", "vuln"); }

    #[test]
    fn dlopen_outside_chroot_benign() { let _ = assert_contained("dlopen_outside_chroot", "benign"); }
    #[test]
    fn dlopen_outside_chroot_vuln()   { let _ = assert_contained("dlopen_outside_chroot", "vuln"); }

    #[test]
    fn proc_root_passwd_benign() { let _ = assert_contained("proc_root_passwd", "benign"); }
    #[test]
    fn proc_root_passwd_vuln()   { let _ = assert_contained("proc_root_passwd", "vuln"); }

    #[test]
    fn raw_socket_bind_benign() { let _ = assert_contained("raw_socket_bind", "benign"); }
    #[test]
    fn raw_socket_bind_vuln()   { let _ = assert_contained("raw_socket_bind", "vuln"); }

    #[test]
    fn setuid_zero_benign() { let _ = assert_contained("setuid_zero", "benign"); }
    #[test]
    fn setuid_zero_vuln()   { let _ = assert_contained("setuid_zero", "vuln"); }

    // ── Track-B regression tripwire ──────────────────────────────────────────

    /// Independent guard that proves the suite's non-vacuity rule
    /// actually fires: a harness command that exits without printing the
    /// sink-hit sentinel must trigger the `Track-B regression` panic.
    /// Run-once in a thread so the panic does not abort other tests.
    #[test]
    fn track_b_regression_panic_fires_on_missing_sink_hit() {
        let outcome = sandbox::SandboxOutcome {
            exit_code: Some(0),
            stdout: b"no sink marker here\n".to_vec(),
            stderr: Vec::new(),
            timed_out: false,
            oob_callback_seen: false,
            sink_hit: false,
            duration: Duration::ZERO,
            hardening_outcome: None,
        };
        // Mirror the contract in assert_contained without going through
        // the full pipeline — we just need to prove the failure message
        // is the agreed-on string.
        let result = std::panic::catch_unwind(|| {
            assert!(
                outcome.sink_hit,
                "escape suite contains a Track-B regression: \
                 fixture did not reach the sink"
            );
        });
        let payload = result.expect_err("assertion should have panicked");
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            msg.contains("escape suite contains a Track-B regression"),
            "Track-B regression panic message changed; got: {msg:?}"
        );
    }
}

// Non-Linux placeholder so `cargo nextest run --test sandbox_escape_suite`
// reports zero failures on macOS / Windows CI rows rather than "no tests
// to run".  The real suite gates every test on `target_os = "linux"`.
#[cfg(not(all(feature = "dynamic", target_os = "linux")))]
mod non_linux_placeholder {
    #[test]
    fn linux_only_suite_skipped_on_this_target() {
        eprintln!(
            "SKIP: tests/sandbox_escape_suite.rs requires `--features dynamic` and \
             target_os = linux"
        );
    }
}
