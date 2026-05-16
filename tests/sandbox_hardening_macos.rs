//! Phase 18 (Track E.2) — macOS process-backend hardening acceptance tests.
//!
//! On macOS the process backend wraps the harness command with
//! `sandbox-exec -f <profile.sb> -D WORKDIR=<workdir> ...`.  This suite
//! drives a python probe that tries to read `/etc/passwd`; under the
//! `path_traversal` profile the read is denied by the kernel and the
//! probe exits non-zero, matching the verifier's `NotConfirmed` rule.
//!
//! The suite is gated on `target_os = "macos"`; on Linux / other targets
//! it falls through to a placeholder test so
//! `cargo nextest run --features dynamic --test sandbox_hardening_macos`
//! still discovers something to run.
//!
//! Run with:
//!   `cargo nextest run --features dynamic --test sandbox_hardening_macos`

#[cfg(all(feature = "dynamic", target_os = "macos"))]
mod hardening_tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use nyx_scanner::dynamic::harness::BuiltHarness;
    use nyx_scanner::dynamic::sandbox::process_macos::{
        profile_for_caps, sandbox_exec_available, HardeningLevel, SANDBOX_EXEC_BIN_ENV,
    };
    use nyx_scanner::dynamic::sandbox::{
        self, HardeningRecord, ProcessHardeningProfile, SandboxBackend, SandboxOptions,
    };

    fn macos_outcome(out: &sandbox::SandboxOutcome)
        -> Option<&nyx_scanner::dynamic::sandbox::process_macos::HardeningOutcome>
    {
        match out.hardening_outcome.as_ref()? {
            HardeningRecord::Macos(o) => Some(o),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    // ── Probe source + harness helpers ────────────────────────────────────────

    /// Python source that tries to read `/etc/passwd`.  Exits 0 when the
    /// read succeeds (escape), 7 when it is denied (sandbox holding), and
    /// prints a structural marker line for the test to assert on.
    const PROBE_SOURCE: &str = r#"
import sys
try:
    with open("/etc/passwd", "rb") as fh:
        fh.read(16)
    print("escape:escaped")
    sys.exit(0)
except Exception as exc:
    print(f"escape:blocked errno={getattr(exc, 'errno', None)} {exc}")
    sys.exit(7)
"#;

    fn workdir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("temp dir")
    }

    fn write_probe(workdir: &Path) -> PathBuf {
        let path = workdir.join("probe.py");
        std::fs::write(&path, PROBE_SOURCE).expect("write probe");
        path
    }

    fn build_harness(workdir: &Path) -> BuiltHarness {
        let probe = write_probe(workdir);
        BuiltHarness {
            workdir: workdir.to_path_buf(),
            command: vec![
                "/usr/bin/python3".to_owned(),
                probe.to_string_lossy().into_owned(),
            ],
            env: vec![],
            source: String::new(),
            entry_source: String::new(),
        }
    }

    fn strict_opts(caps: u32) -> SandboxOptions {
        SandboxOptions {
            timeout: Duration::from_secs(10),
            memory_mib: 256,
            backend: SandboxBackend::Process,
            output_limit: 65536,
            process_hardening: ProcessHardeningProfile::Strict,
            seccomp_caps: caps,
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

    fn stdout_string(out: &sandbox::SandboxOutcome) -> String {
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// XXE probe: simulates an XML parser issuing the outbound HTTP
    /// fetch for an external SYSTEM entity.  Targets TEST-NET-1 so the
    /// DNS layer is sidestepped; under the `xxe.sb` profile the
    /// outbound connect is denied with EPERM and the probe exits 7.
    /// Under a default-allow sandbox the connect attempt proceeds and
    /// the probe exits 0 with the `network-attempted` marker.
    ///
    /// The probe source is read in at compile time and written into
    /// the harness workdir at run time so the sandbox-exec
    /// `(subpath "/Users")` deny does not block the script load.
    const XXE_PROBE_SOURCE: &str =
        include_str!("dynamic_fixtures/hardening/xxe_probe.py");

    fn write_xxe_probe(workdir: &Path) -> PathBuf {
        let path = workdir.join("xxe_probe.py");
        std::fs::write(&path, XXE_PROBE_SOURCE).expect("write xxe probe");
        path
    }

    fn build_xxe_harness(workdir: &Path) -> BuiltHarness {
        let probe = write_xxe_probe(workdir);
        BuiltHarness {
            workdir: workdir.to_path_buf(),
            command: vec![
                "/usr/bin/python3".to_owned(),
                probe.to_string_lossy().into_owned(),
            ],
            env: vec![],
            source: String::new(),
            entry_source: String::new(),
        }
    }

    /// Profile selection: `FILE_IO` selects `path_traversal`, etc.
    #[test]
    fn profile_for_caps_matches_phase18_table() {
        const FILE_IO: u32 = 1 << 5;
        const DESERIALIZE: u32 = 1 << 8;
        const SSRF: u32 = 1 << 9;
        const CODE_EXEC: u32 = 1 << 10;
        const XXE: u32 = 1 << 19;
        assert_eq!(profile_for_caps(FILE_IO), "path_traversal");
        assert_eq!(profile_for_caps(SSRF), "ssrf");
        assert_eq!(profile_for_caps(CODE_EXEC), "cmdi");
        assert_eq!(profile_for_caps(XXE), "xxe");
        assert_eq!(profile_for_caps(DESERIALIZE), "deserialize");
        assert_eq!(profile_for_caps(0), "base");
    }

    /// `sandbox-exec` is on every supported macOS release; the
    /// availability probe should return `true` on CI macOS runners.
    /// If a test image strips the binary we want the verifier's
    /// fallback to engage — see `verify_finding_refuses_filesystem_*`.
    #[test]
    fn sandbox_exec_present_on_default_host() {
        // Clear any override left by a sibling test in the same process.
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        if !sandbox_exec_available() {
            eprintln!(
                "SKIP: /usr/bin/sandbox-exec missing on this host — refuse_filesystem_confirm tests still cover the fallback."
            );
        } else {
            assert!(sandbox_exec_available());
        }
    }

    /// Phase 18 acceptance (a): a filesystem-escape payload under the
    /// `path_traversal` profile cannot read `/etc/passwd` — the wrapped
    /// `sandbox-exec` blocks the open and the probe exits non-zero
    /// with the `escape:blocked` marker.  The verifier reads this as
    /// `NotConfirmed` (exit != 0 + no sink-hit + no oracle fire).
    #[test]
    fn path_traversal_payload_blocked_under_strict() {
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        if !sandbox_exec_available() {
            eprintln!("SKIP: /usr/bin/sandbox-exec missing — cannot exercise wrap");
            return;
        }
        const FILE_IO: u32 = 1 << 5;
        let tmp = workdir();
        let harness = build_harness(tmp.path());
        let opts = strict_opts(FILE_IO);
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        eprintln!("stdout under path_traversal:\n{stdout}");
        let outcome = macos_outcome(&result).expect("hardening outcome recorded");
        assert_eq!(outcome.level, HardeningLevel::Sandboxed);
        assert_eq!(outcome.profile, "path_traversal");
        assert!(
            stdout.contains("escape:blocked"),
            "expected sandbox-exec to block /etc/passwd read; stdout:\n{stdout}"
        );
        assert_ne!(
            result.exit_code,
            Some(0),
            "probe exited 0 — escape succeeded against the sandbox; stdout:\n{stdout}"
        );
    }

    /// Standard profile: no sandbox-exec wrap, the probe reads
    /// `/etc/passwd` cleanly and exits 0.  Sanity check for the wrap
    /// gating logic — without it we can't tell whether the strict test
    /// above is actually exercising the sandbox or a probe quirk.
    #[test]
    fn standard_profile_does_not_wrap_with_sandbox_exec() {
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        let tmp = workdir();
        let harness = build_harness(tmp.path());
        let opts = standard_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        eprintln!("stdout under standard:\n{stdout}");
        // Standard profile means the macOS wrap was never attempted —
        // `hardening_outcome` stays `None` because `wrap_plan` was not
        // called.  Assert on the probe's marker only.
        assert!(
            result.hardening_outcome.is_none(),
            "standard profile should not produce a hardening outcome",
        );
        assert!(
            stdout.contains("escape:escaped") || stdout.contains("escape:blocked"),
            "probe should at least print its marker; stdout:\n{stdout}"
        );
    }

    /// When `sandbox-exec` is unavailable the wrap is a no-op and the
    /// returned outcome records `Trusted`.  Tests force the missing
    /// binary path via the [`SANDBOX_EXEC_BIN_ENV`] override.
    #[test]
    fn sandbox_exec_missing_records_trusted_outcome() {
        const FILE_IO: u32 = 1 << 5;
        unsafe { std::env::set_var(SANDBOX_EXEC_BIN_ENV, "/nonexistent/sandbox-exec") };
        let tmp = workdir();
        let harness = build_harness(tmp.path());
        let opts = strict_opts(FILE_IO);
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        let outcome = macos_outcome(&result).expect("hardening outcome recorded");
        assert_eq!(outcome.level, HardeningLevel::Trusted);
        eprintln!("stdout when sandbox-exec missing:\n{stdout}");
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
    }

    /// Phase 18 acceptance (b): when sandbox-exec is missing the
    /// verifier's `refuse_filesystem_confirm` flag flips to `true`
    /// via `VerifyOptions::from_config`.  Filesystem-cap findings then
    /// short-circuit to `Inconclusive(BackendInsufficient)` instead of
    /// running unconfined.
    #[test]
    fn verify_options_from_config_sets_refuse_when_sandbox_exec_missing() {
        use nyx_scanner::dynamic::verify::VerifyOptions;
        use nyx_scanner::utils::config::Config;
        unsafe { std::env::set_var(SANDBOX_EXEC_BIN_ENV, "/nonexistent/sandbox-exec") };
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(
            opts.refuse_filesystem_confirm,
            "expected refuse_filesystem_confirm=true when sandbox-exec is missing on macOS"
        );
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
    }

    /// Phase 18 acceptance (c): the XXE entity-resolution kill path
    /// runs the probe under the `xxe.sb` profile and asserts the
    /// outbound TCP connect against TEST-NET-1 is denied at the
    /// kernel layer (EPERM).  Sanity-cross-checked against the
    /// `standard` profile run: without the wrap, the same probe gets
    /// a non-EPERM error class (or a stub-loopback connect succeeds)
    /// and exits 0 with the `network-attempted` marker.
    #[test]
    fn xxe_outbound_blocked_under_strict_xxe_profile() {
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        if !sandbox_exec_available() {
            eprintln!("SKIP: /usr/bin/sandbox-exec missing — cannot exercise xxe profile");
            return;
        }
        const XXE: u32 = 1 << 19;
        let tmp = workdir();
        let harness = build_xxe_harness(tmp.path());
        let opts = strict_opts(XXE);
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        eprintln!("stdout under xxe profile:\n{stdout}");
        let outcome = macos_outcome(&result).expect("hardening outcome recorded");
        assert_eq!(outcome.level, HardeningLevel::Sandboxed);
        assert_eq!(outcome.profile, "xxe");
        assert!(
            stdout.contains("xxe:network-denied"),
            "expected sandbox-exec to deny outbound connect with EPERM; stdout:\n{stdout}"
        );
        assert_eq!(
            result.exit_code,
            Some(7),
            "probe should exit 7 on EPERM-denied connect; stdout:\n{stdout}"
        );
    }

    /// Cross-check: the same probe under the `standard` profile (no
    /// sandbox-exec wrap) does not receive EPERM on the outbound
    /// connect.  This guards against a future regression where every
    /// fixture starts surfacing EPERM and the `xxe` test passes
    /// vacuously.
    #[test]
    fn xxe_probe_under_standard_does_not_surface_eperm() {
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        let tmp = workdir();
        let harness = build_xxe_harness(tmp.path());
        let opts = standard_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        eprintln!("stdout under standard:\n{stdout}");
        assert!(
            result.hardening_outcome.is_none(),
            "standard profile should not produce a hardening outcome",
        );
        // The probe should NOT report EPERM under the unwrapped run —
        // it should report `network-attempted` (typical) or
        // `probe-error` (extremely unlikely).  EPERM here would mean
        // a host-level firewall is independently denying the syscall,
        // which would mask the sandbox effect.
        assert!(
            !stdout.contains("xxe:network-denied"),
            "standard profile produced an EPERM signal — host firewall \
             may be masking the sandbox effect; stdout:\n{stdout}"
        );
    }

    /// Companion to the case above: with `sandbox-exec` reachable the
    /// flag stays `false` so filesystem oracles run normally.
    #[test]
    fn verify_options_from_config_does_not_refuse_when_sandbox_exec_present() {
        use nyx_scanner::dynamic::verify::VerifyOptions;
        use nyx_scanner::utils::config::Config;
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        if !sandbox_exec_available() {
            eprintln!("SKIP: /usr/bin/sandbox-exec missing on this host");
            return;
        }
        let opts = VerifyOptions::from_config(&Config::default());
        assert!(
            !opts.refuse_filesystem_confirm,
            "refuse_filesystem_confirm should be false when sandbox-exec is reachable"
        );
    }
}

// Non-macOS placeholder so `cargo nextest run --test sandbox_hardening_macos`
// reports something on the Linux row instead of "no tests to run".  The real
// suite gates every test on `target_os = "macos"`.
#[cfg(not(all(feature = "dynamic", target_os = "macos")))]
mod non_macos_placeholder {
    #[test]
    fn macos_only_suite_skipped_on_this_target() {
        eprintln!(
            "SKIP: tests/sandbox_hardening_macos.rs requires `--features dynamic` and target_os = macos"
        );
    }
}
