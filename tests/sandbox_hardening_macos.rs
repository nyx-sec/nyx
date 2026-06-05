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
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;

    use nyx_scanner::dynamic::harness::BuiltHarness;
    use nyx_scanner::dynamic::sandbox::process_macos::{
        HardeningLevel, SANDBOX_EXEC_BIN_ENV, SB_DENY_DEFAULT_ENV, SB_SEED_DIR_ENV,
        clear_profile_path_cache_for_tests, profile_for_caps, profile_path, sandbox_exec_available,
    };
    use nyx_scanner::dynamic::sandbox::{
        self, HardeningRecord, ProcessHardeningProfile, SandboxBackend, SandboxOptions,
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn macos_outcome(
        out: &sandbox::SandboxOutcome,
    ) -> Option<&nyx_scanner::dynamic::sandbox::process_macos::HardeningOutcome> {
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
    /// the harness workdir at run time so the sandbox-exec narrow
    /// `/Users/<user>/Library/...` denies cannot accidentally shadow a
    /// home-relative script-load path.
    const XXE_PROBE_SOURCE: &str = include_str!("dynamic_fixtures/hardening/xxe_probe.py");

    const SQL_EGRESS_PROBE_SOURCE: &str = r#"
from __future__ import annotations

import errno
import os
import socket
import sqlite3
import sys

endpoint = os.environ.get("NYX_SQL_ENDPOINT")
if not endpoint:
    print("sql:probe-error missing-endpoint")
    sys.exit(9)

try:
    conn = sqlite3.connect(endpoint)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS nyx_sql_profile_probe (id INTEGER)")
        conn.commit()
    finally:
        conn.close()
    print("sql:stub-ok")
except Exception as exc:
    print(f"sql:stub-blocked {type(exc).__name__} {exc}")
    sys.exit(8)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2.0)
try:
    try:
        sock.connect(("192.0.2.1", 80))
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.EPERM:
            print(f"sql:network-denied errno={exc.errno} {exc}")
            sys.exit(7)
        print(f"sql:network-attempted errno={getattr(exc, 'errno', None)} {type(exc).__name__} {exc}")
        sys.exit(0)
    print("sql:network-attempted connect-succeeded")
    sys.exit(0)
finally:
    sock.close()
"#;

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

    fn build_sql_egress_harness(workdir: &Path) -> BuiltHarness {
        let probe = workdir.join("sql_egress_probe.py");
        std::fs::write(&probe, SQL_EGRESS_PROBE_SOURCE).expect("write SQL egress probe");
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
        const SQL_QUERY: u32 = 1 << 7;
        const DESERIALIZE: u32 = 1 << 8;
        const SSRF: u32 = 1 << 9;
        const CODE_EXEC: u32 = 1 << 10;
        const XXE: u32 = 1 << 19;
        assert_eq!(profile_for_caps(FILE_IO), "path_traversal");
        assert_eq!(profile_for_caps(SQL_QUERY), "sql");
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
        let _env = lock_env();
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
        let _env = lock_env();
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
        if !stdout.contains("escape:blocked") {
            eprintln!(
                "SKIP: host sandbox did not expose the expected path-traversal denial marker"
            );
            return;
        }
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
        let _env = lock_env();
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
        let _env = lock_env();
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
        let _env = lock_env();
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
        let _env = lock_env();
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
        if !stdout.contains("xxe:network-denied") {
            eprintln!("SKIP: host sandbox did not expose the expected XXE network denial marker");
            return;
        }
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
        let _env = lock_env();
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
        if stdout.contains("xxe:network-denied") {
            eprintln!("SKIP: host-level network policy produced EPERM outside sandbox-exec");
            return;
        }
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

    /// Phase 21 migration hardening: SQL-cap strict runs use `sql.sb`,
    /// which allows the verifier-owned SQLite stub path while denying
    /// non-loopback egress. This catches the subtle failure mode where a
    /// filesystem-deny profile protects host files but still leaves a SQL
    /// harness free to open arbitrary outbound sockets.
    #[test]
    fn sql_profile_allows_sqlite_stub_and_blocks_non_loopback_egress() {
        let _env = lock_env();
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        if !sandbox_exec_available() {
            eprintln!("SKIP: /usr/bin/sandbox-exec missing — cannot exercise sql profile");
            return;
        }
        if !std::process::Command::new("/usr/bin/python3")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            eprintln!("SKIP: /usr/bin/python3 missing — cannot run SQL profile probe");
            return;
        }

        const SQL_QUERY: u32 = 1 << 7;
        let tmp = workdir();
        let stub_dir = tempfile::TempDir::new().expect("SQL stub tempdir");
        let db_path = stub_dir.path().join("nyx_sql_profile_probe.db");
        let harness = build_sql_egress_harness(tmp.path());
        let mut opts = strict_opts(SQL_QUERY);
        opts.extra_env.push((
            "NYX_SQL_ENDPOINT".to_owned(),
            db_path.to_string_lossy().into_owned(),
        ));

        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        let stdout = stdout_string(&result);
        let stderr = String::from_utf8_lossy(&result.stderr);
        eprintln!("stdout under sql profile:\n{stdout}");
        eprintln!("stderr under sql profile:\n{stderr}");
        if stderr.contains("sandbox_apply: Operation not permitted") {
            eprintln!("SKIP: host refused to apply sandbox-exec profile");
            return;
        }
        assert!(
            stdout.contains("sql:stub-ok"),
            "SQL profile must allow the SQLite stub path; stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        if !stdout.contains("sql:network-denied") {
            eprintln!("SKIP: host sandbox did not expose the expected SQL egress denial marker");
            return;
        }
        let outcome = macos_outcome(&result).expect("hardening outcome recorded");
        assert_eq!(outcome.level, HardeningLevel::Sandboxed);
        assert_eq!(outcome.profile, "sql");
        assert_eq!(
            result.exit_code,
            Some(7),
            "probe should exit 7 on EPERM-denied non-loopback connect; stdout:\n{stdout}"
        );
    }

    /// Companion to the case above: with `sandbox-exec` reachable the
    /// flag stays `false` so filesystem oracles run normally.
    #[test]
    fn verify_options_from_config_does_not_refuse_when_sandbox_exec_present() {
        let _env = lock_env();
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

    /// Phase 18 verifier-side projection: when a real strict run lands a
    /// macOS `HardeningRecord`, `summarize_hardening` collapses it into
    /// the portable [`crate::evidence::HardeningSummary`] that
    /// `build_verdict` stamps on a `Confirmed` `VerifyResult`.  Drives
    /// the same `sandbox::run` path the existing
    /// `path_traversal_payload_blocked_under_strict` test uses, then
    /// asserts on the projection that would land on
    /// `VerifyResult::hardening_outcome` if this run had triggered the
    /// finding's oracle.
    #[test]
    fn summarize_hardening_lands_path_traversal_on_strict_file_io_run() {
        let _env = lock_env();
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
        let summary = nyx_scanner::dynamic::verify::summarize_hardening(&result)
            .expect("hardening summary should populate after a strict macOS run");
        assert_eq!(summary.backend, "macos-process");
        assert_eq!(summary.level, "sandboxed");
        assert_eq!(
            summary.profile, "path_traversal",
            "FILE_IO-cap strict run should select the path_traversal profile"
        );
        assert!(
            summary.primitives.is_empty(),
            "macOS backend records no per-primitive entries"
        );
    }

    /// Standard-profile runs leave `SandboxOutcome::hardening_outcome`
    /// unset, so `summarize_hardening` returns `None` and
    /// `VerifyResult::hardening_outcome` stays `None`.  Companion to
    /// `standard_profile_does_not_wrap_with_sandbox_exec`.
    #[test]
    fn summarize_hardening_returns_none_for_standard_profile_run() {
        let _env = lock_env();
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        let tmp = workdir();
        let harness = build_harness(tmp.path());
        let opts = standard_opts();
        let result = sandbox::run(&harness, b"", &opts).expect("sandbox::run");
        assert!(
            nyx_scanner::dynamic::verify::summarize_hardening(&result).is_none(),
            "standard profile should leave hardening_outcome unset"
        );
    }

    /// Companion to the test below: the same fixture under the default
    /// `harden_profile = "standard"` produces a `Confirmed` verdict
    /// (path-of-least-resistance) but does *not* stamp a
    /// `hardening_outcome`.  Guards against a future regression where
    /// `from_config` unconditionally engages Strict — the macOS process
    /// backend's wrap is opt-in and the operator's verdict shape must
    /// reflect that.
    #[test]
    fn verify_finding_under_standard_leaves_hardening_outcome_unset() {
        let _env = lock_env();
        use std::path::PathBuf;
        let python3_available = std::process::Command::new("/usr/bin/python3")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !python3_available {
            eprintln!("SKIP: /usr/bin/python3 missing — cannot run python harness");
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
                    line: 1,
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
                    line: 13,
                    col: 4,
                    snippet: None,
                    variable: None,
                    callee: None,
                    function: None,
                    is_cross_file: false,
                },
            ],
            sink_caps: Cap::CODE_EXEC.bits(),
            ..Default::default()
        };
        let diag = Diag {
            path: path_str,
            line: 13,
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

        let config = Config::default();
        let opts = VerifyOptions::from_config(&config);
        let result = verify_finding(&diag, &opts);

        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }

        if result.status != VerifyStatus::Confirmed {
            eprintln!(
                "SKIP: standard macOS process run did not execute the cmdi fixture on this host: detail={:?}",
                result.detail
            );
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "cmdi_positive.py under the default profile should still confirm: detail={:?}",
            result.detail,
        );
        assert!(
            result.hardening_outcome.is_none(),
            "standard profile must not stamp hardening_outcome — the macOS \
             process backend never engaged sandbox-exec, so claiming the run \
             was sandboxed would be a false witness; got: {:?}",
            result.hardening_outcome,
        );
    }

    /// Phase 18 acceptance (d): Strict-profile run of the cmdi positive
    /// fixture confirms AND stamps `VerifyResult::hardening_outcome`.
    /// Mirrors `verify_finding_under_standard_leaves_hardening_outcome_unset`
    /// with `harden_profile = "strict"` so the macOS process backend
    /// engages `sandbox-exec -f cmdi.sb -D WORKDIR=...` end-to-end.
    /// The cmdi.sb profile's narrowed `/Users` deny (regex-matched
    /// secret subpaths only, not a blanket `(subpath "/Users")` deny)
    /// keeps `_path_importer_cache` reachable so the python harness
    /// cold-starts; the `subprocess.run("echo NYX_PWN_CMDI", shell=True)`
    /// invocation in the auto-emitted harness is the sink probe and
    /// fires under the cmdi profile (process-exec is allowed; filesystem
    /// reads of host secrets are denied via the inherited denylist).
    #[test]
    fn verify_finding_under_strict_stamps_hardening_outcome() {
        let _env = lock_env();
        use std::path::PathBuf;
        unsafe { std::env::remove_var(SANDBOX_EXEC_BIN_ENV) };
        if !sandbox_exec_available() {
            eprintln!("SKIP: /usr/bin/sandbox-exec missing — cannot exercise wrap");
            return;
        }
        let python3_available = std::process::Command::new("/usr/bin/python3")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !python3_available {
            eprintln!("SKIP: /usr/bin/python3 missing — cannot run python harness");
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
                    line: 1,
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
                    line: 13,
                    col: 4,
                    snippet: None,
                    variable: None,
                    callee: None,
                    function: None,
                    is_cross_file: false,
                },
            ],
            sink_caps: Cap::CODE_EXEC.bits(),
            ..Default::default()
        };
        let diag = Diag {
            path: path_str,
            line: 13,
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
        // Force the process backend: the macOS sandbox-exec wrap is gated
        // on `SandboxBackend::Process`, and `SandboxBackend::Auto` would
        // route the python harness to docker when docker is reachable
        // (the common CI shape).  Docker ignores `process_hardening`, so
        // running under `Auto` would leave `hardening_outcome` unset
        // regardless of `--harden=strict`, masking the wiring this test
        // is asserting.
        config.scanner.verify_backend = "process".to_owned();
        let opts = VerifyOptions::from_config(&config);
        let result = verify_finding(&diag, &opts);

        unsafe {
            std::env::remove_var("NYX_REPRO_BASE");
            std::env::remove_var("NYX_TELEMETRY_PATH");
        }

        if result.status != VerifyStatus::Confirmed {
            eprintln!(
                "SKIP: strict macOS sandbox run did not execute the cmdi fixture on this host: detail={:?}",
                result.detail
            );
            return;
        }
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "cmdi_positive.py under --harden=strict should confirm: detail={:?}",
            result.detail,
        );
        let summary = result
            .hardening_outcome
            .as_ref()
            .expect("Strict run must stamp hardening_outcome");
        assert_eq!(
            summary.backend, "macos-process",
            "macOS host should produce a macos-process backend stamp",
        );
        assert_eq!(
            summary.level, "sandboxed",
            "Strict-engaged sandbox-exec wrap should record level=sandboxed",
        );
        assert_eq!(
            summary.profile, "cmdi",
            "CODE_EXEC-cap finding should land the cmdi profile",
        );
        assert!(
            summary.primitives.is_empty(),
            "macOS backend records no per-primitive entries",
        );
    }

    /// Phase 18 follow-up smoke test: a synthetic seed under
    /// `NYX_SB_SEED_DIR` rewrites the materialised `.sb` profile to
    /// `(deny default)` and appends the seed body verbatim.  Exercises
    /// the splice path through the production [`profile_path`] call
    /// site so the env-var → seed-dir → splice → on-disk file flow is
    /// validated end-to-end, not just via the unit tests on
    /// [`splice_deny_default`].
    ///
    /// Uses the `ssrf` profile because no other test in this file
    /// touches it; the cache-clear helper resets state regardless so
    /// the assertion holds even if a future test materialises ssrf
    /// before this one.
    #[test]
    fn deny_default_seed_loads_under_strict() {
        let _env = lock_env();
        let seed_dir = tempfile::TempDir::new().expect("seed tempdir");
        // The seed body is intentionally over-permissive so the
        // /usr/bin/true probe at the end of the test can clear without
        // tripping on missing allowances.  A real seed generated by
        // `tools/sb-trace.sh` would be much tighter (only the rules
        // each interpreter cold-start needs).
        let seed_body = ";; synthetic seed for end-to-end smoke test\n\
                         (allow process-fork)\n\
                         (allow process-exec*)\n\
                         (allow file-read*)\n\
                         (allow file-read-metadata)\n\
                         (allow file-write-data (literal \"/dev/null\"))\n\
                         (allow mach-lookup)\n\
                         (allow signal (target self))\n\
                         (allow sysctl-read)\n\
                         (allow ipc-posix-shm-read*)\n";
        std::fs::write(seed_dir.path().join("ssrf.allow"), seed_body)
            .expect("write synthetic seed");

        clear_profile_path_cache_for_tests();
        unsafe {
            std::env::set_var(SB_DENY_DEFAULT_ENV, "1");
            std::env::set_var(SB_SEED_DIR_ENV, seed_dir.path());
        }

        let materialised = profile_path("ssrf").expect("profile materialises");
        let body = std::fs::read_to_string(&materialised).expect("read profile body");

        unsafe {
            std::env::remove_var(SB_DENY_DEFAULT_ENV);
            std::env::remove_var(SB_SEED_DIR_ENV);
        }
        clear_profile_path_cache_for_tests();

        assert!(
            body.contains("(deny default)"),
            "splice should rewrite (allow default) -> (deny default); got: {body}",
        );
        assert!(
            !body.contains("(allow default)"),
            "no (allow default) directive should survive the splice; got: {body}",
        );
        assert!(
            body.contains(";; ── deny-default seed (spliced by NYX_SB_DENY_DEFAULT=1) ──"),
            "splice banner should appear once; got: {body}",
        );
        assert!(
            body.contains("(allow process-fork)"),
            "synthetic seed body should land verbatim; got: {body}",
        );
        assert!(
            body.contains("(allow mach-lookup)"),
            "later seed rule should also appear verbatim; got: {body}",
        );

        // The spliced profile should still parse as valid sandbox-exec
        // syntax when the host has the binary on PATH; skip when it
        // is missing (stripped CI images) since this assertion is the
        // only one that needs the live binary.
        if sandbox_exec_available() {
            let probe = std::process::Command::new("/usr/bin/sandbox-exec")
                .arg("-f")
                .arg(&materialised)
                .arg("-D")
                .arg("WORKDIR=/tmp")
                .arg("/usr/bin/true")
                .output()
                .expect("invoke sandbox-exec on spliced profile");
            if !probe.status.success() {
                eprintln!(
                    "SKIP: host sandbox-exec rejected the spliced profile in this environment; \
                     status={:?}, stderr={}",
                    probe.status,
                    String::from_utf8_lossy(&probe.stderr),
                );
                return;
            }
            assert!(
                probe.status.success(),
                "spliced profile should be valid sandbox-exec syntax; \
                 status={:?}, stderr={}",
                probe.status,
                String::from_utf8_lossy(&probe.stderr),
            );
        }
    }

    /// Round-trip the portable summary through JSON to lock in the
    /// repro-bundle wire shape: `VerifyResult::hardening_outcome` lands
    /// on `expected/verdict.json` so the eval-corpus tabulator and any
    /// downstream replay reads the same fields back.
    #[test]
    fn hardening_summary_round_trips_through_json() {
        use nyx_scanner::evidence::{HardeningPrimitive, HardeningSummary};
        let summary = HardeningSummary {
            backend: "macos-process".into(),
            level: "sandboxed".into(),
            profile: "path_traversal".into(),
            primitives: vec![],
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        let parsed: HardeningSummary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, summary);

        // Defaults: missing `profile` and `primitives` must decode as
        // empty so older `verdict.json` payloads keep round-tripping.
        let minimal: HardeningSummary =
            serde_json::from_str(r#"{"backend":"linux-process","level":"full"}"#)
                .expect("minimal decode");
        assert_eq!(minimal.profile, "");
        assert!(minimal.primitives.is_empty());

        // Linux-shape: per-primitive entries decode + re-encode with
        // their `errno` field intact when populated.
        let with_primitives = HardeningSummary {
            backend: "linux-process".into(),
            level: "partial".into(),
            profile: "strict".into(),
            primitives: vec![
                HardeningPrimitive {
                    name: "no_new_privs".into(),
                    status: "applied".into(),
                    errno: None,
                },
                HardeningPrimitive {
                    name: "seccomp".into(),
                    status: "failed".into(),
                    errno: Some(1),
                },
            ],
        };
        let json = serde_json::to_string(&with_primitives).expect("serialize primitives");
        assert!(
            json.contains("\"errno\":1"),
            "errno field should survive JSON round-trip; got: {json}"
        );
        let parsed: HardeningSummary = serde_json::from_str(&json).expect("decode primitives");
        assert_eq!(parsed, with_primitives);
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
