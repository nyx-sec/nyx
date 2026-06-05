//! Phase 19 (Track E.3) — Docker backend pinned-digest + mount tests.
//!
//! Exercises the `src/dynamic/sandbox/docker.rs` helpers end-to-end on the
//! `linux-with-docker` CI matrix row.  Tests skip automatically when docker
//! is not reachable so the `linux-without-docker` and `macos` rows pass
//! without burning a docker pull.
//!
//! The acceptance literal for this phase is "`tests/sandbox_docker.rs` runs
//! only on the `linux-with-docker` matrix row".  We honour that by checking
//! `docker info` at the top of every test and short-circuiting when the
//! daemon is unreachable.
//!
//! Run with:  `cargo nextest run --features dynamic --test sandbox_docker`

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::harness::BuiltHarness;
use nyx_scanner::dynamic::sandbox::docker::{
    STUB_MOUNT_ROOT, WORK_MOUNT_PATH, ensure_image_pulled, image_reference_for_toolchain,
    network_args, stub_mount_args, toolchain_is_pinned, workdir_mount_args,
};
use nyx_scanner::dynamic::sandbox::{
    self, HostPort, NetworkPolicy, SandboxBackend, SandboxOptions,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn write_harness_script(workdir: &Path, body: &str) -> PathBuf {
    let path = workdir.join("harness.py");
    std::fs::write(&path, body).expect("write harness script");
    path
}

fn harness(workdir: &Path) -> BuiltHarness {
    BuiltHarness {
        workdir: workdir.to_path_buf(),
        command: vec!["python3".into(), "harness.py".into()],
        env: vec![],
        source: String::new(),
        entry_source: String::new(),
    }
}

fn docker_opts() -> SandboxOptions {
    SandboxOptions {
        timeout: Duration::from_secs(15),
        backend: SandboxBackend::Docker,
        network_policy: NetworkPolicy::None,
        ..SandboxOptions::default()
    }
}

// ── Pure helper coverage (always runs) ───────────────────────────────────────

#[test]
fn workdir_mount_args_uses_fixed_work_path() {
    let args = workdir_mount_args(Path::new("/tmp/nyx-harness/run-abc"));
    assert_eq!(
        args,
        vec![
            "-v".to_owned(),
            format!("/tmp/nyx-harness/run-abc:{WORK_MOUNT_PATH}:rw"),
        ],
    );
}

#[test]
fn stub_mount_args_uses_indexed_fixed_paths() {
    let roots = [PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")];
    let args = stub_mount_args(&roots);
    assert_eq!(args.len(), 4);
    assert!(args.contains(&format!("/tmp/a:{STUB_MOUNT_ROOT}/0:rw")));
    assert!(args.contains(&format!("/tmp/b:{STUB_MOUNT_ROOT}/1:rw")));
}

#[test]
fn network_args_translate_every_policy() {
    assert!(
        network_args(&NetworkPolicy::None)
            .iter()
            .any(|a| a == "none")
    );
    let stubs = NetworkPolicy::StubsOnly {
        allow: vec![HostPort::new("sql", 5432)],
    };
    let stubs_args = network_args(&stubs);
    assert!(
        stubs_args
            .iter()
            .any(|a| a == "--add-host=sql:host-gateway")
    );
    let open = network_args(&NetworkPolicy::Open);
    assert!(open.iter().any(|a| a == "bridge"));
    assert!(!open.iter().any(|a| a.starts_with("--add-host=")));
}

#[test]
fn image_reference_resolves_known_toolchains() {
    // Every catalogue entry must resolve to something — pinned or unpinned.
    assert!(image_reference_for_toolchain("python-3.11").is_some());
    assert!(image_reference_for_toolchain("node-20").is_some());
    assert!(image_reference_for_toolchain("java-21").is_some());
    // Unknown IDs return None so the legacy path keeps working.
    assert!(image_reference_for_toolchain("python-99.9").is_none());
}

#[test]
fn toolchain_pinning_state_is_observable() {
    // Without a daily-job-run images.toml we expect every entry to still be
    // unpinned.  The assertion flips when the CI workflow lands the first
    // digests — at which point this test starts catching accidental
    // reversions to bare tags.
    let pinned = toolchain_is_pinned("python-3.11");
    let r = image_reference_for_toolchain("python-3.11").unwrap();
    if pinned {
        assert!(
            r.contains("@sha256:"),
            "pinned ref must carry digest, got {r}"
        );
    } else {
        assert!(
            !r.contains("@sha256:"),
            "unpinned ref must not carry digest, got {r}"
        );
    }
}

// ── Live-docker coverage (skips when docker is absent) ───────────────────────

#[test]
fn ensure_image_pulled_returns_true_for_python_slim() {
    if !docker_available() {
        eprintln!("docker unavailable — skipping");
        return;
    }
    let r =
        image_reference_for_toolchain("python-3.11").expect("python-3.11 must be in the catalogue");
    assert!(
        ensure_image_pulled(r),
        "ensure_image_pulled must succeed for `{r}` when docker is available",
    );
}

#[test]
fn harness_runs_under_docker_with_network_none() {
    if !docker_available() {
        eprintln!("docker unavailable — skipping");
        return;
    }
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // Tiny script that just prints a marker; we use it to confirm the
    // backend round-trips through `docker run` + `docker exec` cleanly.
    write_harness_script(
        tmp.path(),
        "import sys; sys.stdout.write('NYX_DOCKER_OK\\n')\n",
    );
    let h = harness(tmp.path());
    let opts = docker_opts();
    let outcome = sandbox::run(&h, b"", &opts).expect("docker backend must run");
    assert_eq!(outcome.exit_code, Some(0), "harness must exit cleanly");
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(
        stdout.contains("NYX_DOCKER_OK"),
        "expected marker in stdout, got: {stdout}",
    );
}

#[test]
fn harness_workdir_is_mounted_at_fixed_work_path() {
    if !docker_available() {
        eprintln!("docker unavailable — skipping");
        return;
    }
    let tmp = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(tmp.path().join("token.txt"), "phase-19-mount-token\n").expect("write fixture");
    write_harness_script(
        tmp.path(),
        // Read from the fixed /work mount path — this passes only when the
        // workdir is bind-mounted there, not just docker-cp'd to /workdir.
        "open('/work/token.txt').read()\n\
         import sys; sys.stdout.write('NYX_WORK_MOUNT_OK\\n')\n",
    );
    let h = harness(tmp.path());
    let opts = docker_opts();
    let outcome = sandbox::run(&h, b"", &opts).expect("docker backend must run");
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "/work mount must be readable inside the container; stdout={stdout} stderr={stderr}",
    );
    assert!(
        stdout.contains("NYX_WORK_MOUNT_OK"),
        "expected /work mount marker; stdout={stdout}",
    );
}
