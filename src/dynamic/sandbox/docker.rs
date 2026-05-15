//! Phase 19 (Track E.3) — Docker backend helpers.
//!
//! This module is the thin layer between the pinned-digest catalogue
//! (`tools/image-builder/images.toml` → `src/dynamic/toolchain.rs::IMAGE_DIGESTS`)
//! and the existing docker invocations in [`super::run_docker`] /
//! [`super::run_native_binary_docker`].
//!
//! Responsibilities:
//!
//! 1. Resolve a `toolchain_id` → pinned image reference (`<base>@sha256:…`),
//!    falling back to the unpinned base tag when no digest is recorded yet.
//! 2. Pull the resolved reference if it is not already present locally so
//!    every backend hop runs against the exact bytes the catalogue pinned.
//! 3. Render the docker CLI arg slice that:
//!    - mounts the harness workdir read-write at the fixed `/work` path,
//!    - mounts each `StubHarness` filesystem root at a fixed `/nyx/stubs/<n>`
//!      path so harness-side shims can find them without hard-coding host
//!      tempdir layouts,
//!    - honours the [`super::NetworkPolicy`] (none / OOB / stubs-only / open)
//!      using the same flag set as the legacy `start_container`.
//!
//! All helpers are infallible w.r.t. docker availability — they return arg
//! slices and `Option<String>` references that the caller (`super::`) ships
//! to the docker CLI.  That keeps the module easy to unit-test on macOS / CI
//! rows that do not have docker installed.

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use crate::dynamic::toolchain::{base_image_ref, pinned_image_ref};

use super::{HostPort, NetworkPolicy};

// ── Image references ────────────────────────────────────────────────────────

/// Container-side mount point for the harness workdir.  Stable so per-language
/// emitters can reference `/work/...` without threading the host tempdir path
/// through every layer.
pub const WORK_MOUNT_PATH: &str = "/work";

/// Container-side mount point root for `StubHarness` filesystem stubs.
/// Each stub is mounted at `STUB_MOUNT_ROOT/<n>` where `<n>` is its index in
/// the harness's stub list.
pub const STUB_MOUNT_ROOT: &str = "/nyx/stubs";

/// Resolve a `toolchain_id` to the docker image reference the backend should
/// pull.  Preference order:
///
/// 1. Pinned digest from `IMAGE_DIGESTS` (`<base>@sha256:…`).  Bytes are
///    immutable across hosts; this is what production uses.
/// 2. Base tag from `IMAGE_BASES` (`python:3.11-slim`).  Used when the
///    catalogue entry has not been built yet — drift is visible because the
///    daily CI workflow runs `nyx-image-builder build --all` and PRs the
///    digest.
/// 3. `None` — the toolchain is not in the catalogue at all.  Callers fall
///    back to the historical hard-coded image map.
pub fn image_reference_for_toolchain(toolchain_id: &str) -> Option<&'static str> {
    if let Some(pinned) = pinned_image_ref(toolchain_id) {
        return Some(pinned);
    }
    base_image_ref(toolchain_id)
}

/// `true` when `image_reference_for_toolchain` would return a pinned digest
/// (rather than a bare tag).  Used by telemetry + tests.
pub fn toolchain_is_pinned(toolchain_id: &str) -> bool {
    pinned_image_ref(toolchain_id).is_some()
}

// ── Pull-by-digest ──────────────────────────────────────────────────────────

/// `docker pull <image>` once per process.  Cached so repeated harness runs
/// against the same image do not re-hit the registry.
///
/// Returns `true` if the image is now present locally; `false` if the pull
/// failed (network outage, untagged digest, registry auth, …).  Callers
/// treat `false` as a docker-backend-unavailable signal so the verifier can
/// route around it cleanly.
pub fn ensure_image_pulled(image: &str) -> bool {
    static CACHE: OnceLock<dashmap::DashMap<String, bool>> = OnceLock::new();
    let cache = CACHE.get_or_init(dashmap::DashMap::new);

    if let Some(entry) = cache.get(image) {
        return *entry;
    }
    // Fast path: a prior `docker pull` (often by an earlier nextest binary in
    // the same machine) may already have the image locally.  `docker image
    // inspect` is a no-network lookup against the local daemon — when it
    // succeeds we can skip the network pull entirely.  When it fails we fall
    // through to `docker pull` so registry-side rotations / first-time runs
    // still settle.
    let ok = if docker_image_present(image) { true } else { docker_pull(image) };
    cache.insert(image.to_owned(), ok);
    ok
}

fn docker_image_present(image: &str) -> bool {
    Command::new(docker_bin())
        .args(["image", "inspect", image])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn docker_pull(image: &str) -> bool {
    Command::new(docker_bin())
        .args(["pull", image])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn docker_bin() -> String {
    std::env::var("NYX_DOCKER_BIN").unwrap_or_else(|_| "docker".to_owned())
}

// ── Argument assembly ───────────────────────────────────────────────────────

/// Render the `docker run` flag slice that mounts the harness workdir at
/// [`WORK_MOUNT_PATH`] read-write.  Always returns a `-v host:/work:rw`
/// pair; an empty workdir is mounted at the same path so harness code can
/// stage outputs under `/work/...` unconditionally.
///
/// Returns owned strings so the caller can `extend` them into its already-
/// built `Vec<String>` arg list without lifetime drag.
pub fn workdir_mount_args(workdir: &Path) -> Vec<String> {
    let host = workdir.to_string_lossy().into_owned();
    vec!["-v".to_owned(), format!("{host}:{WORK_MOUNT_PATH}:rw")]
}

/// Render the `docker run` flag slice that mounts each filesystem-stub root
/// at a fixed path under [`STUB_MOUNT_ROOT`].  Network stubs (SQL TCP loop,
/// HTTP, Redis) do not appear here — they reach the harness via
/// `--add-host=host-gateway` and the env vars threaded through
/// `SandboxOptions::extra_env`.
///
/// Each entry maps to `-v <host>:<STUB_MOUNT_ROOT>/<index>:rw`.  Read-write
/// because stubs record events into the path.
pub fn stub_mount_args(stub_roots: &[std::path::PathBuf]) -> Vec<String> {
    let mut out = Vec::with_capacity(stub_roots.len() * 2);
    for (idx, root) in stub_roots.iter().enumerate() {
        let host = root.to_string_lossy().into_owned();
        out.push("-v".to_owned());
        out.push(format!("{host}:{STUB_MOUNT_ROOT}/{idx}:rw"));
    }
    out
}

/// Render the `--network` + `--add-host` flag slice for a [`NetworkPolicy`].
///
/// Mirrors the legacy block in [`super::start_container`] so callers using
/// the new docker.rs entry point produce byte-identical container layouts
/// to the existing path — important for `tests/dynamic_parity.rs` to keep
/// reading the same verdicts across backends.
pub fn network_args(policy: &NetworkPolicy) -> Vec<String> {
    let mut args = Vec::with_capacity(4);
    match policy {
        NetworkPolicy::None => {
            args.extend(["--network".to_owned(), "none".to_owned()]);
        }
        NetworkPolicy::OobOutbound { .. } => {
            args.extend(["--network".to_owned(), "bridge".to_owned()]);
            args.push("--add-host=host-gateway:host-gateway".to_owned());
        }
        NetworkPolicy::StubsOnly { allow } => {
            args.extend(["--network".to_owned(), "bridge".to_owned()]);
            args.push("--add-host=host-gateway:host-gateway".to_owned());
            for hp in allow {
                args.push(add_host_arg(hp));
            }
        }
        NetworkPolicy::Open => {
            args.extend(["--network".to_owned(), "bridge".to_owned()]);
        }
    }
    args
}

fn add_host_arg(hp: &HostPort) -> String {
    format!("--add-host={}:host-gateway", hp.host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn workdir_mount_args_uses_fixed_path() {
        let path = Path::new("/tmp/nyx-harness/abc");
        let args = workdir_mount_args(path);
        assert_eq!(args, vec!["-v", "/tmp/nyx-harness/abc:/work:rw"]);
    }

    #[test]
    fn stub_mount_args_indexes_each_root() {
        let roots = vec![PathBuf::from("/tmp/stub-a"), PathBuf::from("/tmp/stub-b")];
        let args = stub_mount_args(&roots);
        assert_eq!(
            args,
            vec![
                "-v",
                "/tmp/stub-a:/nyx/stubs/0:rw",
                "-v",
                "/tmp/stub-b:/nyx/stubs/1:rw",
            ],
        );
    }

    #[test]
    fn stub_mount_args_empty_when_no_stubs() {
        assert!(stub_mount_args(&[]).is_empty());
    }

    #[test]
    fn network_args_none_picks_network_none() {
        let args = network_args(&NetworkPolicy::None);
        assert!(args.iter().any(|a| a == "none"));
    }

    #[test]
    fn network_args_stubs_only_adds_host_aliases() {
        let policy = NetworkPolicy::StubsOnly {
            allow: vec![HostPort::new("sql", 5432), HostPort::new("redis", 6379)],
        };
        let args = network_args(&policy);
        assert!(args.iter().any(|a| a == "--add-host=sql:host-gateway"));
        assert!(args.iter().any(|a| a == "--add-host=redis:host-gateway"));
    }

    #[test]
    fn network_args_open_drops_egress_filter() {
        let args = network_args(&NetworkPolicy::Open);
        // Open is bridge but no host-gateway alias.
        assert!(args.iter().any(|a| a == "bridge"));
        assert!(!args.iter().any(|a| a.starts_with("--add-host=")));
    }

    #[test]
    fn network_args_oob_threads_host_gateway() {
        let listener = Arc::new(
            crate::dynamic::oob::OobListener::bind()
                .expect("oob listener must bind on 127.0.0.1 in tests"),
        );
        let args = network_args(&NetworkPolicy::OobOutbound { listener });
        assert!(args.iter().any(|a| a == "--add-host=host-gateway:host-gateway"));
    }

    #[test]
    fn image_reference_for_toolchain_unknown_returns_none() {
        assert_eq!(image_reference_for_toolchain("python-99.x"), None);
    }

    #[test]
    fn image_reference_for_toolchain_known_returns_base_when_unpinned() {
        // The catalogue ships with empty digests; we therefore expect the
        // bare base tag for known IDs.  When the daily CI run pins a real
        // digest this test will start seeing `<base>@sha256:…` instead, and
        // we update the assertion accordingly.
        let r = image_reference_for_toolchain("python-3.11");
        assert!(r.is_some());
        assert!(r.unwrap().contains("python"));
    }

    #[test]
    fn toolchain_is_pinned_false_when_digest_empty() {
        // Fresh catalogue ships with empty digests, so every known toolchain
        // is still considered unpinned until the daily CI run.
        assert!(!toolchain_is_pinned("python-3.11"));
    }
}
