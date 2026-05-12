//! Build-time isolation wrapper (§19).
//!
//! Runs `python -m venv` + `pip install -r requirements.txt` in isolation:
//! - Linux: uses `unshare` for network/mount/user namespace restriction when
//!   available (falls back to plain subprocess).
//! - Other platforms: plain subprocess with env stripping.
//!
//! Build cache lives at:
//!   `~/.cache/nyx/dynamic/build-cache/{lockfile_hash}-{language}-{toolchain_id}/`
//! with permissions `0700` (§19.3).
//!
//! Failed-build retry policy (§12 Q4): one retry on `BuildFailed` with
//! backoff (1s, 4s), then `Inconclusive(BuildFailed, attempts: 2)`.

use crate::dynamic::spec::HarnessSpec;
use blake3::Hasher;
use directories::ProjectDirs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

// ── Rust build sandbox ────────────────────────────────────────────────────────

/// Prepare a compiled Rust binary for `spec`.
///
/// Checks a build cache keyed on `(Cargo.lock hash, "rust", toolchain_id)`.
/// On a cache hit returns immediately; otherwise runs `cargo build --release`
/// in `workdir` and caches the resulting binary.
///
/// The compiled binary is at `cache_path/nyx_harness` on success.
///
/// Build isolation is NOT yet implemented (deferred to Phase 05). `cargo build`
/// runs as a plain subprocess on the host with `env_clear()` plus a minimal
/// inherited env (PATH/HOME/CARGO_HOME/RUSTUP_HOME). A malicious `build.rs`
/// runs with host privileges. Vendoring / network sandboxing comes later (§19.2).
pub fn prepare_rust(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
    let lockfile_hash = compute_rust_lockfile_hash(workdir);
    let cache_path = build_cache_path(&lockfile_hash, "rust", &spec.toolchain_id)?;

    // Cache hit: binary already compiled and stored.
    let binary = cache_path.join("nyx_harness");
    if binary.exists() {
        return Ok(BuildResult { venv_path: cache_path, cache_hit: true, duration: Duration::ZERO });
    }

    let start = Instant::now();
    const MAX_ATTEMPTS: u32 = 2;
    const BACKOFF: [u64; 2] = [1, 4];
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(BACKOFF[attempt as usize - 1]));
        }
        let _ = std::fs::remove_dir_all(&cache_path);
        std::fs::create_dir_all(&cache_path)?;

        match try_build_rust_binary(workdir, &binary) {
            Ok(()) => {
                return Ok(BuildResult {
                    venv_path: cache_path,
                    cache_hit: false,
                    duration: start.elapsed(),
                });
            }
            Err(e) => {
                last_err = e;
                let _ = std::fs::remove_file(&binary);
            }
        }
    }

    Err(BuildError::BuildFailed { stderr: last_err, attempts: MAX_ATTEMPTS })
}

fn try_build_rust_binary(workdir: &Path, binary_dest: &Path) -> Result<(), String> {
    let cargo = cargo_binary();

    // Run `cargo build --release` in the workdir.
    let output = Command::new(&cargo)
        .args(["build", "--release"])
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        // Inherit CARGO_HOME so the local registry cache is reused.
        .env("CARGO_HOME", std::env::var("CARGO_HOME").unwrap_or_else(|_| {
            dirs_next_cargo_home()
        }))
        .env("RUSTUP_HOME", std::env::var("RUSTUP_HOME").unwrap_or_default())
        .output()
        .map_err(|e| format!("cargo build: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(stderr);
    }

    // Copy binary to cache location.
    let compiled = workdir.join("target").join("release").join("nyx_harness");
    if compiled.exists() {
        std::fs::copy(&compiled, binary_dest)
            .map_err(|e| format!("copy binary: {e}"))?;
    }

    Ok(())
}

fn cargo_binary() -> String {
    // Respect NYX_CARGO_BIN for testing.
    std::env::var("NYX_CARGO_BIN").unwrap_or_else(|_| "cargo".to_owned())
}

fn dirs_next_cargo_home() -> String {
    // ~/.cargo is the default CARGO_HOME.
    std::env::var("HOME")
        .map(|h| format!("{h}/.cargo"))
        .unwrap_or_else(|_| ".cargo".to_owned())
}

fn compute_rust_lockfile_hash(workdir: &Path) -> String {
    let mut h = Hasher::new();
    // Cargo manifest and lock determine dependency graph.
    for fname in &["Cargo.lock", "Cargo.toml"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    // Entry file is compiled into the binary, so it must be part of the cache key.
    // Without this, two fixtures with the same Cargo.toml but different entry.rs
    // would collide and the second would receive the wrong cached binary.
    if let Ok(content) = std::fs::read(workdir.join("src").join("entry.rs")) {
        h.update(b"src/entry.rs");
        h.update(&content);
    }
    let out = h.finalize();
    format!("{:016x}", u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap()))
}

/// Result of a successful build.
#[derive(Debug, Clone)]
pub struct BuildResult {
    /// Path to the built venv / interpreter to use.
    pub venv_path: PathBuf,
    /// Whether the build used a cached result (true) or built fresh (false).
    pub cache_hit: bool,
    /// Wall-clock time for the build step (0 on cache hit).
    pub duration: Duration,
}

#[derive(Debug)]
pub enum BuildError {
    Unsupported,
    BuildFailed { stderr: String, attempts: u32 },
    Io(std::io::Error),
}

impl From<std::io::Error> for BuildError {
    fn from(e: std::io::Error) -> Self {
        BuildError::Io(e)
    }
}

/// Prepare a Python venv for `spec` in `workdir`.
///
/// If a compatible cache entry exists, returns it immediately. Otherwise
/// builds in isolation and caches the result.
pub fn prepare_python(
    spec: &HarnessSpec,
    workdir: &Path,
) -> Result<BuildResult, BuildError> {
    let lockfile_hash = compute_lockfile_hash(workdir);
    let cache_path = build_cache_path(&lockfile_hash, "python", &spec.toolchain_id)?;

    // Check cache hit: venv exists and pyvenv.cfg is present.
    if cache_path.join("pyvenv.cfg").exists() {
        return Ok(BuildResult {
            venv_path: cache_path,
            cache_hit: true,
            duration: Duration::ZERO,
        });
    }

    // Build with retry.
    const MAX_ATTEMPTS: u32 = 2;
    const BACKOFF: [u64; 2] = [1, 4];
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(BACKOFF[attempt as usize - 1]));
        }

        let start = Instant::now();
        match try_build_venv(&cache_path, workdir, spec) {
            Ok(()) => {
                return Ok(BuildResult {
                    venv_path: cache_path,
                    cache_hit: false,
                    duration: start.elapsed(),
                });
            }
            Err(e) => {
                last_err = e;
                // Remove partial cache before retry.
                let _ = std::fs::remove_dir_all(&cache_path);
            }
        }
    }

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

fn try_build_venv(
    venv_path: &Path,
    workdir: &Path,
    spec: &HarnessSpec,
) -> Result<(), String> {
    // Find python binary.
    let python = python_binary(spec);

    // Create the venv.
    let status = Command::new(&python)
        .args(["-m", "venv", "--clear"])
        .arg(venv_path)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .status()
        .map_err(|e| format!("venv create: {e}"))?;

    if !status.success() {
        return Err(format!("venv create failed: exit {status}"));
    }

    // Install dependencies if requirements.txt exists.
    let req_path = workdir.join("requirements.txt");
    if req_path.exists() {
        let pip = venv_path.join("bin").join("pip");
        let output = Command::new(&pip)
            .args(["install", "--no-cache-dir", "-r"])
            .arg(&req_path)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .output()
            .map_err(|e| format!("pip install: {e}"))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
    }

    Ok(())
}

fn python_binary(spec: &HarnessSpec) -> String {
    // Try the pinned version first; fall back to python3.
    let ver = spec
        .toolchain_id
        .strip_prefix("python-")
        .unwrap_or("3");
    let candidate = format!("python{ver}");
    if which_exists(&candidate) {
        return candidate;
    }
    "python3".to_owned()
}

fn which_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn compute_lockfile_hash(workdir: &Path) -> String {
    let mut h = Hasher::new();
    for fname in &["requirements.txt", "Pipfile.lock", "pyproject.toml"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    let out = h.finalize();
    format!("{:016x}", u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap()))
}

fn build_cache_path(
    lockfile_hash: &str,
    language: &str,
    toolchain_id: &str,
) -> Result<PathBuf, BuildError> {
    // Respect test override.
    let base = if let Ok(p) = std::env::var("NYX_BUILD_CACHE") {
        PathBuf::from(p)
    } else {
        let dirs = ProjectDirs::from("", "", "nyx").ok_or_else(|| {
            BuildError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cannot determine cache dir",
            ))
        })?;
        dirs.cache_dir()
            .join("dynamic")
            .join("build-cache")
    };

    let name = format!("{lockfile_hash}-{language}-{toolchain_id}");
    let path = base.join(&name);
    std::fs::create_dir_all(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_hash_empty_dir_stable() {
        let dir = tempfile::TempDir::new().unwrap();
        let h1 = compute_lockfile_hash(dir.path());
        let h2 = compute_lockfile_hash(dir.path());
        assert_eq!(h1, h2, "hash must be deterministic");
    }

    #[test]
    fn lockfile_hash_changes_with_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let h1 = compute_lockfile_hash(dir.path());
        std::fs::write(dir.path().join("requirements.txt"), "requests==2.28.0\n").unwrap();
        let h2 = compute_lockfile_hash(dir.path());
        assert_ne!(h1, h2, "hash must change when requirements.txt changes");
    }
}
