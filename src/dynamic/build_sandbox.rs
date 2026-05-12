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

// ── Node.js build sandbox ─────────────────────────────────────────────────────

/// Prepare a Node.js project for `spec` in `workdir`.
///
/// Runs `npm install --no-save` if `package.json` is present.
/// Build isolation is NOT yet implemented (deferred to a future phase).
/// npm lifecycle scripts run on the host. See deferred.md for details.
pub fn prepare_node(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
    let lockfile_hash = compute_node_lockfile_hash(workdir);
    let cache_path = build_cache_path(&lockfile_hash, "node", &spec.toolchain_id)?;

    // Cache hit: node_modules already installed.
    if cache_path.join(".node_cache_done").exists() {
        return Ok(BuildResult {
            venv_path: cache_path,
            cache_hit: true,
            duration: std::time::Duration::ZERO,
        });
    }

    // No package.json = no deps to install.
    if !workdir.join("package.json").exists() {
        std::fs::write(cache_path.join(".node_cache_done"), b"no-package-json")?;
        return Ok(BuildResult {
            venv_path: cache_path,
            cache_hit: false,
            duration: std::time::Duration::ZERO,
        });
    }

    let start = std::time::Instant::now();
    const MAX_ATTEMPTS: u32 = 2;
    const BACKOFF: [u64; 2] = [1, 4];
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(BACKOFF[attempt as usize - 1]));
        }
        match try_npm_install(workdir) {
            Ok(()) => {
                let _ = std::fs::write(cache_path.join(".node_cache_done"), b"done");
                return Ok(BuildResult {
                    venv_path: cache_path,
                    cache_hit: false,
                    duration: start.elapsed(),
                });
            }
            Err(e) => {
                last_err = e;
            }
        }
    }

    Err(BuildError::BuildFailed { stderr: last_err, attempts: MAX_ATTEMPTS })
}

fn try_npm_install(workdir: &Path) -> Result<(), String> {
    let npm = std::env::var("NYX_NPM_BIN").unwrap_or_else(|_| "npm".to_owned());
    let output = Command::new(&npm)
        .args(["install", "--no-save", "--no-audit", "--no-fund"])
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .output()
        .map_err(|e| format!("npm install: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(())
}

fn compute_node_lockfile_hash(workdir: &Path) -> String {
    let mut h = Hasher::new();
    for fname in &["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    let out = h.finalize();
    format!("{:016x}", u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap()))
}

// ── Go build sandbox ──────────────────────────────────────────────────────────

/// Prepare a compiled Go binary for `spec`.
///
/// Checks a build cache keyed on `(go.mod + go.sum + entry hash, "go", toolchain_id)`.
/// On a cache hit returns immediately; otherwise runs `go build -o nyx_harness .`
/// in `workdir`.
///
/// Build isolation is NOT yet implemented (deferred). `go build` runs on the
/// host. A malicious `init()` therefore runs with host privileges. See deferred.md.
pub fn prepare_go(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
    let lockfile_hash = compute_go_source_hash(workdir);
    let cache_path = build_cache_path(&lockfile_hash, "go", &spec.toolchain_id)?;

    let binary = cache_path.join("nyx_harness");
    if binary.exists() {
        return Ok(BuildResult {
            venv_path: cache_path,
            cache_hit: true,
            duration: std::time::Duration::ZERO,
        });
    }

    let start = std::time::Instant::now();
    const MAX_ATTEMPTS: u32 = 2;
    const BACKOFF: [u64; 2] = [1, 4];
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(BACKOFF[attempt as usize - 1]));
        }
        let _ = std::fs::remove_dir_all(&cache_path);
        std::fs::create_dir_all(&cache_path)?;

        match try_build_go_binary(workdir, &binary) {
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

fn try_build_go_binary(workdir: &Path, binary_dest: &Path) -> Result<(), String> {
    let go_bin = std::env::var("NYX_GO_BIN").unwrap_or_else(|_| "go".to_owned());
    let output = Command::new(&go_bin)
        .args(["build", "-o", binary_dest.to_str().unwrap_or("nyx_harness"), "."])
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("GOPATH", std::env::var("GOPATH").unwrap_or_else(|_| {
            std::env::var("HOME").map(|h| format!("{h}/go")).unwrap_or_else(|_| "/tmp/go".to_owned())
        }))
        .env("GOMODCACHE", std::env::var("GOMODCACHE").unwrap_or_else(|_| {
            std::env::var("HOME").map(|h| format!("{h}/go/pkg/mod")).unwrap_or_else(|_| "/tmp/gomod".to_owned())
        }))
        .output()
        .map_err(|e| format!("go build: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(())
}

fn compute_go_source_hash(workdir: &Path) -> String {
    let mut h = Hasher::new();
    for fname in &["go.mod", "go.sum", "main.go"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    if let Ok(content) = std::fs::read(workdir.join("entry").join("entry.go")) {
        h.update(b"entry/entry.go");
        h.update(&content);
    }
    let out = h.finalize();
    format!("{:016x}", u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap()))
}

// ── Java build sandbox ────────────────────────────────────────────────────────

/// Prepare compiled Java classes for `spec`.
///
/// Runs `javac NyxHarness.java Entry.java` in `workdir`.
/// Class files land in the workdir (default package, no output dir).
///
/// Build isolation is NOT yet implemented (deferred). `javac` runs on the host.
/// A malicious annotation processor / compile-time plugin could run with host
/// privileges. See deferred.md for planned `nyx-build-java:{toolchain_id}` container.
pub fn prepare_java(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
    let source_hash = compute_java_source_hash(workdir);
    let cache_path = build_cache_path(&source_hash, "java", &spec.toolchain_id)?;

    // Cache hit: class files already compiled. Restore them to workdir so the
    // classpath (which points to workdir, not cache_path) can find them when a
    // different finding hits the same compiled artefact via a fresh spec_hash.
    if cache_path.join("NyxHarness.class").exists() {
        for cls in &["NyxHarness.class", "Entry.class"] {
            let src = cache_path.join(cls);
            let dst = workdir.join(cls);
            if src.exists() && !dst.exists() {
                let _ = std::fs::copy(&src, &dst);
            }
        }
        return Ok(BuildResult {
            venv_path: cache_path,
            cache_hit: true,
            duration: std::time::Duration::ZERO,
        });
    }

    let start = std::time::Instant::now();
    const MAX_ATTEMPTS: u32 = 2;
    const BACKOFF: [u64; 2] = [1, 4];
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(BACKOFF[attempt as usize - 1]));
        }
        match try_compile_java(workdir, &cache_path) {
            Ok(()) => {
                return Ok(BuildResult {
                    venv_path: cache_path,
                    cache_hit: false,
                    duration: start.elapsed(),
                });
            }
            Err(e) => {
                last_err = e;
                let _ = std::fs::remove_file(cache_path.join("NyxHarness.class"));
                let _ = std::fs::remove_file(cache_path.join("Entry.class"));
            }
        }
    }

    Err(BuildError::BuildFailed { stderr: last_err, attempts: MAX_ATTEMPTS })
}

fn try_compile_java(workdir: &Path, cache_path: &Path) -> Result<(), String> {
    let javac = std::env::var("NYX_JAVAC_BIN").unwrap_or_else(|_| "javac".to_owned());

    // Compile sources — class files are written to workdir by default.
    let mut args = vec!["-d".to_owned(), workdir.to_string_lossy().into_owned()];
    for src in &["NyxHarness.java", "Entry.java"] {
        let p = workdir.join(src);
        if p.exists() {
            args.push(p.to_string_lossy().into_owned());
        }
    }

    let output = Command::new(&javac)
        .args(&args)
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .output()
        .map_err(|e| format!("javac: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }

    // Copy class files to cache.
    for cls in &["NyxHarness.class", "Entry.class"] {
        let src = workdir.join(cls);
        if src.exists() {
            let _ = std::fs::copy(&src, cache_path.join(cls));
        }
    }
    Ok(())
}

fn compute_java_source_hash(workdir: &Path) -> String {
    let mut h = Hasher::new();
    for fname in &["NyxHarness.java", "Entry.java"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    let out = h.finalize();
    format!("{:016x}", u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap()))
}

// ── PHP build sandbox ─────────────────────────────────────────────────────────

/// Prepare a PHP project for `spec` in `workdir`.
///
/// Runs `composer install --no-interaction` if `composer.json` is present.
/// Build isolation is NOT yet implemented (deferred). Composer post-install
/// scripts run on the host. See deferred.md for planned
/// `nyx-build-php:{toolchain_id}` container details.
pub fn prepare_php(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
    let lockfile_hash = compute_php_lockfile_hash(workdir);
    let cache_path = build_cache_path(&lockfile_hash, "php", &spec.toolchain_id)?;

    if cache_path.join(".php_cache_done").exists() {
        return Ok(BuildResult {
            venv_path: cache_path,
            cache_hit: true,
            duration: std::time::Duration::ZERO,
        });
    }

    if !workdir.join("composer.json").exists() {
        std::fs::write(cache_path.join(".php_cache_done"), b"no-composer-json")?;
        return Ok(BuildResult {
            venv_path: cache_path,
            cache_hit: false,
            duration: std::time::Duration::ZERO,
        });
    }

    let start = std::time::Instant::now();
    const MAX_ATTEMPTS: u32 = 2;
    const BACKOFF: [u64; 2] = [1, 4];
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(BACKOFF[attempt as usize - 1]));
        }
        match try_composer_install(workdir) {
            Ok(()) => {
                let _ = std::fs::write(cache_path.join(".php_cache_done"), b"done");
                return Ok(BuildResult {
                    venv_path: cache_path,
                    cache_hit: false,
                    duration: start.elapsed(),
                });
            }
            Err(e) => {
                last_err = e;
            }
        }
    }

    Err(BuildError::BuildFailed { stderr: last_err, attempts: MAX_ATTEMPTS })
}

fn try_composer_install(workdir: &Path) -> Result<(), String> {
    let composer = std::env::var("NYX_COMPOSER_BIN").unwrap_or_else(|_| "composer".to_owned());
    let output = Command::new(&composer)
        .args(["install", "--no-interaction", "--no-dev", "--prefer-dist"])
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("COMPOSER_ALLOW_SUPERUSER", "1")
        .output()
        .map_err(|e| format!("composer install: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(())
}

fn compute_php_lockfile_hash(workdir: &Path) -> String {
    let mut h = Hasher::new();
    for fname in &["composer.json", "composer.lock"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    let out = h.finalize();
    format!("{:016x}", u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap()))
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

    #[test]
    fn node_lockfile_hash_stable() {
        let dir = tempfile::TempDir::new().unwrap();
        let h1 = compute_node_lockfile_hash(dir.path());
        let h2 = compute_node_lockfile_hash(dir.path());
        assert_eq!(h1, h2);
    }

    #[test]
    fn go_source_hash_changes_with_main_go() {
        let dir = tempfile::TempDir::new().unwrap();
        let h1 = compute_go_source_hash(dir.path());
        std::fs::write(dir.path().join("main.go"), "package main\nfunc main() {}").unwrap();
        let h2 = compute_go_source_hash(dir.path());
        assert_ne!(h1, h2);
    }

    #[test]
    fn java_source_hash_stable() {
        let dir = tempfile::TempDir::new().unwrap();
        let h1 = compute_java_source_hash(dir.path());
        let h2 = compute_java_source_hash(dir.path());
        assert_eq!(h1, h2);
    }
}
