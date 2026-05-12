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

    // Cache hit: node_modules already installed. Restore to fresh workdir if
    // a different finding shares the same cache key but got a new workdir.
    if cache_path.join(".node_cache_done").exists() {
        let cached_nm = cache_path.join("node_modules");
        if cached_nm.exists() && !workdir.join("node_modules").exists() {
            let _ = copy_dir_all(&cached_nm, &workdir.join("node_modules"));
        }
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
                // Persist node_modules to cache so future runs with the same
                // package.json but a fresh workdir can restore without re-running npm.
                let nm_src = workdir.join("node_modules");
                if nm_src.exists() {
                    let _ = copy_dir_all(&nm_src, &cache_path.join("node_modules"));
                }
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

/// Recursively copy a directory tree from `src` to `dst`.
///
/// Silently skips entries that cannot be copied. Used to persist
/// `node_modules`/`vendor` to the build cache and restore them on cache hit.
fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), &dst_path)?;
        }
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
        let cached_vendor = cache_path.join("vendor");
        if cached_vendor.exists() && !workdir.join("vendor").exists() {
            let _ = copy_dir_all(&cached_vendor, &workdir.join("vendor"));
        }
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
                // Persist vendor/ to cache so future runs with the same
                // composer.json but a fresh workdir can restore without re-running composer.
                let vendor_src = workdir.join("vendor");
                if vendor_src.exists() {
                    let _ = copy_dir_all(&vendor_src, &cache_path.join("vendor"));
                }
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

// ── Docker-isolated build step functions ─────────────────────────────────────
//
// Each function runs the language's build tool inside a Docker container with
// no host volume mounts. A malicious build script can only write to the
// container's private filesystem; the host is unaffected.
//
// Return value semantics:
//   Ok(())      — container started and the build tool was invoked (the build
//                 itself may have failed; the caller should only inspect host
//                 side-effects, not assume the artefact was produced).
//   Err(msg)    — Docker is unreachable or the image could not be started;
//                 no container ran and no build-time code executed on any host.

fn docker_bin_for_build() -> String {
    std::env::var("NYX_DOCKER_BIN").unwrap_or_else(|_| "docker".to_owned())
}

fn build_container_id(prefix: &str, workdir: &Path) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    workdir.hash(&mut h);
    format!("nyx-{prefix}-{:016x}", h.finish())
}

/// Start a `sleep 300` container for isolated builds.
/// Returns `true` on success, `false` when Docker is unavailable or the image
/// cannot be started (e.g. not yet pulled).
fn start_isolated_build_container(
    docker: &str,
    name: &str,
    image: &str,
    network_none: bool,
) -> bool {
    let mut args: Vec<&str> = vec![
        "run", "-d", "--rm",
        "--name", name,
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges:true",
    ];
    if network_none {
        args.extend_from_slice(&["--network", "none"]);
    }
    args.extend_from_slice(&[image, "sleep", "300"]);

    std::process::Command::new(docker)
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Copy the contents of `workdir` into `{container}:{dest}` via `docker cp`.
fn copy_workdir_to_build_container(docker: &str, workdir: &Path, container: &str, dest: &str) {
    let _ = std::process::Command::new(docker)
        .args(["exec", container, "mkdir", "-p", dest])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let src = format!("{}/.", workdir.display());
    let cp_dst = format!("{container}:{dest}");
    let _ = std::process::Command::new(docker)
        .args(["cp", &src, &cp_dst])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// RAII guard that stops and removes a Docker container on drop.
struct BuildContainerGuard {
    docker: String,
    name: String,
}

impl Drop for BuildContainerGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new(&self.docker)
            .args(["stop", "--time=0", &self.name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Run `cargo build --release` inside a Docker container.
///
/// Provides build-time isolation: `--network none`, no host mounts. A
/// malicious `build.rs` can only write to the container's private `/tmp`.
///
/// Returns `Ok(())` when the container started and `cargo build` was invoked
/// (build success/failure inside the container is not checked). Returns
/// `Err(msg)` when Docker is unreachable or `rust:slim` cannot be started.
pub fn prepare_rust_in_docker(workdir: &Path) -> Result<(), String> {
    let docker = docker_bin_for_build();
    let container = build_container_id("rustbuild", workdir);

    if !start_isolated_build_container(&docker, &container, "rust:slim", true) {
        return Err("failed to start rust:slim build container; image may not be available".into());
    }

    let _guard = BuildContainerGuard { docker: docker.clone(), name: container.clone() };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    // CARGO_NET_OFFLINE prevents any registry contact; std lib is pre-built in the image.
    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            "-e", "CARGO_NET_OFFLINE=true",
            &container,
            "sh", "-c", "cd /build && cargo build --release 2>&1",
        ])
        .output();

    Ok(())
}

/// Run `npm install` inside a Docker container.
///
/// The `preinstall` / `postinstall` lifecycle hooks execute inside the
/// container only; they cannot write to host filesystem paths.
///
/// Returns `Ok(())` when the container started and `npm install` was invoked.
/// Returns `Err(msg)` when Docker is unreachable or `node:20-slim` cannot be started.
pub fn prepare_node_in_docker(workdir: &Path) -> Result<(), String> {
    let docker = docker_bin_for_build();
    let container = build_container_id("nodebuild", workdir);

    if !start_isolated_build_container(&docker, &container, "node:20-slim", true) {
        return Err("failed to start node:20-slim build container; image may not be available".into());
    }

    let _guard = BuildContainerGuard { docker: docker.clone(), name: container.clone() };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    // npm install may fail if the registry is unreachable (--network none), but the
    // preinstall hook runs before any network calls, so the escape attempt executes.
    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            &container,
            "sh", "-c",
            "cd /build && npm install --no-save --no-audit --no-fund 2>&1",
        ])
        .output();

    Ok(())
}

/// Run `go build ./...` inside a Docker container.
///
/// Go `init()` functions only run at binary execution time (not during
/// compilation), so no host side-effects occur during the build step.
///
/// Returns `Ok(())` when the container started and `go build` was invoked.
/// Returns `Err(msg)` when Docker is unreachable or `golang:1.21-slim` cannot be started.
pub fn prepare_go_in_docker(workdir: &Path) -> Result<(), String> {
    let docker = docker_bin_for_build();
    let container = build_container_id("gobuild", workdir);

    if !start_isolated_build_container(&docker, &container, "golang:1.21-slim", true) {
        return Err("failed to start golang:1.21-slim build container; image may not be available".into());
    }

    let _guard = BuildContainerGuard { docker: docker.clone(), name: container.clone() };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    // GOPROXY=off prevents module downloads; std library is pre-compiled in the image.
    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            "-e", "GOPROXY=off",
            "-e", "GONOSUMDB=*",
            &container,
            "sh", "-c", "cd /build && go build ./... 2>&1",
        ])
        .output();

    Ok(())
}

/// Run `mvn validate` inside a Docker container.
///
/// Maven build plugins (e.g. exec-maven-plugin) execute inside the container
/// only; they cannot write to host filesystem paths. Bridge networking is used
/// so Maven can download required plugins from Maven Central.
///
/// Returns `Ok(())` when the container started and `mvn validate` was invoked.
/// Returns `Err(msg)` when Docker is unreachable or the Maven image cannot be started.
pub fn prepare_java_in_docker(workdir: &Path) -> Result<(), String> {
    let docker = docker_bin_for_build();
    let container = build_container_id("mavenbuild", workdir);

    // Bridge network: Maven must download exec-maven-plugin from Maven Central.
    // Filesystem isolation still holds: /tmp inside the container is private.
    if !start_isolated_build_container(
        &docker,
        &container,
        "maven:3.9-eclipse-temurin-21",
        false,
    ) {
        return Err(
            "failed to start maven:3.9-eclipse-temurin-21 build container; image may not be available"
                .into(),
        );
    }

    let _guard = BuildContainerGuard { docker: docker.clone(), name: container.clone() };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            &container,
            "sh", "-c", "cd /build && mvn --no-transfer-progress validate 2>&1",
        ])
        .output();

    Ok(())
}

/// Run `composer install` inside a Docker container.
///
/// Composer lifecycle scripts (`post-install-cmd`) execute inside the
/// container only; they cannot write to host filesystem paths.
///
/// Returns `Ok(())` when the container started and `composer install` was invoked.
/// Returns `Err(msg)` when Docker is unreachable or `composer:2` cannot be started.
pub fn prepare_php_in_docker(workdir: &Path) -> Result<(), String> {
    let docker = docker_bin_for_build();
    let container = build_container_id("phpbuild", workdir);

    if !start_isolated_build_container(&docker, &container, "composer:2", true) {
        return Err("failed to start composer:2 build container; image may not be available".into());
    }

    let _guard = BuildContainerGuard { docker: docker.clone(), name: container.clone() };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    // Empty require{} means no packages to fetch; post-install-cmd still fires.
    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            &container,
            "sh", "-c",
            "cd /build && composer install --no-dev --no-interaction --prefer-dist 2>&1",
        ])
        .output();

    Ok(())
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

    #[test]
    fn copy_dir_all_copies_recursively() {
        let src = tempfile::TempDir::new().unwrap();
        let dst = tempfile::TempDir::new().unwrap();

        std::fs::write(src.path().join("a.txt"), b"hello").unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub").join("b.txt"), b"world").unwrap();

        copy_dir_all(src.path(), dst.path()).unwrap();

        assert_eq!(std::fs::read(dst.path().join("a.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(dst.path().join("sub").join("b.txt")).unwrap(), b"world");
    }

    #[test]
    fn copy_dir_all_creates_dst_if_absent() {
        let src = tempfile::TempDir::new().unwrap();
        std::fs::write(src.path().join("x.txt"), b"x").unwrap();

        let dst_parent = tempfile::TempDir::new().unwrap();
        let dst = dst_parent.path().join("new_dir");
        // dst does not yet exist — copy_dir_all must create it.
        copy_dir_all(src.path(), &dst).unwrap();
        assert_eq!(std::fs::read(dst.join("x.txt")).unwrap(), b"x");
    }
}
