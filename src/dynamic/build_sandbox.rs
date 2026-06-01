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

use crate::dynamic::build_pool::c::CPool;
use crate::dynamic::build_pool::cpp::CppPool;
use crate::dynamic::build_pool::go::GoPool;
use crate::dynamic::build_pool::java::JavacPool;
use crate::dynamic::build_pool::node::NodePool;
use crate::dynamic::build_pool::php::PhpPool;
use crate::dynamic::build_pool::python::PythonPool;
use crate::dynamic::build_pool::ruby::RubyPool;
use crate::dynamic::build_pool::rust::RustPool;
use crate::dynamic::build_pool::{BuildPool, combine_output, is_pool_enabled, ruby_hermetic_env};
use crate::dynamic::sandbox::ProcessHardeningProfile;
use crate::dynamic::spec::HarnessSpec;
use crate::symbol::Lang;
use blake3::Hasher;
use directories::ProjectDirs;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
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
        return Ok(BuildResult {
            venv_path: cache_path,
            cache_hit: true,
            duration: Duration::ZERO,
        });
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

        match build_rust_binary(workdir, &binary) {
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

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

/// Route the Rust harness build through [`RustPool`] when the pool is
/// enabled, falling back to the legacy direct-spawn `cargo build` on a
/// missing toolchain or a crashed pool.  A genuine compile error from a
/// healthy pool is surfaced verbatim (no legacy re-run — it would fail the
/// same way).
fn build_rust_binary(workdir: &Path, binary_dest: &Path) -> Result<(), String> {
    if is_pool_enabled("rust") {
        if let Ok(pool) = RustPool::try_new() {
            let pool_args = [binary_dest.to_string_lossy().into_owned()];
            let res = pool.compile_batch(workdir, &pool_args);
            if res.success {
                return Ok(());
            }
            if pool.is_healthy() {
                return Err(res.stderr);
            }
        }
    }
    try_build_rust_binary(workdir, binary_dest)
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
        .env(
            "CARGO_HOME",
            std::env::var("CARGO_HOME").unwrap_or_else(|_| dirs_next_cargo_home()),
        )
        .env(
            "RUSTUP_HOME",
            std::env::var("RUSTUP_HOME").unwrap_or_default(),
        )
        .output()
        .map_err(|e| format!("cargo build: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(stderr);
    }

    // Copy binary to cache location.
    let compiled = workdir.join("target").join("release").join("nyx_harness");
    if compiled.exists() {
        std::fs::copy(&compiled, binary_dest).map_err(|e| format!("copy binary: {e}"))?;
    } else {
        return Err(format!(
            "cargo build succeeded but expected binary was not produced at {}",
            compiled.display()
        ));
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
    // Every Rust file under src/ feeds the binary so any change must
    // invalidate the cache.  Walk src/ recursively and hash every .rs
    // file path + content in deterministic (sorted) order so the cache
    // key is stable across runs.  Without this, an emitter change to
    // main.rs / nyx_harness_stubs.rs / etc. with no Cargo.toml /
    // entry.rs change would silently re-use a stale binary built from
    // the old emitter source.
    let src_dir = workdir.join("src");
    let mut rs_files: Vec<PathBuf> = Vec::new();
    collect_rs_files(&src_dir, &src_dir, &mut rs_files);
    rs_files.sort();
    for rel in &rs_files {
        if let Ok(content) = std::fs::read(src_dir.join(rel)) {
            h.update(rel.to_string_lossy().as_bytes());
            h.update(b"\0");
            h.update(&content);
        }
    }
    let out = h.finalize();
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
}

fn collect_rs_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(root, &path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs")
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_path_buf());
        }
    }
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
pub fn prepare_python(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
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
        match build_venv(&cache_path, workdir, spec) {
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

/// Route the Python venv build through [`PythonPool`] (shared wheel cache +
/// `compileall` bytecode warm) when enabled, else the legacy path.
fn build_venv(venv_path: &Path, workdir: &Path, spec: &HarnessSpec) -> Result<(), String> {
    if is_pool_enabled("python") {
        let python = python_binary(spec);
        if let Ok(pool) = PythonPool::try_new(&python) {
            let pool_args = [venv_path.to_string_lossy().into_owned(), python.clone()];
            let res = pool.compile_batch(workdir, &pool_args);
            if res.success {
                return Ok(());
            }
            if pool.is_healthy() {
                return Err(res.stderr);
            }
        }
    }
    try_build_venv(venv_path, workdir, spec)
}

fn try_build_venv(venv_path: &Path, workdir: &Path, spec: &HarnessSpec) -> Result<(), String> {
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
    let ver = spec.toolchain_id.strip_prefix("python-").unwrap_or("3");
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
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
}

fn build_cache_path(
    lockfile_hash: &str,
    language: &str,
    toolchain_id: &str,
) -> Result<PathBuf, BuildError> {
    // Respect test override.
    let override_base = std::env::var("NYX_BUILD_CACHE").ok().map(PathBuf::from);
    let base = if let Some(p) = override_base.clone() {
        p
    } else {
        let dirs = ProjectDirs::from("", "", "nyx").ok_or_else(|| {
            BuildError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cannot determine cache dir",
            ))
        })?;
        dirs.cache_dir().join("dynamic").join("build-cache")
    };

    let name = format!("{lockfile_hash}-{language}-{toolchain_id}");
    let path = base.join(&name);
    match create_build_cache_dir(&path) {
        Ok(()) => Ok(path),
        Err(e) if override_base.is_none() && e.kind() == std::io::ErrorKind::PermissionDenied => {
            let fallback = std::env::temp_dir()
                .join("nyx")
                .join("dynamic")
                .join("build-cache")
                .join(&name);
            create_build_cache_dir(&fallback)?;
            Ok(fallback)
        }
        Err(e) => Err(BuildError::Io(e)),
    }
}

fn create_build_cache_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

// ── Ruby build sandbox ───────────────────────────────────────────────────────

/// Prepare Ruby dependencies for `spec` in `workdir`.
///
/// Runs `bundle check` first so hosts that already have the declared gems do
/// not need network access. When the check misses, runs `bundle install` into
/// `vendor/bundle` and caches both that tree and Bundler's local config.
pub fn prepare_ruby(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
    if !workdir.join("Gemfile").exists() {
        return Ok(BuildResult {
            venv_path: workdir.to_path_buf(),
            cache_hit: false,
            duration: Duration::ZERO,
        });
    }

    let lockfile_hash = compute_ruby_lockfile_hash(workdir);
    let cache_path = build_cache_path(&lockfile_hash, "ruby", &spec.toolchain_id).ok();

    if let Some(cache_path) = &cache_path
        && cache_path.join(".ruby_cache_done").exists()
    {
        restore_cached_ruby_bundle(cache_path, workdir);
        return Ok(BuildResult {
            venv_path: cache_path.clone(),
            cache_hit: true,
            duration: Duration::ZERO,
        });
    }

    let start = Instant::now();
    const MAX_ATTEMPTS: u32 = 2;
    const BACKOFF: [u64; 2] = [1, 4];
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(BACKOFF[attempt as usize - 1]));
        }
        match bundle_install(workdir) {
            Ok(()) => {
                if let Some(cache_path) = &cache_path {
                    persist_ruby_bundle(workdir, cache_path);
                    let _ = std::fs::write(cache_path.join(".ruby_cache_done"), b"done");
                }
                return Ok(BuildResult {
                    venv_path: cache_path.unwrap_or_else(|| workdir.to_path_buf()),
                    cache_hit: false,
                    duration: start.elapsed(),
                });
            }
            Err(e) => {
                last_err = e;
            }
        }
    }

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

/// Route Bundler through [`RubyPool`] (shared Bootsnap cache) when enabled,
/// else the legacy `bundle check`/`install` path.
fn bundle_install(workdir: &Path) -> Result<(), String> {
    if is_pool_enabled("ruby") {
        if let Ok(pool) = RubyPool::try_new() {
            let res = pool.compile_batch(workdir, &[]);
            if res.success {
                return Ok(());
            }
            if pool.is_healthy() {
                return Err(res.stderr);
            }
        }
    }
    try_bundle_install(workdir)
}

fn try_bundle_install(workdir: &Path) -> Result<(), String> {
    let bundle = std::env::var("NYX_BUNDLE_BIN").unwrap_or_else(|_| "bundle".to_owned());
    if bundle_check(&bundle, workdir)? {
        return Ok(());
    }

    // No `bundle config set …` step: it is 2.x-only syntax that silently
    // no-ops on Bundler 1.x, which then installs to the root-owned system gem
    // dir and shells out to `sudo`.  `ruby_build_command` pins a writable
    // install target via env (GEM_HOME / BUNDLE_PATH) on every Bundler
    // version, and `--local` keeps the build offline so an absent gem fails
    // fast with a host-limitation error rather than reaching the network.
    let output = ruby_build_command(&bundle, workdir)
        .args(["install", "--local", "--jobs", "4", "--retry", "0"])
        .output()
        .map_err(|e| format!("bundle install: {e}"))?;
    if !output.status.success() {
        // Bundler's resolution error ("Could not find gem …") goes to stdout;
        // combine both streams so the host-limitation classifier sees it.
        return Err(combine_output(&output.stdout, &output.stderr));
    }
    Ok(())
}

fn bundle_check(bundle: &str, workdir: &Path) -> Result<bool, String> {
    let output = ruby_build_command(bundle, workdir)
        .arg("check")
        .output()
        .map_err(|e| format!("bundle check: {e}"))?;
    Ok(output.status.success())
}

/// Build a Bundler/RubyGems `Command` with a scrubbed environment plus the
/// hermetic gem env from [`ruby_hermetic_env`] (writable `GEM_HOME` /
/// `BUNDLE_PATH`).  This is the legacy direct-spawn sibling of
/// [`crate::dynamic::build_pool::ruby::RubyPool::bundle`]; both guarantee the
/// Ruby harness build never invokes `sudo` and never touches the network.
fn ruby_build_command(bundle: &str, workdir: &Path) -> Command {
    let mut cmd = Command::new(bundle);
    cmd.current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default());
    for (k, v) in ruby_hermetic_env(workdir) {
        cmd.env(k, v);
    }
    cmd
}

fn restore_cached_ruby_bundle(cache_path: &Path, workdir: &Path) {
    let cached_vendor = cache_path.join("vendor").join("bundle");
    if cached_vendor.exists() && !workdir.join("vendor").join("bundle").exists() {
        let _ = copy_dir_all(&cached_vendor, &workdir.join("vendor").join("bundle"));
    }
    let cached_bundle_config = cache_path.join(".bundle");
    if cached_bundle_config.exists() && !workdir.join(".bundle").exists() {
        let _ = copy_dir_all(&cached_bundle_config, &workdir.join(".bundle"));
    }
}

fn persist_ruby_bundle(workdir: &Path, cache_path: &Path) {
    let vendor = workdir.join("vendor").join("bundle");
    if vendor.exists() {
        let _ = copy_dir_all(&vendor, &cache_path.join("vendor").join("bundle"));
    }
    let bundle_config = workdir.join(".bundle");
    if bundle_config.exists() {
        let _ = copy_dir_all(&bundle_config, &cache_path.join(".bundle"));
    }
}

fn compute_ruby_lockfile_hash(workdir: &Path) -> String {
    let mut h = Hasher::new();
    for fname in &["Gemfile", "Gemfile.lock"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    let out = h.finalize();
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
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
            std::thread::sleep(std::time::Duration::from_secs(
                BACKOFF[attempt as usize - 1],
            ));
        }
        match npm_install(workdir) {
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

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

/// Route `npm install` through [`NodePool`] (shared npm download cache) when
/// enabled, else the legacy direct-spawn path.
fn npm_install(workdir: &Path) -> Result<(), String> {
    if is_pool_enabled("node") {
        if let Ok(pool) = NodePool::try_new() {
            let res = pool.compile_batch(workdir, &[]);
            if res.success {
                return Ok(());
            }
            if pool.is_healthy() {
                return Err(res.stderr);
            }
        }
    }
    try_npm_install(workdir)
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
    for fname in &[
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    let out = h.finalize();
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
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
            std::thread::sleep(std::time::Duration::from_secs(
                BACKOFF[attempt as usize - 1],
            ));
        }
        let _ = std::fs::remove_dir_all(&cache_path);
        std::fs::create_dir_all(&cache_path)?;

        match build_go_binary(workdir, &binary) {
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

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

/// Route the Go harness build through [`GoPool`] (shared `GOCACHE` /
/// `GOMODCACHE`, `-trimpath -buildvcs=false`) when enabled, else the legacy
/// per-workdir-cache path.
fn build_go_binary(workdir: &Path, binary_dest: &Path) -> Result<(), String> {
    if is_pool_enabled("go") {
        if let Ok(pool) = GoPool::try_new() {
            let pool_args = [binary_dest.to_string_lossy().into_owned()];
            let res = pool.compile_batch(workdir, &pool_args);
            if res.success {
                return Ok(());
            }
            if pool.is_healthy() {
                return Err(res.stderr);
            }
        }
    }
    try_build_go_binary(workdir, binary_dest)
}

fn try_build_go_binary(workdir: &Path, binary_dest: &Path) -> Result<(), String> {
    let go_bin = std::env::var("NYX_GO_BIN").unwrap_or_else(|_| "go".to_owned());
    let go_cache = std::env::var("GOCACHE")
        .unwrap_or_else(|_| workdir.join(".gocache").to_string_lossy().into_owned());
    std::fs::create_dir_all(&go_cache).map_err(|e| format!("create GOCACHE: {e}"))?;
    let go_path = std::env::var("GOPATH").unwrap_or_else(|_| {
        std::env::var("HOME")
            .map(|h| format!("{h}/go"))
            .unwrap_or_else(|_| "/tmp/go".to_owned())
    });
    let go_mod_cache = std::env::var("GOMODCACHE").unwrap_or_else(|_| format!("{go_path}/pkg/mod"));

    if workdir.join("go.mod").exists() {
        let output = Command::new(&go_bin)
            .args(["mod", "tidy"])
            .current_dir(workdir)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("GOCACHE", &go_cache)
            .env("GOPATH", &go_path)
            .env("GOMODCACHE", &go_mod_cache)
            .output()
            .map_err(|e| format!("go mod tidy: {e}"))?;

        if !output.status.success() {
            let mut msg = String::from_utf8_lossy(&output.stderr).into_owned();
            if msg.is_empty() {
                msg = String::from_utf8_lossy(&output.stdout).into_owned();
            }
            return Err(format!("go mod tidy failed: {msg}"));
        }
    }

    let output = Command::new(&go_bin)
        .args([
            "build",
            "-o",
            binary_dest.to_str().unwrap_or("nyx_harness"),
            ".",
        ])
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("GOCACHE", go_cache)
        .env("GOPATH", go_path)
        .env("GOMODCACHE", go_mod_cache)
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
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
}

// ── Java build sandbox ────────────────────────────────────────────────────────

/// Process-wide registry of warm `javac` daemons, keyed on
/// `spec.toolchain_id` (`"java-17"`, `"java-21"`, …).
///
/// One pool per toolchain id is the right shard: different `--release`
/// targets land in different cache slots upstream, and the worker JVM
/// itself binds to a single `javac` install at spawn time.  Cache hits
/// are O(1) lookup; cache misses pay the bootstrap cost (compile +
/// spawn the worker JVM) exactly once per toolchain id per process.
///
/// `OnceLock<Mutex<HashMap<…>>>` rather than a parameterised
/// `OnceLock` because the toolchain id is only known at request time.
fn javac_pool_registry() -> &'static Mutex<HashMap<String, Option<Arc<JavacPool>>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Option<Arc<JavacPool>>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up (or lazily spawn) a `javac` daemon for `toolchain_id`.
///
/// Returns `None` when the bootstrap fails -- the caller is expected
/// to fall back to the direct-spawn legacy path.
fn javac_pool_for(toolchain_id: &str) -> Option<Arc<JavacPool>> {
    let reg = javac_pool_registry();
    let mut guard = reg.lock().ok()?;
    if let Some(slot) = guard.get(toolchain_id) {
        return slot.clone();
    }
    let pool = JavacPool::try_new(toolchain_id).ok().map(Arc::new);
    guard.insert(toolchain_id.to_owned(), pool.clone());
    pool
}

/// Drop the cached `javac` daemon for `toolchain_id` so the next
/// lookup re-spawns it.  Called after the dispatcher observes the
/// worker has crashed mid-request.
fn drop_javac_pool(toolchain_id: &str) {
    if let Ok(mut guard) = javac_pool_registry().lock() {
        guard.remove(toolchain_id);
    }
}

/// Prepare compiled Java classes for `spec`.
///
/// Runs `javac` over every `*.java` file in `workdir` (recursive).  Phase 14
/// shape-aware fixtures may stage additional source files alongside the
/// generated `NyxHarness.java` (annotation stubs, servlet-request stubs,
/// helper classes); the compiler must see all of them in a single
/// invocation so the inter-class references resolve.
///
/// Class files land in the workdir (default package, no output dir).
///
/// Build isolation is NOT yet implemented (deferred). `javac` runs on the host.
/// A malicious annotation processor / compile-time plugin could run with host
/// privileges. See deferred.md for planned `nyx-build-java:{toolchain_id}` container.
pub fn prepare_java(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
    // The source-hash includes the target release so the cache slot does
    // not bleed compiled artefacts across release-version changes: a
    // workdir compiled against `--release 17` is a different cache slot
    // from the same sources targeted at `--release 21`.
    let target_release = java_target_release(&spec.toolchain_id);
    let source_hash = compute_java_source_hash(workdir, target_release);
    let cache_path = build_cache_path(&source_hash, "java", &spec.toolchain_id).ok();

    if let Some(cache_path) = &cache_path {
        let cached_classes = collect_class_files(cache_path);

        // Cache hit: at least the harness class is compiled.  Restore every
        // cached `.class` to workdir so the classpath (which points to
        // workdir, not cache_path) can find them when a different finding
        // hits the same compiled artefact via a fresh spec_hash.
        if cache_path.join("NyxHarness.class").exists() {
            for cls in &cached_classes {
                let src = cache_path.join(cls);
                let dst = workdir.join(cls);
                if src.exists() && !dst.exists() {
                    let _ = std::fs::copy(&src, &dst);
                }
            }
            // Restore cached Maven-resolved jars when the harness shipped a
            // `pom.xml`; the harness command embeds `-cp .:lib/*` so the
            // runtime classpath needs these jars staged in the workdir.
            let cached_lib = cache_path.join("lib");
            let workdir_lib = workdir.join("lib");
            if cached_lib.exists() && !workdir_lib.exists() {
                let _ = copy_dir_all(&cached_lib, &workdir_lib);
            }
            return Ok(BuildResult {
                venv_path: cache_path.clone(),
                cache_hit: true,
                duration: std::time::Duration::ZERO,
            });
        }
    }

    let start = std::time::Instant::now();
    const MAX_ATTEMPTS: u32 = 2;
    const BACKOFF: [u64; 2] = [1, 4];
    let mut last_err = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(
                BACKOFF[attempt as usize - 1],
            ));
        }
        let compile_cache = cache_path.as_deref().unwrap_or(workdir);
        match try_compile_java_with_toolchain(
            workdir,
            compile_cache,
            target_release,
            &spec.toolchain_id,
        ) {
            Ok(()) => {
                let build_root = cache_path.clone().unwrap_or_else(|| workdir.to_path_buf());
                return Ok(BuildResult {
                    venv_path: build_root,
                    cache_hit: false,
                    duration: start.elapsed(),
                });
            }
            Err(e) => {
                last_err = e;
                // Best-effort clean-up: drop every cached `.class` so the
                // next attempt re-compiles from source.
                if let Some(cache_path) = &cache_path
                    && let Ok(entries) = std::fs::read_dir(cache_path)
                {
                    for entry in entries.flatten() {
                        if entry
                            .path()
                            .extension()
                            .map(|e| e == "class")
                            .unwrap_or(false)
                        {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

/// Parse the bytecode target release from a `java-NN` toolchain id.
///
/// The docker backend routes Java harnesses to `eclipse-temurin:<ver>-jre-jammy`
/// (see `java_image_for_toolchain` in `sandbox/mod.rs`), so a host running a
/// newer JDK (macOS dev box at Java 25) emits classfile major version 69
/// that the container's older JRE (Java 21, supports up to major 65) refuses
/// with `UnsupportedClassVersionError`.  Pinning `--release NN` makes the
/// host javac emit a classfile version the container's JRE accepts.
///
/// Returns `None` when the toolchain id is not the expected `java-NN` shape
/// or NN is outside the supported `javac --release` range (`javac` requires
/// the target to be at least the current `--release --help` minimum, and
/// modern JDKs accept 7..=current).  Falls back to no `--release` flag,
/// preserving the legacy "trust the host javac default" behaviour for
/// non-docker invocations.
fn java_target_release(toolchain_id: &str) -> Option<u32> {
    let ver = toolchain_id.strip_prefix("java-")?;
    let parsed: u32 = ver.parse().ok()?;
    // javac `--release` rejects out-of-range targets; constrain to a
    // window we know the CI host(s) accept.
    if (7..=64).contains(&parsed) {
        Some(parsed)
    } else {
        None
    }
}

/// Compile every `.java` under `workdir`.
///
/// `toolchain_id` is threaded down so the pool path (when enabled) can
/// shard its cached [`JavacPool`] handles by JDK version: `"java-17"`
/// and `"java-21"` get separate worker JVMs.
fn try_compile_java_with_toolchain(
    workdir: &Path,
    cache_path: &Path,
    target_release: Option<u32>,
    toolchain_id: &str,
) -> Result<(), String> {
    // If the harness emitter shipped a `pom.xml`, stage Maven-resolved
    // jars under `workdir/lib` so javac (and the runtime classpath
    // baked into the harness command) can resolve framework imports
    // like `org.thymeleaf.*`.
    let lib_on_cp = workdir.join("pom.xml").exists() && {
        fetch_maven_deps(workdir)?;
        workdir.join("lib").exists()
    };

    let sources = collect_java_sources(workdir);
    if sources.is_empty() {
        return Err("no Java sources found in workdir".to_owned());
    }

    // Compile sources — class files are written to workdir by default.
    let mut args = vec!["-d".to_owned(), workdir.to_string_lossy().into_owned()];
    if let Some(rel) = target_release {
        args.push("--release".to_owned());
        args.push(rel.to_string());
    }
    if lib_on_cp {
        args.push("-cp".to_owned());
        args.push(".:lib/*".to_owned());
    }
    for src in &sources {
        args.push(src.to_string_lossy().into_owned());
    }

    // Route through the warm `javac` daemon when the pool is enabled
    // and a worker can be brought up.  Bootstrap failures fall back to
    // the direct-spawn legacy path so an operator with a broken JDK
    // install still gets a deterministic build error from `javac`
    // itself rather than from the pool wrapper.
    if is_pool_enabled("java") {
        if let Some(pool) = javac_pool_for(toolchain_id) {
            let result = pool.compile_batch(workdir, &args);
            if result.success {
                return finalize_java_compile(workdir, cache_path, lib_on_cp);
            }
            if pool.is_healthy() {
                // The compile itself failed (real source error) -- surface
                // the worker's stderr verbatim.
                return Err(result.stderr);
            }
            // Worker crashed: drop the cached pool so the next call
            // re-spawns it, then fall through to the legacy direct-spawn
            // path so this build still has a chance to succeed.
            drop_javac_pool(toolchain_id);
        }
    }

    let javac = std::env::var("NYX_JAVAC_BIN").unwrap_or_else(|_| "javac".to_owned());
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

    finalize_java_compile(workdir, cache_path, lib_on_cp)
}

/// Shared post-compile step: copy class files (and any Maven `lib/`)
/// from the workdir into the cache slot so the next cache-hit restore
/// can rebuild the harness layout without recompiling.
fn finalize_java_compile(workdir: &Path, cache_path: &Path, lib_on_cp: bool) -> Result<(), String> {
    if cache_path != workdir {
        // Copy class files to cache.  `javac -d workdir` writes nested
        // package directories under workdir; preserve the relative layout
        // when caching so the restore path can recreate them.
        for cls in collect_class_files(workdir) {
            let src = workdir.join(&cls);
            let dst = cache_path.join(&cls);
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if src.exists() {
                let _ = std::fs::copy(&src, &dst);
            }
        }
        // Persist Maven-resolved jars alongside the class cache so cache-hit
        // restores can rebuild the `lib/` classpath without re-running mvn.
        if lib_on_cp {
            let lib_src = workdir.join("lib");
            if lib_src.exists() {
                let _ = copy_dir_all(&lib_src, &cache_path.join("lib"));
            }
        }
    }
    Ok(())
}

/// Resolve the `pom.xml` declared dependencies into `workdir/lib`.
///
/// Runs `mvn dependency:copy-dependencies` on the host with test scope
/// included. Framework harnesses often need test-only clients such as
/// MockMvc even when the entry itself is runtime-scoped. Honors
/// `NYX_MAVEN_BIN` so CI hosts with a pinned Maven install can override
/// the binary lookup.
///
/// Returns `Err` with the Maven output on failure so the harness
/// build path can surface it as `BuildFailed` upstream.
fn fetch_maven_deps(workdir: &Path) -> Result<(), String> {
    let mvn = std::env::var("NYX_MAVEN_BIN").unwrap_or_else(|_| "mvn".to_owned());
    let output = Command::new(&mvn)
        .args(maven_copy_dependency_args())
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .output()
        .map_err(|e| format!("mvn dependency:copy-dependencies: {e}"))?;

    if !output.status.success() {
        let mut msg = String::from_utf8_lossy(&output.stderr).into_owned();
        if msg.is_empty() {
            msg = String::from_utf8_lossy(&output.stdout).into_owned();
        }
        return Err(format!("mvn dependency:copy-dependencies failed: {msg}"));
    }
    Ok(())
}

fn maven_copy_dependency_args() -> [&'static str; 5] {
    [
        "-q",
        "-B",
        "dependency:copy-dependencies",
        "-DoutputDirectory=lib",
        "-DincludeScope=test",
    ]
}

/// Recursively enumerate every `*.java` source file under `workdir`.
fn collect_java_sources(workdir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![workdir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().map(|e| e == "java").unwrap_or(false) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Recursively enumerate every `*.class` file relative to `root`.
fn collect_class_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().map(|e| e == "class").unwrap_or(false)
                && let Ok(rel) = path.strip_prefix(root)
            {
                out.push(rel.to_path_buf());
            }
        }
    }
    out.sort();
    out
}

fn compute_java_source_hash(workdir: &Path, target_release: Option<u32>) -> String {
    let mut h = Hasher::new();
    for path in collect_java_sources(workdir) {
        if let Ok(content) = std::fs::read(&path) {
            let rel = path.strip_prefix(workdir).unwrap_or(&path);
            h.update(rel.to_string_lossy().as_bytes());
            h.update(&content);
        }
    }
    // Fold the harness `pom.xml` into the hash so a manifest edit (a
    // new dep, a version bump) busts the build cache and re-runs
    // `mvn dependency:copy-dependencies` on the next build.
    if let Ok(pom) = std::fs::read(workdir.join("pom.xml")) {
        h.update(b":pom=");
        h.update(&pom);
    }
    // Fold the target release into the hash so a workdir compiled at
    // `--release 17` cannot collide with the same workdir at `--release 21`.
    if let Some(rel) = target_release {
        h.update(b":release=");
        h.update(rel.to_le_bytes().as_slice());
    } else {
        h.update(b":release=host");
    }
    let out = h.finalize();
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
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
            std::thread::sleep(std::time::Duration::from_secs(
                BACKOFF[attempt as usize - 1],
            ));
        }
        match composer_install(workdir) {
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

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

/// Route Composer through [`PhpPool`] (shared download cache + opcache
/// file-cache warm) when enabled, else the legacy direct-spawn path.
fn composer_install(workdir: &Path) -> Result<(), String> {
    if is_pool_enabled("php") {
        if let Ok(pool) = PhpPool::try_new() {
            let res = pool.compile_batch(workdir, &[]);
            if res.success {
                return Ok(());
            }
            if pool.is_healthy() {
                return Err(res.stderr);
            }
        }
    }
    try_composer_install(workdir)
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
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
}

// ── C build sandbox ───────────────────────────────────────────────────────────

/// Prepare a compiled C binary for `spec`.
///
/// Checks a build cache keyed on `(main.c + entry.c hash, "c", toolchain_id)`.
/// On a cache hit returns immediately; otherwise runs
/// `cc -O0 -g -o nyx_harness main.c` in `workdir`.
///
/// Build isolation is NOT yet implemented (deferred). `cc` runs on the host.
pub fn prepare_c(
    spec: &HarnessSpec,
    workdir: &Path,
    profile: ProcessHardeningProfile,
) -> Result<BuildResult, BuildError> {
    let static_link = static_link_for_profile(profile);
    let source_hash = compute_c_source_hash(workdir, static_link);
    let cache_path = build_cache_path(&source_hash, "c", &spec.toolchain_id)?;

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
            std::thread::sleep(std::time::Duration::from_secs(
                BACKOFF[attempt as usize - 1],
            ));
        }
        let _ = std::fs::remove_dir_all(&cache_path);
        std::fs::create_dir_all(&cache_path)?;

        match build_c_binary(workdir, &binary, static_link) {
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

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

/// Route the C harness build through [`CPool`] (`ccache` + shared object
/// cache) when enabled, else the legacy direct-spawn `cc` path.  The
/// static-link toggle is forwarded so the pool can reproduce the
/// Strict-profile `-static` fallback.
fn build_c_binary(workdir: &Path, binary_dest: &Path, static_link: bool) -> Result<(), String> {
    if is_pool_enabled("c") {
        if let Ok(pool) = CPool::try_new() {
            let pool_args = [
                binary_dest.to_string_lossy().into_owned(),
                if static_link { "static" } else { "dynamic" }.to_owned(),
            ];
            let res = pool.compile_batch(workdir, &pool_args);
            if res.success {
                return Ok(());
            }
            if pool.is_healthy() {
                return Err(res.stderr);
            }
        }
    }
    try_build_c_binary(workdir, binary_dest, static_link)
}

fn try_build_c_binary(workdir: &Path, binary_dest: &Path, static_link: bool) -> Result<(), String> {
    let cc_bin = std::env::var("NYX_CC_BIN").unwrap_or_else(|_| "cc".to_owned());

    // When the Linux Strict-profile path requests it (or an operator sets
    // `NYX_BUILD_STATIC=1`), try `cc -static` first so the harness survives
    // `chroot(workdir)`.  Fall back to the dynamic link if static fails —
    // the host may lack `libc.a` (musl-cross or `libc6-dev` are the usual
    // sources) and a dynamic-linked binary still works for non-chroot runs.
    // The fallback is announced via `NYX_BUILD_STATIC_FALLBACK=1` so
    // downstream chroot-acceptance tests can skip the leg they need static
    // linking for instead of asserting against a broken harness.
    if static_link {
        match run_cc(&cc_bin, workdir, binary_dest, &["-static", "-O0", "-g"]) {
            Ok(()) => return Ok(()),
            Err(stderr) => {
                unsafe { std::env::set_var("NYX_BUILD_STATIC_FALLBACK", "1") };
                eprintln!("nyx: cc -static failed, retrying without -static: {stderr}");
                let _ = std::fs::remove_file(binary_dest);
            }
        }
    }

    run_cc(&cc_bin, workdir, binary_dest, &["-O0", "-g"])
}

/// Decide whether the C harness should be linked with `-static`.
///
/// Returns `true` when the caller's hardening profile is
/// [`ProcessHardeningProfile::Strict`] — chroot to the workdir hides the
/// host's `/lib`/`/lib64` from the dynamic loader, so a dynamic-linked
/// binary aborts before `main()`.  Operators can also force the static
/// path on a `Standard` run via `NYX_BUILD_STATIC=1` (or `=true`) without
/// flipping the wider hardening profile.
pub(crate) fn static_link_for_profile(profile: ProcessHardeningProfile) -> bool {
    if profile == ProcessHardeningProfile::Strict {
        return true;
    }
    static_link_env_override()
}

/// Manual operator override read from `NYX_BUILD_STATIC`.  Lives separately
/// from [`static_link_for_profile`] so the env-var contract stays testable
/// without standing up a full `ProcessHardeningProfile` plumb.
pub(crate) fn static_link_env_override() -> bool {
    matches!(
        std::env::var("NYX_BUILD_STATIC").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn run_cc(
    cc_bin: &str,
    workdir: &Path,
    binary_dest: &Path,
    leading_flags: &[&str],
) -> Result<(), String> {
    let binary_str = binary_dest.to_str().unwrap_or("nyx_harness");
    let mut args: Vec<&str> = leading_flags.to_vec();
    args.extend(["-o", binary_str, "main.c"]);

    let output = Command::new(cc_bin)
        .args(&args)
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .output()
        .map_err(|e| format!("cc: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(())
}

fn compute_c_source_hash(workdir: &Path, static_link: bool) -> String {
    let mut h = Hasher::new();
    for fname in &["main.c", "entry.c", "Makefile"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    // Fold the static-link toggle into the cache key so a single workdir
    // can produce both a static and a dynamic binary without one shadowing
    // the other in the cache (`prepare_c` keys on this hash).
    if static_link {
        h.update(b"static");
    }
    let out = h.finalize();
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
}

// ── C++ build sandbox ─────────────────────────────────────────────────────────

/// Prepare a compiled C++ binary for `spec`.
pub fn prepare_cpp(spec: &HarnessSpec, workdir: &Path) -> Result<BuildResult, BuildError> {
    let source_hash = compute_cpp_source_hash(workdir);
    let cache_path = build_cache_path(&source_hash, "cpp", &spec.toolchain_id)?;

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
            std::thread::sleep(std::time::Duration::from_secs(
                BACKOFF[attempt as usize - 1],
            ));
        }
        let _ = std::fs::remove_dir_all(&cache_path);
        std::fs::create_dir_all(&cache_path)?;

        match build_cpp_binary(workdir, &binary) {
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

    Err(BuildError::BuildFailed {
        stderr: last_err,
        attempts: MAX_ATTEMPTS,
    })
}

/// Route the C++ harness build through [`CppPool`] (`ccache` + shared object
/// cache) when enabled, else the legacy direct-spawn `c++` path.
fn build_cpp_binary(workdir: &Path, binary_dest: &Path) -> Result<(), String> {
    if is_pool_enabled("cpp") {
        if let Ok(pool) = CppPool::try_new() {
            let pool_args = [binary_dest.to_string_lossy().into_owned()];
            let res = pool.compile_batch(workdir, &pool_args);
            if res.success {
                return Ok(());
            }
            if pool.is_healthy() {
                return Err(res.stderr);
            }
        }
    }
    try_build_cpp_binary(workdir, binary_dest)
}

fn try_build_cpp_binary(workdir: &Path, binary_dest: &Path) -> Result<(), String> {
    let cxx_bin = std::env::var("NYX_CXX_BIN").unwrap_or_else(|_| {
        // Prefer c++ which resolves to the system default compiler driver.
        "c++".to_owned()
    });
    let output = Command::new(&cxx_bin)
        .args([
            "-O0",
            "-g",
            "-std=c++17",
            "-o",
            binary_dest.to_str().unwrap_or("nyx_harness"),
            "main.cpp",
        ])
        .current_dir(workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .output()
        .map_err(|e| format!("c++: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(())
}

fn compute_cpp_source_hash(workdir: &Path) -> String {
    let mut h = Hasher::new();
    for fname in &["main.cpp", "entry.cpp", "CMakeLists.txt"] {
        if let Ok(content) = std::fs::read(workdir.join(fname)) {
            h.update(fname.as_bytes());
            h.update(&content);
        }
    }
    let out = h.finalize();
    format!(
        "{:016x}",
        u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap())
    )
}

// ── Uniform per-language build dispatch (Phase 26 — composite chains) ────────

/// Per-step build outcome surfaced by [`dispatch_prepare`].
///
/// Collapses the per-language [`BuildResult`] into a uniform shape the
/// composite-chain reverifier can fold across steps regardless of the
/// underlying toolchain: a hit/miss bit, wall-clock duration, the cache
/// root, and the source language so callers can report mixed-toolchain
/// cost coverage.
#[derive(Debug, Clone)]
pub struct ChainStepBuildResult {
    /// Source language of the step that was built.
    pub lang: Lang,
    /// True when the prepare step short-circuited via the per-language
    /// cache (zero wall-clock build cost).
    pub cache_hit: bool,
    /// Wall-clock time spent in the build tool.  Zero on cache hit.
    pub duration: Duration,
    /// Cache root the build emitted into.  Maps to `BuildResult::venv_path`
    /// for every per-language `prepare_*` — for compiled languages this
    /// is the directory holding `nyx_harness`; for Python it is the venv
    /// root; for Node/PHP it carries `node_modules`/`vendor`.
    pub build_root: PathBuf,
}

/// Dispatch one chain step's build to the matching per-language
/// `prepare_*` function and return a uniform [`ChainStepBuildResult`].
///
/// Used by composite-chain re-verification ([`crate::chain::reverify`])
/// so a `Vec<HarnessSpec>` can be driven through the build pipeline
/// without per-language match arms scattered across each caller.  The
/// production single-finding runner stays on the per-language match in
/// [`crate::dynamic::runner::execute`] because it folds the build result
/// into command-vector rewrites that vary per language and have no
/// uniform shape — the chain reverifier does not need those rewrites
/// because the sandbox-run sub-task ((c) of Phase 26 follow-up) will
/// build its own per-step command vector.
///
/// `profile` is consulted only on [`Lang::C`] (drives `-static`); the
/// other per-language preparers ignore it.
pub fn dispatch_prepare(
    spec: &HarnessSpec,
    workdir: &Path,
    profile: ProcessHardeningProfile,
) -> Result<ChainStepBuildResult, BuildError> {
    let lang = spec.lang;
    let build = match lang {
        Lang::Rust => prepare_rust(spec, workdir)?,
        Lang::Python => prepare_python(spec, workdir)?,
        Lang::JavaScript | Lang::TypeScript => prepare_node(spec, workdir)?,
        Lang::Go => prepare_go(spec, workdir)?,
        Lang::Java => prepare_java(spec, workdir)?,
        Lang::Php => prepare_php(spec, workdir)?,
        Lang::Ruby => prepare_ruby(spec, workdir)?,
        Lang::C => prepare_c(spec, workdir, profile)?,
        Lang::Cpp => prepare_cpp(spec, workdir)?,
    };
    Ok(ChainStepBuildResult {
        lang,
        cache_hit: build.cache_hit,
        duration: build.duration,
        build_root: build.venv_path,
    })
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
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges:true",
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
            .args(["rm", "-f", &self.name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Run `cargo build --release` inside a Docker container.
///
/// Provides filesystem isolation: no host mounts, only a copied workdir.
/// Network is left available so manifest-backed framework fixtures can fetch
/// crates before the sandboxed runtime executes the harness.
///
/// Returns `Ok(())` when the container started and `cargo build` was invoked
/// (build success/failure inside the container is not checked). Returns
/// `Err(msg)` when Docker is unreachable or `rust:slim` cannot be started.
pub fn prepare_rust_in_docker(workdir: &Path) -> Result<(), String> {
    let docker = docker_bin_for_build();
    let container = build_container_id("rustbuild", workdir);

    if !start_isolated_build_container(&docker, &container, "rust:slim", false) {
        return Err("failed to start rust:slim build container; image may not be available".into());
    }

    let _guard = BuildContainerGuard {
        docker: docker.clone(),
        name: container.clone(),
    };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    let _ = std::process::Command::new(&docker)
        .args(["exec", &container, "sh", "-c", rust_docker_build_script()])
        .output();

    Ok(())
}

fn rust_docker_build_script() -> &'static str {
    "cd /build && cargo fetch && cargo build --release 2>&1"
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
        return Err(
            "failed to start node:20-slim build container; image may not be available".into(),
        );
    }

    let _guard = BuildContainerGuard {
        docker: docker.clone(),
        name: container.clone(),
    };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    // npm install may fail if the registry is unreachable (--network none), but the
    // preinstall hook runs before any network calls, so the escape attempt executes.
    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            &container,
            "sh",
            "-c",
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

    if !start_isolated_build_container(&docker, &container, "golang:1.21-slim", false) {
        return Err(
            "failed to start golang:1.21-slim build container; image may not be available".into(),
        );
    }

    let _guard = BuildContainerGuard {
        docker: docker.clone(),
        name: container.clone(),
    };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            "-e",
            "GONOSUMDB=*",
            &container,
            "sh",
            "-c",
            go_docker_build_script(),
        ])
        .output();

    Ok(())
}

fn go_docker_build_script() -> &'static str {
    "cd /build && if [ -f go.mod ]; then go mod download; fi && go build ./... 2>&1"
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
    if !start_isolated_build_container(&docker, &container, "maven:3.9-eclipse-temurin-21", false) {
        return Err(
            "failed to start maven:3.9-eclipse-temurin-21 build container; image may not be available"
                .into(),
        );
    }

    let _guard = BuildContainerGuard {
        docker: docker.clone(),
        name: container.clone(),
    };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            &container,
            "sh",
            "-c",
            "cd /build && mvn --no-transfer-progress validate 2>&1",
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
        return Err(
            "failed to start composer:2 build container; image may not be available".into(),
        );
    }

    let _guard = BuildContainerGuard {
        docker: docker.clone(),
        name: container.clone(),
    };
    copy_workdir_to_build_container(&docker, workdir, &container, "/build");

    // Empty require{} means no packages to fetch; post-install-cmd still fires.
    let _ = std::process::Command::new(&docker)
        .args([
            "exec",
            &container,
            "sh",
            "-c",
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
    fn go_docker_build_script_downloads_modules_when_manifest_exists() {
        let script = go_docker_build_script();
        assert!(script.contains("if [ -f go.mod ]; then go mod download; fi"));
        assert!(script.contains("go build ./..."));
        assert!(!script.contains("GOPROXY=off"));
    }

    #[test]
    fn rust_docker_build_script_fetches_crates() {
        let script = rust_docker_build_script();
        assert!(script.contains("cargo fetch"));
        assert!(script.contains("cargo build --release"));
        assert!(!script.contains("CARGO_NET_OFFLINE"));
    }

    #[test]
    fn java_source_hash_stable() {
        let dir = tempfile::TempDir::new().unwrap();
        let h1 = compute_java_source_hash(dir.path(), None);
        let h2 = compute_java_source_hash(dir.path(), None);
        assert_eq!(h1, h2);
    }

    #[test]
    fn java_source_hash_differs_across_target_release() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("Vuln.java"), "public class Vuln {}\n").unwrap();
        let h_none = compute_java_source_hash(dir.path(), None);
        let h17 = compute_java_source_hash(dir.path(), Some(17));
        let h21 = compute_java_source_hash(dir.path(), Some(21));
        assert_ne!(h_none, h17);
        assert_ne!(h17, h21);
        assert_ne!(h_none, h21);
    }

    #[test]
    fn java_target_release_parses_toolchain_id() {
        assert_eq!(java_target_release("java-17"), Some(17));
        assert_eq!(java_target_release("java-21"), Some(21));
        assert_eq!(java_target_release("java-8"), Some(8));
    }

    #[test]
    fn java_target_release_rejects_non_java_toolchain() {
        assert_eq!(java_target_release("python-3.11"), None);
        assert_eq!(java_target_release("node-20"), None);
        assert_eq!(java_target_release(""), None);
    }

    #[test]
    fn java_target_release_rejects_out_of_range() {
        // javac --release supports [7, current] today; values outside the
        // conservative window fall back to no flag rather than emit a
        // broken javac invocation.
        assert_eq!(java_target_release("java-6"), None);
        assert_eq!(java_target_release("java-999"), None);
        assert_eq!(java_target_release("java-abc"), None);
    }

    #[test]
    fn maven_dependency_copy_includes_test_scope() {
        let args = maven_copy_dependency_args();
        assert!(args.contains(&"-DincludeScope=test"));
        assert!(!args.contains(&"-DincludeScope=runtime"));
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
        assert_eq!(
            std::fs::read(dst.path().join("sub").join("b.txt")).unwrap(),
            b"world"
        );
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

    // ── NYX_BUILD_STATIC opt-in (Phase 17 follow-up) ────────────────────────
    //
    // These tests live in a serialised submodule so env-var mutation does
    // not race with other parallel tests that read `NYX_BUILD_STATIC`.

    mod static_link {
        use super::*;
        use std::sync::Mutex;

        // Coarse lock: tests in this submodule mutate process env
        // (`NYX_BUILD_STATIC`, and for dispatch tests `NYX_BUILD_CACHE`),
        // so they have to take turns.
        static ENV_LOCK: Mutex<()> = Mutex::new(());

        struct EnvGuard {
            prior: Option<String>,
        }

        impl EnvGuard {
            fn set(value: Option<&str>) -> Self {
                let prior = std::env::var("NYX_BUILD_STATIC").ok();
                match value {
                    Some(v) => unsafe { std::env::set_var("NYX_BUILD_STATIC", v) },
                    None => unsafe { std::env::remove_var("NYX_BUILD_STATIC") },
                }
                Self { prior }
            }
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match self.prior.take() {
                    Some(v) => unsafe { std::env::set_var("NYX_BUILD_STATIC", v) },
                    None => unsafe { std::env::remove_var("NYX_BUILD_STATIC") },
                }
            }
        }

        struct BuildCacheGuard {
            prior: Option<String>,
            _dir: tempfile::TempDir,
        }

        impl BuildCacheGuard {
            fn isolated() -> Self {
                let dir = tempfile::TempDir::new().unwrap();
                let prior = std::env::var("NYX_BUILD_CACHE").ok();
                unsafe { std::env::set_var("NYX_BUILD_CACHE", dir.path()) };
                Self { prior, _dir: dir }
            }
        }

        impl Drop for BuildCacheGuard {
            fn drop(&mut self) {
                match self.prior.take() {
                    Some(v) => unsafe { std::env::set_var("NYX_BUILD_CACHE", v) },
                    None => unsafe { std::env::remove_var("NYX_BUILD_CACHE") },
                }
            }
        }

        #[test]
        fn unset_env_means_dynamic_link() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _g = EnvGuard::set(None);
            assert!(!static_link_env_override());
            assert!(!static_link_for_profile(ProcessHardeningProfile::Standard));
        }

        #[test]
        fn truthy_env_requests_static_link() {
            let _lock = ENV_LOCK.lock().unwrap();
            let _g = EnvGuard::set(Some("1"));
            assert!(static_link_env_override());
            assert!(static_link_for_profile(ProcessHardeningProfile::Standard));

            let _g2 = EnvGuard::set(Some("true"));
            assert!(static_link_env_override());
        }

        #[test]
        fn other_values_do_not_request_static_link() {
            let _lock = ENV_LOCK.lock().unwrap();
            for value in &["0", "false", "yes", "static", ""] {
                let _g = EnvGuard::set(Some(value));
                assert!(
                    !static_link_env_override(),
                    "value {value:?} must not request static link",
                );
                assert!(
                    !static_link_for_profile(ProcessHardeningProfile::Standard),
                    "value {value:?} must not request static link via Standard profile",
                );
            }
        }

        #[test]
        fn strict_profile_forces_static_link() {
            let _lock = ENV_LOCK.lock().unwrap();
            // Even with the env var absent, Strict must pick the static
            // leg so chroot(workdir) does not strand the dynamic loader.
            let _g = EnvGuard::set(None);
            assert!(static_link_for_profile(ProcessHardeningProfile::Strict));

            // Env var off should not flip Strict back to dynamic.
            let _g2 = EnvGuard::set(Some("0"));
            assert!(static_link_for_profile(ProcessHardeningProfile::Strict));
        }

        #[test]
        fn source_hash_includes_static_marker() {
            let _lock = ENV_LOCK.lock().unwrap();
            let dir = tempfile::TempDir::new().unwrap();
            std::fs::write(dir.path().join("main.c"), "int main(){return 0;}").unwrap();

            let dyn_hash = compute_c_source_hash(dir.path(), false);
            let static_hash = compute_c_source_hash(dir.path(), true);

            assert_ne!(
                dyn_hash, static_hash,
                "static and dynamic builds must key into different cache slots",
            );
        }

        // ── Phase 26 sub-task (b): dispatch_prepare helper ─────────────────

        fn mk_spec(lang: Lang, toolchain_suffix: &str) -> HarnessSpec {
            use crate::dynamic::spec::{EntryKind, PayloadSlot, SpecDerivationStrategy};
            use crate::labels::Cap;
            HarnessSpec {
                finding_id: "test".to_owned(),
                entry_file: "entry".to_owned(),
                entry_name: "main".to_owned(),
                entry_kind: EntryKind::Function,
                lang,
                // Unique per test so the per-language `prepare_*` cache root
                // (keyed on `toolchain_id`) does not bleed state between
                // tests in this submodule — `prepare_node` writes a
                // `.node_cache_done` marker that turns subsequent calls into
                // cache hits, which a test asserting "first call is a miss"
                // would fail on.  The user-level cache at
                // `~/Library/Caches/nyx/dynamic/build-cache/{hash}-node-{tid}`
                // persists across cargo runs, so each test needs its own
                // suffix to stay deterministic.
                toolchain_id: format!("dispatch-prepare-test-{toolchain_suffix}"),
                payload_slot: PayloadSlot::Param(0),
                expected_cap: Cap::CODE_EXEC,
                constraint_hints: vec![],
                sink_file: "sink".to_owned(),
                sink_line: 1,
                spec_hash: "0000000000000000".to_owned(),
                derivation: SpecDerivationStrategy::FromFlowSteps,
                stubs_required: vec![],
                framework: None,
                java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
            }
        }

        /// Scrub the cache directory `prepare_node` would land in so a
        /// fresh-cache assertion stays deterministic across reruns.  The
        /// dispatch tests install an isolated `NYX_BUILD_CACHE`, so this
        /// only clears state from earlier calls inside the same test.
        fn purge_node_cache_for(spec: &HarnessSpec, workdir: &Path) {
            let lockfile_hash = compute_node_lockfile_hash(workdir);
            if let Ok(cache_path) = build_cache_path(&lockfile_hash, "node", &spec.toolchain_id) {
                let _ = std::fs::remove_dir_all(&cache_path);
            }
        }

        #[test]
        fn dispatch_prepare_ruby_routes_to_bundler_no_gemfile_path() {
            // Ruby now has the same dependency-prep leg as the other
            // interpreted framework harnesses.  With no Gemfile present,
            // prepare_ruby takes the cheap path and records an empty cache
            // entry without invoking Bundler.
            let _lock = ENV_LOCK.lock().unwrap();
            let _cache = BuildCacheGuard::isolated();
            let dir = tempfile::TempDir::new().unwrap();
            let spec = mk_spec(Lang::Ruby, "ruby-no-gemfile");
            let result = dispatch_prepare(&spec, dir.path(), ProcessHardeningProfile::Standard)
                .expect("Ruby dispatch must succeed on a workdir with no Gemfile");
            assert_eq!(result.lang, Lang::Ruby);
            assert!(!result.cache_hit);
            assert_eq!(result.duration, Duration::ZERO);
            assert!(result.build_root.exists());
        }

        #[test]
        fn dispatch_prepare_typescript_routes_to_node_no_package_json_path() {
            // JavaScript / TypeScript both dispatch to prepare_node.  The
            // cheap path (no package.json) short-circuits without invoking
            // `npm install`, so the helper produces a ChainStepBuildResult
            // with cache_hit=false + duration=0 + lang=TypeScript on first
            // call.  Use TypeScript to also lock in that the JS/TS arm
            // shares one dispatch leg.
            let _lock = ENV_LOCK.lock().unwrap();
            let _cache = BuildCacheGuard::isolated();
            let dir = tempfile::TempDir::new().unwrap();
            let spec = mk_spec(Lang::TypeScript, "ts-no-package-json");
            purge_node_cache_for(&spec, dir.path());

            let result = dispatch_prepare(&spec, dir.path(), ProcessHardeningProfile::Standard)
                .expect("TypeScript dispatch must succeed on a workdir with no package.json");
            assert_eq!(
                result.lang,
                Lang::TypeScript,
                "lang field must echo the spec's"
            );
            assert!(
                !result.cache_hit,
                "first dispatch on a fresh cache must be a cache miss; got {result:?}",
            );
            assert_eq!(
                result.duration,
                Duration::ZERO,
                "no-package-json path skips npm install so duration must be zero",
            );
            assert!(
                result.build_root.exists(),
                "build_root {:?} must exist (the cache dir prepare_node creates)",
                result.build_root,
            );
        }

        #[test]
        fn dispatch_prepare_javascript_and_typescript_share_dispatch_leg() {
            // Both JS and TS route to prepare_node so a back-to-back call
            // with the same toolchain_id + workdir contents must hit the
            // same cache.
            let _lock = ENV_LOCK.lock().unwrap();
            let _cache = BuildCacheGuard::isolated();
            let dir = tempfile::TempDir::new().unwrap();
            // Both specs share one toolchain suffix so they collide in
            // the same cache slot — the contract under test is that JS
            // and TS dispatch through the same leg.
            let js = mk_spec(Lang::JavaScript, "jsts-shared-leg");
            let ts = mk_spec(Lang::TypeScript, "jsts-shared-leg");
            purge_node_cache_for(&js, dir.path());

            let js_result = dispatch_prepare(&js, dir.path(), ProcessHardeningProfile::Standard)
                .expect("JavaScript dispatch ok");
            let ts_result = dispatch_prepare(&ts, dir.path(), ProcessHardeningProfile::Standard)
                .expect("TypeScript dispatch ok");
            assert_eq!(
                js_result.build_root, ts_result.build_root,
                "JS and TS must share the same cache root because both \
                 dispatch through prepare_node with the same toolchain_id",
            );
            assert!(
                ts_result.cache_hit,
                "second dispatch with identical workdir must hit the cache; got {ts_result:?}",
            );
        }

        #[test]
        fn strict_profile_and_standard_profile_produce_distinct_cache_keys() {
            let _lock = ENV_LOCK.lock().unwrap();
            let dir = tempfile::TempDir::new().unwrap();
            std::fs::write(dir.path().join("main.c"), "int main(){return 0;}").unwrap();

            // No env override; the static bit is derived from the profile.
            let _g = EnvGuard::set(None);
            let standard_hash = compute_c_source_hash(
                dir.path(),
                static_link_for_profile(ProcessHardeningProfile::Standard),
            );
            let strict_hash = compute_c_source_hash(
                dir.path(),
                static_link_for_profile(ProcessHardeningProfile::Strict),
            );

            assert_ne!(
                standard_hash, strict_hash,
                "Strict-profile builds must key into a different cache slot \
                 from Standard-profile builds so a chroot-bound static binary \
                 does not shadow the dynamic one (or vice versa)",
            );
        }
    }
}
