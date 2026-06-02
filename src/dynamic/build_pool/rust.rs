//! Rust build pool (Phase 23 / Track O.1).
//!
//! The legacy [`crate::dynamic::build_sandbox::prepare_rust`] runs a fresh
//! `cargo build --release` per finding with a per-workdir `target/`.  Every
//! harness therefore recompiles the (identical) harness scaffold and all of
//! its dependencies from cold.
//!
//! [`RustPool`] keeps two warm caches keyed on the `Cargo.lock` hash:
//! - a shared `CARGO_TARGET_DIR` so incremental artefacts survive across
//!   per-finding workdirs, and
//! - `sccache` as `RUSTC_WRAPPER` when it is on `PATH`, which caches the
//!   per-crate `rustc` invocations across *different* lock hashes too.
//!
//! Both degrade gracefully: a missing `sccache` simply drops the wrapper and
//! a fresh lock hash gets a fresh (empty) shared target dir.  The compile
//! itself is byte-for-byte the same `cargo build --release` the legacy path
//! runs, so success / failure parity holds.

use super::{BuildPool, PoolCompileResult, base_command, binary_runnable, pool_cache_dir};
use blake3::Hasher;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct RustPool {
    cargo_bin: String,
    /// `Some(path)` when an `sccache` binary is runnable.  Wired in as
    /// `RUSTC_WRAPPER`; `None` falls back to plain `rustc`.
    sccache_bin: Option<String>,
}

impl RustPool {
    pub fn try_new() -> Result<Self, String> {
        let cargo_bin = std::env::var("NYX_CARGO_BIN").unwrap_or_else(|_| "cargo".to_owned());
        if !binary_runnable(&cargo_bin, "--version") {
            return Err(format!("rust-pool: {cargo_bin} not runnable"));
        }
        let sccache_bin = detect_sccache();
        Ok(RustPool {
            cargo_bin,
            sccache_bin,
        })
    }
}

fn detect_sccache() -> Option<String> {
    let bin = std::env::var("NYX_SCCACHE_BIN").unwrap_or_else(|_| "sccache".to_owned());
    binary_runnable(&bin, "--version").then_some(bin)
}

impl BuildPool for RustPool {
    fn name(&self) -> &'static str {
        "rust"
    }

    /// `args[0]` = absolute path the compiled `nyx_harness` binary must land
    /// at (the caller's cache slot).
    fn compile_batch(&self, workdir: &Path, args: &[String]) -> PoolCompileResult {
        let start = Instant::now();
        let dest = match args.first() {
            Some(d) => Path::new(d),
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "rust-pool: missing binary destination arg".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };

        let lock_hash = hash_files(workdir, &["Cargo.lock", "Cargo.toml"]);
        let target_dir = match pool_cache_dir("rust", &lock_hash) {
            Some(d) => d,
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "rust-pool: no shared target dir".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };

        // Serialise build + copy across processes for this shared target dir.
        //
        // The target dir is keyed only on the Cargo manifest hash, so every
        // fixture that shares a `Cargo.toml` compiles the same bin name
        // (`nyx_harness`) into the same `release/nyx_harness` path here.
        // `cargo` already serialises the *build* across processes via its own
        // target lock, but releases that lock the moment it exits — before the
        // copy below moves `release/nyx_harness` to the caller's per-fixture
        // cache slot.  A second process's `cargo build` landing in that window
        // overwrites `release/nyx_harness`, so we copy a *different* fixture's
        // binary into our slot and poison its build cache (observed as
        // cross-fixture verdict corruption under a parallel `cargo test`).
        // Holding this lock across build+copy folds the copy into the existing
        // serialised section, so it adds the copy's few milliseconds, not a
        // new build barrier.
        let _build_lock = TargetDirLock::acquire(&target_dir);

        let mut cmd = base_command(&self.cargo_bin);
        cmd.args(["build", "--release"])
            .current_dir(workdir)
            .env(
                "CARGO_HOME",
                std::env::var("CARGO_HOME").unwrap_or_else(|_| default_cargo_home()),
            )
            .env(
                "RUSTUP_HOME",
                std::env::var("RUSTUP_HOME").unwrap_or_default(),
            )
            .env("CARGO_TARGET_DIR", &target_dir);
        if let Some(sccache) = &self.sccache_bin {
            cmd.env("RUSTC_WRAPPER", sccache);
        }

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                return PoolCompileResult {
                    success: false,
                    stderr: format!("rust-pool: cargo build: {e}"),
                    duration: start.elapsed(),
                };
            }
        };
        if !output.status.success() {
            return PoolCompileResult {
                success: false,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                duration: start.elapsed(),
            };
        }

        let compiled = target_dir.join("release").join("nyx_harness");
        if let Err(e) = std::fs::copy(&compiled, dest) {
            return PoolCompileResult {
                success: false,
                stderr: format!(
                    "rust-pool: cargo build ok but copy {} -> {} failed: {e}",
                    compiled.display(),
                    dest.display(),
                ),
                duration: start.elapsed(),
            };
        }
        PoolCompileResult {
            success: true,
            stderr: String::new(),
            duration: start.elapsed(),
        }
    }

    fn is_healthy(&self) -> bool {
        binary_runnable(&self.cargo_bin, "--version")
    }
}

fn default_cargo_home() -> String {
    std::env::var("HOME")
        .map(|h| format!("{h}/.cargo"))
        .unwrap_or_else(|_| ".cargo".to_owned())
}

/// Cross-process advisory lock guarding build+copy for a shared
/// `CARGO_TARGET_DIR` (see the call site in [`RustPool::compile_batch`]).
///
/// Implemented as an atomic `create_new` (O_EXCL) lockfile so it works across
/// the separate processes a parallel `cargo test` spawns — an in-process
/// `Mutex` would not.  A lock older than `STALE_AFTER` is stolen so a crashed
/// holder cannot wedge the pool, and acquisition gives up after `MAX_WAIT`
/// (proceeding unlocked) so a pathological case degrades to the pre-fix
/// behaviour rather than deadlocking.
struct TargetDirLock {
    path: PathBuf,
    /// Only the process that created the lockfile removes it on drop, so a
    /// give-up / steal path never deletes another holder's lock.
    owned: bool,
}

impl TargetDirLock {
    fn acquire(target_dir: &Path) -> Self {
        const MAX_WAIT: Duration = Duration::from_secs(300);
        const STALE_AFTER: Duration = Duration::from_secs(180);
        let path = target_dir.join(".nyx-pool-build.lock");
        let start = Instant::now();
        let mut spins: u64 = 0;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    use std::io::Write;
                    let _ = writeln!(f, "{}", std::process::id());
                    return Self { path, owned: true };
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Steal a stale lock left behind by a crashed holder.
                    if let Ok(meta) = std::fs::metadata(&path)
                        && let Ok(mtime) = meta.modified()
                        && mtime.elapsed().map(|d| d > STALE_AFTER).unwrap_or(false)
                    {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if start.elapsed() > MAX_WAIT {
                        // Best-effort: a slow build beats a deadlock.
                        return Self { path, owned: false };
                    }
                    let nap = 10u64.saturating_add(spins.min(40).saturating_mul(2));
                    std::thread::sleep(Duration::from_millis(nap));
                    spins = spins.saturating_add(1);
                }
                Err(_) => {
                    // Cannot create the lockfile (perms / race on dir) — proceed
                    // unlocked rather than fail the build outright.
                    return Self { path, owned: false };
                }
            }
        }
    }
}

impl Drop for TargetDirLock {
    fn drop(&mut self) {
        if self.owned {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Stable short hash of the named manifest files under `workdir`.
fn hash_files(workdir: &Path, files: &[&str]) -> String {
    let mut h = Hasher::new();
    for fname in files {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_content_sensitive() {
        let dir = tempfile::TempDir::new().unwrap();
        let h1 = hash_files(dir.path(), &["Cargo.lock"]);
        let h2 = hash_files(dir.path(), &["Cargo.lock"]);
        assert_eq!(h1, h2);
        std::fs::write(dir.path().join("Cargo.lock"), b"[[package]]\n").unwrap();
        let h3 = hash_files(dir.path(), &["Cargo.lock"]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn missing_dest_arg_is_an_error_not_a_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        // Construct without a toolchain probe so the test runs JDK/cargo-free.
        let pool = RustPool {
            cargo_bin: "cargo".to_owned(),
            sccache_bin: None,
        };
        let r = pool.compile_batch(dir.path(), &[]);
        assert!(!r.success);
        assert!(r.stderr.contains("missing binary destination"));
    }
}
