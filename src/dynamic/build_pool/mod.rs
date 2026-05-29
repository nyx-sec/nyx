//! Build pools: long-lived compiler / toolchain daemons shared across many
//! per-finding harness builds.
//!
//! The naive `prepare_*` path in [`crate::dynamic::build_sandbox`] spawns a
//! fresh `javac` / `tsc` / `cargo build` subprocess for every finding the
//! verifier touches.  Cold-start dominates the cost: `javac` alone burns
//! ~700ms before it has read a single source.  A 50-harness OWASP run pays
//! that 50× — > 30s of pure JVM startup.
//!
//! A `BuildPool` is a long-running worker process (or in-process service)
//! that compiles batches of harness sources in a single toolchain instance.
//! The per-harness wall-clock collapses to milliseconds once the pool is
//! warm.
//!
//! # Lifecycle
//!
//! `OnceLock<Arc<P>>` per toolchain id, lazily spawned on first request.
//! Pools live for the rest of the process; the OS reaps them on exit.
//! Crashes are non-fatal: callers fall back to the legacy direct-spawn path
//! via [`BuildPool::is_healthy`] and a re-spawn on the next call.
//!
//! # Future-language plug-in
//!
//! Per-language sub-modules (`java.rs`, eventually `node.rs`, `python.rs`,
//! …) implement the [`BuildPool`] trait.  The harness build dispatcher in
//! [`crate::dynamic::build_sandbox`] reads `NYX_DYNAMIC_BUILD_POOL` and
//! routes each request to the matching pool when enabled.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub mod c;
pub mod cpp;
pub mod go;
pub mod java;
pub mod node;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;

/// Outcome of a single batched compile request.
#[derive(Debug)]
pub struct PoolCompileResult {
    /// `true` when the toolchain reported a clean compile.
    pub success: bool,
    /// Toolchain stderr — surfaced as `BuildError::BuildFailed` upstream
    /// when `success == false`.
    pub stderr: String,
    /// Wall-clock for the in-pool compile step (excludes any IPC / queue
    /// wait time).  Useful for telemetry; callers may ignore.
    pub duration: Duration,
}

/// Common contract for every per-language build pool.
///
/// Implementations are expected to be `Send + Sync` so an `Arc<dyn BuildPool>`
/// can be cached in a static `OnceLock` and shared across rayon worker
/// threads.
pub trait BuildPool: Send + Sync {
    /// Stable identifier — used in log lines + telemetry so an operator
    /// can correlate a pool warmup with the harness that triggered it.
    fn name(&self) -> &'static str;

    /// Compile every source file under `workdir` matching the pool's
    /// language convention.  On success the toolchain has written
    /// artefacts back into `workdir` (or wherever the pool's contract
    /// dictates).
    fn compile_batch(&self, workdir: &Path, args: &[String]) -> PoolCompileResult;

    /// Cheap health check — when this returns `false`, the harness build
    /// dispatcher falls back to the direct-spawn legacy path and tears
    /// down the cached handle so the next request triggers a re-spawn.
    fn is_healthy(&self) -> bool;
}

/// Languages that ship a [`BuildPool`] implementation and are therefore
/// enabled by default.  Phase 22 shipped `java`; Phase 23 (Track O.1) adds
/// the remaining eight, so every supported language now has a warm fast path
/// unless an operator opts out via `NYX_DYNAMIC_BUILD_POOL=<lang>=0`.
const POOL_ENABLED_LANGS: &[&str] = &[
    "java", "node", "python", "php", "ruby", "go", "rust", "c", "cpp",
];

/// Parse the `NYX_DYNAMIC_BUILD_POOL` env var.
///
/// Format is a comma-separated list of `lang=bit` entries: `java=1,node=0`.
/// A missing language returns the default: `true` for every language that
/// ships a pool (see [`POOL_ENABLED_LANGS`]), `false` otherwise.
pub fn is_pool_enabled(lang: &str) -> bool {
    let default = POOL_ENABLED_LANGS.contains(&lang);
    let raw = match std::env::var("NYX_DYNAMIC_BUILD_POOL") {
        Ok(v) => v,
        Err(_) => return default,
    };
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (k, v) = match entry.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k.trim().eq_ignore_ascii_case(lang) {
            return matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on");
        }
    }
    default
}

/// Shared root for a pool's persistent caches (sccache dir, shared
/// `GOCACHE`, opcache file-cache, Bootsnap cache, shared venvs, …).
///
/// Honours `NYX_BUILD_POOL_DIR` so tests can redirect the cache into a
/// `TempDir`; otherwise falls back to the platform cache dir, mirroring
/// the javac pool's layout under `dynamic/build-pool/`.
///
/// Returns `None` only when neither the env override nor a platform cache
/// dir is available — callers treat that as "pool unavailable" and fall
/// back to the legacy direct-spawn build path.
pub(crate) fn pool_cache_dir(lang: &str, sub: &str) -> Option<PathBuf> {
    let base = if let Ok(custom) = std::env::var("NYX_BUILD_POOL_DIR") {
        PathBuf::from(custom)
    } else {
        directories::ProjectDirs::from("dev", "nyx", "nyx")?
            .cache_dir()
            .join("dynamic")
            .join("build-pool")
    };
    let dir = base.join(lang).join(sub);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Construct a `Command` for `bin` with a scrubbed environment, matching
/// the isolation envelope every legacy `prepare_*` build uses: `env_clear`
/// plus an inherited `PATH` + `HOME` only.  Pools layer their cache env
/// (`CARGO_TARGET_DIR`, `CCACHE_DIR`, `GOCACHE`, …) on top of this.
pub(crate) fn base_command(bin: &str) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default());
    cmd
}

/// Detect a runnable `ccache` binary (honouring `NYX_CCACHE_BIN`).  Shared
/// by the C and C++ pools to front their compiler with the shared object
/// cache; `None` means "compile bare", preserving legacy parity.
pub(crate) fn detect_ccache() -> Option<String> {
    let bin = std::env::var("NYX_CCACHE_BIN").unwrap_or_else(|_| "ccache".to_owned());
    binary_runnable(&bin, "--version").then_some(bin)
}

/// Cheap "is this binary runnable" probe used by every pool's
/// [`BuildPool::is_healthy`] / `try_new`.  Runs `bin <probe_arg>` with a
/// scrubbed env and reports whether it exited 0.
pub(crate) fn binary_runnable(bin: &str, probe_arg: &str) -> bool {
    base_command(bin)
        .arg(probe_arg)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        prior: Option<String>,
    }

    impl EnvGuard {
        fn set(value: Option<&str>) -> Self {
            let prior = std::env::var("NYX_DYNAMIC_BUILD_POOL").ok();
            match value {
                Some(v) => unsafe { std::env::set_var("NYX_DYNAMIC_BUILD_POOL", v) },
                None => unsafe { std::env::remove_var("NYX_DYNAMIC_BUILD_POOL") },
            }
            Self { prior }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => unsafe { std::env::set_var("NYX_DYNAMIC_BUILD_POOL", v) },
                None => unsafe { std::env::remove_var("NYX_DYNAMIC_BUILD_POOL") },
            }
        }
    }

    #[test]
    fn default_enables_every_shipped_pool() {
        let _l = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(None);
        for lang in POOL_ENABLED_LANGS {
            assert!(is_pool_enabled(lang), "{lang} pool must default on");
        }
        // A language with no pool stays off.
        assert!(!is_pool_enabled("cobol"));
    }

    #[test]
    fn explicit_override_disables_node() {
        let _l = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(Some("node=0"));
        assert!(!is_pool_enabled("node"));
        // Other languages keep their default-on state.
        assert!(is_pool_enabled("python"));
    }

    #[test]
    fn explicit_override_disables_java() {
        let _l = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(Some("java=0"));
        assert!(!is_pool_enabled("java"));
    }

    #[test]
    fn multi_entry_parses_per_lang() {
        let _l = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(Some("java=1,node=1,python=0"));
        assert!(is_pool_enabled("java"));
        assert!(is_pool_enabled("node"));
        assert!(!is_pool_enabled("python"));
    }

    #[test]
    fn case_insensitive_keys() {
        let _l = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(Some("JAVA=0"));
        assert!(!is_pool_enabled("java"));
    }

    #[test]
    fn unknown_value_treated_as_disabled() {
        let _l = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(Some("java=maybe"));
        assert!(!is_pool_enabled("java"));
    }
}
