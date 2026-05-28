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

use std::path::Path;
use std::time::Duration;

pub mod java;

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

/// Parse the `NYX_DYNAMIC_BUILD_POOL` env var.
///
/// Format is a comma-separated list of `lang=bit` entries: `java=1,node=0`.
/// A missing language returns the default (currently `true` for `java`,
/// `false` for every other language because no other pool ships yet).
pub fn is_pool_enabled(lang: &str) -> bool {
    let default = matches!(lang, "java");
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
    fn default_enables_java_only() {
        let _l = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(None);
        assert!(is_pool_enabled("java"));
        assert!(!is_pool_enabled("node"));
        assert!(!is_pool_enabled("python"));
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
