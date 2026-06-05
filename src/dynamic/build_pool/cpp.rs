//! C++ build pool (Phase 23 / Track O.1).
//!
//! Same shape as the C pool: front the C++ driver with `ccache` backed by a
//! shared object cache under the pool cache root.  Falls back to a bare
//! `c++ -std=c++17` compile — byte-for-byte the legacy
//! [`crate::dynamic::build_sandbox::prepare_cpp`] invocation — when `ccache` is
//! absent.

use super::{BuildPool, PoolCompileResult, base_command, binary_runnable, pool_cache_dir};
use std::path::Path;
use std::time::Instant;

pub struct CppPool {
    cxx_bin: String,
    ccache_bin: Option<String>,
}

impl CppPool {
    pub fn try_new() -> Result<Self, String> {
        let cxx_bin = std::env::var("NYX_CXX_BIN").unwrap_or_else(|_| "c++".to_owned());
        if !binary_runnable(&cxx_bin, "--version") {
            return Err(format!("cpp-pool: {cxx_bin} not runnable"));
        }
        Ok(CppPool {
            cxx_bin,
            ccache_bin: super::detect_ccache(),
        })
    }
}

impl BuildPool for CppPool {
    fn name(&self) -> &'static str {
        "cpp"
    }

    /// `args[0]` = absolute path the compiled `nyx_harness` binary lands at.
    fn compile_batch(&self, workdir: &Path, args: &[String]) -> PoolCompileResult {
        let start = Instant::now();
        let dest = match args.first() {
            Some(d) => d.clone(),
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "cpp-pool: missing binary destination arg".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };

        let mut cmd = match (&self.ccache_bin, pool_cache_dir("cpp", "ccache")) {
            (Some(ccache), Some(cache_dir)) => {
                let mut c = base_command(ccache);
                c.arg(&self.cxx_bin).env("CCACHE_DIR", cache_dir);
                c
            }
            _ => base_command(&self.cxx_bin),
        };
        cmd.args(["-O0", "-g", "-std=c++17", "-o", &dest, "main.cpp"])
            .current_dir(workdir);

        match cmd.output() {
            Ok(o) if o.status.success() => PoolCompileResult {
                success: true,
                stderr: String::new(),
                duration: start.elapsed(),
            },
            Ok(o) => PoolCompileResult {
                success: false,
                stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
                duration: start.elapsed(),
            },
            Err(e) => PoolCompileResult {
                success: false,
                stderr: format!("cpp-pool: c++: {e}"),
                duration: start.elapsed(),
            },
        }
    }

    fn is_healthy(&self) -> bool {
        binary_runnable(&self.cxx_bin, "--version")
    }
}
