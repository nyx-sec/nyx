//! C build pool (Phase 23 / Track O.1).
//!
//! Wraps the C compiler in `ccache` (when present) backed by a shared object
//! cache under the pool cache root, so a finding that recompiles a harness
//! whose `main.c` matches a previously-built one gets a cache hit instead of a
//! cold `cc` invocation.
//!
//! `ccache` degrades gracefully: when it is not on `PATH` the pool runs the
//! bare compiler, byte-for-byte the same `cc` invocation the legacy
//! [`crate::dynamic::build_sandbox::prepare_c`] path uses, so success / failure
//! parity holds.  The static-link fallback (drop `-static` and retry) mirrors
//! the legacy `run_cc` behaviour for chroot-bound Strict-profile harnesses.

use super::{BuildPool, PoolCompileResult, base_command, binary_runnable, pool_cache_dir};
use std::path::Path;
use std::time::Instant;

pub struct CPool {
    cc_bin: String,
    ccache_bin: Option<String>,
}

impl CPool {
    pub fn try_new() -> Result<Self, String> {
        let cc_bin = std::env::var("NYX_CC_BIN").unwrap_or_else(|_| "cc".to_owned());
        if !binary_runnable(&cc_bin, "--version") {
            return Err(format!("c-pool: {cc_bin} not runnable"));
        }
        Ok(CPool {
            cc_bin,
            ccache_bin: super::detect_ccache(),
        })
    }
}

impl BuildPool for CPool {
    fn name(&self) -> &'static str {
        "c"
    }

    /// `args[0]` = binary destination, `args[1]` = `"static"` or `"dynamic"`.
    fn compile_batch(&self, workdir: &Path, args: &[String]) -> PoolCompileResult {
        let start = Instant::now();
        let dest = match args.first() {
            Some(d) => d.clone(),
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "c-pool: missing binary destination arg".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };
        let static_link = args.get(1).map(|s| s == "static").unwrap_or(false);

        if static_link {
            match self.run(workdir, &dest, &["-static", "-O0", "-g"]) {
                Ok(()) => {
                    return PoolCompileResult {
                        success: true,
                        stderr: String::new(),
                        duration: start.elapsed(),
                    };
                }
                Err(stderr) => {
                    unsafe { std::env::set_var("NYX_BUILD_STATIC_FALLBACK", "1") };
                    eprintln!("nyx: c-pool cc -static failed, retrying without -static: {stderr}");
                    let _ = std::fs::remove_file(&dest);
                }
            }
        }

        match self.run(workdir, &dest, &["-O0", "-g"]) {
            Ok(()) => PoolCompileResult {
                success: true,
                stderr: String::new(),
                duration: start.elapsed(),
            },
            Err(stderr) => PoolCompileResult {
                success: false,
                stderr,
                duration: start.elapsed(),
            },
        }
    }

    fn is_healthy(&self) -> bool {
        binary_runnable(&self.cc_bin, "--version")
    }
}

impl CPool {
    /// Run one compile of `main.c`, optionally fronted by `ccache`.
    fn run(&self, workdir: &Path, dest: &str, leading_flags: &[&str]) -> Result<(), String> {
        let mut cmd = match (&self.ccache_bin, pool_cache_dir("c", "ccache")) {
            (Some(ccache), Some(cache_dir)) => {
                let mut c = base_command(ccache);
                c.arg(&self.cc_bin).env("CCACHE_DIR", cache_dir);
                c
            }
            _ => base_command(&self.cc_bin),
        };
        cmd.args(leading_flags)
            .args(["-o", dest, "main.c"])
            .current_dir(workdir);

        let output = cmd.output().map_err(|e| format!("c-pool: cc: {e}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        Ok(())
    }
}
