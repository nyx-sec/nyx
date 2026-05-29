//! Go build pool (Phase 23 / Track O.1).
//!
//! The legacy [`crate::dynamic::build_sandbox::prepare_go`] gives each finding
//! its own `GOCACHE`/`GOMODCACHE` (default: a per-workdir `.gocache`), so the
//! Go toolchain recompiles the standard library and every module from cold on
//! every harness.
//!
//! [`GoPool`] mounts one shared `GOCACHE` + `GOMODCACHE` under the pool cache
//! root so compiled std-lib + module artefacts are reused across findings, and
//! builds with `-trimpath -buildvcs=false` so the output is reproducible (no
//! absolute workdir paths or VCS stamping baked in, which otherwise defeats the
//! build cache's keying).

use super::{BuildPool, PoolCompileResult, base_command, binary_runnable, pool_cache_dir};
use std::path::Path;
use std::time::Instant;

pub struct GoPool {
    go_bin: String,
}

impl GoPool {
    pub fn try_new() -> Result<Self, String> {
        let go_bin = std::env::var("NYX_GO_BIN").unwrap_or_else(|_| "go".to_owned());
        if !binary_runnable(&go_bin, "version") {
            return Err(format!("go-pool: {go_bin} not runnable"));
        }
        Ok(GoPool { go_bin })
    }
}

impl BuildPool for GoPool {
    fn name(&self) -> &'static str {
        "go"
    }

    /// `args[0]` = absolute path the compiled `nyx_harness` binary must land
    /// at.
    fn compile_batch(&self, workdir: &Path, args: &[String]) -> PoolCompileResult {
        let start = Instant::now();
        let dest = match args.first() {
            Some(d) => d.clone(),
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "go-pool: missing binary destination arg".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };

        let go_cache = match pool_cache_dir("go", "cache") {
            Some(d) => d,
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "go-pool: no shared GOCACHE".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };
        let go_mod_cache = match pool_cache_dir("go", "modcache") {
            Some(d) => d,
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "go-pool: no shared GOMODCACHE".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };
        let go_path = std::env::var("GOPATH").unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| format!("{h}/go"))
                .unwrap_or_else(|_| "/tmp/go".to_owned())
        });

        // `go mod tidy` resolves imports into the shared module cache.
        if workdir.join("go.mod").exists() {
            let tidy = base_command(&self.go_bin)
                .args(["mod", "tidy"])
                .current_dir(workdir)
                .env("GOCACHE", &go_cache)
                .env("GOPATH", &go_path)
                .env("GOMODCACHE", &go_mod_cache)
                .output();
            match tidy {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let mut msg = String::from_utf8_lossy(&o.stderr).into_owned();
                    if msg.is_empty() {
                        msg = String::from_utf8_lossy(&o.stdout).into_owned();
                    }
                    return PoolCompileResult {
                        success: false,
                        stderr: format!("go mod tidy failed: {msg}"),
                        duration: start.elapsed(),
                    };
                }
                Err(e) => {
                    return PoolCompileResult {
                        success: false,
                        stderr: format!("go-pool: go mod tidy: {e}"),
                        duration: start.elapsed(),
                    };
                }
            }
        }

        let output = base_command(&self.go_bin)
            .args([
                "build",
                "-trimpath",
                "-buildvcs=false",
                "-o",
                &dest,
                ".",
            ])
            .current_dir(workdir)
            .env("GOCACHE", &go_cache)
            .env("GOPATH", &go_path)
            .env("GOMODCACHE", &go_mod_cache)
            .output();

        match output {
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
                stderr: format!("go-pool: go build: {e}"),
                duration: start.elapsed(),
            },
        }
    }

    fn is_healthy(&self) -> bool {
        binary_runnable(&self.go_bin, "version")
    }
}
