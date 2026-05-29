//! Node.js build pool (Phase 23 / Track O.1).
//!
//! `prepare_node` already snapshots `node_modules` per `package.json` hash.
//! What it lacks is a shared npm download cache: a fresh lock hash re-downloads
//! every tarball from cold.
//!
//! [`NodePool`] points `npm_config_cache` at the shared pool root so package
//! tarballs are reused across lock hashes, collapsing a cold `npm install` to
//! an unpack of already-fetched tarballs.  TypeScript harnesses that do not
//! need full type checking are run with `--experimental-strip-types` at
//! execution time (the runner reads [`strip_types_flag`]); the pool itself only
//! owns the install step.

use super::{BuildPool, PoolCompileResult, base_command, binary_runnable, pool_cache_dir};
use std::path::Path;
use std::time::Instant;

pub struct NodePool {
    npm_bin: String,
}

impl NodePool {
    pub fn try_new() -> Result<Self, String> {
        let npm_bin = std::env::var("NYX_NPM_BIN").unwrap_or_else(|_| "npm".to_owned());
        if !binary_runnable(&npm_bin, "--version") {
            return Err(format!("node-pool: {npm_bin} not runnable"));
        }
        Ok(NodePool { npm_bin })
    }
}

/// The Node flag that lets a TS harness skip a full `tsc` compile when the
/// spec does not need type checking.  Surfaced as a free function so the
/// runner can splice it into the harness exec without holding a pool handle.
pub fn strip_types_flag() -> &'static str {
    "--experimental-strip-types"
}

impl BuildPool for NodePool {
    fn name(&self) -> &'static str {
        "node"
    }

    /// Install dependencies declared by `workdir/package.json` into
    /// `workdir/node_modules`.  Args are unused.
    fn compile_batch(&self, workdir: &Path, _args: &[String]) -> PoolCompileResult {
        let start = Instant::now();
        let mut cmd = base_command(&self.npm_bin);
        cmd.args(["install", "--no-save", "--no-audit", "--no-fund"])
            .current_dir(workdir);
        if let Some(cache) = pool_cache_dir("node", "npm-cache") {
            cmd.env("npm_config_cache", cache);
        }

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
                stderr: format!("node-pool: npm install: {e}"),
                duration: start.elapsed(),
            },
        }
    }

    fn is_healthy(&self) -> bool {
        binary_runnable(&self.npm_bin, "--version")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_types_flag_is_the_node_native_ts_flag() {
        assert_eq!(strip_types_flag(), "--experimental-strip-types");
    }
}
