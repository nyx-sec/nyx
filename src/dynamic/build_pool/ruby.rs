//! Ruby build pool (Phase 23 / Track O.1).
//!
//! `prepare_ruby` already vendors gems per `Gemfile.lock` hash.  What it lacks
//! is a warm Bootsnap cache: the first harness to `require` a gem pays the
//! load-path scan + compile.
//!
//! [`RubyPool`] points `BOOTSNAP_CACHE_DIR` at the shared pool root and runs
//! `bundle install` with the shared gem cache.  Bootsnap then persists its
//! compiled require-cache across findings.  Falls back to the legacy path when
//! `bundle` is not runnable.

use super::{
    BuildPool, PoolCompileResult, base_command, binary_runnable, combine_output, pool_cache_dir,
    ruby_hermetic_env,
};
use std::path::Path;
use std::time::Instant;

pub struct RubyPool {
    bundle_bin: String,
}

impl RubyPool {
    pub fn try_new() -> Result<Self, String> {
        let bundle_bin = std::env::var("NYX_BUNDLE_BIN").unwrap_or_else(|_| "bundle".to_owned());
        if !binary_runnable(&bundle_bin, "--version") {
            return Err(format!("ruby-pool: {bundle_bin} not runnable"));
        }
        Ok(RubyPool { bundle_bin })
    }

    fn bundle(&self, workdir: &Path) -> std::process::Command {
        let mut cmd = base_command(&self.bundle_bin);
        cmd.current_dir(workdir);
        // Writable gem target → no privilege escalation → never `sudo`.
        for (k, v) in ruby_hermetic_env(workdir) {
            cmd.env(k, v);
        }
        if let Some(cache) = pool_cache_dir("ruby", "bootsnap") {
            cmd.env("BOOTSNAP_CACHE_DIR", cache);
        }
        cmd
    }
}

impl BuildPool for RubyPool {
    fn name(&self) -> &'static str {
        "ruby"
    }

    /// Resolve `Gemfile` deps into `workdir/vendor/bundle`.  Args are unused.
    fn compile_batch(&self, workdir: &Path, _args: &[String]) -> PoolCompileResult {
        let start = Instant::now();

        // `bundle check` short-circuits when the host already has every gem.
        if let Ok(o) = self.bundle(workdir).arg("check").output()
            && o.status.success()
        {
            return PoolCompileResult {
                success: true,
                stderr: String::new(),
                duration: start.elapsed(),
            };
        }

        // The install target is pinned to a writable vendor dir via
        // `ruby_hermetic_env` (GEM_HOME / BUNDLE_PATH), so the legacy
        // `bundle config set --local path …` step is gone: it is 2.x-only
        // syntax that no-ops on Bundler 1.x (leaving the target pointed at
        // the root-owned system dir — the `sudo` root cause).  `--local`
        // keeps the build offline: missing gems fail fast with a
        // host-limitation error instead of reaching for the network.
        let install = self
            .bundle(workdir)
            .args(["install", "--local", "--jobs", "4", "--retry", "0"])
            .output();
        match install {
            Ok(o) if o.status.success() => PoolCompileResult {
                success: true,
                stderr: String::new(),
                duration: start.elapsed(),
            },
            Ok(o) => PoolCompileResult {
                success: false,
                // Bundler prints its dependency-resolution diagnostics
                // ("Could not find gem '…' in any of the gem sources …") to
                // STDOUT, leaving only the RubyGems extension warning on
                // stderr.  Combine both so the host-limitation classifier at
                // the verify boundary can see the real reason.
                stderr: combine_output(&o.stdout, &o.stderr),
                duration: start.elapsed(),
            },
            Err(e) => PoolCompileResult {
                success: false,
                stderr: format!("ruby-pool: bundle install: {e}"),
                duration: start.elapsed(),
            },
        }
    }

    fn is_healthy(&self) -> bool {
        binary_runnable(&self.bundle_bin, "--version")
    }
}
