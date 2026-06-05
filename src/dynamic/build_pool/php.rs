//! PHP build pool (Phase 23 / Track O.1).
//!
//! Two warm caches keyed off the Composer lockfile:
//! - `COMPOSER_CACHE_DIR` points at the shared pool root so package downloads
//!   are reused across lock hashes, and
//! - an opcache file-cache directory is pre-warmed so the harness `php`
//!   process skips re-parsing the vendored sources on first run.
//!
//! Both degrade gracefully: a missing `composer` makes `try_new` fail and the
//! caller falls back to the legacy
//! [`crate::dynamic::build_sandbox::prepare_php`] path; a missing `php` simply
//! skips the opcache warm (the install still succeeds).

use super::{BuildPool, PoolCompileResult, base_command, binary_runnable, pool_cache_dir};
use std::path::Path;
use std::time::Instant;

pub struct PhpPool {
    composer_bin: String,
}

impl PhpPool {
    pub fn try_new() -> Result<Self, String> {
        let composer_bin =
            std::env::var("NYX_COMPOSER_BIN").unwrap_or_else(|_| "composer".to_owned());
        if !binary_runnable(&composer_bin, "--version") {
            return Err(format!("php-pool: {composer_bin} not runnable"));
        }
        Ok(PhpPool { composer_bin })
    }
}

impl BuildPool for PhpPool {
    fn name(&self) -> &'static str {
        "php"
    }

    /// Install `composer.json` deps into `workdir/vendor` then warm the
    /// shared opcache file-cache.  Args are unused.
    fn compile_batch(&self, workdir: &Path, _args: &[String]) -> PoolCompileResult {
        let start = Instant::now();
        let mut cmd = base_command(&self.composer_bin);
        cmd.args(["install", "--no-interaction", "--no-dev", "--prefer-dist"])
            .current_dir(workdir)
            .env("COMPOSER_ALLOW_SUPERUSER", "1");
        if let Some(cache) = pool_cache_dir("php", "composer-cache") {
            cmd.env("COMPOSER_CACHE_DIR", cache);
        }

        match cmd.output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                return PoolCompileResult {
                    success: false,
                    stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
                    duration: start.elapsed(),
                };
            }
            Err(e) => {
                return PoolCompileResult {
                    success: false,
                    stderr: format!("php-pool: composer install: {e}"),
                    duration: start.elapsed(),
                };
            }
        }

        warm_opcache(workdir);

        PoolCompileResult {
            success: true,
            stderr: String::new(),
            duration: start.elapsed(),
        }
    }

    fn is_healthy(&self) -> bool {
        binary_runnable(&self.composer_bin, "--version")
    }
}

/// Best-effort opcache file-cache pre-warm: compile every vendored `.php`
/// into the shared opcache file-cache so the harness `php` process boots with
/// the bytecode already on disk.  A missing `php` or partial failure is
/// swallowed — the install already succeeded and opcache is a pure speed win.
fn warm_opcache(workdir: &Path) {
    let vendor = workdir.join("vendor");
    if !vendor.exists() {
        return;
    }
    let php = std::env::var("NYX_PHP_BIN").unwrap_or_else(|_| "php".to_owned());
    let file_cache = match pool_cache_dir("php", "opcache") {
        Some(d) => d,
        None => return,
    };
    let _ = base_command(&php)
        .arg("-d")
        .arg("opcache.enable_cli=1")
        .arg("-d")
        .arg(format!("opcache.file_cache={}", file_cache.display()))
        .arg("-d")
        .arg("opcache.file_cache_only=1")
        .arg("-r")
        .arg(
            "foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator('vendor')) \
             as $f){ if(substr($f,-4)==='.php'){ @opcache_compile_file($f); } }",
        )
        .current_dir(workdir)
        .output();
}
