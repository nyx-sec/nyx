//! Python build pool (Phase 23 / Track O.1).
//!
//! `prepare_python` already keys its venv on the requirements hash, so the
//! venv itself is the "shared venv per `requirements_hash`".  What the legacy
//! path lacks is a warm bytecode cache: the first harness to import a package
//! pays the `.py` -> `.pyc` compile.
//!
//! [`PythonPool`] runs `python -m compileall` over the venv's `site-packages`
//! once at venv-creation time so every later harness import is a `__pycache__`
//! hit.  The pip download cache is pointed at the shared pool root so repeated
//! installs across requirements hashes reuse wheels.

use super::{BuildPool, PoolCompileResult, base_command, binary_runnable, pool_cache_dir};
use std::path::Path;
use std::time::Instant;

pub struct PythonPool;

impl PythonPool {
    pub fn try_new(python_bin: &str) -> Result<Self, String> {
        if !binary_runnable(python_bin, "--version") {
            return Err(format!("python-pool: {python_bin} not runnable"));
        }
        Ok(PythonPool)
    }
}

impl BuildPool for PythonPool {
    fn name(&self) -> &'static str {
        "python"
    }

    /// `args[0]` = venv path to create, `args[1]` = python interpreter binary.
    fn compile_batch(&self, workdir: &Path, args: &[String]) -> PoolCompileResult {
        let start = Instant::now();
        let venv_path = match args.first() {
            Some(v) => Path::new(v),
            None => {
                return PoolCompileResult {
                    success: false,
                    stderr: "python-pool: missing venv path arg".to_owned(),
                    duration: start.elapsed(),
                };
            }
        };
        let python = args.get(1).map(String::as_str).unwrap_or("python3");

        // 1. Create the venv.
        let create = base_command(python)
            .args(["-m", "venv", "--clear", "--system-site-packages"])
            .arg(venv_path)
            .status();
        match create {
            Ok(s) if s.success() => {}
            Ok(s) => {
                return PoolCompileResult {
                    success: false,
                    stderr: format!("venv create failed: exit {s}"),
                    duration: start.elapsed(),
                };
            }
            Err(e) => {
                return PoolCompileResult {
                    success: false,
                    stderr: format!("python-pool: venv create: {e}"),
                    duration: start.elapsed(),
                };
            }
        }

        // 2. Install requirements with the shared wheel cache.
        let req_path = workdir.join("requirements.txt");
        if req_path.exists() {
            let pip = venv_path.join("bin").join("pip");
            let mut cmd = base_command(&pip.to_string_lossy());
            cmd.args(["install", "-r"]).arg(&req_path);
            if let Some(cache) = pool_cache_dir("python", "pip-cache") {
                cmd.env("PIP_CACHE_DIR", cache);
            } else {
                cmd.arg("--no-cache-dir");
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
                        stderr: format!("python-pool: pip install: {e}"),
                        duration: start.elapsed(),
                    };
                }
            }
        }

        // 3. Warm __pycache__ for the whole venv (best-effort: a partial
        //    failure to byte-compile one module must not fail the build).
        let venv_python = venv_path.join("bin").join("python");
        let _ = base_command(&venv_python.to_string_lossy())
            .args(["-m", "compileall", "-q"])
            .arg(venv_path)
            .output();

        PoolCompileResult {
            success: true,
            stderr: String::new(),
            duration: start.elapsed(),
        }
    }

    fn is_healthy(&self) -> bool {
        // The interpreter is resolved per-request via args; treat the pool as
        // always healthy and let an unrunnable interpreter surface as a build
        // error, which the dispatcher already falls back from.
        true
    }
}
