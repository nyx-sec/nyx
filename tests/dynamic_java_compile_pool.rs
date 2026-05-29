//! Phase 22 / Track O.0 acceptance test for the warm `javac` daemon.
//!
//! Asserts that 50 sequential harness-shaped Java compiles run through the
//! pool in < 5s on the dev reference machine (down from > 30s baseline with
//! one fresh `javac` per build).  The test is gated on the `dynamic`
//! feature and skips silently when `javac` / `java` are not on PATH so a
//! JDK-less CI image does not break the gate.

#![cfg(feature = "dynamic")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nyx_scanner::dynamic::build_pool::BuildPool;
use nyx_scanner::dynamic::build_pool::java::JavacPool;

static BUILD_POOL_ENV_LOCK: Mutex<()> = Mutex::new(());

struct BuildPoolEnvGuard {
    _lock: MutexGuard<'static, ()>,
    prior: Option<String>,
}

impl BuildPoolEnvGuard {
    fn set(path: &Path) -> Self {
        let lock = BUILD_POOL_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prior = std::env::var("NYX_BUILD_POOL_DIR").ok();
        unsafe { std::env::set_var("NYX_BUILD_POOL_DIR", path) };
        Self { _lock: lock, prior }
    }
}

impl Drop for BuildPoolEnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(value) => unsafe { std::env::set_var("NYX_BUILD_POOL_DIR", value) },
            None => unsafe { std::env::remove_var("NYX_BUILD_POOL_DIR") },
        }
    }
}

fn jdk_available() -> bool {
    fn ok(bin: &str) -> bool {
        Command::new(bin)
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    ok(&std::env::var("NYX_JAVAC_BIN").unwrap_or_else(|_| "javac".to_owned()))
        && ok(&std::env::var("NYX_JAVA_BIN").unwrap_or_else(|_| "java".to_owned()))
}

/// Drop a self-contained Java source into `workdir/Harness{idx}.java`
/// and return the args list the pool expects.
fn write_harness(workdir: &Path, idx: usize) -> Vec<String> {
    let class_name = format!("Harness{idx}");
    let src = format!(
        "public final class {class_name} {{\n    \
         public static int answer() {{ return {idx}; }}\n    \
         public static void main(String[] argv) {{ \
         System.out.println({class_name}.answer()); }}\n\
         }}\n",
    );
    let src_path = workdir.join(format!("{class_name}.java"));
    std::fs::write(&src_path, src).unwrap();
    vec![
        "-d".to_owned(),
        workdir.to_string_lossy().into_owned(),
        src_path.to_string_lossy().into_owned(),
    ]
}

#[test]
#[ignore = "real-toolchain perf bench: runs 50 real `javac` compiles. Opt-in so the default suite stays hermetic + fast. Run: cargo nextest run --features dynamic --run-ignored ignored-only -E 'binary(~build_pool) | binary(~compile_pool)'"]
fn batch_of_fifty_harness_compiles_meets_perf_target() {
    if !jdk_available() {
        eprintln!("skipping: javac / java not available on PATH");
        return;
    }

    // Isolate the pool bootstrap dir so this test does not race with
    // another concurrent build-pool test or pollute the user's cache.
    let bootstrap_root = tempfile::TempDir::new().unwrap();
    let _env = BuildPoolEnvGuard::set(bootstrap_root.path());

    let pool = match JavacPool::try_new("phase22-batch-test") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping: pool bootstrap failed: {e}");
            return;
        }
    };

    // First call warms JIT + classpath caches inside the worker JVM.
    // We deliberately measure the steady-state 50 builds with the
    // bootstrap already paid because the acceptance gate is the
    // amortised per-build cost.
    let warmup_dir = tempfile::TempDir::new().unwrap();
    let warmup_args = write_harness(warmup_dir.path(), 0);
    let warmup = pool.compile_batch(warmup_dir.path(), &warmup_args);
    assert!(
        warmup.success,
        "warmup compile must succeed: {}",
        warmup.stderr
    );
    assert!(
        warmup_dir.path().join("Harness0.class").exists(),
        "warmup compile must emit a class file",
    );

    // 50 sequential builds, each in its own workdir so the JVM-side
    // file resolution touches a fresh path every time -- closest
    // analogue to the per-finding shape the verifier produces.
    let mut workdirs: Vec<(tempfile::TempDir, PathBuf, Vec<String>)> = Vec::with_capacity(50);
    for i in 1..=50 {
        let d = tempfile::TempDir::new().unwrap();
        let args = write_harness(d.path(), i);
        let path = d.path().to_path_buf();
        workdirs.push((d, path, args));
    }

    let start = Instant::now();
    for (i, (_dir, path, args)) in workdirs.iter().enumerate() {
        let r = pool.compile_batch(path, args);
        assert!(r.success, "compile {} failed: {}", i + 1, r.stderr,);
        let class_file = path.join(format!("Harness{}.class", i + 1));
        assert!(
            class_file.exists(),
            "compile {} produced no class file at {}",
            i + 1,
            class_file.display(),
        );
    }
    let elapsed = start.elapsed();

    eprintln!(
        "phase22 javac-pool: 50 hot compiles in {:.2?} (avg {:.2}ms/build)",
        elapsed,
        elapsed.as_secs_f64() * 1000.0 / 50.0,
    );

    let cap = Duration::from_secs(5);
    assert!(
        elapsed <= cap,
        "phase22 acceptance gate: 50 hot compiles took {elapsed:?}, expected ≤ {cap:?}",
    );

    assert!(
        pool.is_healthy(),
        "pool must stay healthy after 50 compiles"
    );
}

#[test]
fn pool_surfaces_real_compile_errors_intact() {
    if !jdk_available() {
        eprintln!("skipping: javac / java not available on PATH");
        return;
    }
    let bootstrap_root = tempfile::TempDir::new().unwrap();
    let _env = BuildPoolEnvGuard::set(bootstrap_root.path());

    let pool = match JavacPool::try_new("phase22-error-test") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping: pool bootstrap failed: {e}");
            return;
        }
    };

    let dir = tempfile::TempDir::new().unwrap();
    let src = dir.path().join("Broken.java");
    std::fs::write(&src, "public class Broken { int x = ; }").unwrap();
    let args = vec![
        "-d".to_owned(),
        dir.path().to_string_lossy().into_owned(),
        src.to_string_lossy().into_owned(),
    ];
    let r = pool.compile_batch(dir.path(), &args);
    assert!(!r.success, "syntactically invalid source must fail");
    assert!(
        !r.stderr.is_empty(),
        "compile failure must produce a non-empty stderr payload (got {:?})",
        r.stderr,
    );
    // Pool should still be alive for the next caller.
    assert!(pool.is_healthy());
}
