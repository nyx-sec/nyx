//! Phase 23 / Track O.1 micro-benchmark for the Rust build pool.
//!
//! Asserts the hot-build P50 (a warm incremental rebuild through the shared
//! `CARGO_TARGET_DIR`) stays ≤ 1s, the compiled-language budget.  Skips when
//! `cargo` is not runnable so a toolchain-less CI image keeps the gate green.

#![cfg(feature = "dynamic")]

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nyx_scanner::dynamic::build_pool::BuildPool;
use nyx_scanner::dynamic::build_pool::rust::RustPool;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct PoolDirGuard {
    _lock: MutexGuard<'static, ()>,
    prior: Option<String>,
    _dir: tempfile::TempDir,
}

impl PoolDirGuard {
    fn isolated() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        let prior = std::env::var("NYX_BUILD_POOL_DIR").ok();
        unsafe { std::env::set_var("NYX_BUILD_POOL_DIR", dir.path()) };
        Self {
            _lock: lock,
            prior,
            _dir: dir,
        }
    }
}

impl Drop for PoolDirGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => unsafe { std::env::set_var("NYX_BUILD_POOL_DIR", v) },
            None => unsafe { std::env::remove_var("NYX_BUILD_POOL_DIR") },
        }
    }
}

fn median(mut ds: Vec<Duration>) -> Duration {
    ds.sort();
    ds[ds.len() / 2]
}

fn write_project(workdir: &Path) {
    std::fs::write(
        workdir.join("Cargo.toml"),
        "[package]\nname = \"nyx_harness\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
         [[bin]]\nname = \"nyx_harness\"\npath = \"src/main.rs\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(workdir.join("src")).unwrap();
    std::fs::write(workdir.join("src/main.rs"), "fn main() {}\n").unwrap();
}

#[test]
#[ignore = "real-toolchain perf bench: spawns `cargo build --release`. Opt-in so the default suite stays hermetic + fast. Run: cargo nextest run --features dynamic --run-ignored ignored-only -E 'binary(~build_pool) | binary(~compile_pool)'"]
fn hot_rebuild_p50_under_one_second() {
    let _guard = PoolDirGuard::isolated();
    let pool = match RustPool::try_new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping rust build-pool bench: {e}");
            return;
        }
    };

    let work = tempfile::TempDir::new().unwrap();
    write_project(work.path());
    let dest = work.path().join("nyx_harness_out");
    let args = [dest.to_string_lossy().into_owned()];

    // Cold build warms the shared target dir; not measured.
    let cold = pool.compile_batch(work.path(), &args);
    assert!(cold.success, "cold build must succeed: {}", cold.stderr);
    assert!(dest.exists(), "cold build must emit the binary");

    let mut hot = Vec::new();
    for _ in 0..5 {
        let _ = std::fs::remove_file(&dest);
        let start = Instant::now();
        let r = pool.compile_batch(work.path(), &args);
        hot.push(start.elapsed());
        assert!(r.success, "hot build must succeed: {}", r.stderr);
    }

    let p50 = median(hot);
    eprintln!("rust build-pool hot P50: {p50:?}");
    assert!(
        p50 <= Duration::from_secs(1),
        "rust hot-build P50 {p50:?} exceeds the 1s compiled budget",
    );
}
