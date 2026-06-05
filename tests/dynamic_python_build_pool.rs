//! Phase 23 / Track O.1 micro-benchmark for the Python build pool.
//!
//! Asserts the warm-cache hot path (a `prepare_python` cache hit backed by the
//! shared venv + `compileall` bytecode warm) stays ≤ 200ms, the interpreted
//! budget.  Skips when `python3` is not runnable.

#![cfg(feature = "dynamic")]

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nyx_scanner::dynamic::build_sandbox::prepare_python;
use nyx_scanner::dynamic::spec::{
    EntryKind, HarnessSpec, JavaToolchain, PayloadSlot, SpecDerivationStrategy,
};
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct CacheGuard {
    _lock: MutexGuard<'static, ()>,
    prior_cache: Option<String>,
    prior_pool: Option<String>,
    _cache: tempfile::TempDir,
    _pool: tempfile::TempDir,
}

impl CacheGuard {
    fn isolated() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cache = tempfile::TempDir::new().unwrap();
        let pool = tempfile::TempDir::new().unwrap();
        let prior_cache = std::env::var("NYX_BUILD_CACHE").ok();
        let prior_pool = std::env::var("NYX_BUILD_POOL_DIR").ok();
        unsafe {
            std::env::set_var("NYX_BUILD_CACHE", cache.path());
            std::env::set_var("NYX_BUILD_POOL_DIR", pool.path());
        }
        Self {
            _lock: lock,
            prior_cache,
            prior_pool,
            _cache: cache,
            _pool: pool,
        }
    }
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        restore("NYX_BUILD_CACHE", self.prior_cache.take());
        restore("NYX_BUILD_POOL_DIR", self.prior_pool.take());
    }
}

fn restore(key: &str, prior: Option<String>) {
    match prior {
        Some(v) => unsafe { std::env::set_var(key, v) },
        None => unsafe { std::env::remove_var(key) },
    }
}

fn median(mut ds: Vec<Duration>) -> Duration {
    ds.sort();
    ds[ds.len() / 2]
}

fn mk_spec() -> HarnessSpec {
    HarnessSpec {
        finding_id: "bench".to_owned(),
        entry_file: "entry".to_owned(),
        entry_name: "main".to_owned(),
        entry_kind: EntryKind::Function,
        lang: Lang::Python,
        toolchain_id: "bench-python".to_owned(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::CODE_EXEC,
        constraint_hints: vec![],
        sink_file: "sink".to_owned(),
        sink_line: 1,
        spec_hash: "0000000000000000".to_owned(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
        framework: None,
        java_toolchain: JavaToolchain::default(),
    }
}

fn write_project(workdir: &Path) {
    // Empty requirements: venv creation succeeds offline; the cached
    // `.python_cache_done` marker turns every later call into a cache hit.
    std::fs::write(workdir.join("requirements.txt"), "").unwrap();
}

#[test]
#[ignore = "real-toolchain perf bench: spawns `python -m venv` + pip. Opt-in so the default suite stays hermetic + fast. Run: cargo nextest run --features dynamic --run-ignored ignored-only -E 'binary(~build_pool) | binary(~compile_pool)'"]
fn warm_prepare_p50_under_200ms() {
    let _guard = CacheGuard::isolated();
    let spec = mk_spec();
    let work = tempfile::TempDir::new().unwrap();
    write_project(work.path());

    match prepare_python(&spec, work.path()) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("skipping python build-pool bench: {e:?}");
            return;
        }
    }

    let mut hot = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let r = prepare_python(&spec, work.path()).expect("warm prepare must succeed");
        hot.push(start.elapsed());
        assert!(r.cache_hit, "warm prepare_python must be a cache hit");
    }

    let p50 = median(hot);
    eprintln!("python build-pool warm P50: {p50:?}");
    assert!(
        p50 <= Duration::from_millis(200),
        "python warm-prepare P50 {p50:?} exceeds the 200ms interpreted budget",
    );
}
