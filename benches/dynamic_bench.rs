/// Dynamic verification benchmarks (§8.4).
///
/// Tracks three cost anchors:
///
/// 1. `harness_build_cold` — fresh workdir, spec → BuiltHarness (source gen + disk write).
/// 2. `harness_build_warm` — same spec, workdir already staged (file write skipped).
/// 3. `sandbox_run_payload` — single payload run via process backend against
///    sqli_positive.py (subprocess + settrace overhead, no networking).
///
/// Baselines committed to `benches/dynamic_bench_baseline.json`.
/// Run: `cargo bench --features dynamic -- dynamic`

use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(feature = "dynamic")]
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
#[cfg(feature = "dynamic")]
use nyx_scanner::labels::Cap;
#[cfg(feature = "dynamic")]
use nyx_scanner::symbol::Lang;

#[cfg(feature = "dynamic")]
fn make_sqli_spec() -> HarnessSpec {
    HarnessSpec {
        finding_id: "bench0000000001".into(),
        entry_file: "tests/dynamic_fixtures/python/sqli_positive.py".into(),
        entry_name: "login".into(),
        entry_kind: EntryKind::Function,
        lang: Lang::Python,
        toolchain_id: "python-3".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::SQL_QUERY,
        constraint_hints: vec![],
        sink_file: "tests/dynamic_fixtures/python/sqli_positive.py".into(),
        sink_line: 7,
        spec_hash: "benchsqli000001".into(),
    }
}

#[cfg(feature = "dynamic")]
fn bench_harness_build_cold(c: &mut Criterion) {
    use nyx_scanner::dynamic::harness;
    let spec = make_sqli_spec();
    c.bench_function("harness_build_cold", |b| {
        b.iter(|| {
            let workdir = std::env::temp_dir()
                .join("nyx-harness")
                .join(&spec.spec_hash);
            let _ = std::fs::remove_dir_all(&workdir);
            harness::build(&spec).expect("harness build")
        });
    });
}

#[cfg(feature = "dynamic")]
fn bench_harness_build_warm(c: &mut Criterion) {
    use nyx_scanner::dynamic::harness;
    let spec = make_sqli_spec();
    harness::build(&spec).expect("harness pre-stage");
    c.bench_function("harness_build_warm", |b| {
        b.iter(|| harness::build(&spec).expect("harness build warm"));
    });
}

#[cfg(feature = "dynamic")]
fn bench_sandbox_run_payload(c: &mut Criterion) {
    use nyx_scanner::dynamic::corpus::payloads_for;
    use nyx_scanner::dynamic::harness;
    use nyx_scanner::dynamic::sandbox::{self, SandboxOptions};

    let spec = make_sqli_spec();
    let harness = harness::build(&spec).expect("harness build");
    let payloads = payloads_for(Cap::SQL_QUERY);
    let payload = payloads.iter().find(|p| !p.is_benign).expect("sqli payload");
    let opts = SandboxOptions {
        timeout: std::time::Duration::from_secs(10),
        ..SandboxOptions::default()
    };

    c.bench_function("sandbox_run_payload", |b| {
        b.iter(|| sandbox::run(&harness, payload, &opts).expect("sandbox run"));
    });
}

#[cfg(feature = "dynamic")]
fn bench_noop(_c: &mut Criterion) {}

// When dynamic feature is off, provide a stub so the binary still links.
#[cfg(not(feature = "dynamic"))]
fn bench_noop(c: &mut Criterion) {
    c.bench_function("dynamic_disabled_noop", |b| b.iter(|| ()));
}

#[cfg(feature = "dynamic")]
criterion_group!(
    dynamic,
    bench_harness_build_cold,
    bench_harness_build_warm,
    bench_sandbox_run_payload,
);

#[cfg(not(feature = "dynamic"))]
criterion_group!(dynamic, bench_noop);

criterion_main!(dynamic);
