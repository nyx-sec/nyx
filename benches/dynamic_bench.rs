/// Dynamic verification benchmarks (§8.4).
///
/// Tracks the per-scan cost anchors:
///
/// 1. `harness_build_cold` — fresh workdir, spec → BuiltHarness (source gen + disk write).
/// 2. `harness_build_warm` — same spec, workdir already staged (file write skipped).
/// 3. `sandbox_run_payload` — single payload run via process backend against
///    sqli_positive.py (subprocess + settrace overhead, no networking).
/// 4. `docker_image_build` — cold image pull/build for the python:3-slim base.
/// 5. `docker_exec_warm` — `docker exec` into a running container (no cold start).
/// 6. `docker_payload_cost` — per-payload sandbox cost via docker backend end-to-end.
/// 7. `composite_chain_reverify_dispatch` — `reverify_top_chains` on a
///    synthetic 3-member chain with no member diags. Measures the no-derive
///    dispatch path (chain_step_specs miss, early-exit build/run loops,
///    Inconclusive verdict allocation, severity downgrade).
/// 8. `composite_chain_reverify_stub_confirmed` — same chain shape, stubbed
///    reverifier returning `Confirmed`. Measures the apply-verdict happy path
///    (no severity bucket change).
/// 9. `composite_chain_reverify_top_n_slice` — 5-chain slice with `top_n=3`.
///    Measures the slice traversal cost so a regression that walks the full
///    slice instead of the prefix is visible.
///
/// Wall-clock budget anchors for the composite reverify path (per the
/// Phase 26 acceptance literal): the live process backend stays under
/// 400ms per 3-member chain, the docker backend under 1500ms. Those
/// live-run numbers are covered by the
/// `flask_eval_chain_reverify_populates_dynamic_verdict` integration
/// test in `tests/chain_emission_e2e.rs`; the microbenches here anchor
/// the dispatch + verdict-application overhead so regressions on the
/// API-shape half land in the criterion baseline.
///
/// Baselines committed to `benches/dynamic_bench_baseline.json`.
/// Run: `cargo bench --features dynamic -- dynamic`
///
/// Docker benchmarks are no-ops when docker is unavailable (skipped, not failed).

use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(feature = "dynamic")]
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy};
#[cfg(feature = "dynamic")]
use nyx_scanner::labels::Cap;
#[cfg(feature = "dynamic")]
use nyx_scanner::symbol::Lang;

#[cfg(feature = "dynamic")]
fn make_rust_sqli_spec() -> HarnessSpec {
    HarnessSpec {
        finding_id: "bench_rust_0001".into(),
        entry_file: "tests/dynamic_fixtures/rust/sqli_positive.rs".into(),
        entry_name: "run".into(),
        entry_kind: nyx_scanner::dynamic::spec::EntryKind::Function,
        lang: Lang::Rust,
        toolchain_id: "rust-stable".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::SQL_QUERY,
        constraint_hints: vec![],
        sink_file: "tests/dynamic_fixtures/rust/sqli_positive.rs".into(),
        sink_line: 18,
        spec_hash: "benchrustsqli0001".into(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
    }
}

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
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
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
        b.iter(|| sandbox::run(&harness, &payload.bytes, &opts).expect("sandbox run"));
    });
}

#[cfg(feature = "dynamic")]
fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Cold docker image pull/build.
///
/// Measures the time to ensure `python:3-slim` is present locally. On a
/// warm cache this is just an inspect call (sub-second). On a cold host it
/// includes the pull from the registry.
///
/// Registers a labelled noop measurement when Docker is absent so criterion's
/// output is never empty for this slot.
#[cfg(feature = "dynamic")]
fn bench_docker_image_build(c: &mut Criterion) {
    if !docker_available() {
        c.bench_function("docker_image_build_no_docker", |b| b.iter(|| ()));
        return;
    }
    c.bench_function("docker_image_build", |b| {
        b.iter(|| {
            // `docker pull` is idempotent and fast when image is already local.
            let _ = std::process::Command::new("docker")
                .args(["pull", "python:3-slim"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        });
    });
}

/// Warm `docker exec` reuse benchmark.
///
/// Starts a single container before the benchmark loop and measures the cost
/// of each `docker exec` call (no cold-start amortisation visible here — that
/// is visible by comparing this vs `bench_docker_payload_cost`).
#[cfg(feature = "dynamic")]
fn bench_docker_exec_warm(c: &mut Criterion) {
    if !docker_available() {
        eprintln!("bench_docker_exec_warm: docker unavailable, skipping");
        return;
    }
    // Start a long-lived container for the benchmark.
    let container = "nyx-bench-exec-warm";
    let _ = std::process::Command::new("docker")
        .args([
            "run", "-d", "--rm", "--name", container,
            "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
            "--network", "none",
            "python:3-slim", "sleep", "300",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    c.bench_function("docker_exec_warm", |b| {
        b.iter(|| {
            let _ = std::process::Command::new("docker")
                .args(["exec", container, "python3", "-c", "pass"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        });
    });

    let _ = std::process::Command::new("docker")
        .args(["stop", container])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Per-payload sandbox cost via docker backend end-to-end.
///
/// Measures the complete path: harness already built + docker backend +
/// process the sqli_positive fixture. The first call includes container
/// start; subsequent calls show exec-reuse cost.
///
/// Registers a labelled noop measurement when Docker is absent so criterion's
/// output is never empty for this slot.
#[cfg(feature = "dynamic")]
fn bench_docker_payload_cost(c: &mut Criterion) {
    if !docker_available() {
        c.bench_function("docker_payload_cost_no_docker", |b| b.iter(|| ()));
        return;
    }
    use nyx_scanner::dynamic::corpus::payloads_for;
    use nyx_scanner::dynamic::harness;
    use nyx_scanner::dynamic::sandbox::{self, SandboxBackend, SandboxOptions};

    let spec = make_sqli_spec();
    let built = harness::build(&spec).expect("harness build");
    let payloads = payloads_for(Cap::SQL_QUERY);
    let payload = payloads.iter().find(|p| !p.is_benign).expect("sqli payload");
    let opts = SandboxOptions {
        timeout: std::time::Duration::from_secs(30),
        backend: SandboxBackend::Docker,
        ..SandboxOptions::default()
    };

    c.bench_function("docker_payload_cost", |b| {
        b.iter(|| {
            let _ = sandbox::run(&built, &payload.bytes, &opts);
        });
    });
}

/// Rust harness build (source gen + disk write, no compilation).
///
/// Measures only `harness::build()` — staging files to the workdir.
/// The expensive `cargo build --release` step is NOT included here
/// (that is the province of an integration benchmark, not this microbench).
#[cfg(feature = "dynamic")]
fn bench_rust_harness_build_cold(c: &mut Criterion) {
    use nyx_scanner::dynamic::harness;
    let spec = make_rust_sqli_spec();
    c.bench_function("rust_harness_build_cold", |b| {
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
fn make_js_sqli_spec() -> HarnessSpec {
    HarnessSpec {
        finding_id: "bench_js_0001".into(),
        entry_file: "tests/dynamic_fixtures/js/sqli_positive.js".into(),
        entry_name: "login".into(),
        entry_kind: nyx_scanner::dynamic::spec::EntryKind::Function,
        lang: Lang::JavaScript,
        toolchain_id: "node-20".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::SQL_QUERY,
        constraint_hints: vec![],
        sink_file: "tests/dynamic_fixtures/js/sqli_positive.js".into(),
        sink_line: 8,
        spec_hash: "benchjssqli000001".into(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
    }
}

#[cfg(feature = "dynamic")]
fn make_go_sqli_spec() -> HarnessSpec {
    HarnessSpec {
        finding_id: "bench_go_0001".into(),
        entry_file: "tests/dynamic_fixtures/go/sqli_positive.go".into(),
        entry_name: "Login".into(),
        entry_kind: nyx_scanner::dynamic::spec::EntryKind::Function,
        lang: Lang::Go,
        toolchain_id: "go-1.21".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::SQL_QUERY,
        constraint_hints: vec![],
        sink_file: "tests/dynamic_fixtures/go/sqli_positive.go".into(),
        sink_line: 12,
        spec_hash: "benchgosqli000001".into(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
    }
}

#[cfg(feature = "dynamic")]
fn make_java_sqli_spec() -> HarnessSpec {
    HarnessSpec {
        finding_id: "bench_java_0001".into(),
        entry_file: "tests/dynamic_fixtures/java/sqli_positive.java".into(),
        entry_name: "login".into(),
        entry_kind: nyx_scanner::dynamic::spec::EntryKind::Function,
        lang: Lang::Java,
        toolchain_id: "java-21".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::SQL_QUERY,
        constraint_hints: vec![],
        sink_file: "tests/dynamic_fixtures/java/sqli_positive.java".into(),
        sink_line: 9,
        spec_hash: "benchjavasqli00001".into(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
    }
}

#[cfg(feature = "dynamic")]
fn make_php_sqli_spec() -> HarnessSpec {
    HarnessSpec {
        finding_id: "bench_php_0001".into(),
        entry_file: "tests/dynamic_fixtures/php/sqli_positive.php".into(),
        entry_name: "login".into(),
        entry_kind: nyx_scanner::dynamic::spec::EntryKind::Function,
        lang: Lang::Php,
        toolchain_id: "php-8".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::SQL_QUERY,
        constraint_hints: vec![],
        sink_file: "tests/dynamic_fixtures/php/sqli_positive.php".into(),
        sink_line: 9,
        spec_hash: "benchphpsqli000001".into(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
    }
}

/// JS harness build (source gen + disk write).
#[cfg(feature = "dynamic")]
fn bench_js_harness_build_cold(c: &mut Criterion) {
    use nyx_scanner::dynamic::harness;
    let spec = make_js_sqli_spec();
    c.bench_function("js_harness_build_cold", |b| {
        b.iter(|| {
            let workdir = std::env::temp_dir()
                .join("nyx-harness")
                .join(&spec.spec_hash);
            let _ = std::fs::remove_dir_all(&workdir);
            harness::build(&spec).expect("JS harness build")
        });
    });
}

/// Go harness build (source gen + disk write, no compilation).
#[cfg(feature = "dynamic")]
fn bench_go_harness_build_cold(c: &mut Criterion) {
    use nyx_scanner::dynamic::harness;
    let spec = make_go_sqli_spec();
    c.bench_function("go_harness_build_cold", |b| {
        b.iter(|| {
            let workdir = std::env::temp_dir()
                .join("nyx-harness")
                .join(&spec.spec_hash);
            let _ = std::fs::remove_dir_all(&workdir);
            harness::build(&spec).expect("Go harness build")
        });
    });
}

/// Java harness build (source gen + disk write, no compilation).
#[cfg(feature = "dynamic")]
fn bench_java_harness_build_cold(c: &mut Criterion) {
    use nyx_scanner::dynamic::harness;
    let spec = make_java_sqli_spec();
    c.bench_function("java_harness_build_cold", |b| {
        b.iter(|| {
            let workdir = std::env::temp_dir()
                .join("nyx-harness")
                .join(&spec.spec_hash);
            let _ = std::fs::remove_dir_all(&workdir);
            harness::build(&spec).expect("Java harness build")
        });
    });
}

/// PHP harness build (source gen + disk write).
#[cfg(feature = "dynamic")]
fn bench_php_harness_build_cold(c: &mut Criterion) {
    use nyx_scanner::dynamic::harness;
    let spec = make_php_sqli_spec();
    c.bench_function("php_harness_build_cold", |b| {
        b.iter(|| {
            let workdir = std::env::temp_dir()
                .join("nyx-harness")
                .join(&spec.spec_hash);
            let _ = std::fs::remove_dir_all(&workdir);
            harness::build(&spec).expect("PHP harness build")
        });
    });
}

#[cfg(feature = "dynamic")]
fn mk_chain_member(hash: u64, idx: usize) -> nyx_scanner::chain::FindingRef {
    use nyx_scanner::surface::SourceLocation;
    nyx_scanner::chain::FindingRef {
        finding_id: format!("bench-chain-member-{idx}"),
        stable_hash: hash,
        location: SourceLocation::new("bench/synthetic.py", (idx as u32) + 1, 1),
        rule_id: "taint-unsanitised-flow".into(),
        cap_bits: 0,
    }
}

#[cfg(feature = "dynamic")]
fn mk_synthetic_chain(hash: u64, members: usize) -> nyx_scanner::chain::ChainFinding {
    use nyx_scanner::chain::{ChainFinding, ChainSeverity, ChainSink, ImpactCategory};
    ChainFinding {
        stable_hash: hash,
        members: (0..members)
            .map(|i| mk_chain_member(hash.wrapping_add(i as u64 + 1), i))
            .collect(),
        sink: ChainSink {
            file: "bench/synthetic.py".into(),
            line: 99,
            col: 1,
            function_name: "sink".into(),
            cap_bits: 0,
        },
        implied_impact: ImpactCategory::Rce,
        severity: ChainSeverity::Critical,
        score: 100.0,
        dynamic_verdict: None,
        reverify_reason: None,
    }
}

#[cfg(feature = "dynamic")]
struct BenchConfirmedReverifier;

#[cfg(feature = "dynamic")]
impl nyx_scanner::chain::CompositeReverifier for BenchConfirmedReverifier {
    fn reverify(
        &self,
        _chain: &nyx_scanner::chain::ChainFinding,
        _member_diags: &[nyx_scanner::commands::scan::Diag],
        _surface: &nyx_scanner::surface::SurfaceMap,
        _opts: &nyx_scanner::dynamic::verify::VerifyOptions,
    ) -> nyx_scanner::evidence::VerifyResult {
        nyx_scanner::evidence::VerifyResult {
            finding_id: "bench".into(),
            status: nyx_scanner::evidence::VerifyStatus::Confirmed,
            triggered_payload: None,
            reason: None,
            inconclusive_reason: None,
            detail: None,
            attempts: vec![],
            toolchain_match: None,
            differential: None,
            replay_stable: None,
            wrong: None,
            hardening_outcome: None,
        }
    }
}

/// Phase 26 dispatch-cost anchor: synthetic 3-member chain with no
/// matching member diags. The reverifier walks chain_step_specs (3
/// HashMap misses → 3 NoFlowSteps errors), the build loop sees zero
/// derived specs and exits early, the run loop sees zero built steps
/// and exits early. The composed VerifyResult is allocated and applied
/// via `apply_dynamic_verdict` (Inconclusive → severity downgrade).
///
/// This is the no-toolchain-dep dispatch overhead — a regression here
/// signals a hot-path allocation introduced into the reverify pipeline.
#[cfg(feature = "dynamic")]
fn bench_composite_chain_reverify_dispatch(c: &mut Criterion) {
    use nyx_scanner::chain::reverify;
    use nyx_scanner::dynamic::verify::VerifyOptions;
    use nyx_scanner::surface::SurfaceMap;

    let surface = SurfaceMap::new();
    let opts = VerifyOptions::default();

    c.bench_function("composite_chain_reverify_dispatch", |b| {
        b.iter(|| {
            let mut chains = [mk_synthetic_chain(0xC1A1, 3)];
            let _ = reverify::reverify_top_chains(&mut chains, &[], &surface, &opts, 1);
        });
    });
}

/// Phase 26 stub-reverifier happy-path anchor: synthetic 3-member
/// chain driven through `reverify_top_chains_with` + a stubbed
/// reverifier returning `Confirmed`. Measures the apply-verdict path
/// when the verdict does NOT trigger a severity downgrade, so the
/// `ChainReverifyResult` allocation + `chain.apply_dynamic_verdict`
/// transition cost is exercised independent of the verdict-side
/// allocation in the dispatch bench.
#[cfg(feature = "dynamic")]
fn bench_composite_chain_reverify_stub_confirmed(c: &mut Criterion) {
    use nyx_scanner::chain::reverify;
    use nyx_scanner::dynamic::verify::VerifyOptions;
    use nyx_scanner::surface::SurfaceMap;

    let surface = SurfaceMap::new();
    let opts = VerifyOptions::default();
    let reverifier = BenchConfirmedReverifier;

    c.bench_function("composite_chain_reverify_stub_confirmed", |b| {
        b.iter(|| {
            let mut chains = [mk_synthetic_chain(0xC2A2, 3)];
            let _ = reverify::reverify_top_chains_with(
                &mut chains,
                &[],
                &surface,
                &opts,
                1,
                &reverifier,
            );
        });
    });
}

/// Phase 26 top-N slice anchor: 5-chain slice with `top_n=3`. Asserts
/// (by way of regression) that the reverify pass never walks past the
/// top-N prefix. The fan-in is the per-chain dispatch cost times three;
/// a regression that drops the `bound = top_n.min(chains.len())` cap
/// would show up as a ~5/3 increase in this bench.
#[cfg(feature = "dynamic")]
fn bench_composite_chain_reverify_top_n_slice(c: &mut Criterion) {
    use nyx_scanner::chain::reverify;
    use nyx_scanner::dynamic::verify::VerifyOptions;
    use nyx_scanner::surface::SurfaceMap;

    let surface = SurfaceMap::new();
    let opts = VerifyOptions::default();
    let reverifier = BenchConfirmedReverifier;

    c.bench_function("composite_chain_reverify_top_n_slice", |b| {
        b.iter(|| {
            let mut chains: [nyx_scanner::chain::ChainFinding; 5] = [
                mk_synthetic_chain(0xC301, 3),
                mk_synthetic_chain(0xC302, 3),
                mk_synthetic_chain(0xC303, 3),
                mk_synthetic_chain(0xC304, 3),
                mk_synthetic_chain(0xC305, 3),
            ];
            let _ = reverify::reverify_top_chains_with(
                &mut chains,
                &[],
                &surface,
                &opts,
                3,
                &reverifier,
            );
        });
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
    bench_docker_image_build,
    bench_docker_exec_warm,
    bench_docker_payload_cost,
    bench_rust_harness_build_cold,
    bench_js_harness_build_cold,
    bench_go_harness_build_cold,
    bench_java_harness_build_cold,
    bench_php_harness_build_cold,
    bench_composite_chain_reverify_dispatch,
    bench_composite_chain_reverify_stub_confirmed,
    bench_composite_chain_reverify_top_n_slice,
);

#[cfg(not(feature = "dynamic"))]
criterion_group!(dynamic, bench_noop);

criterion_main!(dynamic);
