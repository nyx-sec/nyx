/// Dynamic verification benchmarks (§8.4).
///
/// Tracks six cost anchors:
///
/// 1. `harness_build_cold` — fresh workdir, spec → BuiltHarness (source gen + disk write).
/// 2. `harness_build_warm` — same spec, workdir already staged (file write skipped).
/// 3. `sandbox_run_payload` — single payload run via process backend against
///    sqli_positive.py (subprocess + settrace overhead, no networking).
/// 4. `docker_image_build` — cold image pull/build for the python:3-slim base.
/// 5. `docker_exec_warm` — `docker exec` into a running container (no cold start).
/// 6. `docker_payload_cost` — per-payload sandbox cost via docker backend end-to-end.
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
);

#[cfg(not(feature = "dynamic"))]
criterion_group!(dynamic, bench_noop);

criterion_main!(dynamic);
