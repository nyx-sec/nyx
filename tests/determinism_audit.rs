//! Phase 30 (Track C — determinism): run the verifier 10× on the same
//! input and assert byte-identical [`VerifyTrace`] output across runs,
//! plus byte-identical telemetry records once wall-clock fields are
//! stripped.
//!
//! The test deliberately drives the policy-deny short-circuit so it
//! does not depend on a working language toolchain, a sandbox backend,
//! or a populated payload corpus.  That path emits exactly the same
//! pipeline events ([`SpecStarted`], [`Verdict`]) every run, and
//! emits a single telemetry record whose only non-deterministic field
//! is the wall-clock `ts` timestamp.  Stripping `ts` gives a stable
//! envelope the test can compare directly.

#![cfg(feature = "dynamic")]

use nyx_scanner::commands::scan::Diag;
use nyx_scanner::dynamic::telemetry::{self, SamplingPolicy};
use nyx_scanner::dynamic::verify::{verify_finding, VerifyOptions};
use nyx_scanner::evidence::{Confidence, Evidence, VerifyStatus};
use nyx_scanner::patterns::{FindingCategory, Severity};
use serde_json::Value;
use std::collections::BTreeSet;

const RUN_COUNT: usize = 10;

fn deny_diag(stable_hash: u64) -> Diag {
    let mut ev = Evidence::default();
    // Triggers the credentials deny rule via the AWS-key regex from
    // `crate::utils::redact::contains_secret`.  The deny rule fires
    // deterministically because the rule lookup table is `const`.
    ev.notes = vec!["secret=AKIAFAKEDETERM00000000".to_owned()];
    Diag {
        path: "src/handler.py".to_owned(),
        line: 42,
        col: 0,
        severity: Severity::High,
        id: "py.cmdi.os_system".to_owned(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: Some(Confidence::High),
        evidence: Some(ev),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: vec![],
        stable_hash,
    }
}

/// Strip every non-deterministic field from a parsed telemetry record
/// and re-serialise.  Phase 30 acceptance explicitly excludes wall-clock
/// timestamps; `ts` is the only such field today.  Future additions
/// belong in this filter so the canonical "what does deterministic
/// telemetry look like?" surface lives in one place.
fn strip_volatile_fields(line: &str) -> String {
    let mut value: Value = serde_json::from_str(line).expect("telemetry line should be JSON");
    if let Some(obj) = value.as_object_mut() {
        obj.remove("ts");
        // `duration_ms` is zero on the no-sandbox deny path, but strip
        // it defensively so the audit stays correct if a future code
        // path stamps a non-zero duration before the verdict short-
        // circuits.
        obj.remove("duration_ms");
    }
    serde_json::to_string(&value).expect("re-serialisation cannot fail")
}

#[test]
fn ten_runs_produce_byte_identical_telemetry_minus_timestamps() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let log = tmp.path().join("events.jsonl");
    // Pin the telemetry log to the temp file and ensure the
    // `NYX_NO_TELEMETRY` opt-out is not set in this process.
    unsafe {
        std::env::set_var("NYX_TELEMETRY_PATH", &log);
        std::env::remove_var("NYX_NO_TELEMETRY");
    }

    let diag = deny_diag(0x0123_4567_89ab_cdef);

    let mut opts = VerifyOptions::default();
    opts.telemetry_policy = SamplingPolicy::keep_all();
    opts.trace_verbose = false;

    let mut verdict_jsons: BTreeSet<String> = BTreeSet::new();
    for _ in 0..RUN_COUNT {
        let result = verify_finding(&diag, &opts);
        assert_eq!(result.status, VerifyStatus::Inconclusive);
        // Drop `differential` and any future timestamped field by
        // round-tripping through serde; structural equality is the
        // contract.
        verdict_jsons.insert(
            serde_json::to_string(&result)
                .expect("VerifyResult serialises"),
        );
    }
    assert_eq!(
        verdict_jsons.len(),
        1,
        "VerifyResult must be byte-identical across {RUN_COUNT} runs, got {} distinct",
        verdict_jsons.len()
    );

    // Read the telemetry log; expect RUN_COUNT lines, all identical
    // once `ts` is removed.
    let parsed = telemetry::read_events(&log).expect("events.jsonl should parse");
    assert_eq!(
        parsed.len(),
        RUN_COUNT,
        "expected {RUN_COUNT} telemetry records, got {}",
        parsed.len()
    );
    let stripped: BTreeSet<String> = parsed
        .iter()
        .map(|v| {
            // round-trip through string so the strip path matches
            // what the on-disk reader does.
            let line = serde_json::to_string(v).expect("re-serialise");
            strip_volatile_fields(&line)
        })
        .collect();
    assert_eq!(
        stripped.len(),
        1,
        "telemetry records must be byte-identical (sans ts/duration_ms) across {RUN_COUNT} runs, got {} distinct: {:?}",
        stripped.len(),
        stripped
    );

    // Cleanup: leave the env var pointing at the (about-to-be-deleted)
    // tempdir would poison sibling tests that share this process.
    unsafe {
        std::env::remove_var("NYX_TELEMETRY_PATH");
    }
}

/// Recursively strip volatile fields from a `serde_json::Value` tree.
/// The Confirmed-path `VerifyResult` carries timing fields buried under
/// `differential.vuln_probes[].captured_at_ns` etc., so a flat top-level
/// `obj.remove(...)` is not enough.
///
/// Field denylist:
///   - `captured_at_ns` — wall-clock probe capture timestamp.
///   - `ts` / `duration_ms` — telemetry-side timing fields stripped by
///     [`strip_volatile_fields`] but worth re-stripping here too in case
///     a future code path lands them on `VerifyResult` directly.
///   - `repro_bundle` / `bundle_dir` — `NYX_REPRO_BASE` is fed an
///     in-test-tempdir whose path is stable across the loop, but the
///     hashed sub-directory name folds in any per-run randomness; strip
///     defensively.
#[cfg(target_os = "macos")]
fn strip_volatile_recursive(value: &mut Value) {
    const VOLATILE_KEYS: &[&str] = &[
        "captured_at_ns",
        "ts",
        "duration_ms",
        "repro_bundle",
        "bundle_dir",
    ];
    match value {
        Value::Object(map) => {
            for key in VOLATILE_KEYS {
                map.remove(*key);
            }
            for (_, v) in map.iter_mut() {
                strip_volatile_recursive(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_volatile_recursive(v);
            }
        }
        _ => {}
    }
}

/// Confirmed-path determinism: drive the verifier through a real
/// payload run (macOS process backend + sandbox-exec wrap + python3
/// harness) `RUN_COUNT_CONFIRMED` times and assert byte-identical
/// `VerifyResult` once volatile timing fields are stripped.
///
/// Mirrors [`ten_runs_produce_byte_identical_telemetry_minus_timestamps`]
/// (the deny-path determinism contract) but exercises the build →
/// sandbox → probe pipeline instead of the policy-deny short-circuit.
/// Closes the determinism audit's "complete coverage needs an end-to-end
/// Confirmed run" gap.
///
/// macOS-only: the Linux process backend needs `cc -static` + libc.a to
/// drive the C fixture through chroot, and `cc -static` is unsupported
/// by the Darwin clang shipped with Xcode.  The Linux row's analogue
/// lands when the Phase 17 follow-up's `bind_mount_host_libs` opt-in
/// wiring (see `deferred.md`) lets the python harness survive chroot.
///
/// `RUN_COUNT_CONFIRMED = 3` keeps the test cost bounded (~6s per run
/// on a warm cache → ~20s total) while still gating against single-run
/// hash collisions that would flake at N=2.  Bumping to N=10 (matching
/// the deny-path test) is a wall-clock decision, not a coverage one.
#[cfg(all(feature = "dynamic", target_os = "macos"))]
#[test]
fn confirmed_run_is_byte_identical_across_runs() {
    use nyx_scanner::evidence::{FlowStep, FlowStepKind};
    use nyx_scanner::labels::Cap;
    use nyx_scanner::utils::config::Config;
    use std::path::PathBuf;

    const RUN_COUNT_CONFIRMED: usize = 3;

    // Pre-flight skips: the macOS process backend needs the sandbox-exec
    // wrap binary + a working python3 to drive the cmdi_positive fixture.
    if !std::path::Path::new("/usr/bin/sandbox-exec").exists() {
        eprintln!("SKIP: /usr/bin/sandbox-exec missing — cannot exercise process-backend wrap");
        return;
    }
    if !std::process::Command::new("/usr/bin/python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: /usr/bin/python3 missing — cannot run python harness");
        return;
    }

    let fixture_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dynamic_fixtures/python/cmdi_positive.py");

    let tmp = tempfile::TempDir::new().expect("create tempdir");
    let dst = tmp.path().join("cmdi_positive.py");
    std::fs::copy(&fixture_src, &dst).expect("stage fixture into tempdir");

    // Pin the repro bundle + telemetry log to in-test tempdir paths so
    // every run reads + writes the same absolute paths (the per-run path
    // would otherwise leak into VerifyResult and break determinism).
    unsafe {
        std::env::set_var(
            "NYX_REPRO_BASE",
            tmp.path().join("repro").to_str().unwrap(),
        );
        std::env::set_var(
            "NYX_TELEMETRY_PATH",
            tmp.path().join("events.jsonl").to_str().unwrap(),
        );
        std::env::remove_var("NYX_NO_TELEMETRY");
    }

    let path_str = dst.to_string_lossy().into_owned();
    let evidence = Evidence {
        flow_steps: vec![
            FlowStep {
                step: 1,
                kind: FlowStepKind::Source,
                file: path_str.clone(),
                line: 1,
                col: 0,
                snippet: None,
                variable: Some("host".into()),
                callee: None,
                function: Some("run_ping".into()),
                is_cross_file: false,
            },
            FlowStep {
                step: 2,
                kind: FlowStepKind::Sink,
                file: path_str.clone(),
                line: 13,
                col: 4,
                snippet: None,
                variable: None,
                callee: None,
                function: None,
                is_cross_file: false,
            },
        ],
        sink_caps: Cap::CODE_EXEC.bits(),
        ..Default::default()
    };
    let diag = Diag {
        path: path_str,
        line: 13,
        col: 0,
        severity: Severity::High,
        id: "taint-unsanitised-flow".into(),
        category: FindingCategory::Security,
        path_validated: false,
        guard_kind: None,
        message: None,
        labels: vec![],
        confidence: Some(Confidence::High),
        evidence: Some(evidence),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: vec![],
        stable_hash: 0xdec0_de00_dec0_de00,
    };

    let mut config = Config::default();
    config.scanner.harden_profile = "strict".to_owned();
    // Force the process backend: Auto would route python to docker on
    // CI hosts where docker is reachable, and docker ignores the
    // hardening profile.  Pinning to `process` exercises the sandbox-
    // exec wrap on every run, which is the surface the determinism
    // contract covers.
    config.scanner.verify_backend = "process".to_owned();
    let mut opts = VerifyOptions::from_config(&config);
    opts.telemetry_policy = SamplingPolicy::keep_all();
    opts.trace_verbose = false;

    let mut stripped: BTreeSet<String> = BTreeSet::new();
    for i in 0..RUN_COUNT_CONFIRMED {
        let result = verify_finding(&diag, &opts);
        assert_eq!(
            result.status,
            VerifyStatus::Confirmed,
            "run {i}: cmdi_positive.py under --harden=strict must Confirm — got {:?} (detail={:?})",
            result.status,
            result.detail,
        );
        let mut json: Value =
            serde_json::from_str(&serde_json::to_string(&result).expect("VerifyResult serialises"))
                .expect("re-parse");
        strip_volatile_recursive(&mut json);
        stripped.insert(json.to_string());
    }

    assert_eq!(
        stripped.len(),
        1,
        "VerifyResult must be byte-identical across {RUN_COUNT_CONFIRMED} runs once volatile \
         timing fields are stripped; got {} distinct values: {:?}",
        stripped.len(),
        stripped,
    );

    unsafe {
        std::env::remove_var("NYX_REPRO_BASE");
        std::env::remove_var("NYX_TELEMETRY_PATH");
    }
}

#[test]
fn policy_deny_excerpt_is_stable_across_runs() {
    // The PolicyDeniedDynamic verdict carries an excerpt scrubbed via
    // the blake3-keyed `Scrubber`.  blake3 is deterministic, so the
    // excerpt should be byte-identical across runs.  Independent
    // assertion from the telemetry-determinism test because the
    // scrubber-hash path is a separate determinism contract worth
    // pinning on its own.
    let diag = deny_diag(0xfeed_face_0123_4567);
    let opts = VerifyOptions::default();

    let mut excerpts: BTreeSet<String> = BTreeSet::new();
    for _ in 0..RUN_COUNT {
        let result = verify_finding(&diag, &opts);
        match result
            .inconclusive_reason
            .expect("expected PolicyDeniedDynamic on deny path")
        {
            nyx_scanner::evidence::InconclusiveReason::PolicyDeniedDynamic {
                excerpt,
                ..
            } => {
                excerpts.insert(excerpt);
            }
            other => panic!("expected PolicyDeniedDynamic, got {other:?}"),
        }
    }
    assert_eq!(
        excerpts.len(),
        1,
        "scrubbed excerpt must be deterministic across {RUN_COUNT} runs, got {excerpts:?}"
    );
}
