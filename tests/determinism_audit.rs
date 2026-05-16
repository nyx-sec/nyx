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
