//! Phase 27 — Track H.1 integration test.
//!
//! Locks in the on-disk telemetry schema contract that `scripts/m7_ship_gate.sh`
//! Gate 2 relies on:
//!
//! - Records produced today carry the `schema_version`, `nyx_version`, and
//!   `corpus_version` envelope fields, plus a `kind` discriminator.
//! - `read_events(path)` accepts the current schema.
//! - A hand-crafted record with `schema_version: 0` is rejected by
//!   `read_events` with a typed [`TelemetryReadError::SchemaMismatch`] (this
//!   is the explicit Phase 27 acceptance bullet).
//! - The sampling policy retains Confirmed and Inconclusive verdicts even at
//!   `sample_rate_other = 0.0`.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::telemetry::{
    self, RankDeltaEvent, SamplingPolicy, TelemetryEvent, TelemetryReadError, CORPUS_VERSION,
    NYX_VERSION, SCHEMA_VERSION,
};
use nyx_scanner::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot, SpecDerivationStrategy};
use nyx_scanner::evidence::VerifyStatus;
use nyx_scanner::labels::Cap;
use nyx_scanner::symbol::Lang;
use std::time::Duration;
use tempfile::TempDir;

fn make_spec(hash: &str) -> HarnessSpec {
    HarnessSpec {
        finding_id: "0000000000000001".into(),
        entry_file: "handler.py".into(),
        entry_name: "handle".into(),
        entry_kind: EntryKind::Function,
        lang: Lang::Python,
        toolchain_id: "python-3.11".into(),
        payload_slot: PayloadSlot::Param(0),
        expected_cap: Cap::SQL_QUERY,
        constraint_hints: vec![],
        sink_file: "handler.py".into(),
        sink_line: 5,
        spec_hash: hash.into(),
        derivation: SpecDerivationStrategy::FromFlowSteps,
        stubs_required: vec![],
    }
}

#[test]
fn current_record_carries_envelope_fields() {
    let event = TelemetryEvent::new(
        &make_spec("abcd1234"),
        VerifyStatus::Confirmed,
        None,
        "exact",
        Duration::from_millis(7),
        1,
    );
    let v: serde_json::Value = serde_json::to_value(&event).unwrap();
    assert_eq!(v["schema_version"], SCHEMA_VERSION);
    assert_eq!(v["nyx_version"], NYX_VERSION);
    assert_eq!(v["corpus_version"], CORPUS_VERSION);
    assert_eq!(v["kind"], "verdict");

    let rank = RankDeltaEvent::new("a".into(), "Confirmed".into(), 2.0);
    let v: serde_json::Value = serde_json::to_value(&rank).unwrap();
    assert_eq!(v["schema_version"], SCHEMA_VERSION);
    assert_eq!(v["kind"], "rank_delta");
}

#[test]
fn read_events_accepts_current_schema() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut content = String::new();
    for i in 0..3 {
        let event = TelemetryEvent::new(
            &make_spec(&format!("hash{i}")),
            VerifyStatus::Confirmed,
            None,
            "exact",
            Duration::from_millis(1),
            1,
        );
        content.push_str(&serde_json::to_string(&event).unwrap());
        content.push('\n');
    }
    std::fs::write(&log, content).unwrap();

    let records = telemetry::read_events(&log).unwrap();
    assert_eq!(records.len(), 3);
    for r in &records {
        assert_eq!(r["schema_version"], SCHEMA_VERSION);
    }
}

#[test]
fn read_events_rejects_schema_zero_record() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("events.jsonl");
    // Hand-crafted v0 record — exactly the case the Phase 27 acceptance pins.
    std::fs::write(
        &log,
        "{\"schema_version\":0,\"kind\":\"verdict\",\"status\":\"Confirmed\"}\n",
    )
    .unwrap();

    let err = telemetry::read_events(&log).expect_err("schema 0 must be rejected");
    match err {
        TelemetryReadError::SchemaMismatch {
            expected, found, ..
        } => {
            assert_eq!(expected, SCHEMA_VERSION);
            assert_eq!(found, 0);
        }
        other => panic!("expected SchemaMismatch, got {other:?}"),
    }
}

#[test]
fn read_events_rejects_mixed_schema_record_inside_valid_log() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("events.jsonl");
    let good = serde_json::to_string(&TelemetryEvent::new(
        &make_spec("good"),
        VerifyStatus::Confirmed,
        None,
        "exact",
        Duration::from_millis(1),
        1,
    ))
    .unwrap();
    let bad = "{\"schema_version\":0,\"kind\":\"verdict\"}";
    std::fs::write(&log, format!("{good}\n{bad}\n")).unwrap();

    match telemetry::read_events(&log).unwrap_err() {
        TelemetryReadError::SchemaMismatch { line, found, .. } => {
            assert_eq!(line, 2);
            assert_eq!(found, 0);
        }
        other => panic!("expected SchemaMismatch on line 2, got {other:?}"),
    }
}

#[test]
fn sampling_policy_retains_confirmed_and_inconclusive() {
    let strict = SamplingPolicy {
        keep_all_confirmed: true,
        keep_all_inconclusive: true,
        sample_rate_other: 0.0,
    };
    for hash in ["a", "b", "spec-1234", "deadbeef"] {
        assert!(strict.should_sample(VerifyStatus::Confirmed, hash));
        assert!(strict.should_sample(VerifyStatus::Inconclusive, hash));
        assert!(!strict.should_sample(VerifyStatus::NotConfirmed, hash));
        assert!(!strict.should_sample(VerifyStatus::Unsupported, hash));
    }
}

#[test]
fn sampling_policy_is_deterministic_across_runs() {
    let policy = SamplingPolicy {
        keep_all_confirmed: false,
        keep_all_inconclusive: false,
        sample_rate_other: 0.5,
    };
    let mut snapshot: Vec<(String, bool)> = Vec::new();
    for i in 0..50 {
        let hash = format!("spec-{i:08x}");
        let kept = policy.should_sample(VerifyStatus::NotConfirmed, &hash);
        snapshot.push((hash, kept));
    }
    // Re-evaluate; every decision must match the first pass.
    for (hash, expected) in &snapshot {
        assert_eq!(
            *expected,
            policy.should_sample(VerifyStatus::NotConfirmed, hash),
            "sampling decision flipped for spec_hash={hash}"
        );
    }
}
