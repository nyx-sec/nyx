//! Phase 10 (Track D.3) — boundary-stub providers, one positive +
//! one benign per stub kind.
//!
//! Each test wires a [`StubProvider`] to the corresponding fixture's
//! `vuln.txt` / `benign.txt` and asserts that the oracle confirms
//! only when the recorded event matches the kind-specific needle.
//! Synthesises harness behaviour with host-side `record_*` helpers
//! so the suite runs without spawning a language toolchain; the
//! shape mirrors what a real harness would do once the per-language
//! `__nyx_probe` shims gain stub-aware wrappers.
//!
//! Acceptance bullets from `plan.md` phase 10:
//!
//! > `cargo nextest run --features dynamic --test stubs_per_cap` green.
//! > SQL-cap fixture confirms with the captured query visible in the
//! > probe output.
//! > Harness with `stubs_required: []` boots in under 500ms.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::oracle::{
    oracle_fired_with_stubs, Oracle, ProbePredicate,
};
use nyx_scanner::dynamic::probe::{ProbeArg, ProbeChannel, SinkProbe};
use nyx_scanner::dynamic::sandbox::SandboxOutcome;
use nyx_scanner::dynamic::stubs::{
    FilesystemStub, HttpStub, RedisStub, SqlStub, StubHarness, StubKind, StubProvider,
};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

fn fixture_path(stub_dir: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("dynamic_fixtures")
        .join("stubs")
        .join(stub_dir)
        .join(name)
}

fn read_fixture(stub_dir: &str, name: &str) -> String {
    std::fs::read_to_string(fixture_path(stub_dir, name))
        .unwrap_or_else(|e| panic!("read fixture {stub_dir}/{name}: {e}"))
}

/// Extract the last non-comment, non-blank line.  Fixture comments
/// begin with `//`; the payload is the surviving line.
fn extract_payload(s: &str) -> String {
    s.lines()
        .rfind(|l| !l.trim().is_empty() && !l.trim_start().starts_with("//"))
        .unwrap_or("")
        .trim()
        .to_owned()
}

fn empty_outcome() -> SandboxOutcome {
    SandboxOutcome {
        exit_code: Some(0),
        stdout: vec![],
        stderr: vec![],
        timed_out: false,
        oob_callback_seen: false,
        sink_hit: true,
        duration: Duration::from_millis(1),
        hardening_outcome: None,
    }
}

// ── SQL stub ─────────────────────────────────────────────────────────

#[test]
fn sql_stub_vuln_fixture_confirms_with_captured_query() {
    let dir = TempDir::new().unwrap();
    let stub = SqlStub::start(dir.path()).unwrap();

    // Synthetic harness: read the vuln fixture, record the executed
    // query against the stub, then evaluate the oracle.
    let payload = extract_payload(&read_fixture("sql", "vuln.txt"));
    assert!(payload.contains("OR 1=1"), "vuln fixture must carry a tautology");
    stub.record_query(&payload).unwrap();

    let oracle = Oracle::StubEvent {
        kind: StubKind::Sql,
        needle: "OR 1=1",
    };
    let events = stub.drain_events();
    assert_eq!(events.len(), 1, "stub must have captured the executed query");
    assert!(
        events[0].summary.contains("OR 1=1"),
        "captured query must be visible in probe output: {:?}",
        events[0].summary,
    );
    assert!(
        oracle_fired_with_stubs(&oracle, &empty_outcome(), &[], &events),
        "SQL stub oracle must confirm the captured tautology",
    );
}

#[test]
fn sql_stub_benign_fixture_does_not_confirm() {
    let dir = TempDir::new().unwrap();
    let stub = SqlStub::start(dir.path()).unwrap();

    let payload = extract_payload(&read_fixture("sql", "benign.txt"));
    assert!(!payload.contains("OR 1=1"), "benign control must lack tautology");
    stub.record_query(&payload).unwrap();

    let oracle = Oracle::StubEvent {
        kind: StubKind::Sql,
        needle: "OR 1=1",
    };
    let events = stub.drain_events();
    assert!(
        !oracle_fired_with_stubs(&oracle, &empty_outcome(), &[], &events),
        "benign control must not satisfy the oracle",
    );
}

#[test]
fn sql_stub_captured_query_threads_through_probe_predicate() {
    // The plan calls for `ProbePredicate::StubEventMatches` as a
    // cross-cutting predicate inside `Oracle::SinkProbe`.  Confirm
    // the predicate path fires with the same fixture.
    let dir = TempDir::new().unwrap();
    let stub = SqlStub::start(dir.path()).unwrap();
    let payload = extract_payload(&read_fixture("sql", "vuln.txt"));
    stub.record_query(&payload).unwrap();
    let events = stub.drain_events();

    // Pair the stub-event check with a per-probe `CalleeEquals` so
    // we exercise the predicate-partition path in
    // `oracle_fired_with_stubs`.
    let probe = SinkProbe {
        sink_callee: "sqlite3.execute".into(),
        args: vec![ProbeArg::String(payload.clone())],
        captured_at_ns: 1,
        payload_id: "sql-tautology".into(),
        kind: Default::default(),
        witness: Default::default(),
    };
    let oracle = Oracle::SinkProbe {
        predicates: &[
            ProbePredicate::CalleeEquals("sqlite3.execute"),
            ProbePredicate::StubEventMatches {
                kind: StubKind::Sql,
                needle: "OR 1=1",
            },
        ],
    };
    assert!(
        oracle_fired_with_stubs(&oracle, &empty_outcome(), &[probe], &events),
        "ProbePredicate::StubEventMatches must satisfy when stub log has needle",
    );
}

// ── HTTP stub ────────────────────────────────────────────────────────

#[test]
fn http_stub_vuln_fixture_confirms_recorded_request() {
    let workdir = TempDir::new().unwrap();
    let stub = HttpStub::start(workdir.path()).unwrap();
    let payload = extract_payload(&read_fixture("http", "vuln.txt"));
    assert!(payload.contains("169.254"), "vuln fixture must carry metadata host");

    stub.record(payload.clone());
    let events = stub.drain_events();
    assert_eq!(events.len(), 1);
    assert!(events[0].summary.contains("169.254"));

    let oracle = Oracle::StubEvent {
        kind: StubKind::Http,
        needle: "169.254",
    };
    assert!(oracle_fired_with_stubs(&oracle, &empty_outcome(), &[], &events));
}

#[test]
fn http_stub_benign_fixture_does_not_confirm() {
    let workdir = TempDir::new().unwrap();
    let stub = HttpStub::start(workdir.path()).unwrap();
    let payload = extract_payload(&read_fixture("http", "benign.txt"));
    stub.record(payload);
    let events = stub.drain_events();

    let oracle = Oracle::StubEvent {
        kind: StubKind::Http,
        needle: "169.254",
    };
    assert!(!oracle_fired_with_stubs(&oracle, &empty_outcome(), &[], &events));
}

// ── Redis stub ───────────────────────────────────────────────────────

#[test]
fn redis_stub_vuln_fixture_confirms_destructive_command() {
    let stub = RedisStub::start().unwrap();
    let payload = extract_payload(&read_fixture("redis", "vuln.txt"));
    assert!(payload.contains("FLUSHALL"));
    stub.record(payload, &[]);

    let events = stub.drain_events();
    let oracle = Oracle::StubEvent {
        kind: StubKind::Redis,
        needle: "FLUSHALL",
    };
    assert!(oracle_fired_with_stubs(&oracle, &empty_outcome(), &[], &events));
}

#[test]
fn redis_stub_benign_fixture_does_not_confirm() {
    let stub = RedisStub::start().unwrap();
    let payload = extract_payload(&read_fixture("redis", "benign.txt"));
    let mut parts = payload.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let args: Vec<&str> = parts.collect();
    stub.record(cmd, &args);
    let events = stub.drain_events();

    let oracle = Oracle::StubEvent {
        kind: StubKind::Redis,
        needle: "FLUSHALL",
    };
    assert!(!oracle_fired_with_stubs(&oracle, &empty_outcome(), &[], &events));
}

// ── Filesystem stub ──────────────────────────────────────────────────

#[test]
fn filesystem_stub_vuln_fixture_confirms_path_traversal() {
    let dir = TempDir::new().unwrap();
    let stub = FilesystemStub::start(dir.path()).unwrap();
    let payload = extract_payload(&read_fixture("filesystem", "vuln.txt"));
    let (op, path) = payload.split_once(' ').unwrap_or(("read", &payload));
    stub.record_access(op, path);

    let events = stub.drain_events();
    let oracle = Oracle::StubEvent {
        kind: StubKind::Filesystem,
        needle: "/etc/passwd",
    };
    assert!(oracle_fired_with_stubs(&oracle, &empty_outcome(), &[], &events));
}

#[test]
fn filesystem_stub_benign_fixture_does_not_confirm() {
    let dir = TempDir::new().unwrap();
    let stub = FilesystemStub::start(dir.path()).unwrap();
    let payload = extract_payload(&read_fixture("filesystem", "benign.txt"));
    let (op, path) = payload.split_once(' ').unwrap_or(("read", &payload));
    stub.record_access(op, path);

    let events = stub.drain_events();
    let oracle = Oracle::StubEvent {
        kind: StubKind::Filesystem,
        needle: "/etc/passwd",
    };
    assert!(!oracle_fired_with_stubs(&oracle, &empty_outcome(), &[], &events));
}

// ── Performance invariant ────────────────────────────────────────────

#[test]
fn empty_stubs_required_boots_under_500ms() {
    // Phase 10 acceptance bullet: "Harness with `stubs_required: []`
    // boots in under 500ms (performance invariant from cross-cutting
    // concerns)."  Direct measurement on `StubHarness::start`.
    let dir = TempDir::new().unwrap();
    let start = std::time::Instant::now();
    let h = StubHarness::start(&[], dir.path()).unwrap();
    let elapsed = start.elapsed();
    assert!(h.is_empty());
    assert!(
        elapsed < Duration::from_millis(500),
        "stubs_required=[] must boot in <500ms, took {elapsed:?}",
    );
}

#[test]
fn harness_endpoints_carry_well_known_env_names() {
    // Pull every stub kind so the test asserts the full mapping in
    // `StubKind::env_var` survives at the aggregator level.
    let dir = TempDir::new().unwrap();
    let h = StubHarness::start(
        &[
            StubKind::Sql,
            StubKind::Http,
            StubKind::Redis,
            StubKind::Filesystem,
        ],
        dir.path(),
    )
    .unwrap();
    let names: Vec<&str> = h.endpoints().iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"NYX_SQL_ENDPOINT"));
    assert!(names.contains(&"NYX_HTTP_ENDPOINT"));
    assert!(names.contains(&"NYX_REDIS_ENDPOINT"));
    assert!(names.contains(&"NYX_FS_ROOT"));
}

#[test]
fn drained_events_are_kind_tagged() {
    // Cross-stub drain: when a harness aggregates multiple stubs,
    // each drained event must carry its source kind so the oracle's
    // `StubEventMatches { kind, .. }` filter works without external
    // bookkeeping.
    let dir = TempDir::new().unwrap();
    let sql = SqlStub::start(dir.path()).unwrap();
    let fs = FilesystemStub::start(dir.path()).unwrap();
    sql.record_query("SELECT 1").unwrap();
    fs.record_access("read", "/tmp/x");

    let mut all = sql.drain_events();
    all.extend(fs.drain_events());
    let kinds: Vec<StubKind> = all.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&StubKind::Sql));
    assert!(kinds.contains(&StubKind::Filesystem));
}

#[test]
fn sql_stub_captured_query_visible_in_probe_output() {
    // The plan's literal phrasing: "SQL-cap fixture confirms with the
    // captured query visible in the probe output."  Verify that the
    // recorded query lands inside a serialisable probe-shaped record
    // (`StubEvent` round-trips through serde) so downstream tooling
    // can render the captured query alongside per-probe args.
    let dir = TempDir::new().unwrap();
    let workdir = TempDir::new().unwrap();
    let stub = SqlStub::start(dir.path()).unwrap();
    let payload = extract_payload(&read_fixture("sql", "vuln.txt"));
    stub.record_query(&payload).unwrap();

    let events = stub.drain_events();
    let event = events.first().expect("captured event");
    // Round-trip through serde so the assertion mirrors what the
    // verifier writes into a repro bundle.
    let serialised = serde_json::to_string(event).unwrap();
    assert!(
        serialised.contains("OR 1=1"),
        "captured query must survive serialisation: {serialised}",
    );

    // Also confirm the probe channel adjacent to the stub is empty
    // — the captured query lives on the stub event log, not on the
    // probe channel.  This locks the partition the oracle relies on.
    let channel = ProbeChannel::for_workdir(workdir.path()).unwrap();
    assert!(channel.drain().is_empty());
}
