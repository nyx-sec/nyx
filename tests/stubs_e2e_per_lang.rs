//! Phase 10 (Track D.3) — per-(lang, cap) stub end-to-end tests.
//!
//! These tests spin up a real boundary stub, splice the per-language
//! probe shim (which now carries the cap-specific
//! `__nyx_stub_*_record` helpers) ahead of a fixture's source, run the
//! resulting program with the stub's endpoint + recording-path env
//! vars set, then assert the stub captured the boundary event.
//!
//! Unlike `tests/stubs_per_cap.rs` (which synthesises harness
//! behaviour with host-side `SqlStub::record_query` calls), this suite
//! drives a real interpreter subprocess so the per-language shim
//! contract is exercised end-to-end.  When the host is missing the
//! interpreter the test eprintln-skips, matching every other lang
//! fixture suite in-tree.
//!
//! Acceptance bullet from `.pitboss/play/deferred.md` Phase 10
//! follow-up: the Python+SQL pair is the cheapest first bite —
//! `sqlite3` is stdlib so no new toolchain dependency is required for
//! the dynamic CI matrix.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::lang::go::probe_shim as go_probe_shim;
use nyx_scanner::dynamic::lang::javascript::probe_shim as node_probe_shim;
use nyx_scanner::dynamic::lang::php::probe_shim as php_probe_shim;
use nyx_scanner::dynamic::lang::python::probe_shim as python_probe_shim;
use nyx_scanner::dynamic::stubs::{HttpStub, SqlStub, StubProvider};
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn python3_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn php_available() -> bool {
    Command::new("php")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn go_available() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Wrap the body-only Go HTTP fixture in a complete `package main`
/// program: stdlib imports needed by the spliced probe shim plus the
/// fragment's own `fmt` / `os` references, the shim itself, and the
/// fragment as the body of `func main`.  Comments inside the body
/// remain valid Go.
fn wrap_go_fragment(body: &str, shim: &str) -> String {
    format!(
        "package main\n\
         \n\
         import (\n\
         \t\"encoding/json\"\n\
         \t\"fmt\"\n\
         \t\"os\"\n\
         \t\"os/signal\"\n\
         \t\"strings\"\n\
         \t\"syscall\"\n\
         \t\"time\"\n\
         )\n\
         {shim}\n\
         func main() {{\n\
         {body}\n\
         }}\n"
    )
}

fn fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("dynamic_fixtures")
        .join("stubs_e2e")
        .join(rel)
}

#[test]
fn python_sql_stub_captures_tautology_query_via_shim_recorder() {
    if !python3_available() {
        eprintln!("SKIP: python3 not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    // The verifier publishes the SQLite DB path on `NYX_SQL_ENDPOINT`
    // (primary) and the queries-log path on `NYX_SQL_LOG` (companion).
    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    // Splice the probe shim ahead of the fixture source so the
    // generated program carries the `__nyx_stub_sql_record` helper.
    // Mirrors the production `PythonEmitter::emit` ordering.
    let fixture =
        std::fs::read_to_string(fixture_path("python/sql/vuln/main.py")).expect("read fixture");
    let mut combined = String::with_capacity(python_probe_shim().len() + fixture.len() + 64);
    combined.push_str(python_probe_shim());
    combined.push_str("\n# ── fixture begins ─\n");
    combined.push_str(&fixture);

    let script_path = workdir.path().join("driver.py");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("python3")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("python3 driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "SqlStub must capture at least one event after the shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    assert_eq!(
        tautology.detail.get("driver").map(String::as_str),
        Some("sqlite3"),
        "kwargs passed to __nyx_stub_sql_record must surface as event detail entries"
    );
}

#[test]
fn python_sql_shim_recorder_is_noop_without_log_env() {
    if !python3_available() {
        eprintln!("SKIP: python3 not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    // Drive the same fixture but withhold NYX_SQL_LOG.  The shim
    // helper must be a no-op so the same source still runs cleanly
    // under harness modes that didn't spawn a stub.
    let endpoint = stub.endpoint();
    let fixture =
        std::fs::read_to_string(fixture_path("python/sql/vuln/main.py")).expect("read fixture");
    let mut combined = String::new();
    combined.push_str(python_probe_shim());
    combined.push('\n');
    combined.push_str(&fixture);
    let script_path = workdir.path().join("driver_no_log.py");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("python3")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env_remove("NYX_SQL_LOG")
        .output()
        .expect("python3 driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_SQL_LOG; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}

#[test]
fn node_sql_stub_captures_tautology_query_via_shim_recorder() {
    if !node_available() {
        eprintln!("SKIP: node not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    // Splice the Node probe shim ahead of the fixture source so the
    // generated program carries the `__nyx_stub_sql_record` helper.
    // Mirrors the production `JavaScriptEmitter::emit` ordering.
    let fixture =
        std::fs::read_to_string(fixture_path("node/sql/vuln/main.js")).expect("read fixture");
    let mut combined = String::with_capacity(node_probe_shim().len() + fixture.len() + 64);
    combined.push_str(node_probe_shim());
    combined.push_str("\n// ── fixture begins ─\n");
    combined.push_str(&fixture);

    let script_path = workdir.path().join("driver.js");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("node")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("node driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "SqlStub must capture at least one event after the Node shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    let driver = tautology
        .detail
        .get("driver")
        .map(String::as_str)
        .expect("Node shim must publish driver detail on the recorded event");
    assert!(
        driver == "node:sqlite" || driver == "none",
        "driver detail must report node:sqlite when available or `none` when the stdlib module is missing; got {driver:?}"
    );
}

fn strip_php_open_tag(src: &str) -> &str {
    src.strip_prefix("<?php\n")
        .or_else(|| src.strip_prefix("<?php\r\n"))
        .or_else(|| src.strip_prefix("<?php "))
        .unwrap_or(src)
}

#[test]
fn php_sql_stub_captures_tautology_query_via_shim_recorder() {
    if !php_available() {
        eprintln!("SKIP: php not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    // Splice the PHP probe shim ahead of the fixture source so the
    // generated program carries the `__nyx_stub_sql_record` helper.
    // Mirrors the production `PhpEmitter::emit` ordering.  The shim
    // expects to live inside an open `<?php` block, so we strip the
    // fixture's leading `<?php` tag before concatenating.
    let fixture =
        std::fs::read_to_string(fixture_path("php/sql/vuln/main.php")).expect("read fixture");
    let body = strip_php_open_tag(&fixture);
    let mut combined = String::with_capacity(php_probe_shim().len() + body.len() + 64);
    combined.push_str("<?php\n");
    combined.push_str(php_probe_shim());
    combined.push_str("\n// ── fixture begins ─\n");
    combined.push_str(body);

    let script_path = workdir.path().join("driver.php");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("php")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("php driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "SqlStub must capture at least one event after the PHP shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    let driver = tautology
        .detail
        .get("driver")
        .map(String::as_str)
        .expect("PHP shim must publish driver detail on the recorded event");
    assert!(
        driver == "SQLite3" || driver == "none",
        "driver detail must report SQLite3 when the stdlib class is available or `none` when missing; got {driver:?}"
    );
}

#[test]
fn php_sql_shim_recorder_is_noop_without_log_env() {
    if !php_available() {
        eprintln!("SKIP: php not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let fixture =
        std::fs::read_to_string(fixture_path("php/sql/vuln/main.php")).expect("read fixture");
    let body = strip_php_open_tag(&fixture);
    let mut combined = String::new();
    combined.push_str("<?php\n");
    combined.push_str(php_probe_shim());
    combined.push('\n');
    combined.push_str(body);
    let script_path = workdir.path().join("driver_no_log.php");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("php")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env_remove("NYX_SQL_LOG")
        .output()
        .expect("php driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_SQL_LOG; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}

#[test]
fn python_http_stub_captures_attempted_outbound_via_shim_recorder() {
    // Phase 10 (Track D.3) HTTP recording: the side-channel
    // `__nyx_stub_http_record` lets a harness surface outbound HTTP
    // attempts even when the request never reaches the on-the-wire
    // listener (DNS-mocked, network-isolated sandbox, pre-flight
    // check).  This test drives the Python helper.
    if !python3_available() {
        eprintln!("SKIP: python3 not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    let fixture =
        std::fs::read_to_string(fixture_path("python/http/vuln/main.py")).expect("read fixture");
    let mut combined = String::with_capacity(python_probe_shim().len() + fixture.len() + 64);
    combined.push_str(python_probe_shim());
    combined.push_str("\n# ── fixture begins ─\n");
    combined.push_str(&fixture);

    let script_path = workdir.path().join("driver_http.py");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("python3")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("python3 driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the shim recorder fires"
    );
    let hit = events
        .iter()
        .find(|e| e.summary.contains("169.254.169.254"))
        .expect("recorded URL must contain the SSRF marker");
    assert_eq!(
        hit.detail.get("method").map(String::as_str),
        Some("GET"),
        "method detail must surface on the recorded event"
    );
    assert_eq!(
        hit.detail.get("url").map(String::as_str),
        Some("http://169.254.169.254/latest/meta-data/"),
    );
    assert_eq!(
        hit.detail.get("driver").map(String::as_str),
        Some("urllib"),
        "kwargs passed to __nyx_stub_http_record must surface as event detail entries"
    );
}

#[test]
fn python_http_shim_recorder_is_noop_without_log_env() {
    if !python3_available() {
        eprintln!("SKIP: python3 not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fixture =
        std::fs::read_to_string(fixture_path("python/http/vuln/main.py")).expect("read fixture");
    let mut combined = String::new();
    combined.push_str(python_probe_shim());
    combined.push('\n');
    combined.push_str(&fixture);
    let script_path = workdir.path().join("driver_http_no_log.py");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("python3")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env_remove("NYX_HTTP_LOG")
        .output()
        .expect("python3 driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_HTTP_LOG; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}

#[test]
fn node_http_stub_captures_attempted_outbound_via_shim_recorder() {
    // Phase 10 (Track D.3) HTTP recording: Node leg of the side-channel
    // `__nyx_stub_http_record` helper.  Mirrors the Python HTTP test —
    // records an SSRF attempt without issuing the actual network call.
    if !node_available() {
        eprintln!("SKIP: node not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    let fixture =
        std::fs::read_to_string(fixture_path("node/http/vuln/main.js")).expect("read fixture");
    let mut combined = String::with_capacity(node_probe_shim().len() + fixture.len() + 64);
    combined.push_str(node_probe_shim());
    combined.push_str("\n// ── fixture begins ─\n");
    combined.push_str(&fixture);

    let script_path = workdir.path().join("driver_http.js");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("node")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("node driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the Node shim recorder fires"
    );
    let hit = events
        .iter()
        .find(|e| e.summary.contains("169.254.169.254"))
        .expect("recorded URL must contain the SSRF marker");
    assert_eq!(
        hit.detail.get("method").map(String::as_str),
        Some("GET"),
        "method detail must surface on the recorded event"
    );
    assert_eq!(
        hit.detail.get("url").map(String::as_str),
        Some("http://169.254.169.254/latest/meta-data/"),
    );
    assert_eq!(
        hit.detail.get("driver").map(String::as_str),
        Some("node:http"),
        "kwargs passed to __nyx_stub_http_record must surface as event detail entries"
    );
}

#[test]
fn node_http_shim_recorder_is_noop_without_log_env() {
    if !node_available() {
        eprintln!("SKIP: node not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fixture =
        std::fs::read_to_string(fixture_path("node/http/vuln/main.js")).expect("read fixture");
    let mut combined = String::new();
    combined.push_str(node_probe_shim());
    combined.push('\n');
    combined.push_str(&fixture);
    let script_path = workdir.path().join("driver_http_no_log.js");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("node")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env_remove("NYX_HTTP_LOG")
        .output()
        .expect("node driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_HTTP_LOG; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}

#[test]
fn php_http_stub_captures_attempted_outbound_via_shim_recorder() {
    // Phase 10 (Track D.3) HTTP recording: PHP leg of the side-channel
    // `__nyx_stub_http_record` helper.  Mirrors the Python HTTP test —
    // records an SSRF attempt without issuing the actual network call.
    if !php_available() {
        eprintln!("SKIP: php not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    let fixture =
        std::fs::read_to_string(fixture_path("php/http/vuln/main.php")).expect("read fixture");
    let body = strip_php_open_tag(&fixture);
    let mut combined = String::with_capacity(php_probe_shim().len() + body.len() + 64);
    combined.push_str("<?php\n");
    combined.push_str(php_probe_shim());
    combined.push_str("\n// ── fixture begins ─\n");
    combined.push_str(body);

    let script_path = workdir.path().join("driver_http.php");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("php")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("php driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the PHP shim recorder fires"
    );
    let hit = events
        .iter()
        .find(|e| e.summary.contains("169.254.169.254"))
        .expect("recorded URL must contain the SSRF marker");
    assert_eq!(
        hit.detail.get("method").map(String::as_str),
        Some("GET"),
        "method detail must surface on the recorded event"
    );
    assert_eq!(
        hit.detail.get("url").map(String::as_str),
        Some("http://169.254.169.254/latest/meta-data/"),
    );
    assert_eq!(
        hit.detail.get("driver").map(String::as_str),
        Some("curl"),
        "kwargs passed to __nyx_stub_http_record must surface as event detail entries"
    );
}

#[test]
fn php_http_shim_recorder_is_noop_without_log_env() {
    if !php_available() {
        eprintln!("SKIP: php not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fixture =
        std::fs::read_to_string(fixture_path("php/http/vuln/main.php")).expect("read fixture");
    let body = strip_php_open_tag(&fixture);
    let mut combined = String::new();
    combined.push_str("<?php\n");
    combined.push_str(php_probe_shim());
    combined.push('\n');
    combined.push_str(body);
    let script_path = workdir.path().join("driver_http_no_log.php");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("php")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env_remove("NYX_HTTP_LOG")
        .output()
        .expect("php driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_HTTP_LOG; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}

#[test]
fn go_http_stub_captures_attempted_outbound_via_shim_recorder() {
    // Phase 10 (Track D.3) HTTP recording: Go leg of the side-channel
    // `__nyx_stub_http_record` helper.  Mirrors the Python HTTP test —
    // records an SSRF attempt without issuing the actual network call.
    if !go_available() {
        eprintln!("SKIP: go not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    // Go fragments need wrapping: the file under tests/dynamic_fixtures
    // is a body-only fragment, not a standalone program.
    let fragment = std::fs::read_to_string(fixture_path("go/http/vuln/main.go"))
        .expect("read go fragment");
    let combined = wrap_go_fragment(&fragment, go_probe_shim());

    let script_path = workdir.path().join("driver_http.go");
    std::fs::write(&script_path, combined).expect("write go driver");

    let output = Command::new("go")
        .arg("run")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("go driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the Go shim recorder fires"
    );
    let hit = events
        .iter()
        .find(|e| e.summary.contains("169.254.169.254"))
        .expect("recorded URL must contain the SSRF marker");
    assert_eq!(
        hit.detail.get("method").map(String::as_str),
        Some("GET"),
        "method detail must surface on the recorded event"
    );
    assert_eq!(
        hit.detail.get("url").map(String::as_str),
        Some("http://169.254.169.254/latest/meta-data/"),
    );
    assert_eq!(
        hit.detail.get("driver").map(String::as_str),
        Some("net/http"),
        "detail map passed to __nyx_stub_http_record must surface as event detail entries"
    );
}

#[test]
fn go_http_shim_recorder_is_noop_without_log_env() {
    if !go_available() {
        eprintln!("SKIP: go not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("go/http/vuln/main.go"))
        .expect("read go fragment");
    let combined = wrap_go_fragment(&fragment, go_probe_shim());

    let script_path = workdir.path().join("driver_http_no_log.go");
    std::fs::write(&script_path, combined).expect("write go driver");

    let output = Command::new("go")
        .arg("run")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env_remove("NYX_HTTP_LOG")
        .output()
        .expect("go driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_HTTP_LOG; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}

#[test]
fn node_sql_shim_recorder_is_noop_without_log_env() {
    if !node_available() {
        eprintln!("SKIP: node not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let fixture =
        std::fs::read_to_string(fixture_path("node/sql/vuln/main.js")).expect("read fixture");
    let mut combined = String::new();
    combined.push_str(node_probe_shim());
    combined.push('\n');
    combined.push_str(&fixture);
    let script_path = workdir.path().join("driver_no_log.js");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("node")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env_remove("NYX_SQL_LOG")
        .output()
        .expect("node driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_SQL_LOG; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}
