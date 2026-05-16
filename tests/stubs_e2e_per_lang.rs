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

use nyx_scanner::dynamic::lang::c::probe_shim as c_probe_shim;
use nyx_scanner::dynamic::lang::cpp::probe_shim as cpp_probe_shim;
use nyx_scanner::dynamic::lang::go::probe_shim as go_probe_shim;
use nyx_scanner::dynamic::lang::java::probe_shim as java_probe_shim;
use nyx_scanner::dynamic::lang::javascript::probe_shim as node_probe_shim;
use nyx_scanner::dynamic::lang::php::probe_shim as php_probe_shim;
use nyx_scanner::dynamic::lang::python::probe_shim as python_probe_shim;
use nyx_scanner::dynamic::lang::ruby::probe_shim as ruby_probe_shim;
use nyx_scanner::dynamic::lang::rust::probe_shim as rust_probe_shim;
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

fn ruby_available() -> bool {
    Command::new("ruby")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cargo_available() -> bool {
    Command::new("cargo")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cc_available() -> bool {
    // Honours the same NYX_CC_BIN override used by the Phase 29
    // CommandAvailableEnvOverride prereq variant in the C fixture suite.
    let bin = std::env::var("NYX_CC_BIN").unwrap_or_else(|_| "cc".to_owned());
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cxx_available() -> bool {
    let bin = std::env::var("NYX_CXX_BIN").unwrap_or_else(|_| "c++".to_owned());
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cc_bin() -> String {
    std::env::var("NYX_CC_BIN").unwrap_or_else(|_| "cc".to_owned())
}

fn cxx_bin() -> String {
    std::env::var("NYX_CXX_BIN").unwrap_or_else(|_| "c++".to_owned())
}

fn java_available() -> bool {
    // The Java shim helpers use `java MainSource.java` single-file
    // source-mode (JEP 330, JDK 11+) so only the `java` runtime is
    // strictly required.  An older `java` binary that does not support
    // source-mode is treated as missing and the test eprintln-skips.
    Command::new("java")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Wrap the body-only Java HTTP fixture in a complete `public class Main`
/// source: splice the Java probe shim as class members ahead of
/// `public static void main`, then put the fragment in the method body.
/// Mirrors the production [`JavaEmitter::emit`] ordering — the shim is
/// declared first so any sink rewrite in the body has the shim helpers
/// in scope.  The throws clause lets the fragment use checked-exception
/// stdlib calls without per-line try/catch.
fn wrap_java_fragment(body: &str, shim: &str) -> String {
    format!(
        "public class Main {{\n\
         {shim}\n\
         \n\
         public static void main(String[] args) throws Exception {{\n\
         {body}\n\
         }}\n\
         }}\n"
    )
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

/// Wrap the body-only Rust HTTP fragment in a complete crate: prepend
/// the Rust probe shim (which carries `__nyx_stub_http_record`) at
/// file scope and wrap the fragment as the body of `fn main()`.  The
/// caller writes the result alongside a one-line `Cargo.toml` that
/// pins `libc = "0.2"` (the shim's `__nyx_install_crash_guard` path
/// references `libc::sigaction`) and drives the build through
/// `cargo run --quiet`.  Mirrors the production Rust emitter ordering
/// — shim at file scope, then `fn main()` calling into it.
fn wrap_rust_fragment(body: &str, shim: &str) -> String {
    format!(
        "{shim}\n\
         fn main() {{\n\
         {body}\n\
         }}\n"
    )
}

/// Per-fixture Cargo.toml for the Rust stub-recorder driver.  Mirrors
/// the Phase 26 chain_step manifest (session 0014) — `[[bin]]` points
/// at `main.rs` so `cargo run --quiet` builds the source the test
/// just wrote, and `libc = "0.2"` is unconditionally pinned because
/// the spliced probe shim's `__nyx_install_crash_guard` references
/// `libc::sigaction` on Unix.  Caller supplies a unique `slug` per
/// test so the package + binary names do not collide in the shared
/// `CARGO_TARGET_DIR` when nextest runs the Rust stub tests in
/// parallel (every test still benefits from the cached `libc` build,
/// only the final `nyx-stub-driver-<slug>` link is per-test).
/// Wrap a body-only C fragment in a complete translation unit: prepend
/// the C probe shim (which carries `__nyx_stub_sql_record` /
/// `__nyx_stub_http_record`) at file scope, then wrap the fragment as
/// the body of `int main(void)`.  The shim's own `#include` directives
/// pull in stdio / string / signal headers, so the fragment can use
/// `NULL`, string literals, and the recorder helpers without any
/// additional preamble.
fn wrap_c_fragment(body: &str, shim: &str) -> String {
    format!(
        "{shim}\n\
         int main(void) {{\n\
         {body}\n\
         return 0;\n\
         }}\n"
    )
}

/// Wrap a body-only C++ fragment in a complete translation unit: prepend
/// the C++ probe shim and wrap the fragment as the body of `int main()`.
/// The shim's own `#include` block covers `<string>` / `<fstream>` /
/// `<utility>` so initializer-list `{key, value}` literals + `std::string`
/// in the fragment compile cleanly.
fn wrap_cpp_fragment(body: &str, shim: &str) -> String {
    format!(
        "{shim}\n\
         int main() {{\n\
         {body}\n\
         return 0;\n\
         }}\n"
    )
}

fn rust_stub_cargo_toml(slug: &str) -> String {
    format!(
        "[package]\n\
         name = \"nyx-stub-driver-{slug}\"\n\
         version = \"0.0.1\"\n\
         edition = \"2021\"\n\n\
         [[bin]]\n\
         name = \"stub_driver_{slug}\"\n\
         path = \"main.rs\"\n\n\
         [dependencies]\n\
         libc = \"0.2\"\n"
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
fn go_sql_stub_captures_tautology_query_via_shim_recorder() {
    // Phase 10 (Track D.3) SQL recording: Go leg of the side-channel
    // `__nyx_stub_sql_record` helper.  Mirrors the Python / Node / PHP /
    // Rust / Java SQL tests — the Go fragment never opens a live
    // `database/sql` handle (no driver imported; pulling go-sqlite3 /
    // pgx / mysql would force a go.mod dep onto every dynamic CI matrix
    // row) so it surfaces the attempted tautology query through the
    // shim recorder as `driver = "manual"`.
    if !go_available() {
        eprintln!("SKIP: go not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    let fragment =
        std::fs::read_to_string(fixture_path("go/sql/vuln/main.go")).expect("read go fragment");
    let combined = wrap_go_fragment(&fragment, go_probe_shim());

    let script_path = workdir.path().join("driver_sql.go");
    std::fs::write(&script_path, combined).expect("write go driver");

    let output = Command::new("go")
        .arg("run")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
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
        "SqlStub must capture at least one event after the Go shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    assert_eq!(
        tautology.detail.get("driver").map(String::as_str),
        Some("manual"),
        "detail map entries passed to __nyx_stub_sql_record must surface as event detail entries"
    );
}

#[test]
fn go_sql_shim_recorder_is_noop_without_log_env() {
    if !go_available() {
        eprintln!("SKIP: go not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let fragment =
        std::fs::read_to_string(fixture_path("go/sql/vuln/main.go")).expect("read go fragment");
    let combined = wrap_go_fragment(&fragment, go_probe_shim());

    let script_path = workdir.path().join("driver_sql_no_log.go");
    std::fs::write(&script_path, combined).expect("write go driver");

    let output = Command::new("go")
        .arg("run")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env_remove("NYX_SQL_LOG")
        .output()
        .expect("go driver");
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
fn ruby_http_stub_captures_attempted_outbound_via_shim_recorder() {
    // Phase 10 (Track D.3) HTTP recording: Ruby leg of the side-channel
    // `__nyx_stub_http_record` helper.  Mirrors the Python HTTP test —
    // records an SSRF attempt without issuing the actual network call.
    // Ruby has no package / class boundary so the fixture is a plain
    // top-level script and the shim is prepended at the file head.
    if !ruby_available() {
        eprintln!("SKIP: ruby not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    let fixture =
        std::fs::read_to_string(fixture_path("ruby/http/vuln/main.rb")).expect("read fixture");
    let mut combined = String::with_capacity(ruby_probe_shim().len() + fixture.len() + 64);
    combined.push_str(ruby_probe_shim());
    combined.push_str("\n# ── fixture begins ─\n");
    combined.push_str(&fixture);

    let script_path = workdir.path().join("driver_http.rb");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("ruby")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("ruby driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the Ruby shim recorder fires"
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
        "kwargs passed to __nyx_stub_http_record must surface as event detail entries"
    );
}

#[test]
fn ruby_http_shim_recorder_is_noop_without_log_env() {
    if !ruby_available() {
        eprintln!("SKIP: ruby not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fixture =
        std::fs::read_to_string(fixture_path("ruby/http/vuln/main.rb")).expect("read fixture");
    let mut combined = String::new();
    combined.push_str(ruby_probe_shim());
    combined.push('\n');
    combined.push_str(&fixture);
    let script_path = workdir.path().join("driver_http_no_log.rb");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("ruby")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env_remove("NYX_HTTP_LOG")
        .output()
        .expect("ruby driver");
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
fn ruby_sql_stub_captures_tautology_query_via_shim_recorder() {
    // Phase 10 (Track D.3) SQL recording: Ruby leg of the side-channel
    // `__nyx_stub_sql_record` helper.  Mirrors the Python / Node / PHP /
    // Rust / Java / Go SQL tests — the Ruby fragment never opens a live
    // sqlite3 handle (no require, no gem dep) so it surfaces the
    // attempted tautology query through the shim recorder as
    // `driver = "manual"`.
    if !ruby_available() {
        eprintln!("SKIP: ruby not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    let fixture =
        std::fs::read_to_string(fixture_path("ruby/sql/vuln/main.rb")).expect("read fixture");
    let mut combined = String::with_capacity(ruby_probe_shim().len() + fixture.len() + 64);
    combined.push_str(ruby_probe_shim());
    combined.push_str("\n# ── fixture begins ─\n");
    combined.push_str(&fixture);

    let script_path = workdir.path().join("driver_sql.rb");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("ruby")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("ruby driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "SqlStub must capture at least one event after the Ruby shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    assert_eq!(
        tautology.detail.get("driver").map(String::as_str),
        Some("manual"),
        "kwargs passed to __nyx_stub_sql_record must surface as event detail entries"
    );
}

#[test]
fn ruby_sql_shim_recorder_is_noop_without_log_env() {
    if !ruby_available() {
        eprintln!("SKIP: ruby not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let fixture =
        std::fs::read_to_string(fixture_path("ruby/sql/vuln/main.rb")).expect("read fixture");
    let mut combined = String::new();
    combined.push_str(ruby_probe_shim());
    combined.push('\n');
    combined.push_str(&fixture);
    let script_path = workdir.path().join("driver_sql_no_log.rb");
    std::fs::write(&script_path, combined).expect("write driver");

    let output = Command::new("ruby")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env_remove("NYX_SQL_LOG")
        .output()
        .expect("ruby driver");
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
fn java_http_stub_captures_attempted_outbound_via_shim_recorder() {
    // Phase 10 (Track D.3) HTTP recording: Java leg of the side-channel
    // `__nyx_stub_http_record` helper.  Mirrors the Python / Node / PHP /
    // Go / Ruby HTTP tests — records an SSRF attempt without issuing the
    // actual network call.  Uses `java MainSource.java` single-file
    // source-mode (JEP 330, JDK 11+) so no separate `javac` step is
    // required.
    if !java_available() {
        eprintln!("SKIP: java not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    let fragment = std::fs::read_to_string(fixture_path("java/http/vuln/main.java.fragment"))
        .expect("read java fragment");
    let combined = wrap_java_fragment(&fragment, java_probe_shim());

    // Single-file source-mode requires the filename to match the public
    // class — name the file `Main.java` so `java Main.java` compiles
    // and runs in one step.
    let script_path = workdir.path().join("Main.java");
    std::fs::write(&script_path, combined).expect("write java driver");

    let output = Command::new("java")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("java driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the Java shim recorder fires"
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
        Some("HttpURLConnection"),
        "detail map entries passed to __nyx_stub_http_record must surface as event detail entries"
    );
}

#[test]
fn java_sql_stub_captures_tautology_query_via_shim_recorder() {
    // Phase 10 (Track D.3) SQL recording: Java leg of the side-channel
    // `__nyx_stub_sql_record` helper.  Mirrors the Python / Node / PHP /
    // Rust SQL tests — the Java fragment never opens a live JDBC handle
    // (sqlite-jdbc is not stdlib; pulling it would force a classpath
    // prereq onto the dynamic CI matrix) so it surfaces the attempted
    // tautology query through the shim recorder as `driver = "manual"`.
    if !java_available() {
        eprintln!("SKIP: java not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    let fragment = std::fs::read_to_string(fixture_path("java/sql/vuln/main.java.fragment"))
        .expect("read java sql fragment");
    let combined = wrap_java_fragment(&fragment, java_probe_shim());

    let script_path = workdir.path().join("Main.java");
    std::fs::write(&script_path, combined).expect("write java driver");

    let output = Command::new("java")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("java driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "SqlStub must capture at least one event after the Java shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    assert_eq!(
        tautology.detail.get("driver").map(String::as_str),
        Some("manual"),
        "detail map entries passed to __nyx_stub_sql_record must surface as event detail entries"
    );
}

#[test]
fn java_sql_shim_recorder_is_noop_without_log_env() {
    if !java_available() {
        eprintln!("SKIP: java not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("java/sql/vuln/main.java.fragment"))
        .expect("read java sql fragment");
    let combined = wrap_java_fragment(&fragment, java_probe_shim());

    let script_path = workdir.path().join("Main.java");
    std::fs::write(&script_path, combined).expect("write java driver");

    let output = Command::new("java")
        .arg(&script_path)
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env_remove("NYX_SQL_LOG")
        .output()
        .expect("java driver");
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
fn java_http_shim_recorder_is_noop_without_log_env() {
    if !java_available() {
        eprintln!("SKIP: java not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("java/http/vuln/main.java.fragment"))
        .expect("read java fragment");
    let combined = wrap_java_fragment(&fragment, java_probe_shim());

    let script_path = workdir.path().join("Main.java");
    std::fs::write(&script_path, combined).expect("write java driver");

    let output = Command::new("java")
        .arg(&script_path)
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env_remove("NYX_HTTP_LOG")
        .output()
        .expect("java driver");
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

/// Returns a shared CARGO_TARGET_DIR for Rust stub-recorder tests so
/// repeated runs reuse the libc build artifacts instead of paying
/// the full compile cost per test.  Lives under the host crate's
/// own `target/` so `cargo clean` still wipes it.
fn rust_stub_target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("stubs_e2e_rust")
}

#[test]
fn rust_http_stub_captures_attempted_outbound_via_shim_recorder() {
    // Phase 10 (Track D.3) HTTP recording: Rust leg of the side-channel
    // `__nyx_stub_http_record` helper.  Mirrors the Python / Node / PHP /
    // Go / Ruby / Java HTTP tests — records an SSRF attempt without
    // issuing the actual network call.  Uses the `extra_files`-driven
    // `Cargo.toml` shape session 0014 prototyped for chain steps: write
    // a one-line manifest alongside the wrapped fragment so `cargo run
    // --quiet` resolves `libc` (referenced by the spliced probe shim's
    // `__nyx_install_crash_guard`) without any host crate-cache assumptions.
    if !cargo_available() {
        eprintln!("SKIP: cargo not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    let fragment = std::fs::read_to_string(fixture_path("rust/http/vuln/main.rs"))
        .expect("read rust fragment");
    let source = wrap_rust_fragment(&fragment, rust_probe_shim());

    let crate_dir = workdir.path().join("driver");
    std::fs::create_dir_all(&crate_dir).expect("create crate dir");
    std::fs::write(crate_dir.join("Cargo.toml"), rust_stub_cargo_toml("http"))
        .expect("write Cargo.toml");
    std::fs::write(crate_dir.join("main.rs"), source).expect("write main.rs");

    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(crate_dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", rust_stub_target_dir())
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("cargo run rust driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the Rust shim recorder fires"
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
        Some("manual"),
        "detail slice passed to __nyx_stub_http_record must surface as event detail entries"
    );
}

#[test]
fn rust_http_shim_recorder_is_noop_without_log_env() {
    if !cargo_available() {
        eprintln!("SKIP: cargo not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("rust/http/vuln/main.rs"))
        .expect("read rust fragment");
    let source = wrap_rust_fragment(&fragment, rust_probe_shim());

    let crate_dir = workdir.path().join("driver_no_log");
    std::fs::create_dir_all(&crate_dir).expect("create crate dir");
    std::fs::write(crate_dir.join("Cargo.toml"), rust_stub_cargo_toml("http_no_log"))
        .expect("write Cargo.toml");
    std::fs::write(crate_dir.join("main.rs"), source).expect("write main.rs");

    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(crate_dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", rust_stub_target_dir())
        .env("NYX_HTTP_ENDPOINT", &endpoint)
        .env_remove("NYX_HTTP_LOG")
        .output()
        .expect("cargo run rust driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_HTTP_LOG; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
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
fn rust_sql_stub_captures_tautology_query_via_shim_recorder() {
    // Phase 10 (Track D.3) SQL recording: Rust leg of the side-channel
    // `__nyx_stub_sql_record` helper.  Mirrors the Python / Node / PHP
    // SQL tests — the Rust fragment never opens a live SQLite handle
    // (no stdlib driver; rusqlite would force libsqlite3-dev onto the
    // CI matrix) so it surfaces the attempted tautology query through
    // the shim recorder as `driver = "manual"`.  Uses the same
    // `extra_files`-driven `Cargo.toml` shape as the HTTP siblings so
    // `cargo run --quiet` resolves `libc` (referenced by the spliced
    // probe shim's `__nyx_install_crash_guard`).
    if !cargo_available() {
        eprintln!("SKIP: cargo not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    let fragment = std::fs::read_to_string(fixture_path("rust/sql/vuln/main.rs"))
        .expect("read rust sql fragment");
    let source = wrap_rust_fragment(&fragment, rust_probe_shim());

    let crate_dir = workdir.path().join("driver_sql");
    std::fs::create_dir_all(&crate_dir).expect("create crate dir");
    std::fs::write(crate_dir.join("Cargo.toml"), rust_stub_cargo_toml("sql"))
        .expect("write Cargo.toml");
    std::fs::write(crate_dir.join("main.rs"), source).expect("write main.rs");

    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(crate_dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", rust_stub_target_dir())
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env(recording.0, &recording.1)
        .output()
        .expect("cargo run rust sql driver");
    assert!(
        output.status.success(),
        "driver must exit 0; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "SqlStub must capture at least one event after the Rust shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    assert_eq!(
        tautology.detail.get("driver").map(String::as_str),
        Some("manual"),
        "detail slice passed to __nyx_stub_sql_record must surface as event detail entries"
    );
}

#[test]
fn rust_sql_shim_recorder_is_noop_without_log_env() {
    if !cargo_available() {
        eprintln!("SKIP: cargo not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("rust/sql/vuln/main.rs"))
        .expect("read rust sql fragment");
    let source = wrap_rust_fragment(&fragment, rust_probe_shim());

    let crate_dir = workdir.path().join("driver_sql_no_log");
    std::fs::create_dir_all(&crate_dir).expect("create crate dir");
    std::fs::write(crate_dir.join("Cargo.toml"), rust_stub_cargo_toml("sql_no_log"))
        .expect("write Cargo.toml");
    std::fs::write(crate_dir.join("main.rs"), source).expect("write main.rs");

    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(crate_dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", rust_stub_target_dir())
        .env("NYX_SQL_ENDPOINT", &endpoint)
        .env_remove("NYX_SQL_LOG")
        .output()
        .expect("cargo run rust sql driver");
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_SQL_LOG; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}

// ── C ────────────────────────────────────────────────────────────────────────

/// Build + run a wrapped C source: writes the source to
/// `<workdir>/<slug>.c`, drives `cc` to compile to `<workdir>/<slug>`,
/// runs the binary with the supplied env block.  Returns the binary's
/// own `Output` so tests assert on exit code + stdout/stderr.  Build
/// failures surface as a panic with the compiler's stderr.
fn build_and_run_c(
    workdir: &std::path::Path,
    slug: &str,
    source: &str,
    extra_env: &[(&str, &str)],
    suppress_env: &[&str],
) -> std::process::Output {
    let src_path = workdir.join(format!("{slug}.c"));
    let bin_path = workdir.join(slug);
    std::fs::write(&src_path, source).expect("write C source");

    let build = Command::new(cc_bin())
        .arg(&src_path)
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("invoke cc");
    assert!(
        build.status.success(),
        "cc must build the wrapped C source; stderr = {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let mut cmd = Command::new(&bin_path);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    for k in suppress_env {
        cmd.env_remove(*k);
    }
    cmd.output().expect("run C driver")
}

fn build_and_run_cpp(
    workdir: &std::path::Path,
    slug: &str,
    source: &str,
    extra_env: &[(&str, &str)],
    suppress_env: &[&str],
) -> std::process::Output {
    let src_path = workdir.join(format!("{slug}.cpp"));
    let bin_path = workdir.join(slug);
    std::fs::write(&src_path, source).expect("write C++ source");

    let build = Command::new(cxx_bin())
        .arg(&src_path)
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("invoke c++");
    assert!(
        build.status.success(),
        "c++ must build the wrapped C++ source; stderr = {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let mut cmd = Command::new(&bin_path);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    for k in suppress_env {
        cmd.env_remove(*k);
    }
    cmd.output().expect("run C++ driver")
}

#[test]
fn c_sql_stub_captures_tautology_query_via_shim_recorder() {
    // Phase 10 (Track D.3) SQL recording: C leg of the side-channel
    // `__nyx_stub_sql_record` helper.  Mirrors the Rust SQL test —
    // the C fragment never opens a live SQLite handle (no sqlite3.h
    // dependency on the dynamic CI matrix) so it surfaces the
    // attempted tautology query through the shim recorder as
    // `driver = "manual"`.
    if !cc_available() {
        eprintln!("SKIP: cc not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    let fragment = std::fs::read_to_string(fixture_path("c/sql/vuln/main.c.fragment"))
        .expect("read c sql fragment");
    let source = wrap_c_fragment(&fragment, c_probe_shim());

    let output = build_and_run_c(
        workdir.path(),
        "driver_c_sql",
        &source,
        &[
            ("NYX_SQL_ENDPOINT", endpoint.as_str()),
            (recording.0, recording.1.as_str()),
        ],
        &[],
    );
    assert!(
        output.status.success(),
        "driver must exit 0; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "SqlStub must capture at least one event after the C shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    assert_eq!(
        tautology.detail.get("driver").map(String::as_str),
        Some("manual"),
        "parallel-array detail passed to __nyx_stub_sql_record must surface as event detail"
    );
}

#[test]
fn c_sql_shim_recorder_is_noop_without_log_env() {
    if !cc_available() {
        eprintln!("SKIP: cc not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("c/sql/vuln/main.c.fragment"))
        .expect("read c sql fragment");
    let source = wrap_c_fragment(&fragment, c_probe_shim());

    let output = build_and_run_c(
        workdir.path(),
        "driver_c_sql_no_log",
        &source,
        &[("NYX_SQL_ENDPOINT", endpoint.as_str())],
        &["NYX_SQL_LOG"],
    );
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_SQL_LOG; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
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
fn c_http_stub_captures_attempted_outbound_via_shim_recorder() {
    if !cc_available() {
        eprintln!("SKIP: cc not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    let fragment = std::fs::read_to_string(fixture_path("c/http/vuln/main.c.fragment"))
        .expect("read c http fragment");
    let source = wrap_c_fragment(&fragment, c_probe_shim());

    let output = build_and_run_c(
        workdir.path(),
        "driver_c_http",
        &source,
        &[
            ("NYX_HTTP_ENDPOINT", endpoint.as_str()),
            (recording.0, recording.1.as_str()),
        ],
        &[],
    );
    assert!(
        output.status.success(),
        "driver must exit 0; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the C shim recorder fires"
    );
    let imds = events
        .iter()
        .find(|e| e.summary.contains("169.254.169.254"))
        .expect("recorded URL must contain the IMDS metadata host");
    assert_eq!(
        imds.detail.get("method").map(String::as_str),
        Some("GET"),
        "method line must surface in the recorded event detail"
    );
}

#[test]
fn c_http_shim_recorder_is_noop_without_log_env() {
    if !cc_available() {
        eprintln!("SKIP: cc not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("c/http/vuln/main.c.fragment"))
        .expect("read c http fragment");
    let source = wrap_c_fragment(&fragment, c_probe_shim());

    let output = build_and_run_c(
        workdir.path(),
        "driver_c_http_no_log",
        &source,
        &[("NYX_HTTP_ENDPOINT", endpoint.as_str())],
        &["NYX_HTTP_LOG"],
    );
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_HTTP_LOG; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}

// ── C++ ──────────────────────────────────────────────────────────────────────

#[test]
fn cpp_sql_stub_captures_tautology_query_via_shim_recorder() {
    if !cxx_available() {
        eprintln!("SKIP: c++ not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("SqlStub must publish a recording endpoint");

    let fragment = std::fs::read_to_string(fixture_path("cpp/sql/vuln/main.cpp.fragment"))
        .expect("read cpp sql fragment");
    let source = wrap_cpp_fragment(&fragment, cpp_probe_shim());

    let output = build_and_run_cpp(
        workdir.path(),
        "driver_cpp_sql",
        &source,
        &[
            ("NYX_SQL_ENDPOINT", endpoint.as_str()),
            (recording.0, recording.1.as_str()),
        ],
        &[],
    );
    assert!(
        output.status.success(),
        "driver must exit 0; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "SqlStub must capture at least one event after the C++ shim recorder fires"
    );
    let tautology = events
        .iter()
        .find(|e| e.summary.contains("OR 1=1"))
        .expect("recorded query must contain the tautology marker");
    assert_eq!(
        tautology.detail.get("driver").map(String::as_str),
        Some("manual"),
        "initializer-list detail passed to __nyx_stub_sql_record must surface as event detail"
    );
}

#[test]
fn cpp_sql_shim_recorder_is_noop_without_log_env() {
    if !cxx_available() {
        eprintln!("SKIP: c++ not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = SqlStub::start(workdir.path()).expect("SqlStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("cpp/sql/vuln/main.cpp.fragment"))
        .expect("read cpp sql fragment");
    let source = wrap_cpp_fragment(&fragment, cpp_probe_shim());

    let output = build_and_run_cpp(
        workdir.path(),
        "driver_cpp_sql_no_log",
        &source,
        &[("NYX_SQL_ENDPOINT", endpoint.as_str())],
        &["NYX_SQL_LOG"],
    );
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_SQL_LOG; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
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
fn cpp_http_stub_captures_attempted_outbound_via_shim_recorder() {
    if !cxx_available() {
        eprintln!("SKIP: c++ not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let recording = stub
        .recording_endpoint()
        .expect("HttpStub must publish a recording endpoint");

    let fragment = std::fs::read_to_string(fixture_path("cpp/http/vuln/main.cpp.fragment"))
        .expect("read cpp http fragment");
    let source = wrap_cpp_fragment(&fragment, cpp_probe_shim());

    let output = build_and_run_cpp(
        workdir.path(),
        "driver_cpp_http",
        &source,
        &[
            ("NYX_HTTP_ENDPOINT", endpoint.as_str()),
            (recording.0, recording.1.as_str()),
        ],
        &[],
    );
    assert!(
        output.status.success(),
        "driver must exit 0; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        !events.is_empty(),
        "HttpStub must capture at least one event after the C++ shim recorder fires"
    );
    let imds = events
        .iter()
        .find(|e| e.summary.contains("169.254.169.254"))
        .expect("recorded URL must contain the IMDS metadata host");
    assert_eq!(
        imds.detail.get("method").map(String::as_str),
        Some("GET"),
        "method line must surface in the recorded event detail"
    );
}

#[test]
fn cpp_http_shim_recorder_is_noop_without_log_env() {
    if !cxx_available() {
        eprintln!("SKIP: c++ not available");
        return;
    }

    let workdir = TempDir::new().expect("tempdir");
    let stub = HttpStub::start(workdir.path()).expect("HttpStub::start");

    let endpoint = stub.endpoint();
    let fragment = std::fs::read_to_string(fixture_path("cpp/http/vuln/main.cpp.fragment"))
        .expect("read cpp http fragment");
    let source = wrap_cpp_fragment(&fragment, cpp_probe_shim());

    let output = build_and_run_cpp(
        workdir.path(),
        "driver_cpp_http_no_log",
        &source,
        &[("NYX_HTTP_ENDPOINT", endpoint.as_str())],
        &["NYX_HTTP_LOG"],
    );
    assert!(
        output.status.success(),
        "driver must exit 0 even without NYX_HTTP_LOG; stdout = {}\nstderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = stub.drain_events();
    assert!(
        events.is_empty(),
        "no events expected when the recording env var is unset, got {} entries",
        events.len()
    );
}
