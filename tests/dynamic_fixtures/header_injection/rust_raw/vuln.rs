// Phase 08 (Track J.6) — Rust raw-socket HEADER_INJECTION vuln fixture.
//
// Writes the response status line and headers directly to the wire via
// `TcpStream::write_all`, bypassing the framework-level CRLF validator
// that axum / Tomcat would otherwise interpose.  A payload carrying
// `\r\nSet-Cookie: ...` splits the single Set-Cookie header into two on
// the wire, producing the canonical smuggled-second-header shape that
// `ProbeKind::HeaderWireFrame` is designed to catch.
//
// The harness (`src/dynamic/lang/rust.rs::emit_header_injection_harness`)
// detects the `TcpListener::bind` token in this file and routes through
// the tier-(b) wire-frame branch: bind a loopback `TcpListener` via
// `create_server`, spawn the accept loop on a thread (`run_once`),
// issue one raw `GET / HTTP/1.0\r\n` from the harness, read the bytes
// the fixture wrote to the response socket, and emit them as a
// `ProbeKind::HeaderWireFrame` record.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::sync::Mutex;

/// Bytes go straight onto the wire with no encoding pass.  The harness
/// installs the cookie value before booting the accept loop, mirroring
/// the JS `setCookieValue` and Python `Handler.cookie_value =` setters.
static COOKIE_VALUE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

pub fn set_cookie_value(value: &[u8]) {
    let mut guard = COOKIE_VALUE.lock().expect("cookie mutex poisoned");
    guard.clear();
    guard.extend_from_slice(value);
}

pub fn create_server() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port")
}

pub fn run_once(listener: TcpListener) {
    let Ok((mut socket, _addr)) = listener.accept() else {
        return;
    };
    let mut scratch = [0u8; 4096];
    let _ = socket.read(&mut scratch);
    let cookie = COOKIE_VALUE
        .lock()
        .expect("cookie mutex poisoned")
        .clone();
    let body = b"ok\n";
    let mut raw = Vec::new();
    raw.extend_from_slice(b"HTTP/1.0 200 OK\r\n");
    raw.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    raw.extend_from_slice(b"Set-Cookie: ");
    raw.extend_from_slice(&cookie);
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(body);
    let _ = socket.write_all(&raw);
    let _ = socket.shutdown(Shutdown::Both);
}
