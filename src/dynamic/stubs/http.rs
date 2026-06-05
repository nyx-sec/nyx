//! HTTP stub — a localhost listener that records every request
//! (Phase 10 — Track D.3).
//!
//! Binds to `127.0.0.1:0`, accepts connections in a background thread,
//! and parses just enough of HTTP/1.1 to capture the request line,
//! headers, and body. Always responds with `200 OK\r\n\r\n` so the
//! harness perceives the call as successful — the goal is to record
//! that the call *happened*, not to faithfully emulate any real
//! origin server.
//!
//! Endpoint: `http://127.0.0.1:{port}`.
//!
//! # Side-channel recording
//!
//! In addition to the on-the-wire listener, [`HttpStub`] publishes a
//! companion log path under the [`HTTP_STUB_LOG_ENV_VAR`] env var
//! (`NYX_HTTP_LOG`).  A per-language shim helper
//! (`__nyx_stub_http_record`) appends one record per attempted outbound
//! HTTP call to that file, in the same hash-prefixed detail-then-query
//! format the SQL stub uses.  The host merges those records into
//! [`StubProvider::drain_events`] alongside the on-the-wire captures, so
//! a harness whose outbound call never reaches the listener (DNS-mocked,
//! network-isolated sandbox, pre-flight check) still produces an
//! event the oracle can match.
//!
//! # Drop
//!
//! Signals the accept thread to shut down and connects to itself to
//! wake the blocking `accept()`. The thread joins on its next loop
//! iteration; the listener socket is released by the OS.  The
//! recording log lives under the workdir-rooted tempdir which is
//! cleaned up by the verifier's tempdir handle.

use super::{StubEvent, StubKind, StubProvider, monotonic_ns};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// Companion env var that publishes [`HttpStub::log_path`] so a
/// language-side shim can append outbound HTTP attempts the host will
/// pick up on [`HttpStub::drain_events`].
pub const HTTP_STUB_LOG_ENV_VAR: &str = "NYX_HTTP_LOG";

/// Localhost HTTP request recorder.
#[derive(Debug)]
pub struct HttpStub {
    port: u16,
    events: Arc<Mutex<Vec<StubEvent>>>,
    shutdown: Arc<AtomicBool>,
    /// Tempdir holding the side-channel recording log.  Drop releases
    /// the file along with the directory.
    tempdir: Option<TempDir>,
    /// Path to the side-channel recording log.
    log_path: PathBuf,
    /// Read cursor on the log file so `drain_events` only surfaces
    /// records appended since the last drain.
    log_cursor: Mutex<u64>,
}

impl HttpStub {
    /// Bind to a random loopback port, start the accept thread, and
    /// prepare a side-channel recording log under `workdir`.  Falls
    /// back to the process-wide temp directory when `workdir` is not
    /// writable.
    pub fn start(workdir: &Path) -> std::io::Result<Self> {
        let events: Arc<Mutex<Vec<StubEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let port = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                listener.set_nonblocking(false)?;
                let port = listener.local_addr()?.port();
                let events_clone = Arc::clone(&events);
                let shutdown_clone = Arc::clone(&shutdown);
                std::thread::spawn(move || accept_loop(listener, events_clone, shutdown_clone));
                port
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Some host sandboxes deny loopback binds. Keep the
                // side-channel recorder alive so generated shims can
                // still surface attempted outbound calls deterministically.
                0
            }
            Err(e) => return Err(e),
        };

        let tempdir = TempDir::new_in(workdir).or_else(|_| TempDir::new())?;
        let log_path = tempdir.path().join("nyx_http_stub.requests.log");
        std::fs::File::create(&log_path)?;

        Ok(Self {
            port,
            events,
            shutdown,
            tempdir: Some(tempdir),
            log_path,
            log_cursor: Mutex::new(0),
        })
    }

    /// Port the listener is bound to. Useful for tests that need to
    /// assert the URL shape without parsing `endpoint()`.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Absolute path of the side-channel recording log.  The
    /// `__nyx_stub_http_record` shim helpers append outbound HTTP
    /// attempts here; the stub reads new records on drain.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Host-side helper to record a request as if it arrived on the
    /// wire. The Phase 10 integration test uses this to bypass the
    /// `connect → write → parse` path so the test runs without a real
    /// HTTP client.
    pub fn record(&self, summary: impl Into<String>) {
        let ev = StubEvent::new(StubKind::Http, summary);
        if let Ok(mut g) = self.events.lock() {
            g.push(ev);
        }
    }

    /// Drain the side-channel log file, returning every record
    /// appended since the previous call.  Format mirrors the SQL stub
    /// log: `# key: value` lines stitch onto the next non-comment line
    /// (which becomes the event summary).
    fn drain_log_file(&self) -> Vec<StubEvent> {
        let mut cursor = match self.log_cursor.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let file = match std::fs::File::open(&self.log_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        use std::io::Seek;
        let mut reader = BufReader::new(file);
        if reader.seek(std::io::SeekFrom::Start(*cursor)).is_err() {
            return Vec::new();
        }

        let mut events = Vec::new();
        let mut pending_detail = BTreeMap::<String, String>::new();
        let mut bytes_read: u64 = 0;
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = match reader.read_line(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            bytes_read += n as u64;
            let line = buf.trim_end_matches(['\r', '\n']).to_owned();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("# ") {
                if let Some((k, v)) = rest.split_once(':') {
                    pending_detail.insert(k.trim().to_owned(), v.trim().to_owned());
                }
                continue;
            }
            let mut ev = StubEvent {
                kind: StubKind::Http,
                captured_at_ns: monotonic_ns(),
                summary: line,
                detail: BTreeMap::new(),
            };
            ev.detail.append(&mut pending_detail);
            events.push(ev);
        }
        *cursor += bytes_read;
        events
    }
}

impl StubProvider for HttpStub {
    fn kind(&self) -> StubKind {
        StubKind::Http
    }

    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn recording_endpoint(&self) -> Option<(&'static str, String)> {
        Some((
            HTTP_STUB_LOG_ENV_VAR,
            self.log_path.to_string_lossy().into_owned(),
        ))
    }

    fn drain_events(&self) -> Vec<StubEvent> {
        let mut out = match self.events.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        };
        out.extend(self.drain_log_file());
        out
    }
}

impl Drop for HttpStub {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Wake the blocking accept by connecting once.
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        // TempDir's own Drop deletes the side-channel log + dir.
        self.tempdir.take();
    }
}

fn accept_loop(
    listener: TcpListener,
    events: Arc<Mutex<Vec<StubEvent>>>,
    shutdown: Arc<AtomicBool>,
) {
    // Per-connection read budget. Real harnesses send short requests;
    // anything beyond this limit is truncated to keep the stub
    // bounded under adversarial payloads.
    const MAX_REQUEST_BYTES: usize = 64 * 1024;

    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

        if let Some(ev) = handle_connection(stream, MAX_REQUEST_BYTES)
            && let Ok(mut g) = events.lock()
        {
            g.push(ev);
        }
    }
}

/// Read a request, capture metadata, send a minimal 200 OK.
fn handle_connection(mut stream: TcpStream, max_bytes: usize) -> Option<StubEvent> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);

    // Request line.
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        // Shutdown wakeup connection — no request to record.
        return None;
    }
    let request_line = line.trim_end_matches(['\r', '\n']).to_owned();

    // Headers.
    let mut headers: Vec<String> = Vec::new();
    let mut content_length: usize = 0;
    loop {
        let mut hdr = String::new();
        if reader.read_line(&mut hdr).ok()? == 0 {
            break;
        }
        let trimmed = hdr.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.to_ascii_lowercase().strip_prefix("content-length:")
            && let Ok(n) = rest.trim().parse::<usize>()
        {
            content_length = n.min(max_bytes);
        }
        headers.push(trimmed.to_owned());
    }

    // Body, capped at content_length (already clamped to max_bytes).
    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        body.clear();
    }

    // Always reply 200 OK with no body.
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.flush();

    // Build the event. `summary` is the request line; `detail`
    // carries the parsed headers + a UTF-8 view of the body when
    // possible.
    let mut detail = BTreeMap::new();
    if !headers.is_empty() {
        detail.insert("headers".to_owned(), headers.join("\n"));
    }
    if !body.is_empty() {
        match std::str::from_utf8(&body) {
            Ok(s) => {
                detail.insert("body".to_owned(), s.to_owned());
            }
            Err(_) => {
                detail.insert("body_bytes".to_owned(), format!("<{} bytes>", body.len()));
            }
        }
    }

    Some(StubEvent {
        kind: StubKind::Http,
        captured_at_ns: monotonic_ns(),
        summary: request_line,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn send_request(port: u16, request: &[u8]) -> Vec<u8> {
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        s.write_all(request).unwrap();
        s.flush().unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }

    fn start_stub() -> Option<(TempDir, HttpStub)> {
        let dir = TempDir::new().unwrap();
        match HttpStub::start(dir.path()) {
            Ok(stub) => Some((dir, stub)),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(e) => panic!("start http stub: {e}"),
        }
    }

    #[test]
    fn endpoint_uses_loopback_with_assigned_port() {
        let Some((_dir, stub)) = start_stub() else {
            return;
        };
        let ep = stub.endpoint();
        assert!(ep.starts_with("http://127.0.0.1:"));
        assert!(ep.ends_with(&stub.port().to_string()));
    }

    #[test]
    fn captures_request_line_via_real_socket() {
        let Some((_dir, stub)) = start_stub() else {
            return;
        };
        if stub.port() == 0 {
            return;
        }
        let reply = send_request(
            stub.port(),
            b"GET /api/users HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        // Allow the accept thread to flush the event.
        std::thread::sleep(Duration::from_millis(50));
        assert!(reply.starts_with(b"HTTP/1.1 200 OK"));
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert!(
            events[0].summary.contains("/api/users"),
            "summary must contain request line, got {:?}",
            events[0].summary
        );
    }

    #[test]
    fn captures_post_body() {
        let Some((_dir, stub)) = start_stub() else {
            return;
        };
        if stub.port() == 0 {
            return;
        }
        let body = b"username=admin&password=hunter2";
        let req = format!(
            "POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut full = req.into_bytes();
        full.extend_from_slice(body);
        let _ = send_request(stub.port(), &full);
        std::thread::sleep(Duration::from_millis(50));
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].detail.get("body").map(String::as_str),
            Some("username=admin&password=hunter2")
        );
    }

    #[test]
    fn drain_resets_event_buffer() {
        let Some((_dir, stub)) = start_stub() else {
            return;
        };
        stub.record("GET /first HTTP/1.1");
        assert_eq!(stub.drain_events().len(), 1);
        assert!(stub.drain_events().is_empty(), "second drain must be empty");
    }

    #[test]
    fn drop_releases_port_for_rebind() {
        let port = {
            let Some((_dir, stub)) = start_stub() else {
                return;
            };
            stub.port()
        };
        // After drop, the OS releases the port. The accept thread may
        // need a moment to exit; SO_REUSEADDR is enabled by default
        // on most platforms so a near-immediate rebind usually works.
        std::thread::sleep(Duration::from_millis(50));
        let _ = TcpListener::bind(format!("127.0.0.1:{port}"));
        // We don't assert success here — the OS may hold the port in
        // TIME_WAIT — but Drop must not panic or deadlock.
    }

    #[test]
    fn recording_endpoint_publishes_log_path_under_nyx_http_log() {
        let Some((_dir, stub)) = start_stub() else {
            return;
        };
        let pair = stub
            .recording_endpoint()
            .expect("HttpStub must publish a recording endpoint");
        assert_eq!(pair.0, HTTP_STUB_LOG_ENV_VAR);
        assert_eq!(pair.0, "NYX_HTTP_LOG");
        assert_eq!(pair.1, stub.log_path().to_string_lossy());
        assert!(
            stub.log_path().exists(),
            "side-channel log file must be created on start",
        );
    }

    #[test]
    fn drain_events_merges_log_file_records_with_in_memory_events() {
        let Some((_dir, stub)) = start_stub() else {
            return;
        };
        // Simulate the on-the-wire path.
        stub.record("GET /listener-hit HTTP/1.1");
        // Simulate the shim path: append a detail-then-summary record
        // mirroring the SQL stub log format.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(stub.log_path())
            .unwrap();
        f.write_all(
            b"# method: POST\n# url: http://example.com/login\nPOST http://example.com/login\n",
        )
        .unwrap();
        drop(f);

        let events = stub.drain_events();
        assert_eq!(events.len(), 2, "both sources must surface, got {events:?}");
        let summaries: Vec<_> = events.iter().map(|e| e.summary.as_str()).collect();
        assert!(summaries.contains(&"GET /listener-hit HTTP/1.1"));
        assert!(summaries.contains(&"POST http://example.com/login"));
        let shim_event = events
            .iter()
            .find(|e| e.summary.starts_with("POST http://example.com"))
            .unwrap();
        assert_eq!(
            shim_event.detail.get("method").map(String::as_str),
            Some("POST"),
        );
        assert_eq!(
            shim_event.detail.get("url").map(String::as_str),
            Some("http://example.com/login"),
        );
    }

    #[test]
    fn drain_log_file_returns_only_new_entries() {
        let Some((_dir, stub)) = start_stub() else {
            return;
        };
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(stub.log_path())
            .unwrap();
        f.write_all(b"GET /one\n").unwrap();
        drop(f);
        assert_eq!(stub.drain_events().len(), 1);

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(stub.log_path())
            .unwrap();
        f.write_all(b"GET /two\n").unwrap();
        drop(f);
        let second = stub.drain_events();
        assert_eq!(second.len(), 1, "drain must return only the new record");
        assert_eq!(second[0].summary, "GET /two");
    }
}
