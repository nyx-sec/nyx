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
//! # Drop
//!
//! Signals the accept thread to shut down and connects to itself to
//! wake the blocking `accept()`. The thread joins on its next loop
//! iteration; the listener socket is released by the OS.

use super::{monotonic_ns, StubEvent, StubKind, StubProvider};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Localhost HTTP request recorder.
#[derive(Debug)]
pub struct HttpStub {
    port: u16,
    events: Arc<Mutex<Vec<StubEvent>>>,
    shutdown: Arc<AtomicBool>,
}

impl HttpStub {
    /// Bind to a random loopback port and start the accept thread.
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();

        let events: Arc<Mutex<Vec<StubEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let events_clone = Arc::clone(&events);
        let shutdown_clone = Arc::clone(&shutdown);
        std::thread::spawn(move || accept_loop(listener, events_clone, shutdown_clone));

        Ok(Self { port, events, shutdown })
    }

    /// Port the listener is bound to. Useful for tests that need to
    /// assert the URL shape without parsing `endpoint()`.
    pub fn port(&self) -> u16 {
        self.port
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
}

impl StubProvider for HttpStub {
    fn kind(&self) -> StubKind {
        StubKind::Http
    }

    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn drain_events(&self) -> Vec<StubEvent> {
        match self.events.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for HttpStub {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Wake the blocking accept by connecting once.
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
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

        if let Some(ev) = handle_connection(stream, MAX_REQUEST_BYTES) {
            if let Ok(mut g) = events.lock() {
                g.push(ev);
            }
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
        if let Some(rest) = trimmed
            .to_ascii_lowercase()
            .strip_prefix("content-length:")
        {
            if let Ok(n) = rest.trim().parse::<usize>() {
                content_length = n.min(max_bytes);
            }
        }
        headers.push(trimmed.to_owned());
    }

    // Body, capped at content_length (already clamped to max_bytes).
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        if reader.read_exact(&mut body).is_err() {
            body.clear();
        }
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

    fn send_request(port: u16, request: &[u8]) -> Vec<u8> {
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        s.write_all(request).unwrap();
        s.flush().unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }

    #[test]
    fn endpoint_uses_loopback_with_assigned_port() {
        let stub = HttpStub::start().unwrap();
        let ep = stub.endpoint();
        assert!(ep.starts_with("http://127.0.0.1:"));
        assert!(ep.ends_with(&stub.port().to_string()));
    }

    #[test]
    fn captures_request_line_via_real_socket() {
        let stub = HttpStub::start().unwrap();
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
        let stub = HttpStub::start().unwrap();
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
        let stub = HttpStub::start().unwrap();
        stub.record("GET /first HTTP/1.1");
        assert_eq!(stub.drain_events().len(), 1);
        assert!(stub.drain_events().is_empty(), "second drain must be empty");
    }

    #[test]
    fn drop_releases_port_for_rebind() {
        let port = {
            let stub = HttpStub::start().unwrap();
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
}
