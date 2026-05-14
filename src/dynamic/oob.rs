//! Out-of-band (OOB) callback listener.
//!
//! Binds a TCP server to `127.0.0.1:0` (OS-assigned port), spins up a
//! background accept thread, and records every nonce it receives via the
//! URL path.  The lifetime of the listener is per-scan: create one
//! [`OobListener`] at scan start, drop it when the scan finishes.
//!
//! # Wiring
//!
//! As of Phase 05 the listener is load-bearing: [`crate::dynamic::verify::VerifyOptions::from_config`]
//! constructs one per scan via [`OobListener::bind`] and threads it into
//! [`crate::dynamic::sandbox::SandboxOptions::oob_listener`]. The runner
//! polls [`OobListener::was_nonce_hit`] after each sandbox run (see
//! `src/dynamic/runner.rs`) and toggles
//! [`crate::dynamic::sandbox::SandboxOutcome::oob_callback_seen`] when a
//! probe arrives — that is the only signal that turns an OOB-only sink
//! (e.g. blind SSRF) into a `Confirmed` verdict.
//!
//! # Nonce URL
//!
//! The caller generates a per-finding nonce (UUID4 hex) and embeds it in
//! the payload via [`OobListener::nonce_url`].  After each sandbox run the
//! caller calls [`OobListener::was_nonce_hit`] to confirm the callback
//! actually arrived.
//!
//! # Docker sandboxes
//!
//! For Docker sandboxes the OOB host is reachable at the Docker bridge
//! gateway address (`host-gateway` via `--add-host`). The runner populates
//! the `NYX_OOB_URL` env-var inside the container with the correct URL.
//! The process sandbox uses `127.0.0.1` directly.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Per-scan out-of-band callback listener.
///
/// Binds to `127.0.0.1:0` on creation.  Drop to stop the accept thread.
#[derive(Debug)]
pub struct OobListener {
    port: u16,
    hits: Arc<Mutex<HashSet<String>>>,
    shutdown: Arc<AtomicBool>,
}

impl OobListener {
    /// Bind to a random loopback port and start the accept thread.
    pub fn bind() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();

        let hits: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let hits_clone = Arc::clone(&hits);
        let shutdown_clone = Arc::clone(&shutdown);

        std::thread::spawn(move || {
            accept_loop(listener, hits_clone, shutdown_clone);
        });

        Ok(Self { port, hits, shutdown })
    }

    /// Port the listener is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// URL to embed in a payload for `nonce`.
    ///
    /// Format: `http://127.0.0.1:{port}/{nonce}`.  Use this URL for the
    /// process sandbox.  For Docker sandboxes use [`nonce_url_for_host`].
    pub fn nonce_url(&self, nonce: &str) -> String {
        format!("http://127.0.0.1:{}/{}", self.port, nonce)
    }

    /// URL using an explicit host (e.g. `host-gateway` inside Docker).
    pub fn nonce_url_for_host(&self, host: &str, nonce: &str) -> String {
        format!("http://{}:{}/{}", host, self.port, nonce)
    }

    /// Returns `true` if `nonce` was received by the listener.
    pub fn was_nonce_hit(&self, nonce: &str) -> bool {
        self.hits
            .lock()
            .map(|h| h.contains(nonce))
            .unwrap_or(false)
    }

    /// Polls until `nonce` is recorded or `timeout` elapses.
    ///
    /// Returns immediately on hit; polls every 5 ms otherwise.
    /// Prefer this over a fixed sleep + `was_nonce_hit` at call sites.
    pub fn wait_for_nonce(&self, nonce: &str, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.was_nonce_hit(nonce) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            std::thread::sleep(remaining.min(Duration::from_millis(5)));
        }
    }
}

impl Drop for OobListener {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Wake up the blocking accept() call by connecting to ourselves.
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
    }
}

fn accept_loop(
    listener: TcpListener,
    hits: Arc<Mutex<HashSet<String>>>,
    shutdown: Arc<AtomicBool>,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match stream {
            Ok(s) => {
                let h = Arc::clone(&hits);
                std::thread::spawn(move || handle_connection(s, h));
            }
            Err(_) => break,
        }
    }
}

fn handle_connection(stream: TcpStream, hits: Arc<Mutex<HashSet<String>>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut reader = BufReader::new(&stream);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).is_ok() {
        if let Some(nonce) = parse_nonce_from_request_line(&first_line) {
            if let Ok(mut h) = hits.lock() {
                h.insert(nonce);
            }
        }
    }
    // Drain remaining headers so the client doesn't get ECONNRESET.
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Err(_) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            Ok(_) => {}
        }
    }
    let mut w = &stream;
    let _ = w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok");
}

/// Extract the nonce from a `GET /{nonce} HTTP/1.1` request line.
fn parse_nonce_from_request_line(line: &str) -> Option<String> {
    let mut parts = line.trim().splitn(3, ' ');
    let method = parts.next()?;
    let path = parts.next()?;
    if method != "GET" {
        return None;
    }
    let nonce = path.trim_start_matches('/').split('?').next()?;
    if nonce.is_empty() {
        return None;
    }
    Some(nonce.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nonce_standard_get() {
        assert_eq!(
            parse_nonce_from_request_line("GET /abc123 HTTP/1.1"),
            Some("abc123".to_owned()),
        );
    }

    #[test]
    fn parse_nonce_strips_query() {
        assert_eq!(
            parse_nonce_from_request_line("GET /abc123?foo=bar HTTP/1.1"),
            Some("abc123".to_owned()),
        );
    }

    #[test]
    fn parse_nonce_empty_path() {
        assert!(parse_nonce_from_request_line("GET / HTTP/1.1").is_none());
    }

    #[test]
    fn parse_nonce_non_get() {
        assert!(parse_nonce_from_request_line("POST /abc123 HTTP/1.1").is_none());
    }

    #[test]
    fn oob_listener_bind_and_port() {
        let listener = OobListener::bind().expect("bind must succeed on loopback");
        assert_ne!(listener.port(), 0, "OS must assign a non-zero port");
    }

    #[test]
    fn oob_listener_records_nonce_via_http() {
        let listener = OobListener::bind().expect("bind");
        let nonce = "nyx_test_nonce_abc123";
        let url = listener.nonce_url(nonce);

        // Give the accept thread a moment to start.
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Make an HTTP request with the nonce in the path.
        let addr = format!("127.0.0.1:{}", listener.port());
        if let Ok(mut stream) = TcpStream::connect(&addr) {
            let req = format!("GET /{nonce} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
            let _ = stream.write_all(req.as_bytes());
            // Read response to ensure the server processed the request.
            let mut buf = [0u8; 64];
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let _ = std::io::Read::read(&mut stream, &mut buf);
        }

        // Allow the handler thread to update the hits set.
        std::thread::sleep(std::time::Duration::from_millis(50));

        assert!(
            listener.was_nonce_hit(nonce),
            "listener must record the nonce from the HTTP request; url={url}"
        );
    }

    #[test]
    fn oob_listener_unknown_nonce_not_hit() {
        let listener = OobListener::bind().expect("bind");
        assert!(!listener.was_nonce_hit("not_a_real_nonce_xyz"));
    }

    #[test]
    fn nonce_url_format() {
        let listener = OobListener::bind().expect("bind");
        let port = listener.port();
        let url = listener.nonce_url("mynonce");
        assert_eq!(url, format!("http://127.0.0.1:{port}/mynonce"));
    }
}
