//! Minimal RESP-speaking Redis stub (Phase 10 — Track D.3).
//!
//! Speaks just enough of RESP2 to make a real Redis client believe it
//! is talking to a server: inline commands and `*N\r\n$len\r\nvalue\r\n`
//! framed arrays are both accepted; every command is answered with a
//! short canned reply (`+OK\r\n` for writes, `$-1\r\n` for `GET`,
//! `:0\r\n` for `DEL`/`EXISTS`). The point is to capture *which*
//! command + args the harness issued, not to faithfully emulate a
//! cache.
//!
//! Endpoint: `127.0.0.1:{port}` — no scheme prefix because every
//! mainstream Redis client takes a bare `host:port` pair.
//!
//! # Drop
//!
//! Same shutdown shape as [`crate::dynamic::stubs::http::HttpStub`]:
//! signal the accept thread, then connect once to unblock the
//! accept syscall.

use super::{StubEvent, StubKind, StubProvider};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Localhost RESP command recorder.
#[derive(Debug)]
pub struct RedisStub {
    port: u16,
    events: Arc<Mutex<Vec<StubEvent>>>,
    shutdown: Arc<AtomicBool>,
}

impl RedisStub {
    /// Bind to a random loopback port and start accepting connections.
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();

        let events: Arc<Mutex<Vec<StubEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let events_clone = Arc::clone(&events);
        let shutdown_clone = Arc::clone(&shutdown);
        std::thread::spawn(move || accept_loop(listener, events_clone, shutdown_clone));

        Ok(Self {
            port,
            events,
            shutdown,
        })
    }

    /// Port the listener is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Host-side helper to record a synthetic command — used by the
    /// Phase 10 integration test so we don't need a real Redis
    /// client to exercise the event capture path.
    pub fn record(&self, command: impl Into<String>, args: &[&str]) {
        let cmd_s = command.into();
        let mut ev = StubEvent::new(
            StubKind::Redis,
            format!("{} {}", cmd_s, args.join(" ")).trim().to_owned(),
        )
        .with_detail("command", cmd_s);
        if !args.is_empty() {
            ev = ev.with_detail("args", args.join(","));
        }
        if let Ok(mut g) = self.events.lock() {
            g.push(ev);
        }
    }
}

impl StubProvider for RedisStub {
    fn kind(&self) -> StubKind {
        StubKind::Redis
    }

    fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn drain_events(&self) -> Vec<StubEvent> {
        match self.events.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for RedisStub {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
    }
}

fn accept_loop(
    listener: TcpListener,
    events: Arc<Mutex<Vec<StubEvent>>>,
    shutdown: Arc<AtomicBool>,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Ok(s) = stream else { continue };
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
        let events = Arc::clone(&events);
        // Each client gets its own thread so a slow harness does not
        // block subsequent test connections.
        std::thread::spawn(move || handle_client(s, events));
    }
}

/// Loop reading RESP commands from `stream` and recording each one
/// until the client disconnects.
fn handle_client(stream: TcpStream, events: Arc<Mutex<Vec<StubEvent>>>) {
    let mut writer = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    loop {
        let parts = match read_command(&mut reader) {
            Some(p) if !p.is_empty() => p,
            _ => break,
        };
        if let Ok(mut g) = events.lock() {
            g.push(command_to_event(&parts));
        }
        let reply = pick_reply(&parts);
        if writer.write_all(reply.as_bytes()).is_err() {
            break;
        }
    }
}

/// Read one command (inline or array form). Returns `None` on EOF.
fn read_command(reader: &mut BufReader<TcpStream>) -> Option<Vec<String>> {
    let mut first = String::new();
    if reader.read_line(&mut first).ok()? == 0 {
        return None;
    }
    let first_trim = first.trim_end_matches(['\r', '\n']);
    if first_trim.is_empty() {
        return Some(vec![]);
    }

    if let Some(rest) = first_trim.strip_prefix('*') {
        // Array form: `*N\r\n` then N times `$len\r\nbulk\r\n`.
        let n: usize = rest.trim().parse().ok()?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let mut hdr = String::new();
            if reader.read_line(&mut hdr).ok()? == 0 {
                return None;
            }
            let hdr_trim = hdr.trim_end_matches(['\r', '\n']);
            let len: usize = hdr_trim.strip_prefix('$')?.trim().parse().ok()?;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).ok()?;
            // Consume trailing CRLF.
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf);
            out.push(String::from_utf8_lossy(&buf).into_owned());
        }
        Some(out)
    } else {
        // Inline form: whitespace-separated tokens on one line.
        Some(
            first_trim
                .split_whitespace()
                .map(|s| s.to_owned())
                .collect(),
        )
    }
}

fn command_to_event(parts: &[String]) -> StubEvent {
    let (cmd, args) = parts
        .split_first()
        .map(|(c, a)| (c.as_str(), a))
        .unwrap_or(("", &[][..]));
    let summary = if args.is_empty() {
        cmd.to_owned()
    } else {
        format!("{} {}", cmd, args.join(" "))
    };
    let mut detail = BTreeMap::new();
    if !cmd.is_empty() {
        detail.insert("command".to_owned(), cmd.to_ascii_uppercase());
    }
    if !args.is_empty() {
        detail.insert("args".to_owned(), args.join(","));
    }
    StubEvent {
        kind: StubKind::Redis,
        captured_at_ns: super::monotonic_ns(),
        summary,
        detail,
    }
}

fn pick_reply(parts: &[String]) -> &'static str {
    let cmd = parts
        .first()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or_default();
    match cmd.as_str() {
        "GET" | "HGET" | "LPOP" | "RPOP" => "$-1\r\n",
        "DEL" | "EXISTS" | "INCR" | "DECR" | "LLEN" => ":0\r\n",
        "PING" => "+PONG\r\n",
        _ => "+OK\r\n",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_has_no_scheme_prefix() {
        let stub = RedisStub::start().unwrap();
        let ep = stub.endpoint();
        assert!(ep.starts_with("127.0.0.1:"));
        assert!(!ep.contains("://"));
    }

    #[test]
    fn captures_inline_command() {
        let stub = RedisStub::start().unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", stub.port())).unwrap();
        s.write_all(b"SET user:1 alice\r\n").unwrap();
        s.flush().unwrap();
        let mut reply = [0u8; 5];
        let _ = s.read_exact(&mut reply);
        std::thread::sleep(Duration::from_millis(50));
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.starts_with("SET"));
        assert_eq!(
            events[0].detail.get("command").map(String::as_str),
            Some("SET")
        );
    }

    #[test]
    fn captures_resp_array_command() {
        let stub = RedisStub::start().unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", stub.port())).unwrap();
        // `GET sessions`
        s.write_all(b"*2\r\n$3\r\nGET\r\n$8\r\nsessions\r\n")
            .unwrap();
        s.flush().unwrap();
        let mut reply = [0u8; 5];
        let _ = s.read_exact(&mut reply);
        std::thread::sleep(Duration::from_millis(50));
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.contains("sessions"));
        assert_eq!(
            events[0].detail.get("command").map(String::as_str),
            Some("GET")
        );
    }

    #[test]
    fn record_helper_lands_on_drain() {
        let stub = RedisStub::start().unwrap();
        stub.record("FLUSHALL", &[]);
        stub.record("SET", &["key", "val"]);
        let events = stub.drain_events();
        assert_eq!(events.len(), 2);
        assert!(events[0].summary.contains("FLUSHALL"));
        assert!(events[1].summary.contains("key"));
    }

    #[test]
    fn provider_kind_is_redis() {
        let stub = RedisStub::start().unwrap();
        assert_eq!(stub.kind(), StubKind::Redis);
    }
}
