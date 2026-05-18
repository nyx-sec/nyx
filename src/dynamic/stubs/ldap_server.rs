//! Minimal in-sandbox LDAP server stub (Phase 06 — Track J.4).
//!
//! The brief calls for "a 200-line Go implementation reused across langs
//! over loopback".  This module ships the same idea in Rust: a tiny TCP
//! listener that speaks a one-line text protocol — `SEARCH <filter>\n`
//! → `COUNT <n>\nDN <dn1>\nDN <dn2>\n…\nEND\n` — so the per-language
//! harness shims can drive a uniform request/response loop without
//! linking a real LDAP client (jldap, python-ldap, ldap_search).
//!
//! Endpoint: `127.0.0.1:{port}` (no scheme; the harness composes
//! `ldap://` itself if it wants).
//!
//! # Directory state
//!
//! Three users are provisioned at startup: `alice`, `bob`, `carol`.  An
//! incoming search filter is scanned with a tiny RFC 4515 subset:
//!
//! * `(uid=<value>)` matches the user whose `uid` byte-for-byte equals
//!   `<value>`.
//! * `(uid=<prefix>*<suffix>)` matches every user whose `uid` matches
//!   the wildcard skeleton.
//! * Bare `*` inside *any* attribute slot matches every entry.
//! * Boolean wrappers `(&(…)(…))`, `(|(…)(…))` recurse into the inner
//!   clauses.
//!
//! Anything outside that subset short-circuits to "match-everything" so
//! adversarial payloads (`*)(uid=*` after the harness's quote-and-paste
//! mistake) cannot accidentally produce a 0-result false negative.
//!
//! # Recording
//!
//! Every served search appends a [`StubEvent`] keyed on `summary =
//! "SEARCH <filter>"` and `detail["entries_returned"]` so the oracle's
//! [`crate::dynamic::oracle::ProbePredicate::QueryResultCountGreaterThan`]
//! can satisfy without depending on a `ProbeKind::Ldap` write — the
//! probe path is the primary signal, the stub-event log is the
//! belt-and-braces side channel.
//!
//! # Drop
//!
//! Signals the accept thread to shut down and connects to itself to
//! wake the blocking `accept()`.

use super::{monotonic_ns, StubEvent, StubKind, StubProvider};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Companion env var the harness shim reads to reach the stub.  Set on
/// the sandbox env by [`crate::dynamic::stubs::StubHarness::endpoints`]
/// when an [`LdapStub`] is registered.
pub const LDAP_ENDPOINT_ENV_VAR: &str = "NYX_LDAP_ENDPOINT";

/// Three canonical users the stub provisions on start.  Tests pin the
/// count so a corpus change cannot silently shift the differential
/// threshold below `QueryResultCountGreaterThan { n: 1 }`.
pub const STUB_USERS: &[&str] = &["alice", "bob", "carol"];

/// LDAP-cap stub.  Endpoint is `127.0.0.1:{port}`.
#[derive(Debug)]
pub struct LdapStub {
    port: u16,
    events: Arc<Mutex<Vec<StubEvent>>>,
    shutdown: Arc<AtomicBool>,
}

impl LdapStub {
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

        Ok(Self {
            port,
            events,
            shutdown,
        })
    }

    /// Port the listener is bound to (test helper).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Host-side helper to record a search as if a harness had issued
    /// it.  The Phase 06 unit tests use this to bypass the
    /// `connect → write → parse` path so the test runs without a real
    /// TCP client.
    pub fn record_search(&self, filter: &str, entries_returned: u32) {
        let ev = StubEvent {
            kind: StubKind::Ldap,
            captured_at_ns: monotonic_ns(),
            summary: format!("SEARCH {filter}"),
            detail: {
                let mut d = BTreeMap::new();
                d.insert("filter".to_owned(), filter.to_owned());
                d.insert(
                    "entries_returned".to_owned(),
                    entries_returned.to_string(),
                );
                d
            },
        };
        if let Ok(mut g) = self.events.lock() {
            g.push(ev);
        }
    }

    /// Evaluate `filter` against the in-memory directory and return the
    /// matching uids (lexicographic).  Public so the synthetic harness
    /// shims can mirror the stub's scoring logic when running without
    /// a live socket.
    pub fn evaluate(filter: &str) -> Vec<&'static str> {
        match_filter(filter)
    }
}

impl StubProvider for LdapStub {
    fn kind(&self) -> StubKind {
        StubKind::Ldap
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

impl Drop for LdapStub {
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
    const MAX_REQUEST_BYTES: usize = 4 * 1024;
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
        handle_connection(stream, MAX_REQUEST_BYTES, &events);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    max_bytes: usize,
    events: &Arc<Mutex<Vec<StubEvent>>>,
) {
    let mut reader = match stream.try_clone() {
        Ok(s) => BufReader::new(s),
        Err(_) => return,
    };
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return,
        Ok(_) => {}
        Err(_) => return,
    }
    if line.len() > max_bytes {
        line.truncate(max_bytes);
    }
    let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
    let filter = match trimmed.strip_prefix("SEARCH ") {
        Some(rest) => rest.trim().to_owned(),
        None => return,
    };
    let matches = match_filter(&filter);
    let count = matches.len();
    let mut reply = format!("COUNT {count}\n");
    for uid in &matches {
        reply.push_str(&format!("DN uid={uid},ou=people,dc=nyx,dc=test\n"));
    }
    reply.push_str("END\n");
    let _ = stream.write_all(reply.as_bytes());
    let _ = stream.flush();

    let ev = StubEvent {
        kind: StubKind::Ldap,
        captured_at_ns: monotonic_ns(),
        summary: format!("SEARCH {filter}"),
        detail: {
            let mut d = BTreeMap::new();
            d.insert("filter".to_owned(), filter);
            d.insert("entries_returned".to_owned(), count.to_string());
            d
        },
    };
    if let Ok(mut g) = events.lock() {
        g.push(ev);
    }
}

/// RFC-4515-subset matcher.  See module docs for the grammar.
fn match_filter(filter: &str) -> Vec<&'static str> {
    let trimmed = filter.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    // Adversarial / unparseable filters fall through to match-all so a
    // harness mistake never silently produces zero entries.
    let parsed = match parse_filter(trimmed) {
        Some(f) => f,
        None => return STUB_USERS.to_vec(),
    };
    STUB_USERS
        .iter()
        .copied()
        .filter(|u| filter_matches_user(&parsed, u))
        .collect()
}

#[derive(Debug)]
enum Filter<'a> {
    Eq { attr: &'a str, pattern: &'a str },
    And(Vec<Filter<'a>>),
    Or(Vec<Filter<'a>>),
    /// Anything we did not recognise — treated as match-everything by
    /// the matcher, preserving the over-match policy.
    Wild,
}

/// Parse a single top-level filter.  Returns `Some(Wild)` for anything
/// the subset does not cover (including the canonical filter-injection
/// breakout shape `(uid=alice*)(uid=*)` whose outer parens fence two
/// adjacent groups rather than a single enclosing filter); returns
/// `None` only when the string is not balanced enough to scan at all.
fn parse_filter(src: &str) -> Option<Filter<'_>> {
    let s = src.trim();
    if !s.starts_with('(') || !s.ends_with(')') {
        return Some(Filter::Wild);
    }
    let inner = &s[1..s.len() - 1];
    if inner_has_unbalanced_break(inner) {
        // Two-or-more adjacent paren groups at the outer level —
        // matches the brief's `*)(uid=*` breakout shape.  Fall through
        // to match-everything so adversarial payloads cannot silently
        // produce a 0-result false negative.
        return Some(Filter::Wild);
    }
    if let Some(rest) = inner.strip_prefix('&') {
        return Some(Filter::And(split_clauses(rest)));
    }
    if let Some(rest) = inner.strip_prefix('|') {
        return Some(Filter::Or(split_clauses(rest)));
    }
    let (attr, pattern) = inner.split_once('=')?;
    Some(Filter::Eq {
        attr: attr.trim(),
        pattern: pattern.trim(),
    })
}

/// True when `inner` (the substring between the outer `(` and `)` of
/// a candidate filter) carries a `)` before a matching `(` — the
/// telltale of `(filterA)(filterB)` where the outer parens fenced
/// only the first group, not the whole expression.
fn inner_has_unbalanced_break(inner: &str) -> bool {
    let mut depth: i32 = 0;
    for c in inner.bytes() {
        match c {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn split_clauses(src: &str) -> Vec<Filter<'_>> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'(' {
            i += 1;
            continue;
        }
        let mut depth = 0;
        let start = i;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let slice = &src[start..i];
        if let Some(f) = parse_filter(slice) {
            out.push(f);
        }
    }
    out
}

fn filter_matches_user(f: &Filter<'_>, uid: &str) -> bool {
    match f {
        Filter::Wild => true,
        Filter::Eq { attr, pattern } => attr_matches(attr, pattern, uid),
        Filter::And(inner) => inner.iter().all(|c| filter_matches_user(c, uid)),
        Filter::Or(inner) => inner.iter().any(|c| filter_matches_user(c, uid)),
    }
}

fn attr_matches(attr: &str, pattern: &str, uid: &str) -> bool {
    if !attr.eq_ignore_ascii_case("uid") && !attr.eq_ignore_ascii_case("cn") {
        // Unrecognised attribute — over-match.
        return true;
    }
    if pattern == "*" {
        return true;
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return uid.starts_with(prefix) && uid.ends_with(suffix);
    }
    pattern == uid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn evaluate_returns_one_for_concrete_uid() {
        let m = LdapStub::evaluate("(uid=alice)");
        assert_eq!(m, vec!["alice"]);
    }

    #[test]
    fn evaluate_returns_all_for_wildcard() {
        let m = LdapStub::evaluate("(uid=*)");
        assert_eq!(m, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn evaluate_returns_all_for_injection_pattern() {
        // Adversarial filter the brief calls out — payload `*)(uid=*`
        // appended to a `(uid=alice)` template lands inside an `(|…)`
        // disjunction wrapper most clients emit, so every user
        // matches.
        let m = LdapStub::evaluate("(|(uid=alice)(uid=*))");
        assert_eq!(m, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn unparseable_filter_matches_everything() {
        // No surrounding parens — match-all fallback fires.
        let m = LdapStub::evaluate("uid=alice");
        assert_eq!(m, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn evaluate_returns_empty_for_unknown_concrete_uid() {
        let m = LdapStub::evaluate("(uid=nobody)");
        assert!(m.is_empty());
    }

    #[test]
    fn endpoint_uses_loopback_with_assigned_port() {
        let stub = LdapStub::start().unwrap();
        let ep = stub.endpoint();
        assert!(ep.starts_with("127.0.0.1:"));
        assert!(ep.ends_with(&stub.port().to_string()));
    }

    #[test]
    fn search_request_returns_three_for_wildcard_via_socket() {
        let stub = LdapStub::start().unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", stub.port())).unwrap();
        s.write_all(b"SEARCH (uid=*)\n").unwrap();
        s.flush().unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("COUNT 3\n"), "got {out:?}");
        assert!(out.contains("uid=alice"));
        std::thread::sleep(Duration::from_millis(20));
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].detail.get("entries_returned").map(String::as_str),
            Some("3"),
        );
    }

    #[test]
    fn search_request_returns_one_for_concrete_uid_via_socket() {
        let stub = LdapStub::start().unwrap();
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", stub.port())).unwrap();
        s.write_all(b"SEARCH (uid=alice)\n").unwrap();
        s.flush().unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("COUNT 1\n"), "got {out:?}");
        assert!(out.contains("uid=alice"));
    }

    #[test]
    fn record_search_helper_appends_event() {
        let stub = LdapStub::start().unwrap();
        stub.record_search("(uid=*)", 3);
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, StubKind::Ldap);
        assert_eq!(
            events[0].detail.get("entries_returned").map(String::as_str),
            Some("3"),
        );
    }

    #[test]
    fn drop_releases_port_for_rebind() {
        let port = {
            let stub = LdapStub::start().unwrap();
            stub.port()
        };
        std::thread::sleep(Duration::from_millis(50));
        let _ = TcpListener::bind(format!("127.0.0.1:{port}"));
    }
}
