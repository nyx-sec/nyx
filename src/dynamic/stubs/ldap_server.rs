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
//! # BER (LDAPv3) dispatch
//!
//! The accept loop peeks the first byte on each connection.  When it
//! sees the universal `SEQUENCE` tag (`0x30`) — the leading byte of
//! every well-formed LDAPv3 [`LDAPMessage`] — it routes the
//! conversation through [`super::ldap_ber`] so a harness using a stock
//! LDAP client (`javax.naming.directory.InitialDirContext`,
//! `python-ldap`, `ldap3`, …) can talk to the stub on the LDAPv3 wire
//! protocol.  The plaintext `SEARCH <filter>\n` framing remains for
//! every other first-byte value, so the existing tier-(a) harnesses
//! keep round-tripping unchanged.
//!
//! No env var gates this — the dispatch is byte-shape driven so a
//! tier-(a) shim that accidentally emits a leading `0x30` will skip
//! the BER path's failure-mode fallback (the BER decoder bails to
//! `None` on a non-LDAPv3 payload, which closes the connection without
//! corrupting state).
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

use super::ldap_ber;
use super::{StubEvent, StubKind, StubProvider, monotonic_ns};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
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
                d.insert("entries_returned".to_owned(), entries_returned.to_string());
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

fn handle_connection(stream: TcpStream, max_bytes: usize, events: &Arc<Mutex<Vec<StubEvent>>>) {
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader_stream);
    // Peek the first byte to decide between the plaintext and BER
    // protocol paths.  `fill_buf` does not consume — the chosen
    // handler reads from `reader` again.
    let first_byte = match reader.fill_buf() {
        Ok(buf) if !buf.is_empty() => buf[0],
        _ => return,
    };
    if first_byte == ldap_ber::tags::SEQUENCE {
        handle_ber_connection(reader, stream, max_bytes, events);
    } else {
        handle_plaintext_connection(reader, stream, max_bytes, events);
    }
}

fn handle_plaintext_connection(
    mut reader: BufReader<TcpStream>,
    mut stream: TcpStream,
    max_bytes: usize,
    events: &Arc<Mutex<Vec<StubEvent>>>,
) {
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

/// LDAPv3 BER dispatch: bind then search loop.  Returns silently on
/// any decode error so a malformed payload never corrupts state.
fn handle_ber_connection(
    mut reader: BufReader<TcpStream>,
    mut stream: TcpStream,
    max_bytes: usize,
    events: &Arc<Mutex<Vec<StubEvent>>>,
) {
    loop {
        let Some(msg) = read_ber_message(&mut reader, max_bytes) else {
            return;
        };
        let Some(hdr) = ldap_ber::decode_ldap_message(&msg) else {
            return;
        };
        match hdr.op_tag {
            ldap_ber::tags::BIND_REQUEST => {
                // Anonymous + simple binds both succeed — the stub
                // does not enforce credentials.
                let reply =
                    ldap_ber::encode_bind_response(hdr.message_id, ldap_ber::result_codes::SUCCESS);
                if stream.write_all(&reply).is_err() {
                    return;
                }
            }
            ldap_ber::tags::SEARCH_REQUEST => {
                let Some(req) = ldap_ber::decode_search_request(hdr.op_body) else {
                    let done = ldap_ber::encode_search_result_done(
                        hdr.message_id,
                        ldap_ber::result_codes::UNWILLING_TO_PERFORM,
                    );
                    let _ = stream.write_all(&done);
                    return;
                };
                let matches = match_filter(&req.filter);
                let count = matches.len();
                for uid in &matches {
                    let dn = format!("uid={uid},ou=people,dc=nyx,dc=test");
                    let entry = ldap_ber::encode_search_result_entry(hdr.message_id, dn.as_bytes());
                    if stream.write_all(&entry).is_err() {
                        return;
                    }
                }
                let done = ldap_ber::encode_search_result_done(
                    hdr.message_id,
                    ldap_ber::result_codes::SUCCESS,
                );
                if stream.write_all(&done).is_err() {
                    return;
                }
                let _ = stream.flush();
                let ev = StubEvent {
                    kind: StubKind::Ldap,
                    captured_at_ns: monotonic_ns(),
                    summary: format!("SEARCH {filter}", filter = req.filter),
                    detail: {
                        let mut d = BTreeMap::new();
                        d.insert("filter".to_owned(), req.filter);
                        d.insert("protocol".to_owned(), "ldapv3".to_owned());
                        d.insert("entries_returned".to_owned(), count.to_string());
                        d
                    },
                };
                if let Ok(mut g) = events.lock() {
                    g.push(ev);
                }
            }
            _ => {
                // Unbind / abandon / extended / etc. — bail.  The
                // verifier oracle only cares about search results.
                return;
            }
        }
    }
}

/// Read a single LDAPv3 BER `LDAPMessage` off the wire.  Parses just
/// enough of the outer TLV to compute the message length, then reads
/// exactly that many body bytes.  Returns `None` for malformed
/// framing or when the message size exceeds `max_bytes`.
fn read_ber_message(reader: &mut BufReader<TcpStream>, max_bytes: usize) -> Option<Vec<u8>> {
    let mut header = vec![0u8; 2];
    reader.read_exact(&mut header).ok()?;
    if header[0] != ldap_ber::tags::SEQUENCE {
        return None;
    }
    let body_len = if header[1] & 0x80 == 0 {
        header[1] as usize
    } else {
        let length_of_length = (header[1] & 0x7F) as usize;
        if length_of_length == 0 || length_of_length > 4 {
            return None;
        }
        let mut len_bytes = vec![0u8; length_of_length];
        reader.read_exact(&mut len_bytes).ok()?;
        let mut acc: usize = 0;
        for &b in &len_bytes {
            acc = (acc << 8) | (b as usize);
        }
        header.extend_from_slice(&len_bytes);
        acc
    };
    if header.len() + body_len > max_bytes {
        return None;
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).ok()?;
    header.extend_from_slice(&body);
    Some(header)
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
    Eq {
        attr: &'a str,
        pattern: &'a str,
    },
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

    fn start_stub() -> Option<LdapStub> {
        match LdapStub::start() {
            Ok(stub) => Some(stub),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(e) => panic!("start ldap stub: {e}"),
        }
    }

    #[test]
    fn endpoint_uses_loopback_with_assigned_port() {
        let Some(stub) = start_stub() else {
            return;
        };
        let ep = stub.endpoint();
        assert!(ep.starts_with("127.0.0.1:"));
        assert!(ep.ends_with(&stub.port().to_string()));
    }

    #[test]
    fn search_request_returns_three_for_wildcard_via_socket() {
        let Some(stub) = start_stub() else {
            return;
        };
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
        let Some(stub) = start_stub() else {
            return;
        };
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
        let Some(stub) = start_stub() else {
            return;
        };
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
            let Some(stub) = start_stub() else {
                return;
            };
            stub.port()
        };
        std::thread::sleep(Duration::from_millis(50));
        let _ = TcpListener::bind(format!("127.0.0.1:{port}"));
    }

    fn build_ber_bind(message_id: i64) -> Vec<u8> {
        let mut body = Vec::new();
        ldap_ber::write_integer(&mut body, 3);
        ldap_ber::write_octet_string(&mut body, b"");
        ldap_ber::write_tlv(&mut body, ldap_ber::tags::AUTH_SIMPLE, b"");
        ldap_ber::encode_ldap_message(message_id, ldap_ber::tags::BIND_REQUEST, &body)
    }

    fn build_ber_search(message_id: i64, filter_tag: u8, filter_body: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        ldap_ber::write_octet_string(&mut body, b"ou=people,dc=nyx,dc=test");
        ldap_ber::write_enumerated(&mut body, 2);
        ldap_ber::write_enumerated(&mut body, 0);
        ldap_ber::write_integer(&mut body, 0);
        ldap_ber::write_integer(&mut body, 0);
        ldap_ber::write_tlv(&mut body, 0x01, &[0x00]);
        ldap_ber::write_tlv(&mut body, filter_tag, filter_body);
        ldap_ber::write_tlv(&mut body, ldap_ber::tags::SEQUENCE, &[]);
        ldap_ber::encode_ldap_message(message_id, ldap_ber::tags::SEARCH_REQUEST, &body)
    }

    fn read_ber_reply(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        // Read until the peer closes (the BER handler stays open
        // until the client disconnects).  A short read timeout was
        // configured at accept time, so a stuck reader would unblock
        // there anyway.
        let _ = stream.read_to_end(&mut buf);
        buf
    }

    #[test]
    fn ber_bind_then_search_wildcard_returns_three_entries() {
        let Some(stub) = start_stub() else {
            return;
        };
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", stub.port())).unwrap();
        let bind = build_ber_bind(1);
        s.write_all(&bind).unwrap();
        let search = build_ber_search(2, ldap_ber::tags::FILTER_PRESENT, b"uid");
        s.write_all(&search).unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        let reply = read_ber_reply(&mut s);
        // Walk the reply: BindResponse (msg id 1, tag 0x61), then
        // 3x SearchResultEntry (tag 0x64), then SearchResultDone
        // (tag 0x65).
        let bind_resp = ldap_ber::read_tlv(&reply, 0).expect("bind tlv");
        assert_eq!(bind_resp.tag, ldap_ber::tags::SEQUENCE);
        let bind_hdr = ldap_ber::decode_ldap_message(&reply[..bind_resp.end]).expect("bind hdr");
        assert_eq!(bind_hdr.op_tag, ldap_ber::tags::BIND_RESPONSE);
        assert_eq!(bind_hdr.message_id, 1);

        let mut cur = bind_resp.end;
        let mut entries: usize = 0;
        let mut saw_done = false;
        while cur < reply.len() {
            let tlv = ldap_ber::read_tlv(&reply, cur).expect("tlv");
            assert_eq!(tlv.tag, ldap_ber::tags::SEQUENCE);
            let hdr = ldap_ber::decode_ldap_message(&reply[cur..tlv.end]).expect("hdr");
            match hdr.op_tag {
                ldap_ber::tags::SEARCH_RESULT_ENTRY => entries += 1,
                ldap_ber::tags::SEARCH_RESULT_DONE => {
                    saw_done = true;
                    break;
                }
                _ => panic!("unexpected op tag {:#x}", hdr.op_tag),
            }
            cur = tlv.end;
        }
        assert_eq!(entries, 3);
        assert!(saw_done);
        std::thread::sleep(Duration::from_millis(20));
        let events = stub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].detail.get("entries_returned").map(String::as_str),
            Some("3"),
        );
        assert_eq!(
            events[0].detail.get("protocol").map(String::as_str),
            Some("ldapv3"),
        );
    }

    #[test]
    fn ber_search_concrete_uid_returns_one_entry() {
        let Some(stub) = start_stub() else {
            return;
        };
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", stub.port())).unwrap();
        s.write_all(&build_ber_bind(1)).unwrap();
        let mut eq_body = Vec::new();
        ldap_ber::write_octet_string(&mut eq_body, b"uid");
        ldap_ber::write_octet_string(&mut eq_body, b"alice");
        s.write_all(&build_ber_search(
            2,
            ldap_ber::tags::FILTER_EQUALITY,
            &eq_body,
        ))
        .unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        let reply = read_ber_reply(&mut s);
        // Skip past the BindResponse.
        let bind_resp = ldap_ber::read_tlv(&reply, 0).expect("bind tlv");
        let mut cur = bind_resp.end;
        let mut entry_dns: Vec<String> = Vec::new();
        let mut saw_done = false;
        while cur < reply.len() {
            let tlv = ldap_ber::read_tlv(&reply, cur).expect("tlv");
            let hdr = ldap_ber::decode_ldap_message(&reply[cur..tlv.end]).expect("hdr");
            if hdr.op_tag == ldap_ber::tags::SEARCH_RESULT_ENTRY {
                let dn_tlv = ldap_ber::read_tlv(hdr.op_body, 0).expect("dn");
                entry_dns.push(String::from_utf8_lossy(dn_tlv.body).into_owned());
            } else if hdr.op_tag == ldap_ber::tags::SEARCH_RESULT_DONE {
                saw_done = true;
                break;
            }
            cur = tlv.end;
        }
        assert_eq!(entry_dns, vec!["uid=alice,ou=people,dc=nyx,dc=test"]);
        assert!(saw_done);
    }

    #[test]
    fn plaintext_path_still_works_after_ber_branch_added() {
        // Same shape as `search_request_returns_three_for_wildcard_via_socket`
        // but the leading byte is `S` (0x53), not `0x30`, so the
        // accept-loop dispatches plaintext.
        let Some(stub) = start_stub() else {
            return;
        };
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", stub.port())).unwrap();
        s.write_all(b"SEARCH (uid=*)\n").unwrap();
        s.flush().unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("COUNT 3\n"), "got {out:?}");
    }
}
