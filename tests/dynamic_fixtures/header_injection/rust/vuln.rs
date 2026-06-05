// Phase 08 (Track J.6) — Rust HEADER_INJECTION vuln fixture.
//
// The function inserts the attacker-controlled `value` into an axum
// `HeaderMap` via `headers_mut().insert`, bypassing
// `HeaderValue::from_str`'s newline check by passing the tainted
// bytes through `HeaderValue::from_bytes(...).unwrap()`.  A payload
// carrying `\r\nSet-Cookie: nyx-injected=pwn` splits the single
// header into two on the wire.
use axum::http::HeaderMap;
use axum::http::HeaderValue;

pub fn run(headers: &mut HeaderMap, value: &str) {
    headers.insert(
        "set-cookie",
        HeaderValue::from_bytes(value.as_bytes()).unwrap(),
    );
}
