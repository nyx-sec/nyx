// Phase 08 (Track J.6) — Rust HEADER_INJECTION benign control fixture.
//
// Same shape as `vuln.rs` but routes the value through the
// `percent-encoding` crate first, so CRLF bytes land as `%0D%0A` and
// the wire keeps a single header.
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

pub fn run(headers: &mut HeaderMap, value: &str) {
    let encoded: String = utf8_percent_encode(value, NON_ALPHANUMERIC).collect();
    headers.insert(
        "set-cookie",
        HeaderValue::from_str(&encoded).unwrap(),
    );
}
