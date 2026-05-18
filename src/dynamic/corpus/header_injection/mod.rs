//! HTTP response-header CRLF injection (`Cap::HEADER_INJECTION`)
//! per-language payload slices.
//!
//! Phase 08 (Track J.6) carves header injection across the seven HTTP
//! framework ecosystems Nyx supports: Java (`HttpServletResponse.
//! setHeader`), Python (`flask.Response.headers.__setitem__`), PHP
//! (`header()`), Ruby (`Rack::Response#set_header`), JavaScript
//! (`http.ServerResponse#setHeader`), Go (`http.ResponseWriter.
//! Header().Set`), Rust (`axum`-style `HeaderMap::insert`).  Every
//! vuln payload appends a `\r\n` followed by an injected header line
//! (`Set-Cookie: nyx-injected=pwn`) — once the host code splices the
//! attacker bytes into the response writer's value argument the wire
//! actually carries two headers instead of one.  The paired benign
//! control passes the same logical value through the per-language URL
//! encoder so the captured value carries `%0d%0a` (not the raw
//! bytes), the encoded text is preserved verbatim inside a single
//! header value, and the differential rule stays clear.
//!
//! The oracle's
//! [`crate::dynamic::oracle::ProbePredicate::HeaderInjected`] reads
//! the per-payload `ProbeKind::HeaderEmit { name, value }` records
//! and fires when the value contains a literal CRLF byte pair —
//! vuln passes, benign clears, fulfilling the §4.1 differential rule.

pub mod go;
pub mod java;
pub mod js;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;
