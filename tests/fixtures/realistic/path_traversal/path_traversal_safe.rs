// Phase 13 path-traversal sanitized (Rust).  Demonstrates the
// canonical-and-validate pattern with `PathBuf::canonicalize` followed
// by a `starts_with(base)` containment check; the canonical path is
// returned as a `String`, never reaching a FILE_IO sink.  No new label
// rule is required: the absence of a `tokio::fs::*` / `std::fs::*`
// call keeps the fixture silent.
use std::path::PathBuf;

#[allow(unused)]
struct Request;
impl Request {
    fn headers(&self) -> Headers {
        Headers
    }
}
struct Headers;
impl Headers {
    async fn get(&self, _key: &str) -> String {
        String::new()
    }
}

pub async fn safe_handler(req: Request) -> String {
    let name = req.headers().get("X-Path").await;
    let base = PathBuf::from("/var/data");
    let candidate = base.join(&name).canonicalize().unwrap_or_default();
    if !candidate.starts_with(&base) {
        return String::new();
    }
    candidate.to_string_lossy().to_string()
}
