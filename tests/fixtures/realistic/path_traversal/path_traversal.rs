// Phase 13 path-traversal positive (Rust).  axum-shape async handler
// reads a header value (Source via the `headers.get` rule in
// `src/labels/rust.rs`), awaits, and feeds the result into
// `tokio::fs::read` (new FILE_IO sink rule).  Mirrors the existing
// `tests/fixtures/realistic/async_await/handler.rs` source shape.
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

pub async fn handler(req: Request) -> Vec<u8> {
    let path = req.headers().get("X-Path").await;
    tokio::fs::read(path).await.unwrap_or_default()
}
