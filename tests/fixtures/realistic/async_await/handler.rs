// Phase 12 recall-gap fixture (Rust).  axum-style async handler reads a
// header value via `req.headers.get(...)` (a Source-tagged accessor in
// `src/labels/rust.rs`) and awaits the result before passing it to a
// command-injection sink.  Exercises the new explicit
// `"await_expression" => Kind::AwaitForward` mapping in
// `src/labels/rust.rs`: the engine must see the await boundary as a
// 1:1 forward so taint from the headers chain reaches `cmd`.
use std::process::Command;

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

pub async fn handler(req: Request) {
    let cmd = req.headers().get("X-Cmd").await;
    Command::new("sh").arg("-c").arg(&cmd).status().ok();
}
