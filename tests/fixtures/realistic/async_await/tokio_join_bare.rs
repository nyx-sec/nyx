// Phase 12 deferred-fix fixture (Rust combinator, bare macro form).
// `use tokio::join;` brings the macro into scope; the call site then uses
// the bare `join!(...)` shape.  `cfg::push_node` rewrites the bare macro
// callee text to `tokio::join` when the file imports the matching macro,
// so `is_promise_combinator("rust", "tokio::join")` recognises the
// resulting SSA Call op and unions argument taint into the tuple value.
use tokio::join;

pub async fn run() {
    let url_a = std::env::var("URL_A").unwrap_or_default();
    let url_b = std::env::var("URL_B").unwrap_or_default();
    let results = join!(url_a, url_b);
    reqwest::get(results.0).await.ok();
}
