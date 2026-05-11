// Phase 12 recall-gap fixture (Rust combinator).  `tokio::join!` evaluates
// every passed future concurrently and binds the tuple of resolved values.
// `cfg::push_node` lifts the macro_invocation's `arg_uses` from its
// `token_tree`, and `is_promise_combinator("rust", "tokio::join")` (added
// in this phase) routes the SsaOp::Call through the existing combinator
// transfer so each future's tainted inputs surface on the result tuple.
pub async fn run() {
    let url_a = std::env::var("URL_A").unwrap_or_default();
    let url_b = std::env::var("URL_B").unwrap_or_default();
    let results = tokio::join!(url_a, url_b);
    reqwest::get(results.0).await.ok();
}
