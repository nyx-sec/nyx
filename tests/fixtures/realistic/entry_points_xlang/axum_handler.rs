// Phase 16 fixture: axum handler.  The signature contains an axum
// `Query<_>` extractor, so `list` is recognised as an `AxumHandler`
// entry point.  Every formal `Param` in the SSA entry block is seeded
// with `Cap::all()` Source taint, which flows through the destructured
// `q` String value into the `Command::new("sh").arg(&q)` chain.  The
// chained `.arg` call resolves to `command::arg` (SHELL_ESCAPE sink)
// in `src/labels/rust.rs`.
use axum::extract::Query;
use std::process::Command;

pub async fn list(Query(q): Query<String>) -> String {
    Command::new("sh").arg("-c").arg(&q).status().ok();
    q
}
