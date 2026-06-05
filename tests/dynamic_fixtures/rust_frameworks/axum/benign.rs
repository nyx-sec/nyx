//! Phase 17 (Track L.15) — axum benign control fixture.
//!
//! The /run route allow-lists the `cmd` value before invoking
//! `std::process::Command`, so attacker bytes never reach the sink.

use axum::extract::Query;
use axum::Router;
use axum::routing::get;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct RunQuery {
    pub cmd: String,
}

pub async fn run(Query(q): Query<RunQuery>) -> String {
    let allow = ["ls", "ps"];
    if allow.contains(&q.cmd.as_str()) {
        let _ = Command::new(&q.cmd).status();
    }
    "ok".to_owned()
}

pub fn build() -> Router {
    Router::new().route("/run", get(run))
}
