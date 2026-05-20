//! Phase 17 (Track L.15) — axum CMDI vuln fixture.
//!
//! The /run route forwards a `cmd` query parameter straight into
//! `std::process::Command`.  Adapter binding:
//! `Router::new().route("/run", get(run))` with `cmd` arriving via
//! `axum::extract::Query<RunQuery>`.

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
    let _ = Command::new("sh").arg("-c").arg(&q.cmd).status();
    "ok".to_owned()
}

pub fn build() -> Router {
    Router::new().route("/run", get(run))
}
