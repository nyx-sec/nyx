//! Phase 17 (Track L.15) — warp CMDI vuln fixture.
//!
//! The /run filter forwards a query parameter straight into
//! `std::process::Command`.  Adapter binding:
//! `warp::path!("run").and(warp::query::<RunQuery>()).map(run)` with
//! `cmd` arriving via warp's typed query.

use std::process::Command;
use serde::Deserialize;
use warp::Filter;

#[derive(Deserialize)]
pub struct RunQuery {
    pub cmd: String,
}

pub fn run(q: RunQuery) -> &'static str {
    let _ = Command::new("sh").arg("-c").arg(&q.cmd).status();
    "ok"
}

pub fn build() -> impl Filter<Extract = (&'static str,), Error = warp::Rejection> + Clone {
    warp::path!("run")
        .and(warp::query::<RunQuery>())
        .map(run)
}
