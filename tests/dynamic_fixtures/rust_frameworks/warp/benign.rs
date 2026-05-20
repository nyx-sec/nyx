//! Phase 17 (Track L.15) — warp benign control fixture.

use std::process::Command;
use serde::Deserialize;
use warp::Filter;

#[derive(Deserialize)]
pub struct RunQuery {
    pub cmd: String,
}

pub fn run(q: RunQuery) -> &'static str {
    let allow = ["ls", "ps"];
    if allow.contains(&q.cmd.as_str()) {
        let _ = Command::new(&q.cmd).status();
    }
    "ok"
}

pub fn build() -> impl Filter<Extract = (&'static str,), Error = warp::Rejection> + Clone {
    warp::path!("run")
        .and(warp::query::<RunQuery>())
        .map(run)
}
