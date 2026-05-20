//! Phase 17 (Track L.15) — actix-web CMDI vuln fixture.
//!
//! The /run route forwards a `cmd` query parameter straight into
//! `std::process::Command`.  Adapter binding: `#[get("/run")]` on
//! `run` with `cmd` arriving via `web::Query<RunQuery>`.

use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct RunQuery {
    pub cmd: String,
}

#[get("/run")]
pub async fn run(q: web::Query<RunQuery>) -> impl Responder {
    let _ = Command::new("sh").arg("-c").arg(&q.cmd).status();
    HttpResponse::Ok().body("ok")
}
