//! Phase 17 (Track L.15) — actix-web benign control fixture.

use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct RunQuery {
    pub cmd: String,
}

#[get("/run")]
pub async fn run(q: web::Query<RunQuery>) -> impl Responder {
    let allow = ["ls", "ps"];
    if allow.contains(&q.cmd.as_str()) {
        let _ = Command::new(&q.cmd).status();
    }
    HttpResponse::Ok().body("ok")
}
