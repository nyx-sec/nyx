// Fixture: spec derived via FromCallgraphEntry (rule id matches `*.http.*`,
// entry point classified as HttpRoute).
//
// Phase 12 — Track B added HttpRoute to the Python emitter's SUPPORTED list,
// so to keep the entry-kind gate test honest the fixture targets Rust, whose
// emitter still advertises `[EntryKind::Function]` only.

use actix_web::{web, HttpResponse, Responder};

pub async fn echo(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    HttpResponse::Ok().body(query.get("q").cloned().unwrap_or_default())
}
