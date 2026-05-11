// Phase 16 fixture: actix-web handler.  The `#[get("/u/{name}")]`
// routing macro attribute marks `u` as an `ActixHandler` entry point.
// The `name` formal is seeded as `Source(Cap::all())` and flows into
// `Command::new("sh").arg(&name)` (SHELL_ESCAPE sink).
use actix_web::{get, web, HttpResponse};
use std::process::Command;

#[get("/u/{name}")]
pub async fn u(name: web::Path<String>) -> HttpResponse {
    let s: String = name.into_inner();
    Command::new("sh").arg("-c").arg(&s).status().ok();
    HttpResponse::Ok().body(s)
}
