// Actix-web parallel of the axum typed-extractor positive shape.
// `web::Path<String>` is a user-input boundary; the `name` formal
// flows into a shell sink and should produce a
// taint-unsanitised-flow finding via entry-kind seeding.
use actix_web::{get, web, HttpResponse};
use std::process::Command;

#[get("/u/{name}")]
pub async fn u(name: web::Path<String>) -> HttpResponse {
    let s: String = name.into_inner();
    Command::new("sh").arg("-c").arg(&s).status().ok();
    HttpResponse::Ok().body(s)
}
