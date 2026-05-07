// Safe: tainted value flows into a non-Location header.  The actix
// builder gate only activates on `"Location"` so `"Content-Type"` headers
// stay clean.
use actix_web::HttpResponse;
use std::env;

fn render() -> HttpResponse {
    let next = env::var("NEXT").unwrap_or_default();
    HttpResponse::Ok().header("Content-Type", next).finish()
}
