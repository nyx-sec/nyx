// Unsafe: tainted env value flows into actix-web's
// `HttpResponse::Found().header("Location", url)` builder, then chained
// `.finish()` returns the response in one expression. The chained
// `.finish()` is the outer call; without chained inner-gate rebinding
// the outer `.finish()` swallows classification and the inner `.header`
// open-redirect gate never fires.
use actix_web::HttpResponse;
use std::env;

fn bounce() -> HttpResponse {
    let next = env::var("NEXT").unwrap_or_default();
    HttpResponse::Found().header("Location", next).finish()
}
