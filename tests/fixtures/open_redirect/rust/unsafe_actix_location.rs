// Unsafe: tainted env value flows directly into actix-web's
// `HttpResponse::Found().header("Location", url)` builder.  Without an
// allowlist check, a tainted URL is the actix open-redirect vector.
use actix_web::HttpResponse;
use std::env;

fn bounce() -> HttpResponse {
    let next = env::var("NEXT").unwrap_or_default();
    let resp = HttpResponse::Found().header("Location", next);
    resp.finish()
}
