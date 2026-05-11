// Unsafe: tainted env value flows directly into `Redirect::to`, the axum
// open-redirect entry point.
use axum::response::Redirect;
use std::env;

fn bounce() -> Redirect {
    let next = env::var("NEXT").unwrap_or_default();
    Redirect::to(&next)
}
