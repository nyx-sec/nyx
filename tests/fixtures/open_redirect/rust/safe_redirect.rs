// Safe: tainted value routed through `validate_redirect_url` allowlist
// before being passed to `Redirect::to`.
use axum::response::Redirect;
use std::env;

fn validate_redirect_url(raw: &str) -> String {
    if raw.starts_with('/') {
        raw.to_string()
    } else {
        "/".to_string()
    }
}

fn bounce() -> Redirect {
    let next = env::var("NEXT").unwrap_or_default();
    let safe = validate_redirect_url(&next);
    Redirect::to(&safe)
}
