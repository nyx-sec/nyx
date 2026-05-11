// Safe: tainted value routed through `ensure_relative_url` which enforces
// a leading `/` and rejects scheme-prefixed or protocol-relative values
// (relative-only path).
use axum::response::Redirect;
use std::env;

fn ensure_relative_url(raw: &str) -> String {
    if !raw.starts_with('/') || raw.starts_with("//") {
        return "/".to_string();
    }
    raw.to_string()
}

fn bounce() -> Redirect {
    let next = env::var("NEXT").unwrap_or_default();
    let safe = ensure_relative_url(&next);
    Redirect::permanent(&safe)
}
