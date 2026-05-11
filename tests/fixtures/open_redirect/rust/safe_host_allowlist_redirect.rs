// Safe: tainted env value parsed via `url::Url::parse` then host pinned
// against `ALLOWED_HOST`.  Multi-statement form — `parsed = Url::parse(x)`
// happens on a separate line from the `parsed.host_str() == Some(ALLOWED)`
// check.  Recognised by PredicateKind::HostAllowlistValidated which clears
// Cap::OPEN_REDIRECT on the validated branch.
use axum::response::Redirect;
use std::env;
use url::Url;

const ALLOWED_HOST: &str = "trusted.example.com";

fn bounce() -> Redirect {
    let next = env::var("NEXT").unwrap_or_default();
    let parsed = Url::parse(&next).unwrap();
    if parsed.host_str() == Some(ALLOWED_HOST) {
        return Redirect::to(parsed.as_str());
    }
    Redirect::permanent("/")
}
