// Phase 09 (Track J.7) — Rust OPEN_REDIRECT benign control fixture.
//
// The handler ignores the attacker-supplied value and redirects to a
// same-origin path; the captured `Location:` header carries no
// off-origin authority.
use axum::response::Redirect;

pub fn run(_value: String) -> Redirect {
    Redirect::to("/dashboard")
}
