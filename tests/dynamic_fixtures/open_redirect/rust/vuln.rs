// Phase 09 (Track J.7) — Rust OPEN_REDIRECT vuln fixture.
//
// The handler splices `value` straight into `Redirect::to` without
// host validation; an attacker URL routes the captured `Location:`
// header off-origin.
use axum::response::Redirect;

pub fn run(value: String) -> Redirect {
    Redirect::to(&value)
}
