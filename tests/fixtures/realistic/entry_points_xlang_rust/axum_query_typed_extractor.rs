// Rust entry-point seeding precision: typed extractor formals get
// painted as Source(UserInput), while denylist DI handles do not.
//
// The Query<String> extractor formal is a user-input boundary by
// framework contract.  The taint engine should emit
// taint-unsanitised-flow at the Command::new shell sink with `q` as
// the named source variable.
use axum::extract::Query;
use std::process::Command;

pub async fn list(Query(q): Query<String>) -> String {
    Command::new("sh").arg("-c").arg(&q).status().ok();
    q
}
