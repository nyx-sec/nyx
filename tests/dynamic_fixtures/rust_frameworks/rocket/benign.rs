//! Phase 17 (Track L.15) — rocket benign control fixture.

use rocket::get;
use std::process::Command;

#[get("/run?<cmd>")]
pub fn run(cmd: String) -> &'static str {
    let allow = ["ls", "ps"];
    if allow.contains(&cmd.as_str()) {
        let _ = Command::new(&cmd).status();
    }
    "ok"
}
