//! Phase 17 (Track L.15) — rocket CMDI vuln fixture.
//!
//! The /run route forwards a `cmd` query parameter straight into
//! `std::process::Command`.  Adapter binding: `#[get("/run?<cmd>")]`
//! on `run` with `cmd` arriving via the function's positional arg.

use rocket::get;
use std::process::Command;

#[get("/run?<cmd>")]
pub fn run(cmd: String) -> &'static str {
    let _ = Command::new("sh").arg("-c").arg(&cmd).status();
    "ok"
}
