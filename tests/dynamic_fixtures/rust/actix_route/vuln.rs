//! Phase 16 — actix_web route, vulnerable.
//!
//! Marker comment for shape detection: `use actix_web::HttpResponse;`
//! The fixture exposes a synchronous shim with the same conceptual entry
//! signature so the harness build does not need to link real actix_web.
//! Cap: CODE_EXEC

use std::process::Command;

pub fn handler(payload: &str) -> String {
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("echo hello {}", payload))
        .output();
    if let Ok(o) = out {
        print!("{}", String::from_utf8_lossy(&o.stdout));
    }
    String::new()
}
