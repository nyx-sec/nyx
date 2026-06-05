//! Phase 16 — axum handler, vulnerable.
//!
//! Marker comment for shape detection: `use axum::extract::Query;`
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
