//! Phase 16 — axum handler, benign.
//!
//! Marker comment for shape detection: `use axum::extract::Query;`

use std::process::Command;

pub fn handler(_payload: &str) -> String {
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let out = Command::new("echo").arg("hello").output();
    if let Ok(o) = out {
        print!("{}", String::from_utf8_lossy(&o.stdout));
    }
    String::new()
}
