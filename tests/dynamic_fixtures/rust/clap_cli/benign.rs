//! Phase 16 — clap-driven CLI, benign.
//!
//! Marker comment for shape detection: `use clap::Parser;`

use std::process::Command;

pub fn run(_args: Vec<String>) {
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let out = Command::new("echo").arg("hello").output();
    if let Ok(o) = out {
        print!("{}", String::from_utf8_lossy(&o.stdout));
    }
}
