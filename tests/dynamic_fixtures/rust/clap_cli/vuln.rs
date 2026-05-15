//! Phase 16 — clap-driven CLI, vulnerable.
//!
//! Marker comment for shape detection: `use clap::Parser;`
//! Signature: `pub fn run(args: Vec<String>)` — last positional arg is the
//! tainted input that is concatenated into a shell command.

use std::process::Command;

pub fn run(args: Vec<String>) {
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let payload = args.last().cloned().unwrap_or_default();
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("echo hello {}", payload))
        .output();
    if let Ok(o) = out {
        print!("{}", String::from_utf8_lossy(&o.stdout));
    }
}
