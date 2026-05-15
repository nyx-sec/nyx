//! Phase 16 — libfuzzer-style target, vulnerable.
//!
//! Marker comment for shape detection: `libfuzzer_sys::fuzz_target!`
//! Signature: `pub fn fuzz_target(data: &[u8])`.

use std::process::Command;

pub fn fuzz_target(data: &[u8]) {
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let payload = String::from_utf8_lossy(data).into_owned();
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("echo hello {}", payload))
        .output();
    if let Ok(o) = out {
        print!("{}", String::from_utf8_lossy(&o.stdout));
    }
}
