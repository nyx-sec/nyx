//! Phase 16 — libfuzzer-style target, benign.
//!
//! Marker comment for shape detection: `libfuzzer_sys::fuzz_target!`

use std::process::Command;

pub fn fuzz_target(_data: &[u8]) {
    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let out = Command::new("echo").arg("hello").output();
    if let Ok(o) = out {
        print!("{}", String::from_utf8_lossy(&o.stdout));
    }
}
