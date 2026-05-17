//! `tools/sb-trace.sh` is the corpus walker that generates per-cap
//! seed files for the macOS sandbox-exec deny-default rollout.  Its
//! deny-record → allow-rule parser is implemented in bash; this test
//! drives the script's `--selftest` flag so the parser stays exercised
//! in CI on every host, including Linux runners that never run the
//! macOS-specific portion of the script.
//!
//! The selftest is a no-op when `bash` is not on PATH; CI rows that
//! lack a POSIX shell skip rather than fail.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn sb_trace_selftest_passes() {
    let script = repo_root().join("tools").join("sb-trace.sh");
    assert!(
        script.exists(),
        "tools/sb-trace.sh missing at {}",
        script.display()
    );

    let bash = match find_in_path("bash") {
        Some(p) => p,
        None => {
            eprintln!("SKIP: bash not on PATH; sb-trace.sh selftest cannot run");
            return;
        }
    };

    let output = Command::new(&bash)
        .arg(&script)
        .arg("--selftest")
        .output()
        .expect("invoke bash tools/sb-trace.sh --selftest");

    assert!(
        output.status.success(),
        "tools/sb-trace.sh --selftest failed: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sb-trace selftest: all OK"),
        "expected selftest success banner; stdout was: {stdout}",
    );
}
