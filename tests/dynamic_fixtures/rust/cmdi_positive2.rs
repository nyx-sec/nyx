/// Command injection — second positive fixture.
///
/// Variant: builds a script filename from user input and passes it to sh.
/// Expected verdict: Confirmed (payload "; echo NYX_PWN_CMDI" injects into the
/// command string at a different AST site than cmdi_positive.rs).
/// Cap: CODE_EXEC  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    use std::process::Command;

    // Vulnerable: payload used as a path argument, which is shell-interpolated.
    let script = format!("ls -la {}", payload);

    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    match Command::new("sh").args(["-c", &script]).output() {
        Ok(out) => {
            print!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
            }
        }
        Err(e) => eprintln!("exec error: {}", e),
    }
}
