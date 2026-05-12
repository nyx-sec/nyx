/// Command injection — positive fixture.
///
/// Vulnerable function: builds a shell command string from user input.
/// Expected verdict: Confirmed (payload "; echo NYX_PWN_CMDI" echoes the marker).
/// Cap: CODE_EXEC  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    use std::process::Command;

    // Vulnerable: user input concatenated into shell command string.
    let cmd = format!("echo {}", payload);

    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    match Command::new("sh").args(["-c", &cmd]).output() {
        Ok(out) => {
            print!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
            }
        }
        Err(e) => eprintln!("exec error: {}", e),
    }
}
