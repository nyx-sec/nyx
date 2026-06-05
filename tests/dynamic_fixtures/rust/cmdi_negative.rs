/// Command injection — negative fixture.
///
/// Safe function: uses Command with a list of args (no shell expansion).
/// Payload is used as a literal argument, not interpreted by the shell.
/// Expected verdict: NotConfirmed.
/// Cap: CODE_EXEC  Entry: `run(payload: &str)`
pub fn run(payload: &str) {
    use std::process::Command;

    // Safe: list-form args — shell metacharacters in payload are inert.
    let safe_target = payload
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.')
        .collect::<String>();

    println!("__NYX_SINK_HIT__");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    match Command::new("echo").arg(&safe_target).output() {
        Ok(out) => print!("{}", String::from_utf8_lossy(&out.stdout)),
        Err(e) => eprintln!("exec error: {}", e),
    }
}
