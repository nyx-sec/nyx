use std::env;
use std::process::Command;

fn sanitize_shell(raw: &str) -> Option<String> {
    if raw.chars().any(|c| matches!(c, ';' | '|' | '&' | '$' | '`')) {
        None
    } else {
        Some(raw.to_string())
    }
}

fn main() {
    let raw = env::var("ARG").unwrap();
    let safe = match sanitize_shell(&raw) {
        Some(s) => s,
        None => return,
    };
    // Named-arg format: `{safe}` reads `safe`, but the value has been
    // routed through sanitize_shell so the shell-escape sink should
    // not fire.  Regression guard for the format-string named-arg
    // lifting fix: once {safe} is recognised as an arg, the sanitiser
    // chain still has to suppress the resulting flow.
    let cmd = format!("echo {safe}");
    Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
}
