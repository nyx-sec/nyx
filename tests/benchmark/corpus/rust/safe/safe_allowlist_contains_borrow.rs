use std::process::Command;

const ALLOWED: [&str; 2] = ["ls", "pwd"];

fn main() {
    let cmd = std::env::var("CMD").unwrap();
    if !ALLOWED.contains(&cmd.as_str()) {
        return;
    }
    Command::new(&cmd).output().unwrap();
}
