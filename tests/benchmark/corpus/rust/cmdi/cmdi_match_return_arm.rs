use std::env;
use std::process::Command;

fn main() {
    let cmd = env::var("USER_CMD").unwrap();
    let mode = env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "quit" => return,
        _ => {
            Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
        }
    }
}
