use std::env;
use std::process::Command;

fn main() {
    let cmd = env::var("USER_CMD").unwrap();
    let mode = env::args().count();
    match mode {
        1 => {
            Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
        }
        _ => {}
    }
}
