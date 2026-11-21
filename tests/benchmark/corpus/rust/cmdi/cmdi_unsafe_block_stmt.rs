use std::env;
use std::process::Command;

fn main() {
    unsafe {
        let cmd = env::var("USER_CMD").unwrap();
        Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
    }
}
