use std::env;
use std::process::Command;

fn main() {
    match env::var("USER_CMD") {
        Ok(cmd) => {
            Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
        }
        Err(_) => {}
    }
}
