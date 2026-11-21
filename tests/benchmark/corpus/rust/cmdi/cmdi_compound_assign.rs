// `cmd += &user` appends the environment value to the shell command.
use std::env;
use std::process::Command;

fn main() {
    let user = env::var("TARGET").unwrap();
    let mut cmd = String::from("find /tmp -name ");
    cmd += &user;
    Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
}
