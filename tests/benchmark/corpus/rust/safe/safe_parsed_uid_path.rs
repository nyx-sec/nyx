use std::env;
use std::fs::File;
use std::io;
use std::path::PathBuf;

fn open_for_user(user: u32) -> io::Result<File> {
    let mut path = PathBuf::from("/var/run/sudo-rs/ts");
    path.push(user.to_string());
    File::open(&path)
}

fn main() -> io::Result<()> {
    let user = env::var("USER").unwrap();
    let uid: u32 = match user.parse() {
        Ok(n) => n,
        Err(_) => return Ok(()),
    };
    let _ = open_for_user(uid)?;
    Ok(())
}
