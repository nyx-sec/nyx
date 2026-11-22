use std::fs::File;
use std::io::Read;
use std::process::Command;

// The bytes of an open file land in the buffer handed to `read_to_end`.
fn read_all(mut file: File) -> Vec<u8> {
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    data
}

fn run_named_program(path: &str) {
    let file = File::open(path).unwrap();
    let body = read_all(file);
    let program = String::from_utf8_lossy(&body).to_string();
    Command::new(program).status().unwrap();
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_default();
    run_named_program(&path);
}
