use std::fs::File;
use std::io::Read;
use std::process::Command;

// The bytes of an open file land in the buffer handed to `read_to_end`.
fn read_all(mut file: File) -> Vec<u8> {
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    data
}

fn run_script_line(path: &str) {
    let file = File::open(path).unwrap();
    let body = read_all(file);
    let program = String::from_utf8_lossy(&body).to_string();
    Command::new(program).status().unwrap();
}

fn run_script_text(path: &str) {
    let mut file = File::open(path).unwrap();
    let mut text = String::new();
    file.read_to_string(&mut text).unwrap();
    Command::new(text).status().unwrap();
}

// The buffer was an empty Vec before the read; what it held then says nothing
// about what the read stored in it.
fn open_named_file(path: &str) {
    let mut file = File::open(path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let name = String::from_utf8(data).unwrap();
    let _ = File::open(&name);
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_default();
    run_script_line(&path);
    run_script_text(&path);
    open_named_file(&path);
}
