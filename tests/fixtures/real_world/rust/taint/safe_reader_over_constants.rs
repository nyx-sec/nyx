use std::io::{Cursor, Read};
use std::process::Command;

// A reader that is not a file: the bytes are a compile-time constant, so what
// `read_to_end` stores in the buffer is not external input.
fn read_all<R: Read>(mut reader: R) -> Vec<u8> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data).unwrap();
    data
}

fn run_fixed() {
    let body = read_all(Cursor::new(b"ls".to_vec()));
    let program = String::from_utf8_lossy(&body).to_string();
    Command::new(program).status().unwrap();
}

fn run_fixed_text() {
    let mut reader = Cursor::new("ls");
    let mut text = String::new();
    reader.read_to_string(&mut text).unwrap();
    Command::new(text).status().unwrap();
}

fn main() {
    run_fixed();
    run_fixed_text();
}
