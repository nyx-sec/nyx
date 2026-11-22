use std::io::{Cursor, Read};
use std::process::Command;

// The reader is not a file: its bytes are a compile-time constant.
fn read_all<R: Read>(mut reader: R) -> Vec<u8> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data).unwrap();
    data
}

fn run_fixed_program() {
    let body = read_all(Cursor::new(b"ls".to_vec()));
    let program = String::from_utf8_lossy(&body).to_string();
    Command::new(program).status().unwrap();
}

fn main() {
    run_fixed_program();
}
