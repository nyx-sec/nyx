use std::env;
use std::fs;

fn main() {
    let path = env::var("FILE_PATH").unwrap();
    // Rejects `..` but not absolute paths: FILE_PATH=/etc/shadow still reads.
    if path.contains("..") {
        panic!("path traversal detected");
    }
    let contents = fs::read_to_string(&path).unwrap();
    println!("{}", contents);
}
