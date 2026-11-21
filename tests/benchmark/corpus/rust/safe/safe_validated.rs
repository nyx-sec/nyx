use std::env;
use std::fs;

fn main() {
    let path = env::var("FILE_PATH").unwrap();
    if path.contains("..") || path.starts_with('/') {
        panic!("path traversal detected");
    }
    let contents = fs::read_to_string(&path).unwrap();
    println!("{}", contents);
}
