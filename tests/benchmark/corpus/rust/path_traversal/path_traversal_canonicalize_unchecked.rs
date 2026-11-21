use std::fs;
use std::path::Path;

fn main() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    // canonicalize resolves `..` but the result can still leave the base.
    let target = base.join(&file).canonicalize().unwrap();
    let _ = fs::read(&target);
}
