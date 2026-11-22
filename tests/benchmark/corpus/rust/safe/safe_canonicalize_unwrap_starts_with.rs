use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if !target.starts_with(base) {
        return;
    }
    let _ = fs::read(&target);
}
