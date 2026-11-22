// rust-path-traversal-str-starts-with-bare-root: the prefix test runs on a
// string, so it is byte-wise and "/srv/files-old/x" passes it.  Only
// Path::starts_with compares whole components.
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if !target.to_str().unwrap().starts_with("/srv/files") {
        return;
    }
    let _ = fs::read(&target);
}
