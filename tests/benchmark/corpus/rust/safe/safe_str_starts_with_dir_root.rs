// rust-safe-str-starts-with-dir-root: the prefix test runs on a string whose
// root ends with a separator, so a sibling such as "/srv/files-old/x" fails it.
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if !target.to_str().unwrap().starts_with("/srv/files/") {
        return;
    }
    let _ = fs::read(&target);
}
