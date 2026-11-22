//! A prefix test on a string is byte-wise, so a root without a trailing
//! separator admits a sibling directory; `Path::starts_with` compares
//! components and is exact for any root.
use std::fs;
use std::path::{Path, PathBuf};

fn component_wise() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if !target.starts_with("/srv/files") {
        return;
    }
    let _ = fs::read(&target); // @safe Path::starts_with compares components
}

fn string_bare_root() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if !target.to_str().unwrap().starts_with("/srv/files") {
        return;
    }
    let _ = fs::read(&target); // @vuln /srv/files-backup starts with the root
}

fn string_dir_root() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if !target.to_str().unwrap().starts_with("/srv/files/") {
        return;
    }
    let _ = fs::read(&target); // @safe root ends with a separator
}

fn sentinel_reject() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if target.starts_with(base) == false {
        return;
    }
    let _ = fs::read(&target); // @safe reached only when the test is true
}

fn sentinel_serve() {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if target.starts_with(base) == false {
        let _ = fs::read(&target); // @vuln the path is outside the root here
    }
}

fn main() {
    component_wise();
    string_bare_root();
    string_dir_root();
    sentinel_reject();
    sentinel_serve();
}
