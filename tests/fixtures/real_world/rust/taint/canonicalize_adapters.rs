use std::fs;
use std::path::{Path, PathBuf};

// Safe: canonicalize, then a containment check; `unwrap` hands back the value.
pub fn contained_unwrap() -> Vec<u8> {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target: PathBuf = base.join(&file).canonicalize().unwrap();
    if !target.starts_with(base) {
        return Vec::new();
    }
    fs::read(&target).unwrap()
}

// Safe: `map_err` only rewrites the error side.
pub fn contained_map_err() -> Result<Vec<u8>, String> {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target = base.join(&file).canonicalize().map_err(|e| e.to_string())?;
    if !target.starts_with(base) {
        return Ok(Vec::new());
    }
    fs::read(&target).map_err(|e| e.to_string())
}

// Vulnerable: canonicalize alone does not confine.
pub fn unchecked() -> Vec<u8> {
    let file = std::env::var("FILE").unwrap();
    let base = Path::new("/srv/files");
    let target = base.join(&file).canonicalize().unwrap();
    fs::read(&target).unwrap()
}
