use std::fs;
use std::path::Path;

fn read_checked() -> Result<Vec<u8>, String> {
    let file = std::env::var("FILE").map_err(|e| e.to_string())?;
    let base = Path::new("/srv/files");
    let target = base.join(&file).canonicalize().map_err(|e| e.to_string())?;
    if !target.starts_with(base) {
        return Ok(Vec::new());
    }
    fs::read(&target).map_err(|e| e.to_string())
}

fn main() {
    let _ = read_checked();
}
