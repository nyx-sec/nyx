//! Project-mount filter (§17.3).
//!
//! Before mounting the project directory into the sandbox, this module
//! scans for sensitive files and empties them (or excludes them from the
//! overlay). A structured note is emitted for each file stripped.
//!
//! If the harness fails to import after stripping a required file, the
//! verdict is `Unsupported(RequiredFileRedactedForSecrets(path))`.

use std::path::{Path, PathBuf};

/// A record of a file that was filtered before sandbox mount.
#[derive(Debug, Clone)]
pub struct FilterNote {
    /// Project-relative path of the file that was stripped.
    pub path: String,
    /// Why it was stripped (matched pattern name).
    pub pattern: &'static str,
}

/// Check a project root and return notes for all sensitive files found.
///
/// Does NOT modify the filesystem — callers decide how to act on the notes
/// (overlay-empty, exclude from mount, etc.).
pub fn scan_sensitive_files(project_root: &Path) -> Vec<FilterNote> {
    let mut notes = Vec::new();
    scan_dir_recursive(project_root, project_root, &mut notes);
    notes
}

fn scan_dir_recursive(project_root: &Path, dir: &Path, notes: &mut Vec<FilterNote>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            // Recurse into non-excluded dirs
            if !is_excluded_dir(name) {
                scan_dir_recursive(project_root, &path, notes);
            }
            // Check dir-level patterns (e.g. .aws/, .gnupg/, .ssh/)
            if let Some(pattern) = matches_dir_pattern(name) {
                let rel = relative_path(project_root, &path);
                notes.push(FilterNote { path: rel, pattern });
            }
        } else if let Some(pattern) = matches_file_pattern(name, &path) {
            let rel = relative_path(project_root, &path);
            notes.push(FilterNote { path: rel, pattern });
        }
    }
}

fn is_excluded_dir(name: &str) -> bool {
    matches!(name, ".git" | "node_modules" | "__pycache__" | ".tox" | "venv" | ".venv")
}

fn matches_dir_pattern(name: &str) -> Option<&'static str> {
    match name {
        ".aws" => Some(".aws/"),
        ".gnupg" => Some(".gnupg/"),
        ".ssh" => Some(".ssh/"),
        _ => None,
    }
}

/// Returns the pattern name if this file matches a sensitive-file pattern.
fn matches_file_pattern(name: &str, path: &Path) -> Option<&'static str> {
    // Exact name matches
    if matches!(name, "credentials.json") {
        return Some("credentials.json");
    }
    // .env* files
    if name == ".env" || name.starts_with(".env.") {
        return Some(".env*");
    }
    // Extension-based patterns
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "pem" => return Some("*.pem"),
        "key" => return Some("*.key"),
        "p12" => return Some("*.p12"),
        "pfx" => return Some("*.pfx"),
        "token" | "tokens" => return Some("*.token(s)"),
        _ => {}
    }
    // Prefix-based patterns
    if name.starts_with("id_rsa") {
        return Some("id_rsa*");
    }
    if name.starts_with("id_ed25519") {
        return Some("id_ed25519*");
    }
    if name.starts_with("service-account") && (ext == "json" || name.ends_with(".json")) {
        return Some("service-account*.json");
    }
    None
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Build a set of paths (relative to `project_root`) that should be excluded
/// from the sandbox mount, derived from the filter notes.
pub fn excluded_paths(notes: &[FilterNote]) -> Vec<PathBuf> {
    notes.iter().map(|n| PathBuf::from(&n.path)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn detects_dotenv() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "SECRET=abc\n").unwrap();
        let notes = scan_sensitive_files(dir.path());
        assert!(notes.iter().any(|n| n.path.contains(".env")));
    }

    #[test]
    fn detects_pem_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("server.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
        let notes = scan_sensitive_files(dir.path());
        assert!(notes.iter().any(|n| n.path.ends_with(".pem") || n.path.contains("server.pem")));
    }

    #[test]
    fn detects_ssh_key() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("id_rsa"), "private key").unwrap();
        let notes = scan_sensitive_files(dir.path());
        assert!(notes.iter().any(|n| n.pattern == "id_rsa*"));
    }

    #[test]
    fn clean_dir_returns_empty() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.py"), "print('hi')\n").unwrap();
        let notes = scan_sensitive_files(dir.path());
        assert!(notes.is_empty(), "clean dir should produce no notes: {notes:?}");
    }
}
