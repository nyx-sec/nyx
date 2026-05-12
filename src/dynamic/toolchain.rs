//! Toolchain resolver (§22.2).
//!
//! Reads project metadata files to determine the pinned Python version, then
//! maps it to the closest Nyx reference image. Records `pin_origin` (where the
//! version was found) and a `toolchain_drift` flag when the resolved image is
//! not an exact match for the requested version.

use std::path::Path;

/// Resolved toolchain information for a target directory.
#[derive(Debug, Clone)]
pub struct ToolchainResolution {
    /// Nyx reference toolchain identifier (e.g. `"python-3.11"`).
    pub toolchain_id: String,
    /// Where the version pin was read from.
    pub pin_origin: PinOrigin,
    /// Whether the resolved toolchain differs from the exact pinned version.
    pub toolchain_drift: bool,
    /// Resolved semver string (e.g. `"3.11.5"`).
    pub version_string: String,
}

/// Where the toolchain version pin was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinOrigin {
    /// `.python-version` file (pyenv).
    PythonVersion,
    /// `pyproject.toml` `[tool.python]` or `[project] requires-python`.
    PyprojectToml,
    /// `Pipfile` `[requires] python_version`.
    Pipfile,
    /// `runtime.txt` (Heroku-style).
    RuntimeTxt,
    /// `rust-toolchain.toml` `[toolchain] channel`.
    RustToolchainToml,
    /// `rust-toolchain` (plain text channel file).
    RustToolchainFile,
    /// `Cargo.toml` `rust-version` field.
    CargoToml,
    /// No pin found; used the system default.
    SystemDefault,
}

// ── Rust toolchain resolver ───────────────────────────────────────────────────

/// Resolve the Rust toolchain for `project_root` (§22.2).
///
/// Reads project pin files in priority order:
/// `rust-toolchain.toml` > `rust-toolchain` > `Cargo.toml` `rust-version` > default.
pub fn resolve_rust(project_root: &Path) -> ToolchainResolution {
    if let Some(r) = try_rust_toolchain_toml(project_root) {
        return r;
    }
    if let Some(r) = try_rust_toolchain_file(project_root) {
        return r;
    }
    if let Some(r) = try_cargo_toml_rust_version(project_root) {
        return r;
    }
    default_rust()
}

fn try_rust_toolchain_toml(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("rust-toolchain.toml")).ok()?;
    // Look for `channel = "stable"` or `channel = "1.75"` in [toolchain] section.
    let mut in_toolchain = false;
    for line in content.lines() {
        let line = line.trim();
        if line == "[toolchain]" {
            in_toolchain = true;
            continue;
        }
        if line.starts_with('[') {
            in_toolchain = false;
        }
        if in_toolchain && line.starts_with("channel") {
            if let Some(ver) = extract_version_from_toml_value(line) {
                return Some(map_rust_version(&ver, RustPinOrigin::RustToolchainToml));
            }
        }
    }
    None
}

fn try_rust_toolchain_file(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("rust-toolchain")).ok()?;
    let version = content.trim().to_owned();
    if version.is_empty() {
        return None;
    }
    // Simple format: just the channel name (e.g. "stable", "1.75.0", "nightly-2024-01-01")
    Some(map_rust_version(&version, RustPinOrigin::RustToolchainFile))
}

fn try_cargo_toml_rust_version(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("rust-version") {
            if let Some(ver) = extract_version_from_toml_value(line) {
                return Some(map_rust_version(&ver, RustPinOrigin::CargoToml));
            }
        }
    }
    None
}

fn default_rust() -> ToolchainResolution {
    ToolchainResolution {
        toolchain_id: "rust-stable".to_owned(),
        pin_origin: PinOrigin::SystemDefault,
        toolchain_drift: false,
        version_string: "stable".to_owned(),
    }
}

/// Internal origin enum for Rust (mapped to PinOrigin for the public API).
enum RustPinOrigin {
    RustToolchainToml,
    RustToolchainFile,
    CargoToml,
}

fn map_rust_version(version: &str, origin: RustPinOrigin) -> ToolchainResolution {
    let pin_origin = match origin {
        RustPinOrigin::RustToolchainToml => PinOrigin::RustToolchainToml,
        RustPinOrigin::RustToolchainFile => PinOrigin::RustToolchainFile,
        RustPinOrigin::CargoToml => PinOrigin::CargoToml,
    };

    // Named channels.
    if version == "stable" || version.is_empty() {
        return ToolchainResolution {
            toolchain_id: "rust-stable".to_owned(),
            pin_origin,
            toolchain_drift: false,
            version_string: "stable".to_owned(),
        };
    }
    if version.starts_with("nightly") {
        return ToolchainResolution {
            toolchain_id: "rust-nightly".to_owned(),
            pin_origin,
            toolchain_drift: true,  // nightly != stable reference image
            version_string: version.to_owned(),
        };
    }
    if version.starts_with("beta") {
        return ToolchainResolution {
            toolchain_id: "rust-beta".to_owned(),
            pin_origin,
            toolchain_drift: true,
            version_string: version.to_owned(),
        };
    }

    // Semver pinned version like "1.75.0" or "1.75".
    let parts: Vec<&str> = version.splitn(3, '.').collect();
    let major = parts.first().copied().unwrap_or("1");
    let minor = parts.get(1).copied();

    // Map to stable; drift = true when exact version differs from "stable".
    let drift = minor.is_some(); // pin to specific version = drift from "stable" label
    ToolchainResolution {
        toolchain_id: format!("rust-{major}.{}", minor.unwrap_or("x")),
        pin_origin,
        toolchain_drift: drift,
        version_string: version.to_owned(),
    }
}

// ── Python toolchain resolver ─────────────────────────────────────────────────

/// Resolve the Python toolchain for `project_root`.
///
/// Reads project pin files in priority order:
/// `.python-version` > `pyproject.toml` > `Pipfile` > `runtime.txt` > default.
pub fn resolve_python(project_root: &Path) -> ToolchainResolution {
    if let Some(r) = try_python_version_file(project_root) {
        return r;
    }
    if let Some(r) = try_pyproject_toml(project_root) {
        return r;
    }
    if let Some(r) = try_pipfile(project_root) {
        return r;
    }
    if let Some(r) = try_runtime_txt(project_root) {
        return r;
    }
    default_python()
}

fn try_python_version_file(root: &Path) -> Option<ToolchainResolution> {
    let path = root.join(".python-version");
    let content = std::fs::read_to_string(&path).ok()?;
    let version = content.trim().to_owned();
    if version.is_empty() {
        return None;
    }
    Some(map_version(&version, PinOrigin::PythonVersion))
}

fn try_pyproject_toml(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("pyproject.toml")).ok()?;
    // Look for `requires-python = ">=3.11"` or `python = "3.11"`.
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("requires-python") || (line.starts_with("python") && line.contains('=') && !line.starts_with("python_requires")) {
            if let Some(ver) = extract_version_from_toml_value(line) {
                return Some(map_version(&ver, PinOrigin::PyprojectToml));
            }
        }
    }
    None
}

fn try_pipfile(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("Pipfile")).ok()?;
    let mut in_requires = false;
    for line in content.lines() {
        let line = line.trim();
        if line == "[requires]" {
            in_requires = true;
            continue;
        }
        if line.starts_with('[') {
            in_requires = false;
        }
        if in_requires && line.starts_with("python_version") {
            if let Some(ver) = extract_version_from_toml_value(line) {
                return Some(map_version(&ver, PinOrigin::Pipfile));
            }
        }
    }
    None
}

fn try_runtime_txt(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("runtime.txt")).ok()?;
    let line = content.lines().next()?.trim();
    // e.g. "python-3.11.5"
    let version = line.strip_prefix("python-").unwrap_or(line);
    if version.is_empty() {
        return None;
    }
    Some(map_version(version, PinOrigin::RuntimeTxt))
}

fn default_python() -> ToolchainResolution {
    ToolchainResolution {
        toolchain_id: "python-3".to_owned(),
        pin_origin: PinOrigin::SystemDefault,
        toolchain_drift: false,
        version_string: "3".to_owned(),
    }
}

/// Extract the bare version string from a TOML assignment like:
///   `requires-python = ">=3.11"`  → `"3.11"`
///   `python_version = "3.11"`     → `"3.11"`
fn extract_version_from_toml_value(line: &str) -> Option<String> {
    let after_eq = line.splitn(2, '=').nth(1)?;
    let raw = after_eq.trim().trim_matches('"').trim_matches('\'');
    // Strip leading comparators: >=, <=, ==, ~=, ^, >
    let ver = raw.trim_start_matches(|c: char| !c.is_ascii_digit());
    if ver.is_empty() {
        return None;
    }
    Some(ver.to_owned())
}

/// Map a raw version string to a Nyx reference toolchain ID.
///
/// Reference images: `python-3.8`, `python-3.9`, `python-3.10`,
/// `python-3.11`, `python-3.12`, `python-3.13`.
fn map_version(version: &str, origin: PinOrigin) -> ToolchainResolution {
    // Normalise: take major.minor from "3.11.5" → "3.11"
    let parts: Vec<&str> = version.splitn(3, '.').collect();
    let major = parts.first().copied().unwrap_or("3");
    let minor = parts.get(1).copied();

    let (toolchain_id, drift) = match (major, minor) {
        ("3", Some("8")) => ("python-3.8".to_owned(), false),
        ("3", Some("9")) => ("python-3.9".to_owned(), false),
        ("3", Some("10")) => ("python-3.10".to_owned(), false),
        ("3", Some("11")) => ("python-3.11".to_owned(), false),
        ("3", Some("12")) => ("python-3.12".to_owned(), false),
        ("3", Some("13")) => ("python-3.13".to_owned(), false),
        // Older 3.x → nearest supported is 3.8
        ("3", Some(m)) if m.parse::<u32>().map_or(false, |v| v < 8) => {
            ("python-3.8".to_owned(), true)
        }
        // Newer 3.x beyond catalog → use 3.13 as closest
        ("3", Some(_)) => ("python-3.13".to_owned(), true),
        ("3", None) => ("python-3".to_owned(), false),
        // Python 2 → unsupported, use system default as closest
        ("2", _) => ("python-3".to_owned(), true),
        _ => ("python-3".to_owned(), true),
    };

    ToolchainResolution {
        version_string: version.to_owned(),
        toolchain_id,
        pin_origin: origin,
        toolchain_drift: drift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn python_version_file_exact() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".python-version"), "3.11.5\n").unwrap();
        let r = resolve_python(dir.path());
        assert_eq!(r.toolchain_id, "python-3.11");
        assert!(!r.toolchain_drift);
        assert_eq!(r.pin_origin, PinOrigin::PythonVersion);
    }

    #[test]
    fn python_version_file_drift() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".python-version"), "3.7\n").unwrap();
        let r = resolve_python(dir.path());
        assert!(r.toolchain_drift);
    }

    #[test]
    fn pyproject_requires_python() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("pyproject.toml"), "[project]\nrequires-python = \">=3.11\"\n").unwrap();
        let r = resolve_python(dir.path());
        assert_eq!(r.toolchain_id, "python-3.11");
        assert_eq!(r.pin_origin, PinOrigin::PyprojectToml);
    }

    #[test]
    fn pipfile_python_version() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Pipfile"), "[requires]\npython_version = \"3.10\"\n").unwrap();
        let r = resolve_python(dir.path());
        assert_eq!(r.toolchain_id, "python-3.10");
        assert_eq!(r.pin_origin, PinOrigin::Pipfile);
    }

    #[test]
    fn fallback_to_system_default() {
        let dir = TempDir::new().unwrap();
        let r = resolve_python(dir.path());
        assert_eq!(r.pin_origin, PinOrigin::SystemDefault);
    }

    // ── Rust toolchain tests ─────────────────────────────────────────────────

    #[test]
    fn rust_toolchain_toml_stable() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"stable\"\n",
        ).unwrap();
        let r = resolve_rust(dir.path());
        assert_eq!(r.toolchain_id, "rust-stable");
        assert!(!r.toolchain_drift);
        assert_eq!(r.pin_origin, PinOrigin::RustToolchainToml);
    }

    #[test]
    fn rust_toolchain_file_nightly() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("rust-toolchain"), "nightly\n").unwrap();
        let r = resolve_rust(dir.path());
        assert_eq!(r.toolchain_id, "rust-nightly");
        assert!(r.toolchain_drift);
        assert_eq!(r.pin_origin, PinOrigin::RustToolchainFile);
    }

    #[test]
    fn cargo_toml_rust_version() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"foo\"\nrust-version = \"1.75\"\n",
        ).unwrap();
        let r = resolve_rust(dir.path());
        assert_eq!(r.pin_origin, PinOrigin::CargoToml);
        assert!(r.toolchain_id.starts_with("rust-1"));
    }

    #[test]
    fn rust_default_is_stable() {
        let dir = TempDir::new().unwrap();
        let r = resolve_rust(dir.path());
        assert_eq!(r.toolchain_id, "rust-stable");
        assert_eq!(r.pin_origin, PinOrigin::SystemDefault);
    }
}
