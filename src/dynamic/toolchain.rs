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
    /// `package.json` `engines.node` field.
    PackageJson,
    /// `go.mod` `go` directive.
    GoMod,
    /// `pom.xml` `<java.version>` / `<maven.compiler.source>`.
    PomXml,
    /// `build.gradle` `sourceCompatibility` / `java.toolchain.languageVersion`.
    BuildGradle,
    /// `composer.json` `require.php`.
    ComposerJson,
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

// ── Node.js toolchain resolver ────────────────────────────────────────────────

/// Resolve the Node.js toolchain for `project_root`.
///
/// Reads pin files in priority order:
/// `.nvmrc` > `package.json` `engines.node` > `.node-version` > default.
pub fn resolve_node(project_root: &Path) -> ToolchainResolution {
    if let Some(r) = try_nvmrc(project_root) {
        return r;
    }
    if let Some(r) = try_package_json_engines(project_root) {
        return r;
    }
    if let Some(r) = try_node_version_file(project_root) {
        return r;
    }
    default_node()
}

fn try_nvmrc(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join(".nvmrc")).ok()?;
    let version = content.trim().trim_start_matches('v').to_owned();
    if version.is_empty() {
        return None;
    }
    Some(map_node_version(&version, PinOrigin::PackageJson))
}

fn try_package_json_engines(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("package.json")).ok()?;
    // Look for "node": ">=18" or "node": "20.x" under "engines".
    let mut in_engines = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if json_line_has_key(trimmed, "engines") {
            in_engines = true;
        }
        if in_engines && trimmed.contains("\"node\"") {
            // Extract version from: "node": ">=18" or "node": "20"
            if let Some(ver) = extract_version_from_json_value(trimmed) {
                return Some(map_node_version(&ver, PinOrigin::PackageJson));
            }
        }
        if in_engines && trimmed.starts_with('}') {
            in_engines = false;
        }
    }
    None
}

fn try_node_version_file(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join(".node-version")).ok()?;
    let version = content.trim().trim_start_matches('v').to_owned();
    if version.is_empty() {
        return None;
    }
    Some(map_node_version(&version, PinOrigin::PackageJson))
}

fn default_node() -> ToolchainResolution {
    ToolchainResolution {
        toolchain_id: "node-20".to_owned(),
        pin_origin: PinOrigin::SystemDefault,
        toolchain_drift: false,
        version_string: "20".to_owned(),
    }
}

fn map_node_version(version: &str, origin: PinOrigin) -> ToolchainResolution {
    // Strip leading >= <= ~ ^ comparators.
    let ver = version.trim_start_matches(|c: char| !c.is_ascii_digit());
    let parts: Vec<&str> = ver.splitn(3, '.').collect();
    let major = parts.first().copied().unwrap_or("20");

    // Node.js LTS catalog: 18, 20, 22.
    let (toolchain_id, drift) = match major.parse::<u32>() {
        Ok(n) if n < 18 => (format!("node-{n}"), true),
        Ok(18) => ("node-18".to_owned(), false),
        Ok(20) => ("node-20".to_owned(), false),
        Ok(22) => ("node-22".to_owned(), false),
        Ok(n) => (format!("node-{n}"), true),
        _ => ("node-20".to_owned(), true),
    };

    ToolchainResolution {
        toolchain_id,
        pin_origin: origin,
        toolchain_drift: drift,
        version_string: version.to_owned(),
    }
}

/// Return true if `line` contains `"key":` as a JSON object key assignment.
///
/// Prevents false-positives from values like `"type": "require"` that would
/// otherwise match a plain `contains("\"key\"")` check.
fn json_line_has_key(line: &str, key: &str) -> bool {
    let needle = format!("\"{key}\"");
    let mut search = line;
    while let Some(pos) = search.find(needle.as_str()) {
        let rest = &search[pos + needle.len()..];
        if rest.trim_start().starts_with(':') {
            return true;
        }
        search = &search[pos + 1..];
    }
    false
}

/// Extract a version string from a JSON value like `">=18"` or `"20.x"`.
fn extract_version_from_json_value(line: &str) -> Option<String> {
    // Find the second quoted value after the colon.
    let after_colon = line.splitn(2, ':').nth(1)?;
    let raw = after_colon.trim().trim_matches('"').trim_matches('\'');
    let ver = raw.trim_start_matches(|c: char| !c.is_ascii_digit());
    // Strip trailing .x or .* wildcards.
    let ver = if let Some(pos) = ver.find(".x") {
        &ver[..pos]
    } else if let Some(pos) = ver.find(".*") {
        &ver[..pos]
    } else {
        ver
    };
    if ver.is_empty() {
        return None;
    }
    Some(ver.to_owned())
}

// ── Go toolchain resolver ─────────────────────────────────────────────────────

/// Resolve the Go toolchain for `project_root`.
///
/// Reads pin files in priority order: `go.mod` `go` directive > default.
pub fn resolve_go(project_root: &Path) -> ToolchainResolution {
    if let Some(r) = try_go_mod(project_root) {
        return r;
    }
    default_go()
}

fn try_go_mod(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("go.mod")).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("go ") {
            let version = rest.trim().to_owned();
            if !version.is_empty() {
                return Some(map_go_version(&version, PinOrigin::GoMod));
            }
        }
    }
    None
}

fn default_go() -> ToolchainResolution {
    ToolchainResolution {
        toolchain_id: "go-stable".to_owned(),
        pin_origin: PinOrigin::SystemDefault,
        toolchain_drift: false,
        version_string: "stable".to_owned(),
    }
}

fn map_go_version(version: &str, origin: PinOrigin) -> ToolchainResolution {
    let parts: Vec<&str> = version.splitn(3, '.').collect();
    let major = parts.first().copied().unwrap_or("1");
    let minor = parts.get(1).copied();

    // Go 1.21+ is the modern catalog.
    let (toolchain_id, drift) = match (major, minor) {
        ("1", Some("21")) => ("go-1.21".to_owned(), false),
        ("1", Some("22")) => ("go-1.22".to_owned(), false),
        ("1", Some("23")) => ("go-1.23".to_owned(), false),
        ("1", Some(m)) if m.parse::<u32>().map_or(false, |v| v >= 24) => {
            (format!("go-1.{m}"), true)
        }
        ("1", Some(m)) if m.parse::<u32>().map_or(false, |v| v < 21) => {
            (format!("go-1.{m}"), true)
        }
        _ => ("go-stable".to_owned(), false),
    };

    ToolchainResolution {
        toolchain_id,
        pin_origin: origin,
        toolchain_drift: drift,
        version_string: version.to_owned(),
    }
}

// ── Java toolchain resolver ───────────────────────────────────────────────────

/// Resolve the Java toolchain for `project_root`.
///
/// Reads pin files in priority order:
/// `pom.xml` `<java.version>` / `<maven.compiler.source>` >
/// `build.gradle` `sourceCompatibility` > default.
pub fn resolve_java(project_root: &Path) -> ToolchainResolution {
    if let Some(r) = try_pom_xml(project_root) {
        return r;
    }
    if let Some(r) = try_build_gradle(project_root) {
        return r;
    }
    default_java()
}

fn try_pom_xml(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("pom.xml")).ok()?;
    // Look for <java.version>21</java.version> or <maven.compiler.source>21</...>
    for line in content.lines() {
        let trimmed = line.trim();
        for tag in &["<java.version>", "<maven.compiler.source>", "<maven.compiler.release>"] {
            if trimmed.starts_with(tag) {
                if let Some(inner) = trimmed.strip_prefix(tag) {
                    let version = inner.split('<').next().unwrap_or("").trim();
                    if !version.is_empty() {
                        return Some(map_java_version(version, PinOrigin::PomXml));
                    }
                }
            }
        }
    }
    None
}

fn try_build_gradle(root: &Path) -> Option<ToolchainResolution> {
    for fname in &["build.gradle", "build.gradle.kts"] {
        let Ok(content) = std::fs::read_to_string(root.join(fname)) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            // Groovy: sourceCompatibility = '21' or JavaVersion.VERSION_21
            // Kotlin: sourceCompatibility = JavaVersion.VERSION_21
            if trimmed.starts_with("sourceCompatibility") || trimmed.starts_with("languageVersion") {
                if let Some(ver) = extract_java_version_from_gradle_line(trimmed) {
                    return Some(map_java_version(&ver, PinOrigin::BuildGradle));
                }
            }
        }
    }
    None
}

fn extract_java_version_from_gradle_line(line: &str) -> Option<String> {
    // Handle: sourceCompatibility = '21' or sourceCompatibility = 21
    // and: languageVersion.set(JavaLanguageVersion.of(21))
    let after_eq = line.splitn(2, '=').nth(1).unwrap_or(line);
    // Try to find a number in the value.
    let digits: String = after_eq.chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        // Try "VERSION_21" pattern.
        if let Some(pos) = after_eq.find("VERSION_") {
            let rest = &after_eq[pos + 8..];
            let digits: String = rest.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                return Some(digits);
            }
        }
        return None;
    }
    Some(digits)
}

fn default_java() -> ToolchainResolution {
    ToolchainResolution {
        toolchain_id: "java-21".to_owned(),
        pin_origin: PinOrigin::SystemDefault,
        toolchain_drift: false,
        version_string: "21".to_owned(),
    }
}

fn map_java_version(version: &str, origin: PinOrigin) -> ToolchainResolution {
    // Java version: 8, 11, 17, 21, 22 are common LTS/current.
    let major = version.split('.').next().unwrap_or(version);

    let (toolchain_id, drift) = match major.parse::<u32>() {
        Ok(8) => ("java-8".to_owned(), false),
        Ok(11) => ("java-11".to_owned(), false),
        Ok(17) => ("java-17".to_owned(), false),
        Ok(21) => ("java-21".to_owned(), false),
        Ok(n) => (format!("java-{n}"), true),
        _ => ("java-21".to_owned(), true),
    };

    ToolchainResolution {
        toolchain_id,
        pin_origin: origin,
        toolchain_drift: drift,
        version_string: version.to_owned(),
    }
}

// ── PHP toolchain resolver ────────────────────────────────────────────────────

/// Resolve the PHP toolchain for `project_root`.
///
/// Reads pin files in priority order:
/// `composer.json` `require.php` > `.php-version` > default.
pub fn resolve_php(project_root: &Path) -> ToolchainResolution {
    if let Some(r) = try_composer_json(project_root) {
        return r;
    }
    if let Some(r) = try_php_version_file(project_root) {
        return r;
    }
    default_php()
}

fn try_composer_json(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join("composer.json")).ok()?;
    // Look for "php": ">=8.1" under "require".
    let mut in_require = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if json_line_has_key(trimmed, "require") {
            in_require = true;
        }
        if in_require && trimmed.contains("\"php\"") {
            if let Some(ver) = extract_version_from_json_value(trimmed) {
                return Some(map_php_version(&ver, PinOrigin::ComposerJson));
            }
        }
        // Stop at closing brace of require block.
        if in_require && trimmed == "}," || (in_require && trimmed == "}") {
            in_require = false;
        }
    }
    None
}

fn try_php_version_file(root: &Path) -> Option<ToolchainResolution> {
    let content = std::fs::read_to_string(root.join(".php-version")).ok()?;
    let version = content.trim().to_owned();
    if version.is_empty() {
        return None;
    }
    Some(map_php_version(&version, PinOrigin::ComposerJson))
}

fn default_php() -> ToolchainResolution {
    ToolchainResolution {
        toolchain_id: "php-8".to_owned(),
        pin_origin: PinOrigin::SystemDefault,
        toolchain_drift: false,
        version_string: "8".to_owned(),
    }
}

fn map_php_version(version: &str, origin: PinOrigin) -> ToolchainResolution {
    let ver = version.trim_start_matches(|c: char| !c.is_ascii_digit());
    let parts: Vec<&str> = ver.splitn(3, '.').collect();
    let major = parts.first().copied().unwrap_or("8");
    let minor = parts.get(1).copied();

    let (toolchain_id, drift) = match (major.parse::<u32>(), minor) {
        (Ok(8), Some("0")) => ("php-8.0".to_owned(), false),
        (Ok(8), Some("1")) => ("php-8.1".to_owned(), false),
        (Ok(8), Some("2")) => ("php-8.2".to_owned(), false),
        (Ok(8), Some("3")) => ("php-8.3".to_owned(), false),
        (Ok(8), None) => ("php-8".to_owned(), false),
        (Ok(7), _) => ("php-7".to_owned(), true),
        (Ok(n), _) => (format!("php-{n}"), true),
        _ => ("php-8".to_owned(), true),
    };

    ToolchainResolution {
        toolchain_id,
        pin_origin: origin,
        toolchain_drift: drift,
        version_string: version.to_owned(),
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

    // ── Node.js resolver tests ────────────────────────────────────────────────

    #[test]
    fn node_nvmrc_exact() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".nvmrc"), "v20.5.0\n").unwrap();
        let r = resolve_node(dir.path());
        assert_eq!(r.toolchain_id, "node-20");
        assert!(!r.toolchain_drift);
        assert_eq!(r.pin_origin, PinOrigin::PackageJson);
    }

    #[test]
    fn node_package_json_engines() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines": {"node": ">=18.0.0"}}"#,
        ).unwrap();
        let r = resolve_node(dir.path());
        assert_eq!(r.toolchain_id, "node-18");
    }

    #[test]
    fn node_default_is_20() {
        let dir = TempDir::new().unwrap();
        let r = resolve_node(dir.path());
        assert_eq!(r.toolchain_id, "node-20");
        assert_eq!(r.pin_origin, PinOrigin::SystemDefault);
    }

    // ── Go resolver tests ─────────────────────────────────────────────────────

    #[test]
    fn go_mod_version() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("go.mod"), "module example.com/app\n\ngo 1.22\n").unwrap();
        let r = resolve_go(dir.path());
        assert_eq!(r.toolchain_id, "go-1.22");
        assert!(!r.toolchain_drift);
        assert_eq!(r.pin_origin, PinOrigin::GoMod);
    }

    #[test]
    fn go_default_is_stable() {
        let dir = TempDir::new().unwrap();
        let r = resolve_go(dir.path());
        assert_eq!(r.toolchain_id, "go-stable");
        assert_eq!(r.pin_origin, PinOrigin::SystemDefault);
    }

    // ── Java resolver tests ───────────────────────────────────────────────────

    #[test]
    fn java_pom_xml_version() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("pom.xml"),
            "<project>\n  <properties>\n    <java.version>21</java.version>\n  </properties>\n</project>",
        ).unwrap();
        let r = resolve_java(dir.path());
        assert_eq!(r.toolchain_id, "java-21");
        assert!(!r.toolchain_drift);
        assert_eq!(r.pin_origin, PinOrigin::PomXml);
    }

    #[test]
    fn java_build_gradle_source_compat() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("build.gradle"),
            "sourceCompatibility = '17'\ntargetCompatibility = '17'\n",
        ).unwrap();
        let r = resolve_java(dir.path());
        assert_eq!(r.toolchain_id, "java-17");
        assert_eq!(r.pin_origin, PinOrigin::BuildGradle);
    }

    #[test]
    fn java_default_is_21() {
        let dir = TempDir::new().unwrap();
        let r = resolve_java(dir.path());
        assert_eq!(r.toolchain_id, "java-21");
        assert_eq!(r.pin_origin, PinOrigin::SystemDefault);
    }

    // ── PHP resolver tests ────────────────────────────────────────────────────

    #[test]
    fn php_composer_json_version() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("composer.json"),
            r#"{"require": {"php": ">=8.1"}}"#,
        ).unwrap();
        let r = resolve_php(dir.path());
        assert_eq!(r.toolchain_id, "php-8.1");
        assert_eq!(r.pin_origin, PinOrigin::ComposerJson);
    }

    #[test]
    fn php_default_is_8() {
        let dir = TempDir::new().unwrap();
        let r = resolve_php(dir.path());
        assert_eq!(r.toolchain_id, "php-8");
        assert_eq!(r.pin_origin, PinOrigin::SystemDefault);
    }

    #[test]
    fn php_composer_json_require_dev_before_require() {
        // "require-dev" must not shadow the real "require" block even when it
        // appears first. The tightened json_line_has_key check prevents false
        // activation on the "require-dev" key.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("composer.json"),
            "{\n    \"require-dev\": {\n        \"php\": \"^7.0\"\n    },\n    \"require\": {\n        \"php\": \">=8.1\"\n    }\n}",
        ).unwrap();
        let r = resolve_php(dir.path());
        assert_eq!(r.toolchain_id, "php-8.1");
        assert_eq!(r.pin_origin, PinOrigin::ComposerJson);
    }

    #[test]
    fn php_composer_json_require_as_value_not_matched() {
        // "require" appearing as a string value (not a key) must not activate
        // in_require and cause a php constraint from an unrelated block to be
        // returned. Without the json_line_has_key fix, a line like
        // `"type": "require"` would set in_require=true, letting the "php"
        // key inside require-dev be matched instead of falling through.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("composer.json"),
            "{\n    \"extra\": {\"type\": \"require\"},\n    \"require-dev\": {\n        \"php\": \"^7.0\"\n    }\n}",
        ).unwrap();
        let r = resolve_php(dir.path());
        // No real "require": key present — must fall back to system default.
        assert_eq!(r.pin_origin, PinOrigin::SystemDefault);
    }

    // ── json_line_has_key unit tests ─────────────────────────────────────────

    #[test]
    fn json_line_has_key_matches_exact_key() {
        assert!(json_line_has_key(r#"    "require": {"#, "require"));
        assert!(json_line_has_key(r#"{"require": {}}"#, "require"));
        assert!(json_line_has_key(r#"  "engines" : {"#, "engines"));
    }

    #[test]
    fn json_line_has_key_rejects_key_in_value() {
        assert!(!json_line_has_key(r#"    "type": "require","#, "require"));
        assert!(!json_line_has_key(r#"    "desc": "engines config","#, "engines"));
    }

    #[test]
    fn json_line_has_key_rejects_superstring_key() {
        // "require-dev" does not contain "require" as a quoted key.
        assert!(!json_line_has_key(r#"    "require-dev": {"#, "require"));
    }
}
