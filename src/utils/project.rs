use crate::errors::{NyxError, NyxResult};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Determine `<project-name, path/to/<project>.sqlite>`.
pub fn get_project_info(project_path: &Path, config_dir: &Path) -> NyxResult<(String, PathBuf)> {
    let project_name = project_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| NyxError::Other("Unable to determine project name".into()))?;

    let db_name = sanitize_project_name(project_name);
    let db_path = config_dir.join(format!("{db_name}.sqlite"));

    Ok((project_name.to_owned(), db_path))
}

pub fn sanitize_project_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| match c {
            ' ' | '\t' | '\n' | '\r' => '_',
            c if c.is_alphanumeric() || c == '_' || c == '-' => c,
            _ => '_',
        })
        .collect::<String>()
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// A web framework detected from project manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectedFramework {
    Express,
    Koa,
    Fastify,
    React,
    Flask,
    Django,
    Spring,
    Gin,
    Echo,
    Laravel,
    Rails,
    Sinatra,
    ActixWeb,
    Rocket,
    Axum,
}

/// Frameworks detected in the project root.
#[derive(Debug, Clone, Default)]
pub struct FrameworkContext {
    pub frameworks: Vec<DetectedFramework>,
    /// Language ecosystems whose root manifest existed and was inspected.
    /// Lets `lang_has_web_framework` distinguish "no manifest at all" from
    /// "manifest present but listed no matching framework" — the second
    /// case is a positive signal that the project has no HTTP boundary in
    /// that language, the first is just absence-of-information.
    pub inspected_langs: std::collections::HashSet<&'static str>,
}

impl FrameworkContext {
    pub fn has(&self, fw: DetectedFramework) -> bool {
        self.frameworks.contains(&fw)
    }

    /// Three-valued web-framework presence query for a language slug.
    ///
    /// * `Some(true)` ─ at least one framework for `lang` is in `frameworks`.
    /// * `Some(false)` ─ a manifest for `lang` was inspected but listed no
    ///   matching framework.  The project genuinely has no HTTP boundary
    ///   in this language.
    /// * `None` ─ no manifest for `lang` was inspected (e.g. single-file
    ///   scans without a project root).  Caller should fall back to
    ///   prior-behavior heuristics.
    pub fn lang_has_web_framework(&self, lang: &str) -> Option<bool> {
        let (frameworks_for_lang, manifest_lang_key): (&[DetectedFramework], &str) = match lang {
            "javascript" | "typescript" | "js" | "ts" => (
                &[
                    DetectedFramework::Express,
                    DetectedFramework::Koa,
                    DetectedFramework::Fastify,
                ],
                "node",
            ),
            "python" | "py" => (
                &[DetectedFramework::Flask, DetectedFramework::Django],
                "python",
            ),
            "java" => (&[DetectedFramework::Spring], "java"),
            "go" => (&[DetectedFramework::Gin, DetectedFramework::Echo], "go"),
            "ruby" | "rb" => (
                &[DetectedFramework::Rails, DetectedFramework::Sinatra],
                "ruby",
            ),
            "php" => (&[DetectedFramework::Laravel], "php"),
            "rust" | "rs" => (
                &[
                    DetectedFramework::Axum,
                    DetectedFramework::ActixWeb,
                    DetectedFramework::Rocket,
                ],
                "rust",
            ),
            _ => return None,
        };
        if frameworks_for_lang.iter().any(|fw| self.has(*fw)) {
            return Some(true);
        }
        if self.inspected_langs.contains(manifest_lang_key) {
            return Some(false);
        }
        None
    }
}

/// Maximum bytes to read from each manifest file.
const MANIFEST_READ_LIMIT: usize = 64 * 1024;

/// Read up to `MANIFEST_READ_LIMIT` bytes from a file.
fn read_bounded(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut reader = std::io::BufReader::new(file).take(MANIFEST_READ_LIMIT as u64);
    let mut out = String::new();
    reader.read_to_string(&mut out).ok()?;
    Some(out)
}

/// Scan file source bytes for import statements referencing known web
/// frameworks. Used to augment the project-level [`FrameworkContext`] with
/// per-file signals, so that single-file scans (no package.json / go.mod /
/// Gemfile nearby) still trigger framework-conditional rules.
///
/// Intentionally a coarse byte-level substring check against the quoted module
/// specifier (e.g. `'fastify'`, `"github.com/labstack/echo/v4"`,
/// `'sinatra'`). Only the first 8 KiB of the file are inspected, imports /
/// requires live at the top. Returns an empty list for languages without a
/// framework detection policy here.
pub fn detect_in_file_frameworks(bytes: &[u8], lang_slug: &str) -> Vec<DetectedFramework> {
    let head_len = bytes.len().min(8 * 1024);
    let head = match std::str::from_utf8(&bytes[..head_len]) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let matches_module = |name: &str| {
        // Quoted single or double, as appears in `from 'fastify'` /
        // `require("fastify")` / `import('fastify')` / `require 'sinatra'`.
        head.contains(&format!("'{name}'")) || head.contains(&format!("\"{name}\""))
    };
    let mut fws = Vec::new();
    match lang_slug {
        "javascript" | "typescript" | "js" | "ts" => {
            if matches_module("fastify") {
                fws.push(DetectedFramework::Fastify);
            }
            if matches_module("express") {
                fws.push(DetectedFramework::Express);
            }
            if matches_module("koa")
                || matches_module("@koa/router")
                || matches_module("koa-router")
            {
                fws.push(DetectedFramework::Koa);
            }
        }
        "go" => {
            // Go imports are quoted module paths. Match a distinctive prefix
            // so any major version (`/v3`, `/v4`, …) still detects.
            if head.contains("\"github.com/labstack/echo") {
                fws.push(DetectedFramework::Echo);
            }
            if head.contains("\"github.com/gin-gonic/gin\"") {
                fws.push(DetectedFramework::Gin);
            }
        }
        "ruby" | "rb" => {
            // Ruby requires: `require 'sinatra'` or `require 'sinatra/base'`.
            if matches_module("sinatra") || matches_module("sinatra/base") {
                fws.push(DetectedFramework::Sinatra);
            }
            // Rails apps don't always `require 'rails'` directly (they load
            // via config/boot.rb), but when they do, surface it.
            if matches_module("rails") || matches_module("rails/all") {
                fws.push(DetectedFramework::Rails);
            }
        }
        // Rust is intentionally not handled here — adding axum / actix_web
        // / rocket detection here would also flip framework-conditional
        // *label* rules on for files in workspaces whose root Cargo.toml
        // doesn't list the crate (e.g. meilisearch's root, which carries
        // actix-web only in subcrates), and the existing actix label set
        // marks `HttpResponse.json` as a `Cap::HTML_ESCAPE` sink ─ a
        // pattern that fires on every actix route that echoes a path
        // parameter back to the client (legitimate behavior, not XSS).
        //
        // The auth-analysis path uses `auth_analysis::extract`'s own
        // per-file Rust check (see `compute_web_framework_signal`) so the
        // signal is available without touching the label augmentation.
        _ => {}
    }
    fws
}

/// Coarse per-file signal: does the file's leading byte range mention
/// at least one Rust web-framework symbol path (`axum::`, `actix_web::`,
/// `rocket::`)?  Used by [`crate::auth_analysis::extract`] to gate the
/// `is_external_input_param_name` arm of `unit_has_user_input_evidence`
/// without affecting framework-conditional *label* rules.
///
/// Returns `false` for non-Rust source.
pub fn rust_file_imports_web_framework(bytes: &[u8]) -> bool {
    let head_len = bytes.len().min(8 * 1024);
    let head = match std::str::from_utf8(&bytes[..head_len]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    head.contains("axum::")
        || head.contains("axum_extra::")
        || head.contains("actix_web::")
        || head.contains("rocket::")
}

/// Detect frameworks from manifest files in the project root.
pub fn detect_frameworks(root: &Path) -> FrameworkContext {
    let mut fws = Vec::new();
    let mut inspected: std::collections::HashSet<&'static str> = std::collections::HashSet::new();

    // ── Node.js (package.json) ──
    if let Some(content) = read_bounded(&root.join("package.json")) {
        inspected.insert("node");
        // Crude substring search in the "dependencies" block area.
        // Good enough for detection, no JSON parsing overhead.
        if content.contains("\"express\"") {
            fws.push(DetectedFramework::Express);
        }
        if (content.contains("\"koa\"")
            || content.contains("\"@koa/router\"")
            || content.contains("\"koa-router\""))
            && !fws.contains(&DetectedFramework::Koa)
        {
            fws.push(DetectedFramework::Koa);
        }
        if content.contains("\"fastify\"") && !fws.contains(&DetectedFramework::Fastify) {
            fws.push(DetectedFramework::Fastify);
        }
        if content.contains("\"react\"") {
            fws.push(DetectedFramework::React);
        }
    }

    // ── Python ──
    for name in &["requirements.txt", "Pipfile", "pyproject.toml"] {
        if let Some(content) = read_bounded(&root.join(name)) {
            inspected.insert("python");
            let lower = content.to_ascii_lowercase();
            if lower.contains("flask") && !fws.contains(&DetectedFramework::Flask) {
                fws.push(DetectedFramework::Flask);
            }
            if lower.contains("django") && !fws.contains(&DetectedFramework::Django) {
                fws.push(DetectedFramework::Django);
            }
        }
    }

    // ── Java (Maven / Gradle) ──
    for name in &["pom.xml", "build.gradle", "build.gradle.kts"] {
        if let Some(content) = read_bounded(&root.join(name)) {
            inspected.insert("java");
            if (content.contains("spring-boot") || content.contains("spring-web"))
                && !fws.contains(&DetectedFramework::Spring)
            {
                fws.push(DetectedFramework::Spring);
            }
        }
    }

    // ── Go (go.mod) ──
    if let Some(content) = read_bounded(&root.join("go.mod")) {
        inspected.insert("go");
        if content.contains("gin-gonic/gin") {
            fws.push(DetectedFramework::Gin);
        }
        if content.contains("labstack/echo") {
            fws.push(DetectedFramework::Echo);
        }
    }

    // ── PHP (composer.json) ──
    if let Some(content) = read_bounded(&root.join("composer.json")) {
        inspected.insert("php");
        if content.contains("laravel/framework") {
            fws.push(DetectedFramework::Laravel);
        }
    }

    // ── Ruby (Gemfile) ──
    if let Some(content) = read_bounded(&root.join("Gemfile")) {
        inspected.insert("ruby");
        if content.contains("'rails'") || content.contains("\"rails\"") {
            fws.push(DetectedFramework::Rails);
        }
        if content.contains("'sinatra'") || content.contains("\"sinatra\"") {
            fws.push(DetectedFramework::Sinatra);
        }
    }

    // ── Rust (Cargo.toml) ──
    if let Some(content) = read_bounded(&root.join("Cargo.toml")) {
        inspected.insert("rust");
        if content.contains("actix-web") {
            fws.push(DetectedFramework::ActixWeb);
        }
        if content.contains("rocket") && !fws.contains(&DetectedFramework::Rocket) {
            fws.push(DetectedFramework::Rocket);
        }
        if content.contains("axum") {
            fws.push(DetectedFramework::Axum);
        }
    }

    FrameworkContext {
        frameworks: fws,
        inspected_langs: inspected,
    }
}

#[test]
fn sanitize_project_name_is_idempotent_and_lossless_enough() {
    let samples = [
        ("My Project", "my_project"),
        ("Hello-World", "hello-world"),
        ("mixed_case", "mixed_case"),
        ("tabs\tspaces\n", "tabs_spaces"),
        ("   multiple   ", "multiple"),
        ("weird@$*chars", "weird_chars"),
    ];

    for (input, expected) in samples {
        assert_eq!(sanitize_project_name(input), expected, "input: {input}");
        assert_eq!(sanitize_project_name(expected), expected);
    }
}

#[test]
fn get_project_info_uses_sanitized_name_in_sqlite_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let project_dir = root.join("Example Project");
    std::fs::create_dir(&project_dir).unwrap();

    let (project_name, db_path) =
        get_project_info(&project_dir, root).expect("should detect project");

    assert_eq!(project_name, "Example Project");
    assert_eq!(db_path, root.join("example_project.sqlite"));
}

#[test]
fn detect_frameworks_from_package_json() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("package.json"),
        r#"{"dependencies": {"express": "^4.18.0", "koa": "^2.15.0", "fastify": "^4.0.0", "react": "^18.0.0"}}"#,
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Express));
    assert!(ctx.has(DetectedFramework::Koa));
    assert!(ctx.has(DetectedFramework::Fastify));
    assert!(ctx.has(DetectedFramework::React));
    assert!(!ctx.has(DetectedFramework::Flask));
}

#[test]
fn detect_frameworks_empty_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = detect_frameworks(tmp.path());
    assert!(ctx.frameworks.is_empty());
}

#[test]
fn detect_frameworks_gemfile_rails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("Gemfile"), "gem 'rails', '~> 7.0'\ngem 'puma'\n").unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Rails));
    assert!(!ctx.has(DetectedFramework::Sinatra));
}

#[test]
fn detect_frameworks_gemfile_sinatra() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("Gemfile"), "gem 'sinatra'\ngem 'puma'\n").unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Sinatra));
    assert!(!ctx.has(DetectedFramework::Rails));
}

#[test]
fn detect_frameworks_python_flask_from_requirements() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("requirements.txt"),
        "Flask==2.3.0\nrequests>=2.28\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Flask));
    assert!(!ctx.has(DetectedFramework::Django));
}

#[test]
fn detect_frameworks_python_django_from_pyproject() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"myapp\"\ndependencies = [\"django>=4.0\"]\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Django));
    assert!(!ctx.has(DetectedFramework::Flask));
}

#[test]
fn detect_frameworks_go_mod_gin() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("go.mod"),
        "module example.com/app\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Gin));
    assert!(!ctx.has(DetectedFramework::Echo));
}

#[test]
fn detect_frameworks_go_mod_echo() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("go.mod"),
        "module example.com/app\n\nrequire (\n\tgithub.com/labstack/echo/v4 v4.11.0\n)\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Echo));
    assert!(!ctx.has(DetectedFramework::Gin));
}

#[test]
fn detect_frameworks_java_spring_from_pom_xml() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("pom.xml"),
        "<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.springframework.boot</groupId>\n      <artifactId>spring-boot-starter-web</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Spring));
}

#[test]
fn detect_frameworks_java_spring_from_build_gradle() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("build.gradle"),
        "plugins {\n    id 'org.springframework.boot' version '3.1.0'\n}\ndependencies {\n    implementation 'org.springframework.boot:spring-web:3.1.0'\n}\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Spring));
}

#[test]
fn detect_frameworks_php_laravel_from_composer_json() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("composer.json"),
        r#"{"require": {"laravel/framework": "^10.0", "php": "^8.1"}}"#,
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Laravel));
}

#[test]
fn detect_frameworks_rust_axum_from_cargo_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("Cargo.toml"),
        "[dependencies]\naxum = \"0.7\"\ntokio = { version = \"1\", features = [\"full\"] }\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Axum));
    assert!(!ctx.has(DetectedFramework::ActixWeb));
    assert!(!ctx.has(DetectedFramework::Rocket));
}

#[test]
fn detect_frameworks_rust_actix_web_from_cargo_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("Cargo.toml"),
        "[dependencies]\nactix-web = \"4\"\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::ActixWeb));
}

#[test]
fn detect_frameworks_multiple_in_same_project() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // A project using both Express and React
    fs::write(
        root.join("package.json"),
        r#"{"dependencies": {"express": "^4", "@koa/router": "^12", "fastify": "^4", "react": "^18"}}"#,
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Express));
    assert!(ctx.has(DetectedFramework::Koa));
    assert!(ctx.has(DetectedFramework::Fastify));
    assert!(ctx.has(DetectedFramework::React));
    assert_eq!(ctx.frameworks.len(), 4);
}

#[test]
fn sanitize_project_name_numeric_and_special() {
    assert_eq!(sanitize_project_name("project123"), "project123");
    assert_eq!(sanitize_project_name("123"), "123");
    assert_eq!(sanitize_project_name("a.b.c"), "a_b_c");
    // hyphens are preserved as-is (only underscores are collapsed)
    assert_eq!(sanitize_project_name("a--b"), "a--b");
    // Leading/trailing underscores from replacements get collapsed
    assert_eq!(sanitize_project_name("__init__"), "init");
}

#[test]
fn get_project_info_returns_error_for_root_path() {
    let tmp = tempfile::tempdir().unwrap();
    // A path that ends with "/" (root) has no file_name
    let result = get_project_info(std::path::Path::new("/"), tmp.path());
    assert!(result.is_err());
}

#[test]
fn framework_context_has_is_false_for_absent_framework() {
    let ctx = FrameworkContext::default();
    assert!(!ctx.has(DetectedFramework::Express));
    assert!(!ctx.has(DetectedFramework::Flask));
    assert!(!ctx.has(DetectedFramework::Spring));
}

#[test]
fn lang_has_web_framework_three_valued_for_rust() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Cargo.toml present, no axum / actix-web / rocket → Some(false).
    fs::write(root.join("Cargo.toml"), "[dependencies]\nserde = \"1\"\n").unwrap();
    let ctx = detect_frameworks(root);
    assert_eq!(ctx.lang_has_web_framework("rust"), Some(false));
    assert_eq!(ctx.lang_has_web_framework("python"), None);

    // Cargo.toml present and names axum → Some(true).
    fs::write(root.join("Cargo.toml"), "[dependencies]\naxum = \"0.7\"\n").unwrap();
    let ctx = detect_frameworks(root);
    assert_eq!(ctx.lang_has_web_framework("rust"), Some(true));
}

#[test]
fn lang_has_web_framework_none_when_manifest_absent() {
    // No Cargo.toml at root → Rust manifest not inspected → None.
    let tmp = tempfile::tempdir().unwrap();
    let ctx = detect_frameworks(tmp.path());
    assert_eq!(ctx.lang_has_web_framework("rust"), None);
    assert_eq!(ctx.lang_has_web_framework("python"), None);
    assert_eq!(ctx.lang_has_web_framework("ruby"), None);
}

#[test]
fn rust_file_imports_web_framework_recognises_axum_actix_rocket() {
    assert!(rust_file_imports_web_framework(
        b"use axum::Router;\nfn main() {}\n"
    ));
    assert!(rust_file_imports_web_framework(
        b"use actix_web::web;\nfn main() {}\n"
    ));
    assert!(rust_file_imports_web_framework(
        b"use rocket::get;\nfn main() {}\n"
    ));
    assert!(rust_file_imports_web_framework(
        b"use axum_extra::routing::RouterExt;\n"
    ));
    // Not a web framework import → false.
    assert!(!rust_file_imports_web_framework(
        b"use std::path::Path;\nuse serde::Deserialize;\nfn main() {}\n"
    ));
    // Bare crate name in a comment doesn't satisfy the `<crate>::`
    // path prefix — substring is conservative on purpose.
    assert!(!rust_file_imports_web_framework(
        b"// migrating away from axum\nfn main() {}\n"
    ));
}

#[test]
fn detect_in_file_frameworks_go_echo() {
    let src = b"package main\nimport (\n\t\"net/http\"\n\t\"github.com/labstack/echo/v4\"\n)\nfunc x() {}\n";
    let fws = detect_in_file_frameworks(src, "go");
    assert!(fws.contains(&DetectedFramework::Echo));
    assert!(!fws.contains(&DetectedFramework::Gin));
}

#[test]
fn detect_in_file_frameworks_go_gin() {
    let src = b"package main\nimport \"github.com/gin-gonic/gin\"\n";
    let fws = detect_in_file_frameworks(src, "go");
    assert!(fws.contains(&DetectedFramework::Gin));
    assert!(!fws.contains(&DetectedFramework::Echo));
}

#[test]
fn detect_in_file_frameworks_ruby_sinatra() {
    let src = b"require 'sinatra'\nget '/' do\n  'hi'\nend\n";
    let fws = detect_in_file_frameworks(src, "ruby");
    assert!(fws.contains(&DetectedFramework::Sinatra));
    assert!(!fws.contains(&DetectedFramework::Rails));
}

#[test]
fn detect_in_file_frameworks_ruby_sinatra_base() {
    let src = b"require \"sinatra/base\"\nclass App < Sinatra::Base; end\n";
    let fws = detect_in_file_frameworks(src, "ruby");
    assert!(fws.contains(&DetectedFramework::Sinatra));
}

#[test]
fn detect_in_file_frameworks_plain_go_no_framework() {
    let src = b"package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }\n";
    let fws = detect_in_file_frameworks(src, "go");
    assert!(fws.is_empty());
}

#[test]
fn detect_in_file_frameworks_plain_ruby_no_framework() {
    let src = b"require 'json'\nputs JSON.parse('{}')\n";
    let fws = detect_in_file_frameworks(src, "ruby");
    assert!(fws.is_empty());
}
