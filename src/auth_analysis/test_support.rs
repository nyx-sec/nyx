//! Helpers for unit tests that run the auth pass over an inline snippet.

use super::run_auth_analysis;
use crate::utils::config::Config;
use std::path::Path;
use tree_sitter::{Language, Parser};

fn language(slug: &str) -> Language {
    match slug {
        "go" => Language::from(tree_sitter_go::LANGUAGE),
        "javascript" => Language::from(tree_sitter_javascript::LANGUAGE),
        "typescript" => Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        "tsx" => Language::from(tree_sitter_typescript::LANGUAGE_TSX),
        "python" => Language::from(tree_sitter_python::LANGUAGE),
        "ruby" => Language::from(tree_sitter_ruby::LANGUAGE),
        "java" => Language::from(tree_sitter_java::LANGUAGE),
        "rust" => Language::from(tree_sitter_rust::LANGUAGE),
        other => panic!("no grammar for {other}"),
    }
}

/// Run the auth pass on `src` as file `path` and return `(rule suffix, line)`
/// pairs, e.g. `("missing_ownership_check", 12)`.  `slug` is the language
/// slug (`"go"`, `"javascript"`, `"typescript"`); `"tsx"` parses with the TSX
/// grammar and runs the TypeScript rules.
pub(crate) fn findings_at(slug: &str, path: &str, src: &str) -> Vec<(String, usize)> {
    let mut parser = Parser::new();
    parser.set_language(&language(slug)).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let rules_slug = if slug == "tsx" { "typescript" } else { slug };
    let diags = run_auth_analysis(
        &tree,
        src.as_bytes(),
        rules_slug,
        Path::new(path),
        &Config::default(),
        None,
        None,
        None,
    );
    let mut out: Vec<(String, usize)> = diags
        .into_iter()
        .map(|d| {
            let id = d.id.rsplit('.').next().unwrap_or(&d.id).to_string();
            (id, d.line)
        })
        .collect();
    out.sort();
    out
}

/// Lines of `missing_ownership_check` findings for `src`.
pub(crate) fn ownership_lines(slug: &str, src: &str) -> Vec<usize> {
    let path = match slug {
        "go" => "h.go",
        "javascript" => "h.js",
        "typescript" => "h.ts",
        "tsx" => "h.tsx",
        "python" => "h.py",
        "ruby" => "h.rb",
        "java" => "H.java",
        _ => "h.rs",
    };
    findings_at(slug, path, src)
        .into_iter()
        .filter(|(rule, _)| rule == "missing_ownership_check")
        .map(|(_, line)| line)
        .collect()
}
