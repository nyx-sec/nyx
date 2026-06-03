//! Shared helpers used by the per-(language, framework) probes.
//!
//! Each probe extracts an [`EntryPoint`](crate::surface::EntryPoint) node from a parsed source file
//! by walking the framework's route declaration shape.  These helpers
//! cover the bookkeeping common to every probe: building a stable
//! [`SourceLocation`] from a tree-sitter node, decoding common string
//! literal shapes, and identifier-based auth marker lookups.

use crate::surface::{SourceLocation, relative_path_string};
use std::path::Path;
use tree_sitter::Node;

/// Build a [`SourceLocation`] for the start of `node`, relative to
/// `scan_root` when supplied.
pub fn loc_for(node: Node<'_>, file_rel: &str) -> SourceLocation {
    let pos = node.start_position();
    SourceLocation::new(file_rel, (pos.row + 1) as u32, (pos.column + 1) as u32)
}

/// Project-relative POSIX file string used as the [`SourceLocation`]
/// `file` field across every node a probe emits.
pub fn rel_file(path: &Path, scan_root: Option<&Path>) -> String {
    relative_path_string(path, scan_root)
}

/// Strip Python / JS / Ruby / PHP string-literal prefixes (`b"…"`,
/// `r"…"`, `f"…"`, leading `'`/`"`) and return the literal content.
/// Used by every probe that lifts a route path out of a string node.
pub fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut s = trimmed;
    // Python prefixes
    while let Some(rest) = s.strip_prefix(['b', 'r', 'B', 'R', 'f', 'F']) {
        if rest.starts_with('\'') || rest.starts_with('"') {
            s = rest;
        } else {
            break;
        }
    }
    s.trim_start_matches(['\'', '"', '`'])
        .trim_end_matches(['\'', '"', '`'])
        .to_string()
}

/// Read the literal text of a tree-sitter `string` node and return its
/// unquoted content; `None` when the slice is not valid UTF-8.
pub fn string_node_value(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    Some(unquote(node.utf8_text(bytes).ok()?))
}

/// Return `true` when the leaf segment of `text` (split on `.` or `::`)
/// matches one of the entries in `markers`, case-insensitive on the
/// underscored form.  Used by every probe's auth-decorator allowlist.
pub fn leaf_matches(text: &str, markers: &[&str]) -> bool {
    let leaf = text.rsplit(['.', ':']).next().unwrap_or(text).trim();
    markers.iter().any(|m| leaf.eq_ignore_ascii_case(m))
}

/// Walk every descendant of `root` whose kind matches `target_kind`,
/// invoking `visit` on each match.  Bounded by recursion on tree-sitter
/// node count.
pub fn for_each_node<'tree, F>(root: Node<'tree>, target_kind: &str, mut visit: F)
where
    F: FnMut(Node<'tree>),
{
    fn recurse<'tree, F>(node: Node<'tree>, kind: &str, visit: &mut F)
    where
        F: FnMut(Node<'tree>),
    {
        if node.kind() == kind {
            visit(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            recurse(child, kind, visit);
        }
    }
    recurse(root, target_kind, &mut visit);
}

/// Find the first child of `parent` whose kind matches `kind`, with a
/// `child_by_field_name(kind)` fast path.  Used by Java probes where
/// `class_declaration` / `method_declaration` modifiers / body live as
/// unnamed children rather than fielded children in tree-sitter-java.
pub fn child_or_named<'tree>(parent: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    if let Some(n) = parent.child_by_field_name(kind) {
        return Some(n);
    }
    let mut cursor = parent.walk();
    parent.children(&mut cursor).find(|c| c.kind() == kind)
}

/// Return `true` when `bytes` contains a top-level Python `import` /
/// `from … import …` statement whose leading package segment starts
/// with one of `modules` (case-insensitive prefix match).  This means
/// `["flask"]` matches `flask`, `flask_login`, and `flask_jwt_extended`
/// — the canonical Flask framework family — but does not match
/// `os.flask_helper` or a comment that mentions flask.
pub fn python_imports_any(bytes: &[u8], modules: &[&str]) -> bool {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in text.lines() {
        let line = line.trim_start();
        let pkg = if let Some(rest) = line.strip_prefix("from ") {
            rest.split_whitespace().next().unwrap_or("")
        } else if let Some(rest) = line.strip_prefix("import ") {
            rest.split([',', ' ', ';']).next().unwrap_or("").trim()
        } else {
            continue;
        };
        if pkg.is_empty() {
            continue;
        }
        let head = pkg.split('.').next().unwrap_or(pkg);
        if matches_prefix_ci(head, modules) {
            return true;
        }
    }
    false
}

fn matches_prefix_ci(head: &str, prefixes: &[&str]) -> bool {
    let head_lc = head.to_ascii_lowercase();
    prefixes
        .iter()
        .any(|p| head_lc.starts_with(&p.to_ascii_lowercase()))
}

/// Return `true` when `bytes` contains a top-level Rust `use` (or
/// `extern crate`) statement whose leading path segment matches one of
/// `crates` (case-insensitive). Optional `pub` / `pub(crate)` /
/// `pub(super)` visibility prefixes are stripped before the `use`
/// keyword check.
pub fn rust_uses_any(bytes: &[u8], crates: &[&str]) -> bool {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in text.lines() {
        let mut line = line.trim_start();
        if let Some(rest) = line.strip_prefix("pub") {
            let rest = rest.trim_start();
            line = if let Some(r) = rest.strip_prefix("(crate)") {
                r.trim_start()
            } else if let Some(r) = rest.strip_prefix("(super)") {
                r.trim_start()
            } else if let Some(r) = rest.strip_prefix("(self)") {
                r.trim_start()
            } else {
                rest
            };
        }
        let rest = if let Some(r) = line.strip_prefix("use ") {
            r
        } else if let Some(r) = line.strip_prefix("extern crate ") {
            r
        } else {
            continue;
        };
        let head = rest
            .split(['{', ';', ' ', ':', '/'])
            .next()
            .unwrap_or("")
            .trim();
        if head.is_empty() {
            continue;
        }
        if matches_prefix_ci(head, crates) {
            return true;
        }
    }
    false
}

/// Return `true` when `bytes` contains a top-level Java `import`
/// statement (including `import static`) whose package path begins
/// with one of `prefixes`.  Comment-only mentions do *not* match.
pub fn java_imports_any(bytes: &[u8], prefixes: &[&str]) -> bool {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in text.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("import ") else {
            continue;
        };
        let path = rest
            .strip_prefix("static ")
            .unwrap_or(rest)
            .trim()
            .trim_end_matches(';')
            .trim();
        if prefixes.iter().any(|p| path.starts_with(p)) {
            return true;
        }
    }
    false
}

/// Walk every descendant of `root`, invoking `visit` once per node.
/// Useful when a probe needs to look at multiple node kinds in a single
/// pass (e.g. annotations + method declarations on the same walk).
pub fn for_each_node_any<'tree, F>(root: Node<'tree>, mut visit: F)
where
    F: FnMut(Node<'tree>),
{
    fn recurse<'tree, F>(node: Node<'tree>, visit: &mut F)
    where
        F: FnMut(Node<'tree>),
    {
        visit(node);
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            recurse(child, visit);
        }
    }
    recurse(root, &mut visit);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquote_strips_python_prefixes() {
        assert_eq!(unquote("b\"path\""), "path");
        assert_eq!(unquote("r'/api'"), "/api");
        assert_eq!(unquote("f\"/users/{id}\""), "/users/{id}");
        assert_eq!(unquote("\"plain\""), "plain");
    }

    #[test]
    fn leaf_matches_handles_dot_and_colon_paths() {
        assert!(leaf_matches(
            "flask_login.login_required",
            &["login_required"]
        ));
        assert!(leaf_matches("Auth::JwtRequired", &["JwtRequired"]));
        assert!(!leaf_matches("OtherDecorator", &["login_required"]));
    }

    #[test]
    fn python_imports_any_matches_actual_imports() {
        assert!(python_imports_any(b"from flask import Flask\n", &["flask"]));
        assert!(python_imports_any(b"import flask\n", &["flask"]));
        assert!(python_imports_any(
            b"from flask.app import Flask\n",
            &["flask"]
        ));
        assert!(python_imports_any(b"import django.urls\n", &["django"]));
        // Comment-only mention must not match.
        assert!(!python_imports_any(b"# flask is great\n", &["flask"]));
        // String-only mention must not match.
        assert!(!python_imports_any(b"x = 'flask'\n", &["flask"]));
        // Wrong module.
        assert!(!python_imports_any(b"import os\n", &["flask"]));
    }

    #[test]
    fn rust_uses_any_matches_use_statements() {
        assert!(rust_uses_any(b"use actix_web::web;\n", &["actix_web"]));
        assert!(rust_uses_any(b"use actix_web;\n", &["actix_web"]));
        assert!(rust_uses_any(b"pub use axum::Router;\n", &["axum"]));
        assert!(rust_uses_any(
            b"pub(crate) use axum::extract::Path;\n",
            &["axum"]
        ));
        assert!(rust_uses_any(b"extern crate axum;\n", &["axum"]));
        // Comment-only mention must not match.
        assert!(!rust_uses_any(b"// use actix_web::web;\n", &["actix_web"]));
        // Wrong crate.
        assert!(!rust_uses_any(b"use serde::Deserialize;\n", &["actix_web"]));
    }

    #[test]
    fn java_imports_any_matches_package_prefix() {
        assert!(java_imports_any(
            b"import io.quarkus.runtime.Quarkus;\n",
            &["io.quarkus"]
        ));
        assert!(java_imports_any(
            b"import jakarta.ws.rs.GET;\n",
            &["jakarta.ws.rs"]
        ));
        assert!(java_imports_any(
            b"import static io.quarkus.runtime.Quarkus.run;\n",
            &["io.quarkus"]
        ));
        // Comment-only mention must not match.
        assert!(!java_imports_any(
            b"// import io.quarkus.runtime.Quarkus;\n",
            &["io.quarkus"]
        ));
        // Wrong prefix.
        assert!(!java_imports_any(
            b"import org.springframework.web.bind.annotation.GetMapping;\n",
            &["io.quarkus"]
        ));
    }
}
