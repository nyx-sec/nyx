//! Shared helpers used by the per-(language, framework) probes.
//!
//! Each probe extracts an [`EntryPoint`] node from a parsed source file
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
        assert!(leaf_matches("flask_login.login_required", &["login_required"]));
        assert!(leaf_matches("Auth::JwtRequired", &["JwtRequired"]));
        assert!(!leaf_matches("OtherDecorator", &["login_required"]));
    }
}
