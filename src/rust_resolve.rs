//! Rust-specific module-path derivation and `use` declaration resolution.
//!
//! This module is entirely Rust-flavored helpers for the cross-file call graph.
//! Other languages do not need it. The two pieces are:
//!
//! * [`derive_module_path`], given a Rust source file path and an optional
//!   crate root, produce its canonical crate-relative module path
//!   (`src/foo/bar.rs` → `"foo::bar"`, `src/lib.rs` → `""`).
//!
//! * [`parse_rust_use_map`], walk the top-level `use_declaration` nodes of a
//!   parsed tree and produce a [`RustUseMap`] mapping local aliases to fully
//!   qualified paths plus a list of wildcard imports.
//!
//! The output is consumed by call-graph resolution in `callgraph.rs` to
//! disambiguate same-name functions defined in different Rust modules.
//!
//! ## Forms recognised by `parse_rust_use_map`
//!
//! * `use crate::auth::token::validate;`           → `{"validate" → "crate::auth::token::validate"}`
//! * `use crate::auth::token::{validate, verify};` → both mapped
//! * `use crate::auth::token::validate as ok;`     → `{"ok" → "crate::auth::token::validate"}`
//! * `use crate::auth::token::*;`                  → recorded in `wildcards`
//! * Nested groups like `use a::{b::c, d::e};`     → each leaf mapped under its own prefix
//!
//! ## Deliberately not supported (yet)
//!
//! * Macro-expanded `use` statements
//! * `pub use` re-exports across modules
//! * `extern crate alias_name;`
//! * Self-prefixed imports (`use self::sub::foo;`), treated as `self::sub::foo`
//!
//! These are flagged in the final pass-1 telemetry but do not block resolution.

use std::collections::BTreeMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

/// Per-file Rust import surface produced once during pass 1.
///
/// `aliases` maps local identifiers to their fully qualified paths
/// (`"validate"` → `"crate::auth::token::validate"`). `wildcards` records the
/// fully qualified prefixes of every `use ::*` import in declaration order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RustUseMap {
    pub aliases: BTreeMap<String, String>,
    pub wildcards: Vec<String>,
}

impl RustUseMap {
    pub fn is_empty(&self) -> bool {
        self.aliases.is_empty() && self.wildcards.is_empty()
    }
}

//  Module path derivation

/// Find the crate root by walking up from `file_path` looking for `Cargo.toml`.
///
/// Returns the directory containing the `Cargo.toml`, or `None` if no parent
/// has one. When `scan_root` is provided we stop at the scan root rather than
/// climbing past it, so a project nested inside the workspace does not pick
/// up an outer crate's `Cargo.toml`.
fn find_crate_root(file_path: &Path, scan_root: Option<&Path>) -> Option<std::path::PathBuf> {
    let mut cur = file_path.parent()?;
    loop {
        if cur.join("Cargo.toml").is_file() {
            return Some(cur.to_path_buf());
        }
        if let Some(root) = scan_root
            && cur == root
        {
            return None;
        }
        cur = cur.parent()?;
    }
}

/// Derive the crate-relative module path for a Rust source file.
///
/// Standard Rust layout:
/// * `src/lib.rs` / `src/main.rs` / `src/bin/foo.rs` → `""` (top-level)
/// * `src/foo.rs`           → `"foo"`
/// * `src/foo/mod.rs`       → `"foo"`
/// * `src/foo/bar.rs`       → `"foo::bar"`
///
/// Returns `None` when the file is not under a recognised `src/` tree of any
/// crate root, or when the file extension is not `.rs`.
///
/// `scan_root` is the project root used everywhere else for namespace
/// normalization. When supplied it bounds the search for `Cargo.toml`.
pub fn derive_module_path(file_path: &Path, scan_root: Option<&Path>) -> Option<String> {
    if file_path.extension().and_then(|s| s.to_str()) != Some("rs") {
        return None;
    }

    let crate_root =
        find_crate_root(file_path, scan_root).or_else(|| scan_root.map(|p| p.to_path_buf()))?;

    let rel = file_path.strip_prefix(&crate_root).ok()?;
    let mut segments: Vec<&str> = rel.iter().filter_map(|s| s.to_str()).collect();

    // Strip a leading `src` directory if present. Files outside `src/` (e.g.
    // tests, examples, build.rs) get a `None` here, we do not have a stable
    // module path for them and resolution should fall back to file-based.
    match segments.first().copied() {
        Some("src") => {
            segments.remove(0);
        }
        _ => return None,
    }

    if segments.is_empty() {
        return None;
    }

    let last = segments.pop()?;
    let leaf = match last {
        "lib.rs" | "main.rs" | "mod.rs" => None,
        other => other.strip_suffix(".rs").map(|s| s.to_string()),
    };

    // `src/bin/foo.rs` is conventionally a separate binary; treat it as
    // top-level rather than module `bin::foo`.
    if matches!(segments.first().copied(), Some("bin")) {
        return Some(String::new());
    }

    let mut path = segments.join("::");
    if let Some(name) = leaf {
        if !path.is_empty() {
            path.push_str("::");
        }
        path.push_str(&name);
    }
    Some(path)
}

//  Use-declaration parsing

/// Parse every top-level `use_declaration` of a Rust source tree into a
/// [`RustUseMap`].
///
/// The walk only inspects direct children of the source root. Nested `use`s
/// inside functions or impls are deliberately skipped, their scope is local
/// and does not influence the cross-file call graph at the module level.
pub fn parse_rust_use_map(src: &[u8], tree: &Tree) -> RustUseMap {
    let mut map = RustUseMap::default();
    let root = tree.root_node();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "use_declaration" {
            continue;
        }
        // The argument field on use_declaration holds the use_clause body.
        let arg = match child.child_by_field_name("argument") {
            Some(n) => n,
            None => {
                // tree-sitter-rust 0.24 sometimes exposes the body as a named
                // child instead of a field, fall back to the first named child.
                match child.named_child(0) {
                    Some(n) => n,
                    None => continue,
                }
            }
        };
        collect_use_paths(arg, src, &[], &mut map);
    }
    map
}

/// Recursively flatten a use clause into `(local_alias, fully_qualified)`
/// entries, accumulating segments along the way.
///
/// `prefix` carries the parent path segments already consumed (so a nested
/// `b::c` inside `a::{b::c}` is flattened to `a::b::c`).
fn collect_use_paths(node: Node<'_>, src: &[u8], prefix: &[String], map: &mut RustUseMap) {
    match node.kind() {
        // `crate::auth::token::validate`, terminal scoped path, leaf is the alias.
        "scoped_identifier" => {
            let segments = scoped_segments(node, src);
            if segments.is_empty() {
                return;
            }
            let full = join_segments(prefix, &segments);
            let leaf = segments.last().cloned().unwrap_or_default();
            if !leaf.is_empty() {
                map.aliases.insert(leaf, full);
            }
        }
        // `validate`, bare identifier (e.g. `use foo::validate`).
        "identifier" => {
            let name = node_text(node, src).to_string();
            if name.is_empty() {
                return;
            }
            let mut segs = prefix.to_vec();
            segs.push(name.clone());
            map.aliases.insert(name, segs.join("::"));
        }
        // `crate::auth::token::{validate, verify}`, left side is the prefix,
        // right side is a use_list of further use clauses.
        "scoped_use_list" => {
            // path field carries the prefix; the list field carries the body.
            let path_node = node
                .child_by_field_name("path")
                .or_else(|| node.named_child(0));
            let mut new_prefix: Vec<String> = prefix.to_vec();
            if let Some(p) = path_node {
                let segs = scoped_segments_or_ident(p, src);
                new_prefix.extend(segs);
            }
            let list_node = node.child_by_field_name("list").or_else(|| {
                let mut found = None;
                for i in 0..node.named_child_count() as u32 {
                    if let Some(n) = node.named_child(i)
                        && n.kind() == "use_list"
                    {
                        found = Some(n);
                        break;
                    }
                }
                found
            });
            if let Some(list) = list_node {
                let mut cursor = list.walk();
                for c in list.named_children(&mut cursor) {
                    collect_use_paths(c, src, &new_prefix, map);
                }
            }
        }
        // Bare `use_list`, e.g. `use {foo, bar};` (rare at top level).
        "use_list" => {
            let mut cursor = node.walk();
            for c in node.named_children(&mut cursor) {
                collect_use_paths(c, src, prefix, map);
            }
        }
        // `crate::auth::token::validate as ok`, alias the leaf identifier.
        "use_as_clause" => {
            let path_node = node
                .child_by_field_name("path")
                .or_else(|| node.named_child(0));
            let alias_node = node
                .child_by_field_name("alias")
                .or_else(|| node.named_child(1));
            let alias = alias_node.map(|n| node_text(n, src).to_string());
            if let (Some(p), Some(alias_name)) = (path_node, alias)
                && !alias_name.is_empty()
            {
                let segs = scoped_segments_or_ident(p, src);
                let full = join_segments(prefix, &segs);
                map.aliases.insert(alias_name, full);
            }
        }
        // `crate::auth::token::*`, record the prefix as a wildcard import.
        "use_wildcard" => {
            // The wildcard's child is the path being wildcarded.
            let path_node = node.named_child(0);
            if let Some(p) = path_node {
                let segs = scoped_segments_or_ident(p, src);
                let full = join_segments(prefix, &segs);
                if !full.is_empty() {
                    map.wildcards.push(full);
                }
            }
        }
        _ => {
            // Unknown/unsupported form (e.g. macro_invocation in use position,
            // attribute-prefixed clauses), flag in pass-1 telemetry, skip
            // here to keep the walk total.
        }
    }
}

/// Pull dotted identifier segments out of a `scoped_identifier` node.
fn scoped_segments(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut segs = Vec::new();
    if let Some(path) = node.child_by_field_name("path") {
        let inner = scoped_segments_or_ident(path, src);
        segs.extend(inner);
    }
    if let Some(name) = node.child_by_field_name("name") {
        let n = node_text(name, src).to_string();
        if !n.is_empty() {
            segs.push(n);
        }
    }
    if segs.is_empty() {
        // Fallback: split by `::` from the raw text.
        let raw = node_text(node, src);
        for part in raw.split("::") {
            if !part.is_empty() {
                segs.push(part.to_string());
            }
        }
    }
    segs
}

/// Helper that handles both `scoped_identifier` and bare `identifier` nodes.
fn scoped_segments_or_ident(node: Node<'_>, src: &[u8]) -> Vec<String> {
    match node.kind() {
        "scoped_identifier" => scoped_segments(node, src),
        "identifier" | "crate" | "self" | "super" => {
            vec![node_text(node, src).to_string()]
        }
        _ => {
            let raw = node_text(node, src);
            raw.split("::")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        }
    }
}

fn node_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    std::str::from_utf8(&src[node.byte_range()]).unwrap_or("")
}

fn join_segments(prefix: &[String], suffix: &[String]) -> String {
    let mut all: Vec<&str> = prefix.iter().map(String::as_str).collect();
    all.extend(suffix.iter().map(String::as_str));
    all.join("::")
}

//  Resolution helpers

/// Resolve a Rust callee `(qualifier, name)` against a use map.
///
/// Resolution order:
/// 1. If the call is qualified (`Some(qualifier)`):
///    a. Try the full qualifier as an exact alias (e.g. `use foo::bar::baz; baz::quux();`
///    lifts `baz` → `foo::bar::baz`).
///    b. Otherwise try the qualifier's first segment as an alias and graft
///    the remaining segments + `name` on top.
/// 2. If the call is unqualified, try `name` directly in the alias map.
/// 3. Otherwise return `None` and let the caller fall back to wildcards or
///    bare-name lookup.
///
/// Returns the fully qualified callee path, e.g. `"crate::auth::token::validate"`.
pub fn resolve_with_use_map(
    use_map: &RustUseMap,
    qualifier: Option<&str>,
    name: &str,
) -> Option<String> {
    if let Some(q) = qualifier.filter(|q| !q.is_empty()) {
        if let Some(full) = use_map.aliases.get(q) {
            return Some(format!("{full}::{name}"));
        }
        let mut segments = q.split("::");
        if let Some(first) = segments.next()
            && let Some(full) = use_map.aliases.get(first)
        {
            let rest: Vec<&str> = segments.collect();
            let mut joined = full.clone();
            for r in rest {
                joined.push_str("::");
                joined.push_str(r);
            }
            joined.push_str("::");
            joined.push_str(name);
            return Some(joined);
        }
        return None;
    }
    use_map.aliases.get(name).cloned()
}

/// Given a fully qualified callee path (e.g. `"crate::auth::token::validate"`),
/// strip the leading `crate::` segment so it lines up with module paths
/// computed by [`derive_module_path`] (which are crate-relative and do not
/// include `crate::`).
///
/// Returns the (module_path, name) pair, e.g. `("auth::token", "validate")`.
/// If the input has no `::` separators the module path is empty.
pub fn split_module_and_name(qualified: &str) -> (String, String) {
    let trimmed = qualified.strip_prefix("crate::").unwrap_or(qualified);
    if let Some(pos) = trimmed.rfind("::") {
        (trimmed[..pos].to_string(), trimmed[pos + 2..].to_string())
    } else {
        (String::new(), trimmed.to_string())
    }
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tree_sitter::Parser;

    fn parse(src: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    // ── derive_module_path ─────────────────────────────────────────────

    #[test]
    fn module_path_lib_root() {
        let root = PathBuf::from("/proj");
        std::fs::create_dir_all("/tmp/nyx_mp_test_lib").ok();
        std::fs::write("/tmp/nyx_mp_test_lib/Cargo.toml", "").ok();
        std::fs::create_dir_all("/tmp/nyx_mp_test_lib/src").ok();
        std::fs::write("/tmp/nyx_mp_test_lib/src/lib.rs", "").ok();
        let p = PathBuf::from("/tmp/nyx_mp_test_lib/src/lib.rs");
        assert_eq!(derive_module_path(&p, Some(&root)), Some(String::new()));
    }

    #[test]
    fn module_path_top_module() {
        let dir = PathBuf::from("/tmp/nyx_mp_test_top");
        std::fs::create_dir_all(dir.join("src")).ok();
        std::fs::write(dir.join("Cargo.toml"), "").ok();
        std::fs::write(dir.join("src/foo.rs"), "").ok();
        let p = dir.join("src/foo.rs");
        assert_eq!(derive_module_path(&p, None), Some("foo".to_string()));
    }

    #[test]
    fn module_path_mod_rs() {
        let dir = PathBuf::from("/tmp/nyx_mp_test_modrs");
        std::fs::create_dir_all(dir.join("src/foo")).ok();
        std::fs::write(dir.join("Cargo.toml"), "").ok();
        std::fs::write(dir.join("src/foo/mod.rs"), "").ok();
        let p = dir.join("src/foo/mod.rs");
        assert_eq!(derive_module_path(&p, None), Some("foo".to_string()));
    }

    #[test]
    fn module_path_nested() {
        let dir = PathBuf::from("/tmp/nyx_mp_test_nested");
        std::fs::create_dir_all(dir.join("src/foo")).ok();
        std::fs::write(dir.join("Cargo.toml"), "").ok();
        std::fs::write(dir.join("src/foo/bar.rs"), "").ok();
        let p = dir.join("src/foo/bar.rs");
        assert_eq!(derive_module_path(&p, None), Some("foo::bar".to_string()));
    }

    #[test]
    fn module_path_no_cargo_toml_with_scan_root() {
        // No Cargo.toml anywhere, fall back to scan root.
        let dir = PathBuf::from("/tmp/nyx_mp_test_no_cargo");
        std::fs::create_dir_all(dir.join("src")).ok();
        // Make sure no Cargo.toml exists.
        let _ = std::fs::remove_file(dir.join("Cargo.toml"));
        std::fs::write(dir.join("src/foo.rs"), "").ok();
        let p = dir.join("src/foo.rs");
        assert_eq!(derive_module_path(&p, Some(&dir)), Some("foo".to_string()));
    }

    #[test]
    fn module_path_non_rust_returns_none() {
        let p = PathBuf::from("/tmp/whatever/src/lib.py");
        assert_eq!(derive_module_path(&p, None), None);
    }

    // ── parse_rust_use_map ─────────────────────────────────────────────

    #[test]
    fn use_map_simple() {
        let src = b"use crate::auth::token::validate;";
        let tree = parse(std::str::from_utf8(src).unwrap());
        let m = parse_rust_use_map(src, &tree);
        assert_eq!(
            m.aliases.get("validate").map(String::as_str),
            Some("crate::auth::token::validate")
        );
        assert!(m.wildcards.is_empty());
    }

    #[test]
    fn use_map_list() {
        let src = b"use crate::auth::token::{validate, verify};";
        let tree = parse(std::str::from_utf8(src).unwrap());
        let m = parse_rust_use_map(src, &tree);
        assert_eq!(
            m.aliases.get("validate").map(String::as_str),
            Some("crate::auth::token::validate")
        );
        assert_eq!(
            m.aliases.get("verify").map(String::as_str),
            Some("crate::auth::token::verify")
        );
    }

    #[test]
    fn use_map_alias() {
        let src = b"use crate::auth::token::validate as ok;";
        let tree = parse(std::str::from_utf8(src).unwrap());
        let m = parse_rust_use_map(src, &tree);
        assert_eq!(
            m.aliases.get("ok").map(String::as_str),
            Some("crate::auth::token::validate")
        );
        assert!(!m.aliases.contains_key("validate"), "alias only");
    }

    #[test]
    fn use_map_wildcard() {
        let src = b"use crate::auth::token::*;";
        let tree = parse(std::str::from_utf8(src).unwrap());
        let m = parse_rust_use_map(src, &tree);
        assert!(m.aliases.is_empty());
        assert_eq!(m.wildcards, vec!["crate::auth::token".to_string()]);
    }

    #[test]
    fn use_map_nested_group() {
        let src = b"use crate::a::{b::c, d::e};";
        let tree = parse(std::str::from_utf8(src).unwrap());
        let m = parse_rust_use_map(src, &tree);
        assert_eq!(
            m.aliases.get("c").map(String::as_str),
            Some("crate::a::b::c")
        );
        assert_eq!(
            m.aliases.get("e").map(String::as_str),
            Some("crate::a::d::e")
        );
    }

    #[test]
    fn use_map_malformed_does_not_panic() {
        // Truncated input, must not panic.
        let src = b"use crate::auth::";
        let tree = parse(std::str::from_utf8(src).unwrap());
        let _ = parse_rust_use_map(src, &tree);
    }

    #[test]
    fn use_map_skips_inner_function_uses() {
        // Inner `use` inside a function body should not appear in the top-level map.
        let src = b"fn main() { use crate::inner::helper; helper(); }";
        let tree = parse(std::str::from_utf8(src).unwrap());
        let m = parse_rust_use_map(src, &tree);
        assert!(
            !m.aliases.contains_key("helper"),
            "inner uses should not leak into the top-level map"
        );
    }

    // ── resolve_with_use_map ───────────────────────────────────────────

    #[test]
    fn resolve_unqualified_alias() {
        let mut m = RustUseMap::default();
        m.aliases.insert(
            "validate".to_string(),
            "crate::auth::token::validate".to_string(),
        );
        assert_eq!(
            resolve_with_use_map(&m, None, "validate"),
            Some("crate::auth::token::validate".to_string())
        );
    }

    #[test]
    fn resolve_qualified_via_alias_prefix() {
        // `use crate::auth::token; token::validate(...)` lifts `token`.
        let mut m = RustUseMap::default();
        m.aliases
            .insert("token".to_string(), "crate::auth::token".to_string());
        assert_eq!(
            resolve_with_use_map(&m, Some("token"), "validate"),
            Some("crate::auth::token::validate".to_string())
        );
    }

    #[test]
    fn resolve_unqualified_unknown_returns_none() {
        let m = RustUseMap::default();
        assert_eq!(resolve_with_use_map(&m, None, "validate"), None);
    }

    // ── split_module_and_name ──────────────────────────────────────────

    #[test]
    fn split_strips_crate_prefix() {
        assert_eq!(
            split_module_and_name("crate::auth::token::validate"),
            ("auth::token".to_string(), "validate".to_string())
        );
    }

    #[test]
    fn split_no_crate_prefix() {
        assert_eq!(
            split_module_and_name("auth::token::validate"),
            ("auth::token".to_string(), "validate".to_string())
        );
    }

    #[test]
    fn split_bare_name() {
        assert_eq!(
            split_module_and_name("validate"),
            (String::new(), "validate".to_string())
        );
    }
}
