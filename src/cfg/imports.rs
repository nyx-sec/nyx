use super::{
    ImportBinding, ImportBindings, PromisifyAlias, PromisifyAliases, member_expr_text, text_of,
};
use std::collections::HashMap;
use tree_sitter::{Node, Tree};

/// File-local view of every JS/TS import binding: local-name → source-module
/// specifier (verbatim from the `import` / `require` site, without `node:`
/// stripping). Built once per CFG pass; consumed by the gated-label
/// post-pass via [`crate::labels::ClassificationContext::local_imports`].
///
/// Records every binding regardless of aliasing (the legacy
/// [`extract_import_bindings`] only preserves *renamed* bindings, which is
/// not enough for Phase 05's `import { readFile } from 'fs/promises'`
/// shape where `local_name == imported_name`).
///
/// Shares its top-level walk with [`crate::resolve::walk_js_top_level_imports`]
/// so the import-clause / require-declarator parsing logic only lives in one
/// place; this view simply discards the resolver verdict and side-effect-only
/// markers.
pub(super) fn extract_local_import_view(tree: &Tree, code: &[u8]) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for raw in crate::resolve::walk_js_top_level_imports(tree, code) {
        if raw.local.is_empty() {
            continue;
        }
        out.insert(raw.local, raw.source_spec);
    }
    extend_with_promises_alias(tree, code, &mut out);
    out
}

/// Recognise top-level `const fsp = fs.promises;` /
/// `const fsp = require('fs').promises;` aliasing and add the new local
/// name to the import view as `fs/promises` (or `node:fs/promises`,
/// whichever the source binding spelt).
///
/// The Phase 05 `LabelGate::ImportedFromModule(&["fs/promises", ...])`
/// only consults `local_imports[leading_identifier(callee)]`. Without
/// this extension, `fsp.readFile(x)` evades the gate because `fsp`
/// itself is not an import binding — only the underlying `fs`
/// namespace is.
fn extend_with_promises_alias(tree: &Tree, code: &[u8], out: &mut HashMap<String, String>) {
    let root = tree.root_node();
    let mut top_cursor = root.walk();
    for child in root.children(&mut top_cursor) {
        if !matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
            continue;
        }
        let mut decl_cursor = child.walk();
        for decl in child.children(&mut decl_cursor) {
            if decl.kind() != "variable_declarator" {
                continue;
            }
            let (Some(name_node), Some(value_node)) = (
                decl.child_by_field_name("name"),
                decl.child_by_field_name("value"),
            ) else {
                continue;
            };
            if name_node.kind() != "identifier" {
                continue;
            }
            let Some(local_name) = text_of(name_node, code) else {
                continue;
            };
            if value_node.kind() != "member_expression" {
                continue;
            }
            let property = value_node
                .child_by_field_name("property")
                .and_then(|p| text_of(p, code));
            if property.as_deref() != Some("promises") {
                continue;
            }
            let Some(obj) = value_node.child_by_field_name("object") else {
                continue;
            };
            let Some(source) = promises_alias_source(obj, code, out) else {
                continue;
            };
            // Don't override an existing import entry for the same name —
            // an explicit import of `fsp` from `fs/promises` already says
            // what we'd be inferring here.
            out.entry(local_name).or_insert(source);
        }
    }
}

/// Resolve the object side of a `<lhs> = <obj>.promises` member-expression
/// to a source-module string when `<obj>` is a known `fs` binding.
///
/// Recognised shapes:
/// - identifier `X` where `local_imports[X]` is `fs` or `node:fs`
/// - `require('fs')` / `require("node:fs")` call expression
fn promises_alias_source(
    obj: Node,
    code: &[u8],
    imports_so_far: &HashMap<String, String>,
) -> Option<String> {
    match obj.kind() {
        "identifier" => {
            let id = text_of(obj, code)?;
            let module = imports_so_far.get(&id)?;
            map_fs_module_to_promises(module)
        }
        "call_expression" => {
            let func = obj.child_by_field_name("function")?;
            if text_of(func, code).as_deref() != Some("require") {
                return None;
            }
            let args = obj.child_by_field_name("arguments")?;
            let mut cursor = args.walk();
            for arg in args.children(&mut cursor) {
                if !matches!(arg.kind(), "string" | "template_string") {
                    continue;
                }
                let raw = text_of(arg, code)?;
                let spec = raw.trim_matches(|c: char| c == '\'' || c == '"' || c == '`');
                return map_fs_module_to_promises(spec);
            }
            None
        }
        _ => None,
    }
}

fn map_fs_module_to_promises(module: &str) -> Option<String> {
    if module.eq_ignore_ascii_case("fs") {
        Some("fs/promises".to_string())
    } else if module.eq_ignore_ascii_case("node:fs") {
        Some("node:fs/promises".to_string())
    } else {
        None
    }
}

// -------------------------------------------------------------------------
//  Import binding extraction
// -------------------------------------------------------------------------

/// Walk the top-level AST nodes and collect import alias bindings:
///
/// - ES6: `import { A as B } from 'mod'` → B → ImportBinding { original: A, module: mod }
/// - CommonJS: `const { A: B } = require('mod')` → B → ImportBinding { original: A, module: mod }
///
/// Only aliased (renamed) bindings are recorded, same-name imports (e.g.
/// `import { exec }`) are already resolvable by their original name.
pub(super) fn extract_import_bindings(tree: &Tree, code: &[u8]) -> ImportBindings {
    let mut bindings = ImportBindings::new();
    let root = tree.root_node();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        match child.kind() {
            // ES6: import { A as B } from 'mod'
            "import_statement" => {
                let source_str = child
                    .child_by_field_name("source")
                    .and_then(|s| text_of(s, code))
                    .map(|s| s.trim_matches(|c| c == '\'' || c == '"').to_string());

                let mut c1 = child.walk();
                for clause_child in child.children(&mut c1) {
                    if clause_child.kind() != "import_clause" {
                        continue;
                    }
                    let mut c2 = clause_child.walk();
                    for part in clause_child.children(&mut c2) {
                        if part.kind() != "named_imports" {
                            continue;
                        }
                        let mut c3 = part.walk();
                        for spec in part.children(&mut c3) {
                            if spec.kind() != "import_specifier" {
                                continue;
                            }
                            let original = spec
                                .child_by_field_name("name")
                                .and_then(|n| text_of(n, code));
                            let alias = spec
                                .child_by_field_name("alias")
                                .and_then(|a| text_of(a, code));
                            if let (Some(orig), Some(al)) = (original, alias) {
                                if orig != al {
                                    bindings.insert(
                                        al,
                                        ImportBinding {
                                            original: orig,
                                            module_path: source_str.clone(),
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
            // CommonJS: const { A: B } = require('mod')
            "lexical_declaration" | "variable_declaration" => {
                let mut c1 = child.walk();
                for decl in child.children(&mut c1) {
                    if decl.kind() != "variable_declarator" {
                        continue;
                    }
                    let (pattern, value) = match (
                        decl.child_by_field_name("name"),
                        decl.child_by_field_name("value"),
                    ) {
                        (Some(p), Some(v)) => (p, v),
                        _ => continue,
                    };
                    if pattern.kind() != "object_pattern" {
                        continue;
                    }
                    let module_path = extract_require_module(value, code);
                    if module_path.is_none() {
                        continue;
                    }
                    let mut c2 = pattern.walk();
                    for pair in pattern.children(&mut c2) {
                        if pair.kind() != "pair_pattern" {
                            continue;
                        }
                        let key = pair
                            .child_by_field_name("key")
                            .and_then(|n| text_of(n, code));
                        let val = pair
                            .child_by_field_name("value")
                            .and_then(|n| text_of(n, code));
                        if let (Some(orig), Some(al)) = (key, val) {
                            if orig != al {
                                bindings.insert(
                                    al,
                                    ImportBinding {
                                        original: orig,
                                        module_path: module_path.clone(),
                                    },
                                );
                            }
                        }
                    }
                }
            }
            // Python: from module import A as B
            "import_from_statement" => {
                // Extract module path from the module_name field.
                let module_path = child
                    .child_by_field_name("module_name")
                    .and_then(|m| text_of(m, code));

                let mut c1 = child.walk();
                for part in child.children(&mut c1) {
                    if part.kind() != "aliased_import" {
                        continue;
                    }
                    let original = part
                        .child_by_field_name("name")
                        .and_then(|n| text_of(n, code));
                    let alias = part
                        .child_by_field_name("alias")
                        .and_then(|a| text_of(a, code));
                    if let (Some(orig), Some(al)) = (original, alias) {
                        if orig != al {
                            bindings.insert(
                                al,
                                ImportBinding {
                                    original: orig,
                                    module_path: module_path.clone(),
                                },
                            );
                        }
                    }
                }
            }
            // PHP: use Namespace\ClassName as Alias;
            "namespace_use_declaration" => {
                let mut c1 = child.walk();
                for clause in child.children(&mut c1) {
                    if clause.kind() != "namespace_use_clause" {
                        continue;
                    }
                    // The alias is accessed via the "alias" field (a `name` node).
                    // The qualified name has no field, find it by kind.
                    let alias_node = clause.child_by_field_name("alias");
                    let mut c2 = clause.walk();
                    let qname_node = clause
                        .children(&mut c2)
                        .find(|n| n.kind() == "qualified_name" || n.kind() == "name");
                    if let (Some(qn), Some(alias_n)) = (qname_node, alias_node) {
                        let full_path = text_of(qn, code);
                        let alias = text_of(alias_n, code);
                        if let (Some(path_str), Some(al)) = (full_path, alias) {
                            // Extract the last segment as the original name.
                            let orig = path_str
                                .rsplit('\\')
                                .next()
                                .unwrap_or(&path_str)
                                .to_string();
                            if orig != al {
                                bindings.insert(
                                    al,
                                    ImportBinding {
                                        original: orig,
                                        module_path: Some(path_str),
                                    },
                                );
                            }
                        }
                    }
                }
            }
            // Rust: use crate::module::func as alias;
            "use_declaration" => {
                // Walk all descendants looking for use_as_clause nodes
                // (may be nested inside use_list / scoped_use_list).
                let mut stack = vec![child];
                while let Some(node) = stack.pop() {
                    if node.kind() == "use_as_clause" {
                        let path_node = node.child_by_field_name("path");
                        let alias_node = node.child_by_field_name("alias");
                        if let (Some(p), Some(a)) = (path_node, alias_node) {
                            let path_text = text_of(p, code);
                            let alias_text = text_of(a, code);
                            if let (Some(path_str), Some(al)) = (path_text, alias_text) {
                                // Extract the last segment of the path as the original name.
                                let orig = path_str
                                    .rsplit("::")
                                    .next()
                                    .unwrap_or(&path_str)
                                    .to_string();
                                if orig != al {
                                    bindings.insert(
                                        al,
                                        ImportBinding {
                                            original: orig,
                                            module_path: Some(path_str),
                                        },
                                    );
                                }
                            }
                        }
                    } else {
                        let mut c1 = node.walk();
                        for ch in node.children(&mut c1) {
                            stack.push(ch);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    bindings
}

/// Walk the AST and collect promisify-alias bindings for JS/TS.
///
/// Recognises declarations of the forms:
///   - `const alias = util.promisify(wrapped)`
///   - `const alias = promisify(wrapped)`   (when `promisify` was destructured
///     from `util`, matched structurally without tracking the import)
///
/// The `wrapped` callee is stored as its canonical textual form (e.g.
/// `child_process.exec`).  Only single-argument calls are captured; wrappers
/// that rename more than the first argument are skipped conservatively.
///
/// The walk recurses through function bodies so aliases declared inside a
/// handler are still recorded (they are file-local bindings regardless).
pub(super) fn extract_promisify_aliases(tree: &Tree, code: &[u8]) -> PromisifyAliases {
    let mut aliases = PromisifyAliases::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "lexical_declaration" | "variable_declaration" => {
                let mut c = node.walk();
                for decl in node.children(&mut c) {
                    if decl.kind() != "variable_declarator" {
                        continue;
                    }
                    let (name_node, value_node) = match (
                        decl.child_by_field_name("name"),
                        decl.child_by_field_name("value"),
                    ) {
                        (Some(n), Some(v)) => (n, v),
                        _ => continue,
                    };
                    if name_node.kind() != "identifier" {
                        continue;
                    }
                    let alias_name = match text_of(name_node, code) {
                        Some(s) => s,
                        None => continue,
                    };
                    if let Some(wrapped) = extract_promisify_wrapped(value_node, code) {
                        aliases.insert(alias_name, PromisifyAlias { wrapped });
                    }
                }
            }
            "assignment_expression" => {
                let (Some(lhs), Some(rhs)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    continue;
                };
                if lhs.kind() != "identifier" {
                    continue;
                }
                let alias_name = match text_of(lhs, code) {
                    Some(s) => s,
                    None => continue,
                };
                if let Some(wrapped) = extract_promisify_wrapped(rhs, code) {
                    aliases.insert(alias_name, PromisifyAlias { wrapped });
                }
            }
            _ => {}
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            stack.push(child);
        }
    }
    aliases
}

/// If `value` is a call expression of the shape `util.promisify(X)` or
/// `promisify(X)`, return the textual representation of `X` (`child_process.exec`,
/// `fs.readFile`, `foo`).  Otherwise `None`.
fn extract_promisify_wrapped(value: Node, code: &[u8]) -> Option<String> {
    if value.kind() != "call_expression" {
        return None;
    }
    let func = value.child_by_field_name("function")?;
    let func_text = match func.kind() {
        "identifier" => text_of(func, code)?,
        "member_expression" => member_expr_text(func, code)?,
        _ => return None,
    };
    let matches = matches!(func_text.as_str(), "util.promisify" | "promisify");
    if !matches {
        return None;
    }
    let args = value.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let mut wrapped: Option<String> = None;
    let mut arg_count = 0;
    for arg in args.children(&mut cursor) {
        if arg.is_extra() {
            continue;
        }
        match arg.kind() {
            "," | "(" | ")" => continue,
            _ => {}
        }
        arg_count += 1;
        if arg_count == 1 {
            wrapped = match arg.kind() {
                "identifier" => text_of(arg, code),
                "member_expression" => member_expr_text(arg, code),
                _ => None,
            };
        }
    }
    if arg_count != 1 {
        return None;
    }
    wrapped
}

/// Extract the module path from a `require('...')` call expression.
fn extract_require_module(node: Node, code: &[u8]) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    let func_text = text_of(func, code)?;
    if func_text != "require" {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() == "string" || arg.kind() == "template_string" {
            return text_of(arg, code).map(|s| {
                s.trim_matches(|c| c == '\'' || c == '"' || c == '`')
                    .to_string()
            });
        }
    }
    None
}

/// Per-file Rust scan: did the file `use` a join-style macro from `tokio` or
/// `futures`? Returns the crate prefix to use when the file calls a bare
/// `join!` / `try_join!` macro.
///
/// Rationale: tree-sitter records `tokio::join!(...)` with a fully qualified
/// `macro` field text, but `use tokio::join; ... join!(a, b)` records the
/// bare leaf. Without this lookup, the SSA-level promise-combinator
/// recogniser (`crate::labels::is_promise_combinator`) misses the bare form
/// and the macro's argument taint is dropped. Conservative: returns `None`
/// when both `tokio::<name>` and `futures::<name>` are imported (ambiguous)
/// or when neither is, leaving the bare `join` callee alone.
pub(super) fn rust_bare_join_crate_prefix(
    root: Node,
    code: &[u8],
    leaf: &str,
) -> Option<&'static str> {
    if !matches!(leaf, "join" | "try_join") {
        return None;
    }
    let mut cursor = root.walk();
    let mut tokio_seen = false;
    let mut futures_seen = false;
    for child in root.children(&mut cursor) {
        if child.kind() != "use_declaration" {
            continue;
        }
        if rust_use_decl_imports_leaf(child, code, "tokio", leaf) {
            tokio_seen = true;
        }
        if rust_use_decl_imports_leaf(child, code, "futures", leaf) {
            futures_seen = true;
        }
    }
    match (tokio_seen, futures_seen) {
        (true, false) => Some("tokio"),
        (false, true) => Some("futures"),
        _ => None,
    }
}

/// True when `use_decl` brings `<crate_prefix>::<leaf>` into scope.
///
/// Recognises the common shapes:
/// * `use tokio::join;`                          → leaf at the path tail
/// * `use tokio::{join, select};`                → leaf inside a use_list
/// * `use tokio::join as my_join;`               → aliased; we detect the
///   original path even though the aliased name is unused (the macro is
///   typically invoked under its alias, but if the alias and the bare form
///   collide the rewrite is still safe).
/// * `use tokio::*;` is NOT recognised — wildcard imports are too permissive
///   for the bare-leaf rewrite to stay precise.
fn rust_use_decl_imports_leaf(use_decl: Node, code: &[u8], crate_prefix: &str, leaf: &str) -> bool {
    let mut stack = vec![use_decl];
    while let Some(node) = stack.pop() {
        match node.kind() {
            // `use tokio::join;` — argument is a `scoped_identifier`.
            "scoped_identifier" => {
                if scoped_identifier_matches(node, code, crate_prefix, leaf) {
                    return true;
                }
            }
            // `use tokio::{join, select};` — the `path` field is `tokio`,
            // and a `use_list` enumerates leaves.
            "scoped_use_list" => {
                let path_ok = node
                    .child_by_field_name("path")
                    .and_then(|p| text_of(p, code))
                    .as_deref()
                    == Some(crate_prefix);
                if path_ok && let Some(list) = node.child_by_field_name("list") {
                    let mut lc = list.walk();
                    for entry in list.named_children(&mut lc) {
                        match entry.kind() {
                            "identifier" => {
                                if text_of(entry, code).as_deref() == Some(leaf) {
                                    return true;
                                }
                            }
                            "use_as_clause" => {
                                if entry
                                    .child_by_field_name("path")
                                    .and_then(|p| text_of(p, code))
                                    .as_deref()
                                    == Some(leaf)
                                {
                                    return true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            // `use tokio::join as my_join;` — aliased clause sits directly
            // under the use_declaration; check the path side.
            "use_as_clause" => {
                if let Some(p) = node.child_by_field_name("path")
                    && p.kind() == "scoped_identifier"
                    && scoped_identifier_matches(p, code, crate_prefix, leaf)
                {
                    return true;
                }
            }
            _ => {
                // Walk children for nested groups (`use a::{b::{c, d}}`).
                let mut c = node.walk();
                for ch in node.children(&mut c) {
                    stack.push(ch);
                }
            }
        }
    }
    false
}

fn scoped_identifier_matches(node: Node, code: &[u8], crate_prefix: &str, leaf: &str) -> bool {
    let path_text = node
        .child_by_field_name("path")
        .and_then(|p| text_of(p, code));
    let leaf_text = node
        .child_by_field_name("name")
        .and_then(|n| text_of(n, code));
    matches!((path_text.as_deref(), leaf_text.as_deref()),
        (Some(p), Some(l)) if p == crate_prefix && l == leaf)
}

// -------------------------------------------------------------------------
//  === PUBLIC ENTRY POINT =================================================
// -------------------------------------------------------------------------
