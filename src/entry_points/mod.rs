//! Phase 10 — Next.js entry-point detection.
//!
//! Recognises the three entry-point shapes specific to the Next.js
//! React framework so the SSA taint engine can seed their parameters
//! with `TaintOrigin::Source` at function entry without waiting for a
//! caller-side flow:
//!
//! * **`'use server'` directive (file-level)**, marks every exported
//!   function in the file as a server action whose arguments are
//!   adversary-controlled.
//! * **`'use server'` directive (function-level)**, the directive
//!   appears as the first statement inside a function body. Marks
//!   that single function as a server action.
//! * **App Router route handler**, files at `app/**/route.{ts,tsx,
//!   js,jsx}` exporting one of `GET`/`HEAD`/`POST`/`PUT`/`PATCH`/
//!   `DELETE`/`OPTIONS`. Each exported method function takes a
//!   `Request` (or `NextRequest`) as its first parameter.
//!
//! Detection runs at pass-1 summary extraction time and writes
//! [`EntryKind`] onto the matching [`crate::summary::FuncSummary`] /
//! [`crate::summary::ssa_summary::SsaFuncSummary`].  Pass 2 reads the
//! tag back from the per-body summary and seeds parameters before the
//! taint worklist starts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

/// The HTTP method an App Router route-handler is responding to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    GET,
    HEAD,
    POST,
    PUT,
    PATCH,
    DELETE,
    OPTIONS,
}

impl HttpMethod {
    /// Parse a Next.js App Router export name (`GET`, `POST`, ...).
    pub fn from_ident(ident: &str) -> Option<Self> {
        match ident {
            "GET" => Some(Self::GET),
            "HEAD" => Some(Self::HEAD),
            "POST" => Some(Self::POST),
            "PUT" => Some(Self::PUT),
            "PATCH" => Some(Self::PATCH),
            "DELETE" => Some(Self::DELETE),
            "OPTIONS" => Some(Self::OPTIONS),
            _ => None,
        }
    }
}

/// Entry-point classification recorded on a function summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryKind {
    /// `'use server'` directive (file-level *or* function-level).  The
    /// file-level form marks every exported function in the file; the
    /// function-level form marks one specific function whose first
    /// statement is the directive.
    UseServerDirective,
    /// A function exported from `app/**/route.{ts,tsx,js,jsx}` whose
    /// name is one of the recognised HTTP methods.
    AppRouteHandler { method: HttpMethod },
    /// A `<form action={...}>` server-action callee.  Reserved for
    /// future detection; not produced by [`detect_entries_in_file`]
    /// today, but the variant is part of the on-disk shape so older
    /// summaries serialise / deserialise cleanly when this expands.
    FormAction,
}

/// Detect every entry-point function in a single parsed file.
///
/// The result keys each detected function by its tree-sitter byte
/// span `(start, end)`.  The summary-extraction pipeline matches
/// against [`crate::cfg::BodyMeta::span`] to attach the [`EntryKind`]
/// to the corresponding summary.
///
/// Returns an empty map for non-JS/TS files and for JS/TS files
/// without any recognised entry shape.  No caller has to special-case
/// the empty result.
pub fn detect_entries_in_file(
    tree: &Tree,
    bytes: &[u8],
    path: &Path,
    lang_slug: &str,
) -> HashMap<(usize, usize), EntryKind> {
    if !is_js_or_ts(lang_slug) {
        return HashMap::new();
    }

    let mut entries: HashMap<(usize, usize), EntryKind> = HashMap::new();
    let root = tree.root_node();

    let file_use_server = file_level_use_server(root, bytes);
    let route_methods = if is_app_route_path(path) {
        Some(collect_route_handler_exports(root, bytes))
    } else {
        None
    };

    walk_functions(root, bytes, &mut |node, name| {
        let span = (node.start_byte(), node.end_byte());

        if function_level_use_server(node, bytes) {
            entries
                .entry(span)
                .or_insert(EntryKind::UseServerDirective);
            return;
        }

        if file_use_server && exports_function(node, root, bytes, name) {
            entries
                .entry(span)
                .or_insert(EntryKind::UseServerDirective);
            return;
        }

        if let (Some(map), Some(name)) = (&route_methods, name) {
            if let Some(method) = map.get(name).copied() {
                entries
                    .entry(span)
                    .or_insert(EntryKind::AppRouteHandler { method });
            }
        }
    });

    entries
}

/// `true` for the JS/TS family of grammars Phase 10 cares about.
fn is_js_or_ts(lang_slug: &str) -> bool {
    matches!(lang_slug, "javascript" | "typescript" | "tsx")
}

/// Path-based recogniser for `app/**/route.{ts,tsx,js,jsx}`.
fn is_app_route_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let recognised_basename = matches!(
        name,
        "route.ts" | "route.tsx" | "route.js" | "route.jsx"
    );
    if !recognised_basename {
        return false;
    }
    // `app/...` segment must appear somewhere up the path.
    path.components()
        .any(|c| c.as_os_str().to_string_lossy() == "app")
}

/// Read the first non-comment top-level statement and return `true`
/// when it is a string-literal directive `'use server'` /
/// `"use server"`.
fn file_level_use_server(root: Node, bytes: &[u8]) -> bool {
    // The tree-sitter program node has the file's top-level statements
    // as direct children.  A `'use server'` directive shows up as an
    // `expression_statement` whose only child is a `string` whose text
    // (after quote stripping) equals `use server`.
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            // Skip comments / hashbang shebangs.
            "comment" | "hash_bang_line" => continue,
            "expression_statement" => {
                if let Some(stmt) = first_string_child(child)
                    && string_literal_equals(stmt, bytes, "use server")
                {
                    return true;
                }
                return false;
            }
            _ => return false,
        }
    }
    false
}

/// Per-function recogniser: `function() { 'use server'; ... }`.
fn function_level_use_server(func_node: Node, bytes: &[u8]) -> bool {
    let Some(body) = function_body(func_node) else {
        return false;
    };
    let mut cursor = body.walk();
    for stmt in body.children(&mut cursor) {
        match stmt.kind() {
            "comment" => continue,
            "expression_statement" => {
                if let Some(s) = first_string_child(stmt) {
                    return string_literal_equals(s, bytes, "use server");
                }
                return false;
            }
            "{" | "}" => continue,
            _ => return false,
        }
    }
    false
}

/// Walk every function-like definition in the tree and invoke
/// `visit(node, name)` for each.
fn walk_functions<F: FnMut(Node, Option<&str>)>(root: Node, bytes: &[u8], visit: &mut F) {
    let mut cursor = root.walk();
    visit_recursive(root, bytes, &mut cursor, visit);
}

fn visit_recursive<F: FnMut(Node, Option<&str>)>(
    node: Node,
    bytes: &[u8],
    cursor: &mut tree_sitter::TreeCursor,
    visit: &mut F,
) {
    match node.kind() {
        "function_declaration"
        | "function_expression"
        | "generator_function_declaration"
        | "generator_function" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok());
            visit(node, name);
        }
        "arrow_function" => {
            // Arrow's name (if any) comes from the enclosing
            // `variable_declarator` — caller-side decoration handled by
            // `function_name_for_arrow`.
            let name = function_name_for_arrow(node, bytes);
            visit(node, name.as_deref());
        }
        "method_definition" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok());
            visit(node, name);
        }
        _ => {}
    }
    let mut walker = node.walk();
    for child in node.children(&mut walker) {
        visit_recursive(child, bytes, cursor, visit);
    }
}

/// Resolve the textual name attached to an arrow function via the
/// enclosing `const NAME = (…) => …` shape.  Returns `None` when the
/// arrow is not the initialiser of a `variable_declarator`.
fn function_name_for_arrow(node: Node, bytes: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "variable_declarator" {
        return None;
    }
    let name_node = parent.child_by_field_name("name")?;
    let text = name_node.utf8_text(bytes).ok()?;
    Some(text.to_string())
}

/// Get the body of a function-like node.  Returns the
/// `statement_block` for declarations / expressions; `None` for arrow
/// functions whose body is an expression rather than a block (those
/// cannot host a directive prologue).
fn function_body<'a>(func_node: Node<'a>) -> Option<Node<'a>> {
    let body = func_node.child_by_field_name("body")?;
    if body.kind() == "statement_block" {
        Some(body)
    } else {
        None
    }
}

/// Extract the first `string` child of an `expression_statement`.
fn first_string_child<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "string" {
            return Some(child);
        }
    }
    None
}

/// Compare the textual content of a `string` node (quotes stripped)
/// to `expected`.
fn string_literal_equals(string_node: Node, bytes: &[u8], expected: &str) -> bool {
    let Ok(raw) = string_node.utf8_text(bytes) else {
        return false;
    };
    let trimmed = raw
        .trim()
        .trim_start_matches(['\'', '"', '`'])
        .trim_end_matches(['\'', '"', '`']);
    trimmed == expected
}

/// Decide whether a function declaration / arrow definition with the
/// given name is exported at the top level of the program.
///
/// Used by the file-level `'use server'` path: the directive marks
/// only exported functions as server actions, internal helpers stay
/// at their default classification.
fn exports_function(func_node: Node, root: Node, bytes: &[u8], name: Option<&str>) -> bool {
    // `export function foo() { … }` / `export async function foo() { … }`
    if let Some(parent) = func_node.parent()
        && parent.kind() == "export_statement"
    {
        return true;
    }
    // `export const foo = (…) => { … }` — arrow inside an exported
    // variable declaration.  Walk up: variable_declarator →
    // (lexical|variable)_declaration → export_statement.
    let mut cur = func_node;
    for _ in 0..4 {
        let Some(parent) = cur.parent() else {
            break;
        };
        if parent.kind() == "export_statement" {
            return true;
        }
        cur = parent;
    }
    // Trailing `export { foo }` re-export.
    if let Some(target) = name {
        let mut walker = root.walk();
        for child in root.children(&mut walker) {
            if child.kind() != "export_statement" {
                continue;
            }
            let mut cur = child.walk();
            for export_child in child.children(&mut cur) {
                if export_child.kind() == "export_clause" {
                    let mut spec = export_child.walk();
                    for s in export_child.children(&mut spec) {
                        if s.kind() == "export_specifier"
                            && s.child_by_field_name("name")
                                .and_then(|n| n.utf8_text(bytes).ok())
                                .is_some_and(|t| t == target)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Collect the names of exported HTTP-method functions in a
/// route-handler file.  The map binds each name to the matching
/// [`HttpMethod`].
fn collect_route_handler_exports(root: Node, bytes: &[u8]) -> HashMap<String, HttpMethod> {
    let mut out = HashMap::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "export_statement" {
            continue;
        }
        // Walk into the export's payload.
        let mut walker = child.walk();
        for export_child in child.children(&mut walker) {
            // `export async function GET(…)` — function_declaration.
            // `export const GET = (…) => …` — lexical_declaration.
            collect_named_exports(export_child, bytes, &mut out);
        }
    }
    out
}

fn collect_named_exports(node: Node, bytes: &[u8], out: &mut HashMap<String, HttpMethod>) {
    match node.kind() {
        "function_declaration" | "generator_function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok())
                && let Some(m) = HttpMethod::from_ident(name)
            {
                out.insert(name.to_string(), m);
            }
        }
        "lexical_declaration" | "variable_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator"
                    && let Some(name) = child
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(bytes).ok())
                    && let Some(m) = HttpMethod::from_ident(name)
                {
                    out.insert(name.to_string(), m);
                }
            }
        }
        _ => {}
    }
}
