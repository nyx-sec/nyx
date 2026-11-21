//! Go scope facts for the auth extractor: which names hold the request, and
//! which names are package-level declarations.
//!
//! Both feed the ownership rule.  Accessor calls such as `Get`, `Query` and
//! `Param` are user input only on a request or a framework context, and a
//! selector rooted at an imported package or a file const is a declaration,
//! never a per-request value.

use super::common::{named_children, text};
use std::collections::HashSet;
use tree_sitter::Node;

/// Request roots a function-like node declares: its receiver and parameters
/// whose type is the request or a framework request context.
pub(super) fn request_root_params(definition: Node<'_>, bytes: &[u8]) -> HashSet<String> {
    let mut roots = HashSet::new();
    for field in ["receiver", "parameters"] {
        if let Some(list) = definition.child_by_field_name(field) {
            collect_request_params(list, bytes, &mut roots);
        }
    }
    roots
}

/// Add the request-typed parameters of one `parameter_list` to `out`.
pub(super) fn collect_request_params(list: Node<'_>, bytes: &[u8], out: &mut HashSet<String>) {
    for decl in named_children(list) {
        if !matches!(
            decl.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            continue;
        }
        let Some(type_node) = decl.child_by_field_name("type") else {
            continue;
        };
        if !is_request_type(type_node, bytes) {
            continue;
        }
        let mut cursor = decl.walk();
        for name in decl.children_by_field_name("name", &mut cursor) {
            if name.kind() == "identifier" {
                out.insert(text(name, bytes));
            }
        }
    }
}

/// `*http.Request`, `*gin.Context`, `echo.Context`, `*fiber.Ctx`,
/// `*fasthttp.RequestCtx`, a framework's own `*context.APIContext`, or a
/// package-local `*Context`.  The stdlib `context.Context` is an interface
/// passed by value, so only its pointer form (a framework's own `context`
/// package, as in gitea) counts.
fn is_request_type(type_node: Node<'_>, bytes: &[u8]) -> bool {
    let mut node = type_node;
    let mut through_pointer = false;
    while node.kind() == "pointer_type" {
        through_pointer = true;
        let Some(inner) = node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0))
        else {
            return false;
        };
        node = inner;
    }
    match node.kind() {
        "qualified_type" => {
            let package = node
                .child_by_field_name("package")
                .map(|n| text(n, bytes))
                .unwrap_or_default();
            let name = node
                .child_by_field_name("name")
                .map(|n| text(n, bytes))
                .unwrap_or_default();
            if package == "context" && name == "Context" {
                return through_pointer;
            }
            if package == "context" && name == "CancelFunc" {
                return false;
            }
            matches!(name.as_str(), "Request" | "Ctx" | "RequestCtx") || name.ends_with("Context")
        }
        "type_identifier" => matches!(
            text(node, bytes).as_str(),
            "Context" | "Ctx" | "APIContext" | "PrivateContext" | "WebContext" | "Request"
        ),
        _ => false,
    }
}

/// Leftmost identifier of an expression: `r` for `r.URL.Query()`, `ctx` for
/// `ctx.Req.Form["id"]`, `c` for `&c.Request`.
pub(super) fn expr_root<'a>(node: Node<'a>, bytes: &[u8]) -> Option<String> {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier" => return Some(text(cur, bytes)),
            "selector_expression" => cur = cur.child_by_field_name("operand")?,
            "call_expression" => cur = cur.child_by_field_name("function")?,
            "index_expression" | "slice_expression" => cur = cur.child_by_field_name("operand")?,
            "type_assertion_expression" => cur = cur.child_by_field_name("operand")?,
            "parenthesized_expression" | "unary_expression" => cur = cur.named_child(0)?,
            _ => return None,
        }
    }
}

/// First segment of a dotted callee text: `r` for `r.URL.Query().Get`.
pub(super) fn callee_root(callee: &str) -> &str {
    callee.split(['.', '(']).next().unwrap_or(callee)
}

/// Names a `short_var_declaration` / `assignment_statement` binds on its
/// left-hand side.
pub(super) fn bound_names(stmt: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(left) = stmt.child_by_field_name("left") {
        for target in expression_items(left) {
            if target.kind() == "identifier" {
                let name = text(target, bytes);
                if name != "_" {
                    out.push(name);
                }
            }
        }
    }
    out
}

/// Items of an `expression_list`, or the node itself when it is a single
/// expression.
pub(super) fn expression_items(node: Node<'_>) -> Vec<Node<'_>> {
    if node.kind() == "expression_list" {
        named_children(node)
    } else {
        vec![node]
    }
}

/// Standard-library packages whose types are in-memory containers or
/// synchronisation primitives, never a data-layer client.
const IN_MEMORY_PACKAGES: &[&str] = &["sync", "atomic", "list", "ring", "heap", "orderedmap"];

/// `(package, type)` pairs outside those packages that are in-memory values.
const IN_MEMORY_TYPES: &[(&str, &str)] = &[
    ("url", "Values"),
    ("http", "Header"),
    ("strings", "Builder"),
    ("bytes", "Buffer"),
    ("bytes", "Reader"),
    ("strings", "Reader"),
];

/// Constructor functions of the project-level set types
/// (`container.SetOf(ids...)`, `mapset.NewSet[int64]()`).
const IN_MEMORY_CONSTRUCTORS: &[&str] = &["SetOf", "NewSet", "NewSetOf", "NewSafeSet", "NewMap"];

/// True when a declared Go type is an in-memory container or primitive: a
/// map, slice, array or channel, a `sync.*` / `atomic.*` value, `url.Values`,
/// `http.Header`.  Methods called on such a variable are not data-layer
/// operations.
pub(super) fn type_is_in_memory(node: Node<'_>, bytes: &[u8]) -> bool {
    match node.kind() {
        "map_type" | "slice_type" | "array_type" | "channel_type" => true,
        "pointer_type" | "parenthesized_type" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0))
            .is_some_and(|inner| type_is_in_memory(inner, bytes)),
        "generic_type" => node
            .child_by_field_name("type")
            .is_some_and(|inner| type_is_in_memory(inner, bytes)),
        "qualified_type" => {
            let package = node
                .child_by_field_name("package")
                .map(|n| text(n, bytes))
                .unwrap_or_default();
            let name = node
                .child_by_field_name("name")
                .map(|n| text(n, bytes))
                .unwrap_or_default();
            IN_MEMORY_PACKAGES.contains(&package.as_str())
                || IN_MEMORY_TYPES.contains(&(package.as_str(), name.as_str()))
        }
        _ => false,
    }
}

/// True when a Go expression builds an in-memory container: `make(..)`, a
/// map/slice/`sync.Map`/`url.Values` literal (optionally behind `&`), or one
/// of the project set constructors.
pub(super) fn value_is_in_memory(node: Node<'_>, bytes: &[u8]) -> bool {
    match node.kind() {
        "expression_list" => node
            .named_child(0)
            .is_some_and(|first| node.named_child_count() == 1 && value_is_in_memory(first, bytes)),
        "unary_expression" | "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|inner| value_is_in_memory(inner, bytes)),
        "composite_literal" => node
            .child_by_field_name("type")
            .is_some_and(|ty| type_is_in_memory(ty, bytes)),
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return false;
            };
            let callee = text(function, bytes);
            // Strip explicit type arguments: `mapset.NewSet[int64]`.
            let callee = callee.split('[').next().unwrap_or(&callee);
            let last = callee.rsplit('.').next().unwrap_or(callee);
            callee == "make" || IN_MEMORY_CONSTRUCTORS.contains(&last)
        }
        _ => false,
    }
}

/// File-level names no function can reassign: imported package names and
/// top-level consts.
pub(super) fn package_level_names(root: Node<'_>, bytes: &[u8]) -> HashSet<String> {
    let mut names = HashSet::new();
    for decl in named_children(root) {
        match decl.kind() {
            "import_declaration" => collect_imports(decl, bytes, &mut names),
            "const_declaration" => collect_consts(decl, bytes, &mut names),
            _ => {}
        }
    }
    names
}

fn collect_imports(decl: Node<'_>, bytes: &[u8], out: &mut HashSet<String>) {
    for child in named_children(decl) {
        match child.kind() {
            "import_spec" => add_import_name(child, bytes, out),
            "import_spec_list" => {
                for spec in named_children(child) {
                    if spec.kind() == "import_spec" {
                        add_import_name(spec, bytes, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn add_import_name(spec: Node<'_>, bytes: &[u8], out: &mut HashSet<String>) {
    if let Some(alias) = spec.child_by_field_name("name") {
        let alias = text(alias, bytes);
        // `_` and `.` imports name nothing a selector can be rooted at.
        if alias != "_" && alias != "." && !alias.is_empty() {
            out.insert(alias);
        }
        return;
    }
    let Some(path) = spec.child_by_field_name("path") else {
        return;
    };
    let path = text(path, bytes);
    let path = path.trim_matches(['"', '`']);
    for name in package_names_for_import_path(path) {
        out.insert(name);
    }
}

/// Candidate package names for an import path.  The package clause is not in
/// the path, so this takes the last element, drops a `/vN` major suffix, and
/// also yields the usual `go-foo` / `foo.v3` / `foo-bar` spellings.
fn package_names_for_import_path(path: &str) -> Vec<String> {
    let mut elems: Vec<&str> = path.split('/').collect();
    if let Some(last) = elems.last().copied()
        && elems.len() > 1
        && last.len() > 1
        && last.starts_with('v')
        && last[1..].bytes().all(|b| b.is_ascii_digit())
    {
        elems.pop();
    }
    let Some(last) = elems.last().copied() else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let base = last.split(".v").next().unwrap_or(last);
    let mut push = |name: String| {
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    };
    push(base.replace(['-', '.'], "_"));
    if let Some(rest) = base
        .strip_prefix("go-")
        .or_else(|| base.strip_prefix("go_"))
    {
        push(rest.replace(['-', '.'], "_"));
    }
    if let Some(rest) = base
        .strip_suffix("-go")
        .or_else(|| base.strip_suffix("_go"))
    {
        push(rest.replace(['-', '.'], "_"));
    }
    names
}

fn collect_consts(decl: Node<'_>, bytes: &[u8], out: &mut HashSet<String>) {
    let mut specs = Vec::new();
    for child in named_children(decl) {
        match child.kind() {
            "const_spec" => specs.push(child),
            "const_spec_list" => specs.extend(named_children(child)),
            _ => {}
        }
    }
    for spec in specs {
        let mut cursor = spec.walk();
        for name in spec.children_by_field_name("name", &mut cursor) {
            if name.kind() == "identifier" {
                let name = text(name, bytes);
                if name != "_" {
                    out.insert(name);
                }
            }
        }
    }
}

/// Every name a function declares for itself: parameters, results, receiver,
/// `:=` and `var` bindings, `range` variables.  A package-level name that
/// appears here is shadowed inside the function.
pub(super) fn declared_names(definition: Node<'_>, bytes: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    declared_names_visit(definition, bytes, &mut out);
    out
}

fn declared_names_visit(node: Node<'_>, bytes: &[u8], out: &mut HashSet<String>) {
    match node.kind() {
        "parameter_declaration" | "variadic_parameter_declaration" | "var_spec" | "const_spec" => {
            let mut cursor = node.walk();
            for name in node.children_by_field_name("name", &mut cursor) {
                if name.kind() == "identifier" {
                    out.insert(text(name, bytes));
                }
            }
        }
        "short_var_declaration" | "range_clause" | "receive_statement" => {
            if let Some(left) = node.child_by_field_name("left") {
                for target in expression_items(left) {
                    if target.kind() == "identifier" {
                        out.insert(text(target, bytes));
                    }
                }
            }
        }
        _ => {}
    }
    for child in named_children(node) {
        declared_names_visit(child, bytes, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Language, Parser};

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&Language::from(tree_sitter_go::LANGUAGE))
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    fn first_func(root: Node<'_>) -> Node<'_> {
        named_children(root)
            .into_iter()
            .find(|n| matches!(n.kind(), "function_declaration" | "method_declaration"))
            .expect("a function")
    }

    #[test]
    fn request_typed_params_are_roots() {
        let src = "package p\nfunc h(w http.ResponseWriter, r *http.Request, c *gin.Context, e echo.Context, ctx *context.APIContext, std context.Context, cache *Cache, n int64) {}";
        let tree = parse(src);
        let roots = request_root_params(first_func(tree.root_node()), src.as_bytes());
        let mut got: Vec<_> = roots.into_iter().collect();
        got.sort();
        assert_eq!(got, ["c", "ctx", "e", "r"]);
    }

    #[test]
    fn pointer_context_is_a_framework_context_but_stdlib_is_not() {
        let src = "package p\nfunc h(ctx *context.Context) {}\nfunc g(ctx context.Context) {}";
        let tree = parse(src);
        let funcs: Vec<_> = named_children(tree.root_node())
            .into_iter()
            .filter(|n| n.kind() == "function_declaration")
            .collect();
        assert!(request_root_params(funcs[0], src.as_bytes()).contains("ctx"));
        assert!(request_root_params(funcs[1], src.as_bytes()).is_empty());
    }

    #[test]
    fn method_receiver_of_context_type_is_a_root() {
        let src = "package p\nfunc (ctx *Context) Foo() {}\nfunc (c *Cache) Bar() {}";
        let tree = parse(src);
        let funcs: Vec<_> = named_children(tree.root_node())
            .into_iter()
            .filter(|n| n.kind() == "method_declaration")
            .collect();
        assert!(request_root_params(funcs[0], src.as_bytes()).contains("ctx"));
        assert!(request_root_params(funcs[1], src.as_bytes()).is_empty());
    }

    #[test]
    fn package_names_cover_imports_and_consts() {
        let src = r#"package p
import (
	"fmt"
	xhttp "example.com/internal/http"
	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v3"
	"github.com/mattn/go-sqlite3"
	_ "example.com/driver"
	"example.com/models/repo_model"
)
import "net/http"
const storageRESTDiskID = "diskID"
const (
	LDAPUID = "uid"
	other, more = 1, 2
)
var mutable = 1
"#;
        let tree = parse(src);
        let names = package_level_names(tree.root_node(), src.as_bytes());
        for want in [
            "fmt",
            "xhttp",
            "echo",
            "yaml",
            "sqlite3",
            "repo_model",
            "http",
            "storageRESTDiskID",
            "LDAPUID",
            "other",
            "more",
        ] {
            assert!(names.contains(want), "missing {want}: {names:?}");
        }
        assert!(!names.contains("mutable"));
        assert!(!names.contains("_"));
    }

    #[test]
    fn declared_names_cover_params_locals_and_ranges() {
        let src = "package p\nfunc h(repo *Repo, ids ...int64) (out int, err error) {\n\tx, y := 1, 2\n\tvar z int\n\tfor i, v := range ids {}\n\tf := func(inner string) {}\n}";
        let tree = parse(src);
        let names = declared_names(first_func(tree.root_node()), src.as_bytes());
        for want in [
            "repo", "ids", "out", "err", "x", "y", "z", "i", "v", "f", "inner",
        ] {
            assert!(names.contains(want), "missing {want}: {names:?}");
        }
    }

    #[test]
    fn callee_root_stops_at_first_selector_or_call() {
        assert_eq!(callee_root("c.Param"), "c");
        assert_eq!(callee_root("r.URL.Query().Get"), "r");
        assert_eq!(callee_root("Param"), "Param");
    }
}
