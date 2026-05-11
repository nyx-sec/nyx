//! Per-file extraction of class fields whose `.get(...)` lookups are
//! provably safe.
//!
//! Recognises Java `final` fields whose initializer is `Map.of(K1, V1,
//! K2, V2, ...)` with all string-literal arguments.  At a downstream
//! `<FIELD>.get(taintedKey)` call the result is bounded to the literal
//! value set, so the SSA taint engine can suppress propagation from the
//! key to the result.  Without this pre-pass the engine sees `<FIELD>`
//! as a free identifier with no SSA value, fails to resolve the
//! container, and falls back to default arg-to-result propagation.
//!
//! Strictly additive: unrecognised initializer shapes (factory chains,
//! `Map.ofEntries`, builders) produce no entry and the engine keeps
//! its prior behaviour.

use std::cell::RefCell;
use std::collections::HashMap;

use tree_sitter::Node;

use super::helpers::text_of;

thread_local! {
    /// Per-file safe-lookup field map published by [`with_safe_lookup_fields`]
    /// around taint passes that need it.  The SSA taint engine's container
    /// Load fallback consults this view via [`safe_lookup_field_values`] when
    /// the receiver is a free identifier (no SSA value to resolve against).
    static SAFE_LOOKUP_FIELDS_TLS: RefCell<Option<HashMap<String, Vec<String>>>> =
        const { RefCell::new(None) };
}

/// Run `f` with `fields` published as the per-thread safe-lookup view.
/// Restores the prior value on drop so nested calls compose; pass `None`
/// to suppress the gate for callers that lack a file context.
pub fn with_safe_lookup_fields<R>(
    fields: Option<&HashMap<String, Vec<String>>>,
    f: impl FnOnce() -> R,
) -> R {
    let prev = SAFE_LOOKUP_FIELDS_TLS.with(|cell| {
        cell.borrow_mut()
            .replace(fields.cloned().unwrap_or_default())
    });
    let restore_to = if fields.is_some() { prev } else { None };
    struct Guard(Option<HashMap<String, Vec<String>>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            SAFE_LOOKUP_FIELDS_TLS.with(|cell| *cell.borrow_mut() = self.0.take());
        }
    }
    let _guard = Guard(restore_to);
    f()
}

/// Look up the literal value set for a safe field.  Returns `None` when
/// no view is published, the field is not a known safe lookup, or the
/// value list is empty.
pub fn safe_lookup_field_values(name: &str) -> Option<Vec<String>> {
    SAFE_LOOKUP_FIELDS_TLS.with(|cell| {
        let borrowed = cell.borrow();
        let map = borrowed.as_ref()?;
        let values = map.get(name)?;
        if values.is_empty() {
            None
        } else {
            Some(values.clone())
        }
    })
}

/// Per-file safe-lookup field map: field name → finite set of literal
/// values that `<field>.get(...)` may return.  Empty for non-Java files.
pub fn collect_safe_lookup_fields(
    root: Node<'_>,
    lang: &str,
    code: &[u8],
) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    if lang == "java" {
        collect_java(root, code, &mut out);
    }
    out
}

/// Per-file file-level constant scalar map: name → literal value text.
///
/// Recognises declarations that bind a name to a primitive scalar literal at
/// file or class scope, where the per-function SSA const-prop has no view of
/// the binding (the name is a free identifier from inside any function body):
///
/// - Java: `static final TYPE NAME = LITERAL;` fields (any class depth).
/// - Python: `NAME = LITERAL` at module scope.
/// - Go: `const NAME = LITERAL` and `const NAME TYPE = LITERAL` at package scope.
/// - Rust: `const NAME: TYPE = LITERAL;` and `static NAME: TYPE = LITERAL;` at
///   crate or module scope.
///
/// Used by `cfg_analysis::guards` to suppress `cfg-unguarded-sink` when a
/// sink's argument is one of these bindings.  `LITERAL` covers strings (no
/// interpolation), integers in any supported base, floats, booleans, null /
/// nil / None, and unary negation / not over those.
///
/// Empty for unsupported languages.  Scalar means single-value, not
/// container; the `Map.of(...)` form is captured by
/// [`collect_safe_lookup_fields`].
pub fn collect_class_constant_scalars(
    root: Node<'_>,
    lang: &str,
    code: &[u8],
) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    match lang {
        "java" => collect_java_constant_scalars(root, code, &mut out),
        "python" => collect_python_constant_scalars(root, code, &mut out),
        "go" => collect_go_constant_scalars(root, code, &mut out),
        "rust" => collect_rust_constant_scalars(root, code, &mut out),
        _ => {}
    }
    out
}

fn collect_java_constant_scalars(root: Node<'_>, code: &[u8], out: &mut HashMap<String, String>) {
    walk(root, &mut |node| {
        if node.kind() != "field_declaration" {
            return;
        }
        if !has_static_modifier(node) || !has_final_modifier(node) {
            return;
        }
        // A single `field_declaration` may carry multiple
        // `variable_declarator` children (`static final int A = 1, B = 2;`).
        // Iterate every declarator field; tree-sitter exposes them under
        // the `declarator` field name as repeated entries.
        let mut cursor = node.walk();
        for child in node.children_by_field_name("declarator", &mut cursor) {
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let Some(field_name) = text_of(name_node, code) else {
                continue;
            };
            let Some(value_node) = child.child_by_field_name("value") else {
                continue;
            };
            let Some(literal) = scalar_literal_text(value_node, code) else {
                continue;
            };
            out.insert(field_name, literal);
        }
    });
}

/// Python: module-level `NAME = LITERAL` assignments.  Only top-level
/// expression statements are considered; assignments inside function bodies,
/// class bodies, or other blocks are out of scope (a per-function SSA pass
/// already sees those).
fn collect_python_constant_scalars(root: Node<'_>, code: &[u8], out: &mut HashMap<String, String>) {
    if root.kind() != "module" {
        return;
    }
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "expression_statement" {
            continue;
        }
        let Some(assign) = child.named_child(0) else {
            continue;
        };
        if assign.kind() != "assignment" {
            continue;
        }
        let Some(target) = assign.child_by_field_name("left") else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let Some(name) = text_of(target, code) else {
            continue;
        };
        let Some(value) = assign.child_by_field_name("right") else {
            continue;
        };
        let Some(literal) = python_scalar_literal_text(value, code) else {
            continue;
        };
        out.insert(name, literal);
    }
}

/// Go: package-level `const NAME = LITERAL` and `const NAME TYPE = LITERAL`,
/// including the grouped `const (...)` form.  Iterates direct
/// `const_declaration` children of the source file, then per-`const_spec`
/// reads the `name` list and `value` expression list, binding by position.
fn collect_go_constant_scalars(root: Node<'_>, code: &[u8], out: &mut HashMap<String, String>) {
    if root.kind() != "source_file" {
        return;
    }
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "const_declaration" {
            continue;
        }
        let mut spec_cursor = child.walk();
        for spec in child.named_children(&mut spec_cursor) {
            if spec.kind() != "const_spec" {
                continue;
            }
            collect_go_const_spec(spec, code, out);
        }
    }
}

fn collect_go_const_spec(spec: Node<'_>, code: &[u8], out: &mut HashMap<String, String>) {
    // tree-sitter-go `const_spec`:
    //   name: <identifier> (repeated)  — one or more identifiers
    //   value: <expression_list>       — list of value expressions
    // For a multi-target spec `const A, B = 1, 2`, identifiers and values pair
    // up positionally.  The simpler single-target form parses the same way
    // with one entry per side.
    let mut name_cursor = spec.walk();
    let names: Vec<Node<'_>> = spec
        .children_by_field_name("name", &mut name_cursor)
        .collect();
    if names.is_empty() {
        return;
    }
    let Some(value_list) = spec.child_by_field_name("value") else {
        return;
    };
    let mut value_cursor = value_list.walk();
    let values: Vec<Node<'_>> = value_list.named_children(&mut value_cursor).collect();
    if values.len() != names.len() {
        return;
    }
    for (name_node, value_node) in names.iter().zip(values.iter()) {
        if name_node.kind() != "identifier" {
            continue;
        }
        let Some(name) = text_of(*name_node, code) else {
            continue;
        };
        let Some(literal) = go_scalar_literal_text(*value_node, code) else {
            continue;
        };
        out.insert(name, literal);
    }
}

/// Rust: module-level `const NAME: TYPE = LITERAL;` and `static NAME: TYPE =
/// LITERAL;`.  Only direct children of `source_file` participate so a `const`
/// defined inside a function body does not bleed across scopes.
fn collect_rust_constant_scalars(root: Node<'_>, code: &[u8], out: &mut HashMap<String, String>) {
    if root.kind() != "source_file" {
        return;
    }
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if !matches!(child.kind(), "const_item" | "static_item") {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let Some(name) = text_of(name_node, code) else {
            continue;
        };
        let Some(value_node) = child.child_by_field_name("value") else {
            continue;
        };
        let Some(literal) = rust_scalar_literal_text(value_node, code) else {
            continue;
        };
        out.insert(name, literal);
    }
}

/// `true` when `field_declaration` carries a `static` modifier.
fn has_static_modifier(field_decl: Node<'_>) -> bool {
    let mut cursor = field_decl.walk();
    for child in field_decl.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        let mut sub = child.walk();
        for mod_child in child.children(&mut sub) {
            if mod_child.kind() == "static" {
                return true;
            }
        }
    }
    false
}

/// Return the source text when `value` is a primitive scalar literal node.
/// Covers the Java grammar's literal kinds.  Returns `None` for compound
/// expressions, identifier references, method invocations, and other
/// non-literal initializers.
fn scalar_literal_text(value: Node<'_>, code: &[u8]) -> Option<String> {
    match value.kind() {
        "string_literal"
        | "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal"
        | "decimal_floating_point_literal"
        | "hex_floating_point_literal"
        | "character_literal"
        | "true"
        | "false"
        | "null_literal" => text_of(value, code),
        // Unary `-1`, `+0`, `!true` over a literal child still resolve to a
        // compile-time constant; recurse into the operand.
        "unary_expression" => {
            let operand = value.child_by_field_name("operand")?;
            scalar_literal_text(operand, code)
        }
        _ => None,
    }
}

/// Python scalar literal classifier.  Rejects f-strings with interpolation
/// (`f"x{var}"` parses as `string` with an `interpolation` child); returns
/// the source text otherwise.
fn python_scalar_literal_text(value: Node<'_>, code: &[u8]) -> Option<String> {
    match value.kind() {
        "string" => {
            if python_string_has_interpolation(value) {
                None
            } else {
                text_of(value, code)
            }
        }
        "integer" | "float" | "true" | "false" | "none" => text_of(value, code),
        "unary_operator" => {
            let operand = value.child_by_field_name("argument")?;
            python_scalar_literal_text(operand, code)
        }
        _ => None,
    }
}

fn python_string_has_interpolation(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "interpolation" {
            return true;
        }
    }
    false
}

/// Go scalar literal classifier.  `interpreted_string_literal` and
/// `raw_string_literal` cover both `"x"` and `` `x` `` forms.
fn go_scalar_literal_text(value: Node<'_>, code: &[u8]) -> Option<String> {
    match value.kind() {
        "interpreted_string_literal"
        | "raw_string_literal"
        | "int_literal"
        | "float_literal"
        | "imaginary_literal"
        | "rune_literal"
        | "true"
        | "false"
        | "nil" => text_of(value, code),
        "unary_expression" => {
            let operand = value.child_by_field_name("operand")?;
            go_scalar_literal_text(operand, code)
        }
        _ => None,
    }
}

/// Rust scalar literal classifier.  Accepts `string_literal`, `raw_string_literal`
/// (both unwrappable to a single text run), integer / float / boolean / char.
fn rust_scalar_literal_text(value: Node<'_>, code: &[u8]) -> Option<String> {
    match value.kind() {
        "string_literal" | "raw_string_literal" | "integer_literal" | "float_literal"
        | "char_literal" | "boolean_literal" => text_of(value, code),
        // `true` / `false` are leaf identifier-ish nodes in some grammars but
        // tree-sitter-rust gives them the `boolean_literal` kind; defensively
        // accept the leaf form too in case the grammar is upgraded.
        "true" | "false" => text_of(value, code),
        "unary_expression" => {
            let mut cursor = value.walk();
            value
                .named_children(&mut cursor)
                .find_map(|c| rust_scalar_literal_text(c, code))
        }
        _ => None,
    }
}

fn collect_java(root: Node<'_>, code: &[u8], out: &mut HashMap<String, Vec<String>>) {
    walk(root, &mut |node| {
        if node.kind() != "field_declaration" {
            return;
        }
        if !has_final_modifier(node) {
            return;
        }
        let Some(decl) = node.child_by_field_name("declarator") else {
            return;
        };
        let Some(name_node) = decl.child_by_field_name("name") else {
            return;
        };
        let Some(field_name) = text_of(name_node, code) else {
            return;
        };
        let Some(value_node) = decl.child_by_field_name("value") else {
            return;
        };
        let Some(values) = extract_map_of_literal_values(value_node, code) else {
            return;
        };
        out.insert(field_name, values);
    });
}

/// `true` when `field_declaration` carries a `final` modifier (static or
/// instance — both block reassignment after construction).
fn has_final_modifier(field_decl: Node<'_>) -> bool {
    let mut cursor = field_decl.walk();
    for child in field_decl.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        let mut sub = child.walk();
        for mod_child in child.children(&mut sub) {
            if mod_child.kind() == "final" {
                return true;
            }
        }
    }
    false
}

/// If `value_node` is `Map.of(LIT, LIT, LIT, LIT, ...)` with at least one
/// key/value pair and every argument a `string_literal`, return the
/// value-position literals (positions 1, 3, 5, ...).
fn extract_map_of_literal_values(value_node: Node<'_>, code: &[u8]) -> Option<Vec<String>> {
    if value_node.kind() != "method_invocation" {
        return None;
    }
    let object_node = value_node.child_by_field_name("object")?;
    let method_node = value_node.child_by_field_name("name")?;
    let method_text = text_of(method_node, code)?;
    if method_text != "of" {
        return None;
    }
    if !receiver_is_map_class(object_node, code) {
        return None;
    }
    let args_node = value_node.child_by_field_name("arguments")?;
    let mut cursor = args_node.walk();
    let args: Vec<Node<'_>> = args_node.named_children(&mut cursor).collect();
    if args.is_empty() || !args.len().is_multiple_of(2) {
        return None;
    }
    let mut values = Vec::with_capacity(args.len() / 2);
    for (i, arg) in args.iter().enumerate() {
        if arg.kind() != "string_literal" {
            return None;
        }
        if i % 2 == 1 {
            let literal = string_literal_value(*arg, code)?;
            values.push(literal);
        }
    }
    Some(values)
}

/// `true` when `node` resolves to the `Map` class — either the bare
/// identifier `Map` or a `field_access` whose tail segment is `Map`
/// (covers `java.util.Map.of(...)`).
fn receiver_is_map_class(node: Node<'_>, code: &[u8]) -> bool {
    match node.kind() {
        "identifier" => text_of(node, code).as_deref() == Some("Map"),
        "field_access" => {
            // tail segment lives on the `field` field
            let Some(field) = node.child_by_field_name("field") else {
                return false;
            };
            text_of(field, code).as_deref() == Some("Map")
        }
        _ => false,
    }
}

/// Extract the inner content of a Java `string_literal` node.  The
/// grammar wraps the value in `string_fragment` children between quote
/// tokens; concatenate every `string_fragment` so escaped quotes inside
/// the literal are not lost.  Returns `None` for literals containing
/// interpolation / escape-sequence children that do not classify as a
/// pure string fragment.
fn string_literal_value(node: Node<'_>, code: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let mut out = String::new();
    let mut saw_fragment = false;
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_fragment" => {
                saw_fragment = true;
                out.push_str(&text_of(child, code)?);
            }
            "escape_sequence" => {
                // A real escape sequence keeps the literal pure-string but
                // we cannot trivially decode it; return None to be
                // conservative on header-injection safety.
                return None;
            }
            _ => return None,
        }
    }
    if saw_fragment {
        Some(out)
    } else {
        // Empty literal `""` — has no `string_fragment` children but is
        // a valid empty string.
        let raw = text_of(node, code)?;
        if raw == "\"\"" {
            Some(String::new())
        } else {
            None
        }
    }
}

fn walk<'a, F: FnMut(Node<'a>)>(node: Node<'a>, f: &mut F) {
    f(node);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn collect(src: &str) -> HashMap<String, Vec<String>> {
        let mut p = Parser::new();
        p.set_language(&tree_sitter_java::LANGUAGE.into()).unwrap();
        let tree = p.parse(src, None).unwrap();
        collect_safe_lookup_fields(tree.root_node(), "java", src.as_bytes())
    }

    #[test]
    fn static_final_map_of_two_pairs() {
        let src = r#"
            class C {
                private static final java.util.Map<String, String> T = Map.of(
                    "a", "x", "b", "y"
                );
            }
        "#;
        let out = collect(src);
        assert_eq!(out.get("T"), Some(&vec!["x".to_string(), "y".to_string()]));
    }

    #[test]
    fn instance_final_map_of_one_pair() {
        let src = r#"
            class C {
                private final java.util.Map<String, String> T = Map.of("a", "x");
            }
        "#;
        let out = collect(src);
        assert_eq!(out.get("T"), Some(&vec!["x".to_string()]));
    }

    #[test]
    fn rejects_non_final_field() {
        let src = r#"
            class C {
                private static java.util.Map<String, String> T = Map.of("a", "x");
            }
        "#;
        let out = collect(src);
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_non_literal_value() {
        let src = r#"
            class C {
                private static final String SAFE = "x";
                private static final java.util.Map<String, String> T = Map.of("a", SAFE);
            }
        "#;
        let out = collect(src);
        // SAFE is an identifier, not a string_literal — even though const-
        // foldable, the syntactic check rejects to stay simple.
        assert!(!out.contains_key("T"));
    }

    #[test]
    fn rejects_odd_arg_count() {
        // Compiler would reject this too, but the extractor must not panic.
        let src = r#"
            class C {
                private static final java.util.Map<String, String> T = Map.of("a", "x", "b");
            }
        "#;
        let out = collect(src);
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_empty_map_of() {
        let src = r#"
            class C {
                private static final java.util.Map<String, String> T = Map.of();
            }
        "#;
        let out = collect(src);
        assert!(out.is_empty());
    }

    #[test]
    fn fully_qualified_map_of() {
        let src = r#"
            class C {
                private static final java.util.Map<String, String> T = java.util.Map.of(
                    "a", "x", "b", "y"
                );
            }
        "#;
        let out = collect(src);
        assert_eq!(out.get("T"), Some(&vec!["x".to_string(), "y".to_string()]));
    }

    #[test]
    fn rejects_escape_sequence_value() {
        let src = r#"
            class C {
                private static final java.util.Map<String, String> T = Map.of(
                    "a", "with\nnewline"
                );
            }
        "#;
        let out = collect(src);
        // `\n` would smuggle a CRLF-style metachar through the static
        // gate; conservative reject keeps header-injection suppression
        // honest.
        assert!(!out.contains_key("T"));
    }

    #[test]
    fn ignores_non_java_lang() {
        let src = "const x = 1;";
        let mut p = Parser::new();
        p.set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = p.parse(src, None).unwrap();
        let out = collect_safe_lookup_fields(tree.root_node(), "javascript", src.as_bytes());
        assert!(out.is_empty());
    }

    fn collect_consts(src: &str) -> HashMap<String, String> {
        let mut p = Parser::new();
        p.set_language(&tree_sitter_java::LANGUAGE.into()).unwrap();
        let tree = p.parse(src, None).unwrap();
        collect_class_constant_scalars(tree.root_node(), "java", src.as_bytes())
    }

    #[test]
    fn class_constants_capture_string_int_bool() {
        let src = r#"
            class C {
                private static final String DRIVER = "com.mysql.cj.jdbc.Driver";
                public static final int LIMIT = 100;
                static final boolean DEBUG = false;
            }
        "#;
        let out = collect_consts(src);
        assert_eq!(
            out.get("DRIVER"),
            Some(&"\"com.mysql.cj.jdbc.Driver\"".to_string())
        );
        assert_eq!(out.get("LIMIT"), Some(&"100".to_string()));
        assert_eq!(out.get("DEBUG"), Some(&"false".to_string()));
    }

    #[test]
    fn class_constants_capture_multi_declarator() {
        let src = r#"
            class C {
                private static final int A = 1, B = 2, C2 = 3;
            }
        "#;
        let out = collect_consts(src);
        assert_eq!(out.get("A"), Some(&"1".to_string()));
        assert_eq!(out.get("B"), Some(&"2".to_string()));
        assert_eq!(out.get("C2"), Some(&"3".to_string()));
    }

    #[test]
    fn class_constants_capture_unary_negation() {
        let src = r#"
            class C {
                private static final int OFFSET = -1;
            }
        "#;
        let out = collect_consts(src);
        // text_of returns the operand text, not the wrapper text.
        assert_eq!(out.get("OFFSET"), Some(&"1".to_string()));
    }

    #[test]
    fn class_constants_reject_non_static() {
        let src = r#"
            class C {
                private final String NAME = "x";
            }
        "#;
        let out = collect_consts(src);
        assert!(!out.contains_key("NAME"));
    }

    #[test]
    fn class_constants_reject_non_final() {
        let src = r#"
            class C {
                private static String NAME = "x";
            }
        "#;
        let out = collect_consts(src);
        assert!(!out.contains_key("NAME"));
    }

    #[test]
    fn class_constants_reject_identifier_value() {
        let src = r#"
            class C {
                private static final String OTHER = computed();
                private static final String COPY = OTHER;
            }
        "#;
        let out = collect_consts(src);
        assert!(!out.contains_key("OTHER"));
        assert!(!out.contains_key("COPY"));
    }

    #[test]
    fn class_constants_capture_inside_inner_class() {
        let src = r#"
            class Outer {
                static class Inner {
                    private static final String DRIVER = "x";
                }
            }
        "#;
        let out = collect_consts(src);
        assert_eq!(out.get("DRIVER"), Some(&"\"x\"".to_string()));
    }

    #[test]
    fn class_constants_ignore_non_supported_lang() {
        let src = "const x = 1;";
        let mut p = Parser::new();
        p.set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = p.parse(src, None).unwrap();
        let out = collect_class_constant_scalars(tree.root_node(), "javascript", src.as_bytes());
        assert!(out.is_empty());
    }

    fn collect_consts_lang(src: &str, lang: &str) -> HashMap<String, String> {
        let mut p = Parser::new();
        match lang {
            "python" => p
                .set_language(&tree_sitter_python::LANGUAGE.into())
                .unwrap(),
            "go" => p.set_language(&tree_sitter_go::LANGUAGE.into()).unwrap(),
            "rust" => p.set_language(&tree_sitter_rust::LANGUAGE.into()).unwrap(),
            _ => unreachable!("unsupported lang in test helper: {lang}"),
        };
        let tree = p.parse(src, None).unwrap();
        collect_class_constant_scalars(tree.root_node(), lang, src.as_bytes())
    }

    #[test]
    fn python_module_constants_capture_scalars() {
        let src = "DRIVER = \"sqlite3\"\nLIMIT = 100\nDEBUG = False\nNAME = None\n";
        let out = collect_consts_lang(src, "python");
        assert_eq!(out.get("DRIVER"), Some(&"\"sqlite3\"".to_string()));
        assert_eq!(out.get("LIMIT"), Some(&"100".to_string()));
        assert_eq!(out.get("DEBUG"), Some(&"False".to_string()));
        assert_eq!(out.get("NAME"), Some(&"None".to_string()));
    }

    #[test]
    fn python_module_constants_capture_unary_negation() {
        // The recogniser recurses into the operand and returns its text, so
        // `OFFSET = -1` stores `"1"`.  The downstream suppression consumer
        // only cares about name binding, not the decoded numeric value.
        let src = "OFFSET = -1\n";
        let out = collect_consts_lang(src, "python");
        assert_eq!(out.get("OFFSET"), Some(&"1".to_string()));
    }

    #[test]
    fn python_module_constants_reject_fstring_with_interpolation() {
        let src = "import os\nVAR = f\"hi {os.getcwd()}\"\n";
        let out = collect_consts_lang(src, "python");
        assert!(!out.contains_key("VAR"));
    }

    #[test]
    fn python_module_constants_reject_call_value() {
        let src = "from os import getcwd\nPATH = getcwd()\n";
        let out = collect_consts_lang(src, "python");
        assert!(!out.contains_key("PATH"));
    }

    #[test]
    fn python_module_constants_skip_inside_function_body() {
        // An assignment inside a function body is per-function SSA's job.
        // Only top-level module assignments should land in the map.
        let src = "def f():\n    INNER = \"x\"\n    return INNER\n";
        let out = collect_consts_lang(src, "python");
        assert!(!out.contains_key("INNER"));
    }

    #[test]
    fn go_package_constants_capture_scalars() {
        let src =
            "package main\nconst DRIVER = \"postgres\"\nconst LIMIT = 100\nconst FLAG = true\n";
        let out = collect_consts_lang(src, "go");
        assert_eq!(out.get("DRIVER"), Some(&"\"postgres\"".to_string()));
        assert_eq!(out.get("LIMIT"), Some(&"100".to_string()));
        assert_eq!(out.get("FLAG"), Some(&"true".to_string()));
    }

    #[test]
    fn go_package_constants_capture_grouped_const_block() {
        let src = "package main\nconst (\n    A = \"x\"\n    B int = 42\n    C = false\n)\n";
        let out = collect_consts_lang(src, "go");
        assert_eq!(out.get("A"), Some(&"\"x\"".to_string()));
        assert_eq!(out.get("B"), Some(&"42".to_string()));
        assert_eq!(out.get("C"), Some(&"false".to_string()));
    }

    #[test]
    fn go_package_constants_reject_non_literal() {
        let src = "package main\nconst OTHER = foo()\n";
        let out = collect_consts_lang(src, "go");
        assert!(!out.contains_key("OTHER"));
    }

    #[test]
    fn go_package_constants_skip_inside_function_body() {
        // `const` inside a function body is per-function SSA's territory.
        let src = "package main\nfunc f() string { const INNER = \"x\"; return INNER }\n";
        let out = collect_consts_lang(src, "go");
        assert!(!out.contains_key("INNER"));
    }

    #[test]
    fn rust_module_consts_capture_scalars() {
        let src = "const DRIVER: &str = \"sqlite\";\nconst LIMIT: i32 = 100;\nstatic FLAG: bool = false;\n";
        let out = collect_consts_lang(src, "rust");
        assert_eq!(out.get("DRIVER"), Some(&"\"sqlite\"".to_string()));
        assert_eq!(out.get("LIMIT"), Some(&"100".to_string()));
        assert_eq!(out.get("FLAG"), Some(&"false".to_string()));
    }

    #[test]
    fn rust_module_consts_reject_non_literal() {
        let src = "const VAL: i32 = some_func();\n";
        let out = collect_consts_lang(src, "rust");
        assert!(!out.contains_key("VAL"));
    }

    #[test]
    fn rust_module_consts_skip_inside_function_body() {
        let src = "fn f() -> &'static str { const INNER: &str = \"x\"; INNER }\n";
        let out = collect_consts_lang(src, "rust");
        assert!(!out.contains_key("INNER"));
    }
}
