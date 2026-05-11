//! per-language class / trait / interface hierarchy extraction.
//!
//! Walks a parsed file's AST and emits `(sub_container, super_container)`
//! pairs for every declared inheritance / impl / implements relationship.
//! The result is consumed by [`crate::callgraph::TypeHierarchyIndex`] to
//! fan out method-call edges to every concrete implementer when a
//! receiver's static type is a super-class / trait / interface.
//!
//! Strictly additive: a language without an extractor (Go, C) returns
//! the empty vector and the resolver falls back to today's
//! single-container behaviour.

use std::collections::HashSet;

use tree_sitter::Node;

use super::helpers::text_of;

/// Collect `(sub_container, super_container)` edges for a parsed file.
///
/// The returned vector is **deduplicated within the file** but may
/// contain duplicates across files (each file emits its own edges).
/// The downstream [`crate::callgraph::TypeHierarchyIndex::build`]
/// dedups across files.
pub(crate) fn collect_hierarchy_edges(
    root: Node<'_>,
    lang: &str,
    code: &[u8],
) -> Vec<(String, String)> {
    let mut acc: Vec<(String, String)> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut push = |sub: String, sup: String| {
        if sub.is_empty() || sup.is_empty() {
            return;
        }
        if seen.insert((sub.clone(), sup.clone())) {
            acc.push((sub, sup));
        }
    };

    match lang {
        "java" => collect_java(root, code, &mut push),
        "rust" | "rs" => collect_rust(root, code, &mut push),
        "typescript" | "ts" | "tsx" | "javascript" | "js" => collect_ts(root, code, &mut push),
        "python" | "py" => collect_python(root, code, &mut push),
        "ruby" | "rb" => collect_ruby(root, code, &mut push),
        "php" => collect_php(root, code, &mut push),
        "cpp" | "c++" => collect_cpp(root, code, &mut push),
        // Go: structural / implicit interface satisfaction is intractable
        // per-file; deliberately skipped it.
        // C: no inheritance.
        _ => {}
    }
    acc
}

// ─────────────────────────────────────────────────────────────────────
//  Java
// ─────────────────────────────────────────────────────────────────────

fn collect_java<F: FnMut(String, String)>(root: Node<'_>, code: &[u8], push: &mut F) {
    walk(root, &mut |node| {
        let kind = node.kind();
        if kind != "class_declaration" && kind != "interface_declaration" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(sub) = text_of(name_node, code) else {
            return;
        };
        // `superclass` field on class_declaration, singular `extends Y`.
        if let Some(superclass) = node.child_by_field_name("superclass") {
            let mut cursor = superclass.walk();
            for c in superclass.named_children(&mut cursor) {
                if let Some(t) = type_identifier_text(c, code) {
                    push(sub.clone(), t);
                }
            }
        }
        // `interfaces` field on class_declaration, `implements I, J`
        // wraps a `super_interfaces` → `type_list`.
        if let Some(ifaces) = node.child_by_field_name("interfaces") {
            collect_java_type_list(ifaces, code, &sub, push);
        }
        // `extends_interfaces` is an unnamed child on
        // interface_declaration, `extends Foo, Bar` for an
        // interface.  Walk children directly since it's not a field.
        let mut cursor = node.walk();
        for c in node.named_children(&mut cursor) {
            if c.kind() == "extends_interfaces" {
                collect_java_type_list(c, code, &sub, push);
            }
        }
    });
}

fn collect_java_type_list<F: FnMut(String, String)>(
    n: Node<'_>,
    code: &[u8],
    sub: &str,
    push: &mut F,
) {
    let mut cursor = n.walk();
    for child in n.named_children(&mut cursor) {
        match child.kind() {
            "type_list" | "interface_type_list" => {
                collect_java_type_list(child, code, sub, push);
            }
            _ => {
                if let Some(t) = type_identifier_text(child, code) {
                    push(sub.to_string(), t);
                }
            }
        }
    }
}

/// Strip generic / nested `type_arguments` from a type-reference node
/// down to the bare identifier.
fn type_identifier_text(n: Node<'_>, code: &[u8]) -> Option<String> {
    match n.kind() {
        "type_identifier" | "identifier" => text_of(n, code),
        "generic_type" => {
            // `Foo<T>`, the leading child is the bare type identifier.
            let mut cursor = n.walk();
            for c in n.named_children(&mut cursor) {
                if matches!(
                    c.kind(),
                    "type_identifier" | "identifier" | "scoped_type_identifier"
                ) {
                    return text_of(c, code);
                }
            }
            None
        }
        "scoped_type_identifier" => {
            // `pkg.Foo`, return last segment.
            text_of(n, code).map(|s| {
                let last = s.rsplit('.').next().unwrap_or(&s);
                last.to_string()
            })
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Rust
// ─────────────────────────────────────────────────────────────────────

/// Walk for `impl_item` nodes and emit edges from the concrete type to
/// the trait being implemented.  Inherent impls (`impl Foo {}`) emit
/// no edge, there is no super-trait relationship to record.
fn collect_rust<F: FnMut(String, String)>(root: Node<'_>, code: &[u8], push: &mut F) {
    walk(root, &mut |node| {
        if node.kind() != "impl_item" {
            return;
        }
        // tree-sitter-rust uses `trait` and `type` field names.
        let Some(trait_node) = node.child_by_field_name("trait") else {
            return; // inherent impl
        };
        let Some(type_node) = node.child_by_field_name("type") else {
            return;
        };
        let Some(trait_name) = rust_path_leaf(trait_node, code) else {
            return;
        };
        let Some(type_name) = rust_path_leaf(type_node, code) else {
            return;
        };
        push(type_name, trait_name);
    });
}

fn rust_path_leaf(n: Node<'_>, code: &[u8]) -> Option<String> {
    match n.kind() {
        "type_identifier" | "identifier" => text_of(n, code),
        "scoped_type_identifier" | "scoped_identifier" => {
            // `crate::foo::Bar`, last segment.
            let s = text_of(n, code)?;
            Some(s.rsplit("::").next().unwrap_or(&s).to_string())
        }
        "generic_type" => {
            let mut cursor = n.walk();
            for c in n.named_children(&mut cursor) {
                if matches!(
                    c.kind(),
                    "type_identifier" | "scoped_type_identifier" | "identifier"
                ) {
                    return rust_path_leaf(c, code);
                }
            }
            None
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────
//  TypeScript / JavaScript
// ─────────────────────────────────────────────────────────────────────

fn collect_ts<F: FnMut(String, String)>(root: Node<'_>, code: &[u8], push: &mut F) {
    walk(root, &mut |node| {
        let kind = node.kind();
        if kind != "class_declaration" && kind != "interface_declaration" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(sub) = text_of(name_node, code) else {
            return;
        };

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "class_heritage" => {
                    let mut h = child.walk();
                    for c in child.named_children(&mut h) {
                        match c.kind() {
                            "extends_clause" => collect_ts_heritage(c, code, &sub, push),
                            "implements_clause" => collect_ts_heritage(c, code, &sub, push),
                            _ => {}
                        }
                    }
                }
                "extends_clause" => collect_ts_heritage(child, code, &sub, push),
                "extends_type_clause" => collect_ts_heritage(child, code, &sub, push),
                "implements_clause" => collect_ts_heritage(child, code, &sub, push),
                _ => {}
            }
        }
    });
}

fn collect_ts_heritage<F: FnMut(String, String)>(
    clause: Node<'_>,
    code: &[u8],
    sub: &str,
    push: &mut F,
) {
    let mut cursor = clause.walk();
    for c in clause.named_children(&mut cursor) {
        match c.kind() {
            "identifier" | "type_identifier" => {
                if let Some(t) = text_of(c, code) {
                    push(sub.to_string(), t);
                }
            }
            "generic_type" | "type_arguments" | "type_query" => {
                let mut cursor2 = c.walk();
                for inner in c.named_children(&mut cursor2) {
                    if matches!(inner.kind(), "identifier" | "type_identifier")
                        && let Some(t) = text_of(inner, code)
                    {
                        push(sub.to_string(), t);
                        break;
                    }
                }
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Python
// ─────────────────────────────────────────────────────────────────────

fn collect_python<F: FnMut(String, String)>(root: Node<'_>, code: &[u8], push: &mut F) {
    walk(root, &mut |node| {
        if node.kind() != "class_definition" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(sub) = text_of(name_node, code) else {
            return;
        };
        let Some(superclasses) = node.child_by_field_name("superclasses") else {
            return; // no parents
        };
        // `superclasses` is an `argument_list`, each non-keyword
        // argument is a base class.
        let mut cursor = superclasses.walk();
        for arg in superclasses.named_children(&mut cursor) {
            if let Some(t) = python_base_text(arg, code) {
                // Skip Python `object`, not informative.
                if t != "object" {
                    push(sub.clone(), t);
                }
            }
        }
    });
}

fn python_base_text(n: Node<'_>, code: &[u8]) -> Option<String> {
    match n.kind() {
        "identifier" => text_of(n, code),
        "attribute" => {
            // `pkg.Base`, last segment.
            let s = text_of(n, code)?;
            Some(s.rsplit('.').next().unwrap_or(&s).to_string())
        }
        // Skip keyword arguments like `metaclass=...`.
        "keyword_argument" => None,
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Ruby
// ─────────────────────────────────────────────────────────────────────

fn collect_ruby<F: FnMut(String, String)>(root: Node<'_>, code: &[u8], push: &mut F) {
    walk(root, &mut |node| {
        if node.kind() != "class" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(sub) = text_of(name_node, code) else {
            return;
        };
        if let Some(superclass) = node.child_by_field_name("superclass") {
            // `superclass` wraps the parent identifier.
            let mut cursor = superclass.walk();
            for c in superclass.named_children(&mut cursor) {
                if matches!(c.kind(), "constant" | "scope_resolution")
                    && let Some(t) = text_of(c, code)
                {
                    let leaf = t.rsplit("::").next().unwrap_or(&t).to_string();
                    push(sub, leaf);
                    break;
                }
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────
//  PHP
// ─────────────────────────────────────────────────────────────────────

fn collect_php<F: FnMut(String, String)>(root: Node<'_>, code: &[u8], push: &mut F) {
    walk(root, &mut |node| {
        let kind = node.kind();
        if kind != "class_declaration" && kind != "interface_declaration" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(sub) = text_of(name_node, code) else {
            return;
        };
        // PHP class_declaration may have base_clause and class_interface_clause.
        let mut cursor = node.walk();
        for c in node.named_children(&mut cursor) {
            match c.kind() {
                "base_clause" | "class_interface_clause" => {
                    let mut cc = c.walk();
                    for inner in c.named_children(&mut cc) {
                        if matches!(inner.kind(), "name" | "qualified_name")
                            && let Some(t) = text_of(inner, code)
                        {
                            let leaf = t.rsplit('\\').next().unwrap_or(&t).to_string();
                            push(sub.clone(), leaf);
                        }
                    }
                }
                _ => {}
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────
//  C++
// ─────────────────────────────────────────────────────────────────────

fn collect_cpp<F: FnMut(String, String)>(root: Node<'_>, code: &[u8], push: &mut F) {
    walk(root, &mut |node| {
        let kind = node.kind();
        if kind != "class_specifier" && kind != "struct_specifier" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(sub) = text_of(name_node, code) else {
            return;
        };
        // tree-sitter-cpp uses `base_class_clause` for the `: public Y` part.
        let mut cursor = node.walk();
        for c in node.named_children(&mut cursor) {
            if c.kind() == "base_class_clause" {
                let mut cc = c.walk();
                for inner in c.named_children(&mut cc) {
                    if matches!(
                        inner.kind(),
                        "type_identifier" | "qualified_identifier" | "template_type"
                    ) {
                        if let Some(t) = text_of(inner, code) {
                            let leaf = t.rsplit("::").next().unwrap_or(&t).to_string();
                            push(sub.clone(), leaf);
                        }
                    }
                }
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────

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

    fn collect(lang: &str, src: &str) -> Vec<(String, String)> {
        let mut parser = tree_sitter::Parser::new();
        let ts_lang = match lang {
            "java" => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
            "rust" => tree_sitter::Language::from(tree_sitter_rust::LANGUAGE),
            "python" => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
            "typescript" => {
                tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT)
            }
            "ruby" => tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE),
            "php" => tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP),
            "cpp" => tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE),
            _ => panic!("unsupported test lang: {lang}"),
        };
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(src.as_bytes(), None).unwrap();
        collect_hierarchy_edges(tree.root_node(), lang, src.as_bytes())
    }

    #[test]
    fn java_class_extends_emits_edge() {
        let src = "class Derived extends Base {}";
        let edges = collect("java", src);
        assert!(edges.contains(&("Derived".into(), "Base".into())));
    }

    #[test]
    fn java_class_implements_emits_per_interface_edge() {
        let src = "class UserRepo implements Repository, Cache {}";
        let edges = collect("java", src);
        assert!(edges.contains(&("UserRepo".into(), "Repository".into())));
        assert!(edges.contains(&("UserRepo".into(), "Cache".into())));
    }

    #[test]
    fn java_interface_extends_emits_edges() {
        let src = "interface Mine extends Foo, Bar {}";
        let edges = collect("java", src);
        // tree-sitter-java models `extends` on interface as `extends_interfaces`
        // rooted at the same node, at least one of the parents should land.
        assert!(
            edges.iter().any(|(s, _)| s == "Mine"),
            "interface extends should emit at least one edge; got {edges:?}"
        );
    }

    #[test]
    fn rust_impl_trait_for_type_emits_edge() {
        let src = "impl Repository for UserRepo {}";
        let edges = collect("rust", src);
        assert!(edges.contains(&("UserRepo".into(), "Repository".into())));
    }

    #[test]
    fn rust_inherent_impl_emits_no_edge() {
        let src = "impl UserRepo { fn new() {} }";
        let edges = collect("rust", src);
        assert!(
            edges.is_empty(),
            "inherent impl must not emit; got {edges:?}"
        );
    }

    #[test]
    fn ts_class_extends_implements_emits_edges() {
        let src = "class UserRepo extends BaseRepo implements Repository {}";
        let edges = collect("typescript", src);
        assert!(edges.contains(&("UserRepo".into(), "BaseRepo".into())));
        assert!(edges.contains(&("UserRepo".into(), "Repository".into())));
    }

    #[test]
    fn python_class_inherits_from_bases() {
        let src = "class Derived(Base, Mixin):\n    pass\n";
        let edges = collect("python", src);
        assert!(edges.contains(&("Derived".into(), "Base".into())));
        assert!(edges.contains(&("Derived".into(), "Mixin".into())));
    }

    #[test]
    fn python_class_object_base_skipped() {
        // Inheriting from `object` is not informative, Python's
        // implicit root.  We omit these edges to keep the
        // hierarchy index focused on user-defined relationships.
        let src = "class Plain(object):\n    pass\n";
        let edges = collect("python", src);
        assert!(
            !edges.contains(&("Plain".into(), "object".into())),
            "object base must be filtered; got {edges:?}"
        );
    }

    #[test]
    fn ruby_class_lt_super_emits_edge() {
        let src = "class Derived < Base\nend\n";
        let edges = collect("ruby", src);
        assert!(edges.contains(&("Derived".into(), "Base".into())));
    }

    #[test]
    fn dedup_within_file() {
        let src = r#"
class A extends B {}
class A extends B {}
"#;
        let edges = collect("java", src);
        let count = edges.iter().filter(|(s, p)| s == "A" && p == "B").count();
        assert_eq!(count, 1, "duplicates within a file must be deduped");
    }
}
