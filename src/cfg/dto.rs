//! per-language DTO definition collectors.
//!
//! Walks a parsed file's AST and emits `(class_name, DtoFields)` pairs
//! for class / interface / struct / Pydantic-model declarations whose
//! field types resolve to a recognised [`TypeKind`].
//!
//! Strictly additive: classes whose fields cannot be classified produce
//! a `DtoFields` with an empty `fields` map, the caller must decide
//! whether to use that as a "Dto with no inferred fields" or fall back
//! to the generic Object/Unknown classification.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use super::helpers::text_of;
use super::params::{
    java_type_to_kind, python_primitive_to_kind, ts_type_to_kind, ts_type_to_local_collection,
};
use crate::ssa::type_facts::{DtoFields, TypeKind};

/// Collect all DTO-shaped class definitions in a parsed file.
///
/// Dispatches per-language; returns an empty map for languages without
/// a collector (Go, Ruby, PHP, C/C++, DTOs in those ecosystems
/// either don't follow framework conventions Nyx tracks today, or are
/// already covered by other type-inference paths).
pub(super) fn collect_dto_classes(
    root: Node<'_>,
    lang: &str,
    code: &[u8],
) -> HashMap<String, DtoFields> {
    let mut out: HashMap<String, DtoFields> = HashMap::new();
    match lang {
        "java" => collect_java(root, code, &mut out),
        "typescript" | "ts" | "javascript" | "js" => collect_ts(root, code, &mut out),
        "rust" | "rs" => collect_rust(root, code, &mut out),
        "python" | "py" => collect_python(root, code, &mut out),
        _ => {}
    }
    out
}

/// Collect same-file `type X = Map<...>` / `Set<...>` / `T[]`
/// aliases for TS / JS so the param classifier can resolve a
/// parameter typed `m: ElementsMap` (where
/// `type ElementsMap = Map<K, V>`) to
/// [`TypeKind::LocalCollection`].
///
/// Empty for non-JS/TS languages.  Cross-file aliases are not
/// resolved here, that requires the multi-file type-resolution
/// pipeline that doesn't yet exist for TS.  Excalidraw's
/// `type ElementsMap = Map<...>` is in
/// `packages/element/src/types.ts`; users that import the alias
/// without a same-file copy still see the original FP.  Most
/// real-repo aliases the FP cluster touched were declared in the
/// same file as their consumers (see fixture).
pub(super) fn collect_type_alias_local_collections(
    root: Node<'_>,
    lang: &str,
    code: &[u8],
) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    if matches!(lang, "typescript" | "ts" | "javascript" | "js") {
        collect_ts_type_alias_local_collections(root, code, &mut out);
    }
    out
}

fn collect_ts_type_alias_local_collections(root: Node<'_>, code: &[u8], out: &mut HashSet<String>) {
    walk(root, &mut |node| {
        if node.kind() != "type_alias_declaration" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(alias_name) = text_of(name_node, code) else {
            return;
        };
        let Some(value_node) = node.child_by_field_name("value") else {
            return;
        };
        let Some(value_text) = text_of(value_node, code) else {
            return;
        };
        if ts_type_to_local_collection(value_text.trim()).is_some() {
            out.insert(alias_name);
        }
    });
}

// Java

/// Walk the AST for `class_declaration` nodes whose body contains
/// `field_declaration`s with classifiable types.  Only class-level
/// fields are collected; method-local declarations are ignored.
fn collect_java(root: Node<'_>, code: &[u8], out: &mut HashMap<String, DtoFields>) {
    walk(root, &mut |node| {
        if node.kind() != "class_declaration" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(class_name) = text_of(name_node, code) else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let mut fields = DtoFields::new(class_name.clone());
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            if child.kind() != "field_declaration" {
                continue;
            }
            let Some(type_node) = child.child_by_field_name("type") else {
                continue;
            };
            let Some(type_text) = text_of(type_node, code) else {
                continue;
            };
            let Some(kind) = java_type_to_kind(&type_text) else {
                continue;
            };
            // The declarator field carries the variable name(s).
            let Some(declarator) = child.child_by_field_name("declarator") else {
                continue;
            };
            // `variable_declarator` has a `name` field for the simple case.
            let Some(name_inner) = declarator.child_by_field_name("name") else {
                continue;
            };
            if let Some(field_name) = text_of(name_inner, code) {
                fields.insert(field_name, kind.clone());
            }
        }
        if !fields.fields.is_empty() {
            out.insert(class_name, fields);
        }
    });
}

// TypeScript / JavaScript

/// Walk for `interface_declaration` and `class_declaration` nodes.
/// Interfaces with `property_signature` children and classes with
/// `public_field_definition` children produce DTO entries.
fn collect_ts(root: Node<'_>, code: &[u8], out: &mut HashMap<String, DtoFields>) {
    walk(root, &mut |node| match node.kind() {
        "interface_declaration" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let Some(class_name) = text_of(name_node, code) else {
                return;
            };
            let Some(body) = node.child_by_field_name("body") else {
                return;
            };
            let mut fields = DtoFields::new(class_name.clone());
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                if child.kind() != "property_signature" {
                    continue;
                }
                let Some((field_name, kind)) = extract_ts_property(child, code) else {
                    continue;
                };
                fields.insert(field_name, kind);
            }
            if !fields.fields.is_empty() {
                out.insert(class_name, fields);
            }
        }
        "class_declaration" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let Some(class_name) = text_of(name_node, code) else {
                return;
            };
            let Some(body) = node.child_by_field_name("body") else {
                return;
            };
            let mut fields = DtoFields::new(class_name.clone());
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                if child.kind() != "public_field_definition" && child.kind() != "field_definition" {
                    continue;
                }
                let Some((field_name, kind)) = extract_ts_property(child, code) else {
                    continue;
                };
                fields.insert(field_name, kind);
            }
            if !fields.fields.is_empty() {
                out.insert(class_name, fields);
            }
        }
        _ => {}
    });
}

/// Extract `(field_name, TypeKind)` from a TS `property_signature` /
/// `public_field_definition`.  Returns None when either piece is absent
/// or the type doesn't classify.
fn extract_ts_property<'a>(node: Node<'a>, code: &'a [u8]) -> Option<(String, TypeKind)> {
    let name_node = node.child_by_field_name("name")?;
    let field_name = text_of(name_node, code)?;
    let type_anno = node.child_by_field_name("type")?;
    // type_annotation node text is `: T`, walk to the inner type.
    let type_text = type_anno
        .named_child(0)
        .and_then(|t| text_of(t, code))
        .or_else(|| text_of(type_anno, code))?;
    let stripped = type_text.trim().trim_start_matches(':').trim();
    let kind = ts_type_to_kind(stripped)?;
    Some((field_name, kind))
}

// Rust

/// Walk for `struct_item` nodes whose body lists named fields.
fn collect_rust(root: Node<'_>, code: &[u8], out: &mut HashMap<String, DtoFields>) {
    walk(root, &mut |node| {
        if node.kind() != "struct_item" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(class_name) = text_of(name_node, code) else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        if body.kind() != "field_declaration_list" {
            // Tuple struct or unit struct, no named fields.
            return;
        }
        let mut fields = DtoFields::new(class_name.clone());
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            if child.kind() != "field_declaration" {
                continue;
            }
            let Some(name_inner) = child.child_by_field_name("name") else {
                continue;
            };
            let Some(type_inner) = child.child_by_field_name("type") else {
                continue;
            };
            let Some(field_name) = text_of(name_inner, code) else {
                continue;
            };
            let Some(type_text) = text_of(type_inner, code) else {
                continue;
            };
            let Some(kind) = super::params::rust_primitive_to_kind(type_text.trim()) else {
                continue;
            };
            fields.insert(field_name, kind);
        }
        if !fields.fields.is_empty() {
            out.insert(class_name, fields);
        }
    });
}

// Python (Pydantic)

/// Walk for `class_definition` nodes whose superclass list contains
/// `BaseModel` / `pydantic.BaseModel`.  Each `expression_statement` in
/// the class body that is a typed assignment (`name: type`) produces a
/// field entry.
fn collect_python(root: Node<'_>, code: &[u8], out: &mut HashMap<String, DtoFields>) {
    walk(root, &mut |node| {
        if node.kind() != "class_definition" {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(class_name) = text_of(name_node, code) else {
            return;
        };
        if !python_inherits_basemodel(node, code) {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let mut fields = DtoFields::new(class_name.clone());
        let mut cursor = body.walk();
        for stmt in body.named_children(&mut cursor) {
            // Field declarations show up as `expression_statement` wrapping
            // either an `assignment` (`name: type = default`) or a bare
            // typed assignment.
            if stmt.kind() != "expression_statement" {
                continue;
            }
            let Some(inner) = stmt.named_child(0) else {
                continue;
            };
            if inner.kind() != "assignment" {
                continue;
            }
            let Some(left) = inner.child_by_field_name("left") else {
                continue;
            };
            let Some(field_name) = text_of(left, code) else {
                continue;
            };
            let Some(type_node) = inner.child_by_field_name("type") else {
                continue;
            };
            let Some(type_text) = text_of(type_node, code) else {
                continue;
            };
            let Some(kind) = python_primitive_to_kind(type_text.trim()) else {
                continue;
            };
            fields.insert(field_name, kind);
        }
        if !fields.fields.is_empty() {
            out.insert(class_name, fields);
        }
    });
}

/// Conservative supertype scan: returns true when the class definition
/// has a superclass list whose text mentions `BaseModel` (covers both
/// `BaseModel` and `pydantic.BaseModel`).  No false positives on
/// non-Pydantic classes named `BaseModel`-something, match is on the
/// full token, not a substring.
fn python_inherits_basemodel<'a>(class_node: Node<'a>, code: &'a [u8]) -> bool {
    let Some(supers) = class_node.child_by_field_name("superclasses") else {
        return false;
    };
    let mut cursor = supers.walk();
    for child in supers.named_children(&mut cursor) {
        if let Some(text) = text_of(child, code) {
            let head = text.trim();
            if head == "BaseModel" || head == "pydantic.BaseModel" {
                return true;
            }
        }
    }
    false
}

// Walk helper

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

    fn collect(lang: &str, src: &str) -> HashMap<String, DtoFields> {
        let mut parser = tree_sitter::Parser::new();
        let language = match lang {
            "java" => tree_sitter_java::LANGUAGE.into(),
            "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            "rust" => tree_sitter_rust::LANGUAGE.into(),
            "python" => tree_sitter_python::LANGUAGE.into(),
            other => panic!("unsupported lang: {other}"),
        };
        parser.set_language(&language).unwrap();
        let tree = parser.parse(src, None).unwrap();
        collect_dto_classes(tree.root_node(), lang, src.as_bytes())
    }

    #[test]
    fn java_class_with_long_and_string_fields() {
        let src = r#"
            public class CreateUser {
                private Long age;
                private String email;
            }
        "#;
        let dtos = collect("java", src);
        let dto = dtos.get("CreateUser").expect("CreateUser DTO recorded");
        assert_eq!(dto.get("age"), Some(&TypeKind::Int));
        assert_eq!(dto.get("email"), Some(&TypeKind::String));
    }

    #[test]
    fn java_unclassifiable_field_dropped() {
        let src = r#"
            public class HoldsList {
                private List<String> items;
                private Long count;
            }
        "#;
        let dtos = collect("java", src);
        let dto = dtos.get("HoldsList").expect("class recorded");
        // Only the Long field qualifies; List<String> is not currently
        // recognised by `java_type_to_kind`.
        assert_eq!(dto.get("count"), Some(&TypeKind::Int));
        assert!(dto.get("items").is_none());
    }

    #[test]
    fn ts_interface_with_number_and_string_fields() {
        let src = r#"
            export interface CreateUser {
                age: number;
                email: string;
            }
        "#;
        let dtos = collect("typescript", src);
        let dto = dtos.get("CreateUser").expect("CreateUser interface");
        assert_eq!(dto.get("age"), Some(&TypeKind::Int));
        assert_eq!(dto.get("email"), Some(&TypeKind::String));
    }

    #[test]
    fn ts_class_with_typed_field_definitions() {
        let src = r#"
            export class CreateUser {
                age!: number;
                email!: string;
            }
        "#;
        let dtos = collect("typescript", src);
        let dto = dtos.get("CreateUser").expect("CreateUser class");
        assert_eq!(dto.get("age"), Some(&TypeKind::Int));
        assert_eq!(dto.get("email"), Some(&TypeKind::String));
    }

    #[test]
    fn rust_struct_with_int_and_string_fields() {
        let src = r#"
            pub struct CreateUser {
                pub age: i64,
                pub email: String,
            }
        "#;
        let dtos = collect("rust", src);
        let dto = dtos.get("CreateUser").expect("CreateUser struct");
        assert_eq!(dto.get("age"), Some(&TypeKind::Int));
        assert_eq!(dto.get("email"), Some(&TypeKind::String));
    }

    #[test]
    fn rust_tuple_struct_skipped() {
        let src = r#"
            pub struct Wrap(i64, String);
        "#;
        let dtos = collect("rust", src);
        // Tuple structs have no named fields and must NOT produce a
        // DtoFields entry, This collector only handles named-field DTOs.
        assert!(!dtos.contains_key("Wrap"));
    }

    #[test]
    fn python_pydantic_basemodel_with_int_and_str() {
        let src = r#"
class CreateUser(BaseModel):
    age: int
    email: str
"#;
        let dtos = collect("python", src);
        let dto = dtos.get("CreateUser").expect("CreateUser model");
        assert_eq!(dto.get("age"), Some(&TypeKind::Int));
        assert_eq!(dto.get("email"), Some(&TypeKind::String));
    }

    #[test]
    fn python_class_without_basemodel_is_skipped() {
        // Hard Rule 3 spirit: only Pydantic models should be lifted as
        // DTOs.  Plain classes with typed attributes don't qualify.
        let src = r#"
class NotADto:
    age: int
    email: str
"#;
        let dtos = collect("python", src);
        assert!(!dtos.contains_key("NotADto"));
    }
}
