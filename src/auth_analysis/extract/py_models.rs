//! Python ORM model classes defined in a file, found from import provenance.
//!
//! Peewee and Tortoise read a row with a bare `Model.get(..)`
//! (`Note.get(Note.id == pk)`, `await Note.get(id=pk)`).  By name alone that
//! call is indistinguishable from `Settings.get(key)` or `Cache.get(key)`, so
//! the classifier needs to know which PascalCase names are ORM models.  A
//! class counts only when its base resolves, through this file's own imports,
//! to the peewee or tortoise `Model`, or to a class of the file that does.
//! pydantic's `BaseModel` and a `Model` imported from anywhere else never
//! qualify.

use super::common::{named_children, text};
use std::collections::HashSet;
use tree_sitter::Node;

/// Modules whose `Model` is a row-mapped ORM base class with a class-level
/// `get`.
const ORM_MODULES: &[&str] = &["peewee", "tortoise.models", "playhouse.signals"];

/// Names of the ORM model classes defined in the file, or an empty set.
pub(super) fn orm_model_classes(root: Node<'_>, bytes: &[u8]) -> HashSet<String> {
    let mut bases: HashSet<String> = HashSet::new();
    let mut classes: Vec<(String, Vec<String>)> = Vec::new();
    for stmt in named_children(root) {
        match stmt.kind() {
            "import_statement" => note_import(stmt, bytes, &mut bases),
            "import_from_statement" => note_import_from(stmt, bytes, &mut bases),
            "class_definition" => note_class(stmt, bytes, &mut classes),
            "decorated_definition" => {
                if let Some(def) = stmt.child_by_field_name("definition")
                    && def.kind() == "class_definition"
                {
                    note_class(def, bytes, &mut classes);
                }
            }
            _ => {}
        }
    }
    let mut models = HashSet::new();
    if bases.is_empty() {
        return models;
    }
    // Same-file subclasses (`class BaseModel(Model)`, `class Note(BaseModel)`)
    // reach a fixed point in at most `classes.len()` passes.
    loop {
        let mut changed = false;
        for (name, supers) in &classes {
            if !models.contains(name) && supers.iter().any(|b| bases.contains(b)) {
                models.insert(name.clone());
                bases.insert(name.clone());
                changed = true;
            }
        }
        if !changed {
            return models;
        }
    }
}

fn note_class(class: Node<'_>, bytes: &[u8], out: &mut Vec<(String, Vec<String>)>) {
    let Some(name) = class.child_by_field_name("name") else {
        return;
    };
    let supers = class
        .child_by_field_name("superclasses")
        .map(|args| {
            named_children(args)
                .into_iter()
                .filter(|n| matches!(n.kind(), "identifier" | "attribute"))
                .map(|n| text(n, bytes))
                .collect()
        })
        .unwrap_or_default();
    out.push((text(name, bytes), supers));
}

/// `import peewee`, `import peewee as pw`, `import tortoise.models`.
fn note_import(stmt: Node<'_>, bytes: &[u8], bases: &mut HashSet<String>) {
    for item in named_children(stmt) {
        let (module, alias) = match item.kind() {
            "dotted_name" => (text(item, bytes), None),
            "aliased_import" => (
                item.child_by_field_name("name")
                    .map(|n| text(n, bytes))
                    .unwrap_or_default(),
                item.child_by_field_name("alias").map(|n| text(n, bytes)),
            ),
            _ => continue,
        };
        if ORM_MODULES.contains(&module.as_str()) {
            bases.insert(format!("{}.Model", alias.unwrap_or(module)));
        }
    }
}

/// `from peewee import Model`, `from tortoise.models import Model as M`,
/// `from tortoise import models`, `from peewee import *`.
fn note_import_from(stmt: Node<'_>, bytes: &[u8], bases: &mut HashSet<String>) {
    let Some(module) = stmt
        .child_by_field_name("module_name")
        .map(|n| text(n, bytes))
    else {
        return;
    };
    let is_orm_module = ORM_MODULES.contains(&module.as_str());
    let tortoise_pkg = module == "tortoise";
    if !is_orm_module && !tortoise_pkg {
        return;
    }
    let mut cursor = stmt.walk();
    for item in stmt.children_by_field_name("name", &mut cursor) {
        let (name, alias) = match item.kind() {
            "dotted_name" => (text(item, bytes), None),
            "aliased_import" => (
                item.child_by_field_name("name")
                    .map(|n| text(n, bytes))
                    .unwrap_or_default(),
                item.child_by_field_name("alias").map(|n| text(n, bytes)),
            ),
            _ => continue,
        };
        let local = alias.unwrap_or_else(|| name.clone());
        if is_orm_module && name == "Model" {
            bases.insert(local);
        } else if tortoise_pkg && name == "models" {
            bases.insert(format!("{local}.Model"));
        }
    }
    if is_orm_module
        && named_children(stmt)
            .iter()
            .any(|n| n.kind() == "wildcard_import")
    {
        bases.insert("Model".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Language, Parser};

    fn models(src: &str) -> Vec<String> {
        let mut parser = Parser::new();
        parser
            .set_language(&Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let mut found: Vec<String> = orm_model_classes(tree.root_node(), src.as_bytes())
            .into_iter()
            .collect();
        found.sort();
        found
    }

    #[test]
    fn peewee_and_tortoise_bases_resolve_through_imports() {
        assert_eq!(
            models("from peewee import Model\nclass Note(Model):\n    pass\n"),
            ["Note"]
        );
        assert_eq!(
            models("import peewee as pw\nclass Note(pw.Model):\n    pass\n"),
            ["Note"]
        );
        assert_eq!(
            models("from tortoise.models import Model\nclass Note(Model):\n    pass\n"),
            ["Note"]
        );
        assert_eq!(
            models("from tortoise import models\nclass Note(models.Model):\n    pass\n"),
            ["Note"]
        );
    }

    #[test]
    fn same_file_subclass_chain_is_followed() {
        let src =
            "from peewee import Model\nclass Base(Model):\n    pass\nclass Note(Base):\n    pass\n";
        assert_eq!(models(src), ["Base", "Note"]);
    }

    #[test]
    fn unrelated_model_bases_do_not_qualify() {
        assert!(
            models("from pydantic import BaseModel\nclass Cache(BaseModel):\n    pass\n")
                .is_empty()
        );
        assert!(models("from other import Model\nclass Note(Model):\n    pass\n").is_empty());
        assert!(models("class Settings:\n    pass\n").is_empty());
    }
}
