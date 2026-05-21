//! JavaScript / TypeScript [`super::super::FrameworkAdapter`] matching
//! `Object.assign` invocations with attacker-controlled RHS — the
//! shallowest prototype-pollution gadget.  Fires on bare
//! `Object.assign(target, src)` plus the spread form (`{ ...src }`
//! desugars to `Object.assign({}, src)`).
//!
//! Phase 10 (Track J.8).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

fn callee_is_object_assign(name: &str) -> bool {
    matches!(name, "Object.assign" | "assign")
}

fn source_uses_object_assign(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[b"Object.assign"];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

fn build_binding(adapter_name: &'static str) -> FrameworkBinding {
    FrameworkBinding {
        adapter: adapter_name.to_owned(),
        kind: EntryKind::Function,
        route: None,
        request_params: Vec::new(),
        response_writer: None,
        middleware: Vec::new(),
    }
}

pub struct PpObjectAssignJsAdapter;

const JS_ADAPTER_NAME: &str = "pp-object-assign-js";

impl FrameworkAdapter for PpObjectAssignJsAdapter {
    fn name(&self) -> &'static str {
        JS_ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::JavaScript
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if super::source_filters_proto_keys(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_object_assign);
        let matches_source = source_uses_object_assign(file_bytes);
        if matches_call && matches_source {
            Some(build_binding(JS_ADAPTER_NAME))
        } else {
            None
        }
    }
}

pub struct PpObjectAssignTsAdapter;

const TS_ADAPTER_NAME: &str = "pp-object-assign-ts";

impl FrameworkAdapter for PpObjectAssignTsAdapter {
    fn name(&self) -> &'static str {
        TS_ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::TypeScript
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if super::source_filters_proto_keys(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_object_assign);
        let matches_source = source_uses_object_assign(file_bytes);
        if matches_call && matches_source {
            Some(build_binding(TS_ADAPTER_NAME))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_js(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_object_assign_call() {
        let src: &[u8] = b"function run(payload) { return Object.assign({}, payload); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Object.assign")],
            ..Default::default()
        };
        assert!(PpObjectAssignJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_unrelated_assign() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(PpObjectAssignJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_object_create_null_mitigation() {
        let src: &[u8] =
            b"function run(payload) { return Object.create(null); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Object.create")],
            ..Default::default()
        };
        assert!(PpObjectAssignJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_proto_key_filter_present() {
        let src: &[u8] = b"function run(payload) {\n\
              for (const k of Object.keys(payload)) {\n\
                if (k === '__proto__' || k === 'constructor') continue;\n\
              }\n\
              return Object.assign({}, payload);\n\
            }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("Object.assign")],
            ..Default::default()
        };
        assert!(PpObjectAssignJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}
