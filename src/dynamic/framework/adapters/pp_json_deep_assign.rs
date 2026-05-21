//! JavaScript / TypeScript [`super::super::FrameworkAdapter`] matching
//! the `JSON.parse`-followed-by-deep-assign prototype-pollution
//! gadget: the host parses an attacker-controlled JSON string and
//! then walks the resulting object into a vanilla target through a
//! hand-rolled recursive merge.
//!
//! Phase 10 (Track J.8).  Fires when the function body invokes
//! `JSON.parse` and the surrounding source carries a recursive merge
//! helper (literal `function merge`, `function deepAssign`,
//! `function extend`, etc.) — the static-side signal that an
//! attacker-controlled JSON tree can reach `Object.prototype`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

fn callee_is_json_parse(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "parse")
}

fn source_has_deep_merge_helper(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"function deepMerge",
        b"function deepAssign",
        b"function extend",
        b"function merge",
        b"function setByPath",
        b"deepMerge =",
        b"deepAssign =",
        b"JSON.parse",
    ];
    let mut json_parse = false;
    let mut deep_merge = false;
    for n in NEEDLES {
        if file_bytes.windows(n.len()).any(|w| w == *n) {
            if *n == b"JSON.parse" {
                json_parse = true;
            } else {
                deep_merge = true;
            }
        }
    }
    json_parse && deep_merge
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

pub struct PpJsonDeepAssignJsAdapter;

const JS_ADAPTER_NAME: &str = "pp-json-deep-assign-js";

impl FrameworkAdapter for PpJsonDeepAssignJsAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_json_parse);
        let matches_source = source_has_deep_merge_helper(file_bytes);
        if matches_call && matches_source {
            Some(build_binding(JS_ADAPTER_NAME))
        } else {
            None
        }
    }
}

pub struct PpJsonDeepAssignTsAdapter;

const TS_ADAPTER_NAME: &str = "pp-json-deep-assign-ts";

impl FrameworkAdapter for PpJsonDeepAssignTsAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_json_parse);
        let matches_source = source_has_deep_merge_helper(file_bytes);
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
    fn fires_on_json_parse_with_deep_merge() {
        let src: &[u8] = b"function deepMerge(t, s) { for (const k of Object.keys(s)) t[k] = s[k]; return t; }\n\
            function run(payload) { return deepMerge({}, JSON.parse(payload)); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("JSON.parse")],
            ..Default::default()
        };
        assert!(PpJsonDeepAssignJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_json_parse_without_merge() {
        let src: &[u8] = b"function run(payload) { return JSON.parse(payload); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("JSON.parse")],
            ..Default::default()
        };
        assert!(PpJsonDeepAssignJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_proto_key_filter_present() {
        let src: &[u8] = b"function deepMerge(t, s) {\n\
              for (const k of Object.keys(s)) {\n\
                if (k === '__proto__' || k === 'constructor') continue;\n\
                t[k] = s[k];\n\
              }\n\
              return t;\n\
            }\n\
            function run(payload) { return deepMerge({}, JSON.parse(payload)); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("JSON.parse")],
            ..Default::default()
        };
        assert!(PpJsonDeepAssignJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}
