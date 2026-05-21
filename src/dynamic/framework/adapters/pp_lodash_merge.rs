//! JavaScript / TypeScript [`super::super::FrameworkAdapter`] matching
//! `lodash.merge` (and the equivalent `lodash.defaultsDeep`,
//! `lodash.set`) prototype-pollution sinks.
//!
//! Phase 10 (Track J.8).  Fires when the function body invokes one of
//! the canonical lodash deep-merge entry points and the surrounding
//! source imports lodash.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

fn callee_is_lodash_merge(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "merge" | "mergeWith" | "defaultsDeep" | "set" | "setWith")
}

/// True when `receiver` looks like a lodash module handle (`_`, `lodash`,
/// or any expression where lodash sits to the left of the dot).
///
/// Filters out `state.set(k, v)` on `Map`, `cache.set(k, v)` on `LRU`,
/// `tokens.merge(...)` on a user class, and similar same-name collisions
/// outside lodash scope.  Receivers of `None` (bare callees like
/// `set(state, key, value)` from `const { set } = require('lodash')`
/// or unit-test `CalleeSite::bare`) pass through to preserve the
/// standalone-import path.
fn receiver_is_lodash(receiver: &str) -> bool {
    matches!(receiver, "_" | "lodash" | "lodashImport") || receiver.starts_with("_.")
}

fn source_imports_lodash(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"require('lodash')",
        b"require(\"lodash\")",
        b"require('lodash.merge')",
        b"require(\"lodash.merge\")",
        b"from 'lodash'",
        b"from \"lodash\"",
        b"from 'lodash/merge'",
        b"from \"lodash/merge\"",
        b"_.merge",
        b"_.defaultsDeep",
        b"_.set",
    ];
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

pub struct PpLodashMergeJsAdapter;

const JS_ADAPTER_NAME: &str = "pp-lodash-merge-js";

impl FrameworkAdapter for PpLodashMergeJsAdapter {
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
        let matches_call = super::any_callee_matches_with_receiver(
            summary,
            callee_is_lodash_merge,
            receiver_is_lodash,
        );
        let matches_source = source_imports_lodash(file_bytes);
        if matches_call && matches_source {
            Some(build_binding(JS_ADAPTER_NAME))
        } else {
            None
        }
    }
}

pub struct PpLodashMergeTsAdapter;

const TS_ADAPTER_NAME: &str = "pp-lodash-merge-ts";

impl FrameworkAdapter for PpLodashMergeTsAdapter {
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
        let matches_call = super::any_callee_matches_with_receiver(
            summary,
            callee_is_lodash_merge,
            receiver_is_lodash,
        );
        let matches_source = source_imports_lodash(file_bytes);
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
    fn fires_on_lodash_merge_call() {
        let src: &[u8] = b"const _ = require('lodash');\n\
            function run(payload) { return _.merge({}, payload); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("merge")],
            ..Default::default()
        };
        assert!(PpLodashMergeJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_function_without_lodash_import() {
        let src: &[u8] = b"function add(a, b) { return a + b; }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(PpLodashMergeJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_map_set_collision() {
        // `state.set(k, v)` on a Map collides with `_.set(state, k, v)`
        // on the bare callee name.  Receiver text `state` is not in the
        // lodash allowlist, so the adapter rejects.  The lodash import
        // is intentionally present to ensure the source-import gate
        // alone would have fired.
        let src: &[u8] = b"const _ = require('lodash');\n\
            function run(payload) {\n\
              const state = new Map();\n\
              state.set('key', payload);\n\
              return state;\n\
            }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite {
                name: "set".into(),
                receiver: Some("state".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(PpLodashMergeJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn fires_on_underscore_receiver() {
        // Receiver `_` is the canonical lodash binding.
        let src: &[u8] = b"const _ = require('lodash');\n\
            function run(payload) { return _.merge({}, payload); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite {
                name: "merge".into(),
                receiver: Some("_".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(PpLodashMergeJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_when_proto_key_filter_present() {
        let src: &[u8] = b"const _ = require('lodash');\n\
            function run(payload) {\n\
              for (const k of Object.keys(payload)) {\n\
                if (k === '__proto__' || k === 'constructor') continue;\n\
              }\n\
              return _.merge({}, payload);\n\
            }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("merge")],
            ..Default::default()
        };
        assert!(PpLodashMergeJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_object_prototype_frozen() {
        let src: &[u8] = b"const _ = require('lodash');\n\
            Object.freeze(Object.prototype);\n\
            function run(payload) { return _.merge({}, payload); }\n";
        let tree = parse_js(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("merge")],
            ..Default::default()
        };
        assert!(PpLodashMergeJsAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}
