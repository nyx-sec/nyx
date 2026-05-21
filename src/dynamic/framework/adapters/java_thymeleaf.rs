//! Java [`super::super::FrameworkAdapter`] matching Thymeleaf SSTI
//! sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes
//! `TemplateEngine::process(<tainted>)` (matched by the last segment
//! of the callee — the call graph normaliser drops the receiver).
//!
//! Strengthened to walk the AST for a real `method_invocation` whose
//! first positional argument names a parameter listed in
//! `summary.tainted_sink_params` or `summary.propagating_params`,
//! removing the comment-substring FP.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

pub struct JavaThymeleafAdapter;

const ADAPTER_NAME: &str = "java-thymeleaf";

fn is_thymeleaf_entry(name: &str) -> bool {
    matches!(name, "process" | "processSpring")
}

fn ast_confirms_tainted_call(root: Node<'_>, bytes: &[u8], summary: &FuncSummary) -> bool {
    let mut found = false;
    walk(root, bytes, summary, &mut found);
    found
}

fn walk(node: Node<'_>, bytes: &[u8], summary: &FuncSummary, found: &mut bool) {
    if *found {
        return;
    }
    if node.kind() == "method_invocation"
        && let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(bytes).ok())
        && is_thymeleaf_entry(name)
        && let Some(args) = node.child_by_field_name("arguments")
        && let Some(first) = first_positional_arg(args)
        && let Ok(text) = first.utf8_text(bytes)
        && super::arg_is_tainted_param(summary, text)
    {
        *found = true;
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk(child, bytes, summary, found);
    }
}

fn first_positional_arg<'a>(args: Node<'a>) -> Option<Node<'a>> {
    let mut cur = args.walk();
    args.named_children(&mut cur).next()
}

impl FrameworkAdapter for JavaThymeleafAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let cheap_filter = file_bytes
            .windows(b"org.thymeleaf".len())
            .any(|w| w == b"org.thymeleaf")
            || file_bytes
                .windows(b"TemplateEngine".len())
                .any(|w| w == b"TemplateEngine");
        if !cheap_filter {
            return None;
        }
        if !ast_confirms_tainted_call(ast, file_bytes, summary) {
            return None;
        }
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::Function,
            route: None,
            request_params: Vec::new(),
            response_writer: None,
            middleware: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary_for(name: &str, params: &[&str], tainted: &[usize]) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            param_count: params.len(),
            param_names: params.iter().map(|s| (*s).to_owned()).collect(),
            tainted_sink_params: tainted.to_vec(),
            callees: vec![crate::summary::CalleeSite::bare("process")],
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_template_engine_process() {
        let src: &[u8] = b"import org.thymeleaf.TemplateEngine;\npublic class V { public static String run(String body) { TemplateEngine e = new TemplateEngine(); return e.process(body, null); } }\n";
        let tree = parse_java(src);
        let summary = summary_for("run", &["body"], &[0]);
        assert!(JavaThymeleafAdapter
            .detect(&summary, tree.root_node(), src)
            .is_some());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] =
            b"public class V { public static String run(String b) { return b + b; } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(JavaThymeleafAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_comment_substring_with_constant_arg() {
        // The comment mentions `org.thymeleaf`; the call passes a
        // literal — no tainted parameter reaches the engine.
        let src: &[u8] = b"// org.thymeleaf.TemplateEngine is great\npublic class V { public static String run(String body) { TemplateEngine e = new TemplateEngine(); return e.process(\"static\", null); } }\n";
        let tree = parse_java(src);
        let summary = summary_for("run", &["body"], &[0]);
        assert!(JavaThymeleafAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_param_not_in_tainted_set() {
        let src: &[u8] = b"import org.thymeleaf.TemplateEngine;\npublic class V { public static String run(String body) { TemplateEngine e = new TemplateEngine(); return e.process(body, null); } }\n";
        let tree = parse_java(src);
        let summary = summary_for("run", &["body"], &[]);
        assert!(JavaThymeleafAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}
