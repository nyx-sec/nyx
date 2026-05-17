//! Java [`super::super::FrameworkAdapter`] matching Thymeleaf SSTI
//! sinks.
//!
//! Phase 04 (Track J.2).  Fires when the function body invokes
//! `TemplateEngine::process(<tainted>)` (matched by the last segment
//! of the callee — the call graph normaliser drops the receiver).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct JavaThymeleafAdapter;

const ADAPTER_NAME: &str = "java-thymeleaf";

fn callee_is_thymeleaf(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "process" | "processSpring")
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
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_thymeleaf);
        let matches_source = file_bytes
            .windows(b"org.thymeleaf".len())
            .any(|w| w == b"org.thymeleaf")
            || file_bytes
                .windows(b"TemplateEngine".len())
                .any(|w| w == b"TemplateEngine");
        if matches_call && matches_source {
            return Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            });
        }
        if matches_source
            && file_bytes
                .windows(b".process(".len())
                .any(|w| w == b".process(")
        {
            return Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            });
        }
        None
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

    #[test]
    fn fires_on_template_engine_process() {
        let src: &[u8] = b"import org.thymeleaf.TemplateEngine;\npublic class V { public static String run(String body) { TemplateEngine e = new TemplateEngine(); return e.process(body, null); } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("process")],
            ..Default::default()
        };
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
}
