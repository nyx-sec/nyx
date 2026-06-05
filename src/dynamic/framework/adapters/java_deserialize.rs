//! Java [`super::super::FrameworkAdapter`] matching deserialization sinks.
//!
//! Fires when the function body invokes `ObjectInputStream.readObject`
//! or `XMLDecoder.readObject` (matched by the last segment of the
//! callee name — the call graph normaliser drops the receiver).

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct JavaDeserializeAdapter;

const ADAPTER_NAME: &str = "java-deserialize";

fn callee_is_java_deserialize(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(last, "readObject" | "fromXML" | "deserialize")
}

impl FrameworkAdapter for JavaDeserializeAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_java_deserialize);
        let matches_source = file_bytes
            .windows(b"ObjectInputStream".len())
            .any(|w| w == b"ObjectInputStream")
            || file_bytes
                .windows(b"XMLDecoder".len())
                .any(|w| w == b"XMLDecoder");
        if matches_call || matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            })
        } else {
            None
        }
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
    fn fires_when_source_imports_object_input_stream() {
        let src: &[u8] = b"import java.io.ObjectInputStream;\npublic class V { public static void run(byte[] b) {} }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        let binding = JavaDeserializeAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("must fire on ObjectInputStream source");
        assert_eq!(binding.adapter, ADAPTER_NAME);
        assert_eq!(binding.kind, EntryKind::Function);
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] =
            b"public class V { public static void run(String b) { System.out.println(b); } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(
            JavaDeserializeAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}
