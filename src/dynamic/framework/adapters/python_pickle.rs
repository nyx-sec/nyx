//! Python [`super::super::FrameworkAdapter`] matching pickle / yaml
//! deserialization sinks.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct PythonPickleAdapter;

const ADAPTER_NAME: &str = "python-pickle";

fn callee_is_python_deserialize(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "loads" | "load" | "unsafe_load" | "Unpickler" | "find_class"
    )
}

impl FrameworkAdapter for PythonPickleAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        let matches_call = super::any_callee_matches(summary, callee_is_python_deserialize);
        let matches_source = file_bytes.windows(b"pickle".len()).any(|w| w == b"pickle")
            || file_bytes
                .windows(b"yaml.unsafe_load".len())
                .any(|w| w == b"yaml.unsafe_load")
            || file_bytes
                .windows(b"yaml.load".len())
                .any(|w| w == b"yaml.load");
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

    fn parse_python(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_when_source_imports_pickle() {
        let src: &[u8] = b"import pickle\n\ndef run(blob):\n    return pickle.loads(blob)\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(
            PythonPickleAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"def run(x):\n    return x + 1\n";
        let tree = parse_python(src);
        let summary = FuncSummary {
            name: "run".into(),
            ..Default::default()
        };
        assert!(
            PythonPickleAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}
