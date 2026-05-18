//! Java [`super::super::FrameworkAdapter`] matching XXE-prone XML parser
//! constructions.
//!
//! Phase 05 (Track J.3).  Fires when the function body invokes a
//! `DocumentBuilder.parse` / `SAXParser.parse` / `XMLInputFactory`
//! call site and the surrounding source pulls in one of the
//! `javax.xml.parsers` / `org.w3c.dom` / `org.xml.sax` packages —
//! i.e. an XML parser that, by default and without
//! `disallow-doctype-decl`, expands external entities.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct XxeJavaAdapter;

const ADAPTER_NAME: &str = "xxe-java";

fn callee_is_xml_parse(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "parse"
            | "newDocumentBuilder"
            | "newSAXParser"
            | "createXMLEventReader"
            | "createXMLStreamReader"
            | "newInstance"
    )
}

fn source_imports_xml_parser(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"javax.xml.parsers",
        b"DocumentBuilderFactory",
        b"DocumentBuilder",
        b"SAXParserFactory",
        b"XMLInputFactory",
        b"org.xml.sax",
        b"org.w3c.dom",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for XxeJavaAdapter {
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
        let matches_call = super::any_callee_matches(summary, callee_is_xml_parse);
        let matches_source = source_imports_xml_parser(file_bytes);
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
        // Fall-back: source clearly imports the XXE-prone parser even
        // when the call-graph summary did not capture the parse call.
        if matches_source
            && file_bytes
                .windows(b".parse(".len())
                .any(|w| w == b".parse(")
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
    fn fires_on_document_builder_parse() {
        let src: &[u8] = b"import javax.xml.parsers.DocumentBuilderFactory;\n\
            public class V {\n  public static void run(byte[] b) throws Exception {\n\
                DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n\
                f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(b));\n\
            }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("parse")],
            ..Default::default()
        };
        let binding = XxeJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .expect("must fire on DocumentBuilder.parse fixture");
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
        assert!(XxeJavaAdapter
            .detect(&summary, tree.root_node(), src)
            .is_none());
    }
}
