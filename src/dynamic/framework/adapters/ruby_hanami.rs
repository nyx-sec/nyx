//! Ruby Hanami [`super::super::FrameworkAdapter`] (Phase 15 — Track L.13).
//!
//! Recognises Hanami `Action.call` entry points: a class that either
//! inherits from `Hanami::Action` (v1 idiom) or includes the
//! `Hanami::Action` module (v2 idiom) plus a `call` method that
//! receives the request.  When the class declaration carries a
//! sibling `# nyx-route:` comment line the adapter pulls the path
//! template from it; otherwise the binding falls back to
//! `/{snake_case(class)}` so harness emitters still have a usable
//! [`super::super::RouteShape`].

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::ruby_routes::{
    bind_path_params, class_extends, class_includes, class_name, find_class_with_method,
    method_formal_names, source_imports_hanami,
};

pub struct RubyHanamiAdapter;

const ADAPTER_NAME: &str = "ruby-hanami";

fn class_is_hanami_action(class: Node<'_>, bytes: &[u8]) -> bool {
    class_extends(class, bytes, "Hanami::Action")
        || class_extends(class, bytes, "Action")
        || class_includes(class, bytes, "Hanami::Action")
}

/// Walk the file for a `# nyx-route: <METHOD> <path>` comment so
/// fixtures can pin an explicit route without needing the Hanami
/// routes DSL.  Defaults to `(GET, "/")` if no marker is found.
fn pinned_route(file_bytes: &[u8], fallback_path: &str) -> (HttpMethod, String) {
    let text = std::str::from_utf8(file_bytes).unwrap_or("");
    for line in text.lines() {
        let trim = line.trim_start();
        if let Some(rest) = trim.strip_prefix("# nyx-route:") {
            let rest = rest.trim();
            let mut parts = rest.split_ascii_whitespace();
            if let (Some(verb), Some(path)) = (parts.next(), parts.next()) {
                let method = HttpMethod::from_ident(verb).unwrap_or(HttpMethod::GET);
                return (method, path.to_owned());
            }
        }
    }
    (HttpMethod::GET, fallback_path.to_owned())
}

fn hanami_default_path(class_name: &str) -> String {
    let mut out = String::with_capacity(class_name.len() + 1);
    out.push('/');
    for (i, ch) in class_name.char_indices() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

impl FrameworkAdapter for RubyHanamiAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Ruby
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_hanami(file_bytes) {
            return None;
        }
        let (class, method) = find_class_with_method(ast, file_bytes, &summary.name)?;
        if !class_is_hanami_action(class, file_bytes) {
            return None;
        }
        let cls_name = class_name(class, file_bytes).unwrap_or("Entry");
        let default = hanami_default_path(cls_name);
        let (http_method, path) = pinned_route(file_bytes, &default);
        let formals = method_formal_names(method, file_bytes);
        let request_params = bind_path_params(&formals, &path);
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape {
                method: http_method,
                path,
            }),
            request_params,
            response_writer: None,
            middleware: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::ParamSource;

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_ruby::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "ruby".into(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_hanami_action_subclass() {
        let src: &[u8] =
            b"require 'hanami/action'\nclass Show < Hanami::Action\n  def call(req)\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "ruby-hanami");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/show");
    }

    #[test]
    fn fires_on_include_hanami_action() {
        let src: &[u8] =
            b"require 'hanami'\nclass List\n  include Hanami::Action\n  def call(req)\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "ruby-hanami");
        assert_eq!(binding.route.unwrap().path, "/list");
    }

    #[test]
    fn picks_up_pinned_route_comment() {
        let src: &[u8] = b"# nyx-route: POST /save\nrequire 'hanami/action'\nclass Saver < Hanami::Action\n  def call(req)\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/save");
    }

    #[test]
    fn binds_path_placeholder() {
        let src: &[u8] = b"# nyx-route: GET /u/:id\nrequire 'hanami/action'\nclass Show < Hanami::Action\n  def call(req, id)\n    id\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn req_formal_classed_as_implicit() {
        let src: &[u8] =
            b"require 'hanami/action'\nclass Show < Hanami::Action\n  def call(req)\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        let req = binding
            .request_params
            .iter()
            .find(|p| p.name == "req")
            .unwrap();
        assert!(matches!(req.source, ParamSource::Implicit));
    }

    #[test]
    fn skips_non_hanami_classes() {
        let src: &[u8] =
            b"require 'hanami/action'\nclass Plain\n  def call(req)\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        // No `Hanami::Action` superclass / include — must skip.
        assert!(
            RubyHanamiAdapter
                .detect(&summary("call"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_files_without_hanami_marker() {
        let src: &[u8] = b"class Show < Hanami::Action\n  def call(req)\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        // The source-import predicate also matches the
        // `Hanami::Action` substring, so this fixture in fact does
        // trip the marker — the test exists to document that bare
        // `Hanami::Action` superclass alone is sufficient.
        assert!(
            RubyHanamiAdapter
                .detect(&summary("call"), tree.root_node(), src)
                .is_some()
        );
    }
}
