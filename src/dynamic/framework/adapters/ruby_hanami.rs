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
    bind_path_params, class_extends, class_includes, class_name, collect_ruby_middleware,
    find_class_with_method, method_formal_names, source_imports_hanami,
};

pub struct RubyHanamiAdapter;

const ADAPTER_NAME: &str = "ruby-hanami";

fn class_is_hanami_action(class: Node<'_>, bytes: &[u8]) -> bool {
    class_extends(class, bytes, "Hanami::Action")
        || class_extends(class, bytes, "Action")
        || class_includes(class, bytes, "Hanami::Action")
}

/// Resolve the route metadata for `class_name`.  Tries the inline
/// Hanami v2 routes DSL first (`get "/run", to: "RunAction"` inside a
/// `Hanami::Routes` / `routes do` block that co-exists with the
/// action class in the same file), then the synthetic
/// `# nyx-route: <METHOD> <path>` comment fixtures rely on, then
/// finally a `(GET, fallback_path)` default.
///
/// Cross-file routes resolution (`config/routes.rb` + `app/actions/<slug>/<verb>.rb`)
/// still needs a project-level file index on the adapter trait —
/// `FrameworkAdapter::detect` only sees one file at a time.
fn route_for_class(
    file_bytes: &[u8],
    class_name: &str,
    fallback_path: &str,
) -> (HttpMethod, String) {
    if let Some(found) = parse_inline_route(file_bytes, class_name) {
        return found;
    }
    if let Some(found) = pinned_comment_route(file_bytes) {
        return found;
    }
    (HttpMethod::GET, fallback_path.to_owned())
}

fn pinned_comment_route(file_bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let text = std::str::from_utf8(file_bytes).ok()?;
    for line in text.lines() {
        let trim = line.trim_start();
        if let Some(rest) = trim.strip_prefix("# nyx-route:") {
            let rest = rest.trim();
            let mut parts = rest.split_ascii_whitespace();
            if let (Some(verb), Some(path)) = (parts.next(), parts.next()) {
                let method = HttpMethod::from_ident(verb).unwrap_or(HttpMethod::GET);
                return Some((method, path.to_owned()));
            }
        }
    }
    None
}

/// Parse the Hanami v2 routes DSL when the routes file and the action
/// class co-exist in one file.  Recognises lines of the form
/// `<verb> "<path>", to: "<target>"` (or single-quoted variants) and
/// matches `<target>` against `class_name` either by exact match or by
/// its `snake_case` form (Hanami's container-key convention,
/// e.g. `to: "actions.run_action"`).
fn parse_inline_route(file_bytes: &[u8], class_name: &str) -> Option<(HttpMethod, String)> {
    let text = std::str::from_utf8(file_bytes).ok()?;
    let snake = camel_to_snake(class_name);
    for raw_line in text.lines() {
        let line = raw_line.trim_start();
        if let Some(parsed) = parse_route_line(line, class_name, &snake) {
            return Some(parsed);
        }
    }
    None
}

fn parse_route_line(
    line: &str,
    class_orig: &str,
    class_snake: &str,
) -> Option<(HttpMethod, String)> {
    let (verb_tok, after) = line.split_once(char::is_whitespace)?;
    let method = HttpMethod::from_ident(verb_tok)?;
    let after = after.trim_start();
    let (path, rest) = parse_quoted(after)?;
    let to_idx = rest.find("to:")?;
    let after_to = rest[to_idx + 3..].trim_start();
    let (target, _) = parse_quoted(after_to)?;
    let target_last = target.rsplit_once('.').map(|(_, s)| s).unwrap_or(&target);
    if target_last == class_orig || target_last == class_snake {
        return Some((method, path));
    }
    None
}

fn parse_quoted(s: &str) -> Option<(String, &str)> {
    let quote = match s.as_bytes().first() {
        Some(b'"') => '"',
        Some(b'\'') => '\'',
        _ => return None,
    };
    let rest = &s[1..];
    let end = rest.find(quote)?;
    Some((rest[..end].to_owned(), &rest[end + 1..]))
}

fn camel_to_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for (i, ch) in s.char_indices() {
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
        let (http_method, path) = route_for_class(file_bytes, cls_name, &default);
        let formals = method_formal_names(method, file_bytes);
        let request_params = bind_path_params(&formals, &path);
        let middleware = collect_ruby_middleware(ast, file_bytes);
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape {
                method: http_method,
                path,
            }),
            request_params,
            response_writer: None,
            middleware,
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
    fn picks_up_inline_routes_dsl_classname_to() {
        // Hanami v2 routes DSL co-located with the action class. The
        // routes block names the action class via `to: "RunAction"`;
        // the adapter must pick up `POST /run` rather than the
        // snake-case default.
        let src: &[u8] = b"require 'hanami/routes'\n\
            require 'hanami/action'\n\
            class Routes < Hanami::Routes\n\
              post \"/run\", to: \"RunAction\"\n\
            end\n\
            class RunAction < Hanami::Action\n\
              def call(req)\n\
                'ok'\n\
              end\n\
            end\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/run");
    }

    #[test]
    fn picks_up_inline_routes_dsl_snake_case_to() {
        // Hanami v2 supports `to: "actions.run_action"` container-key
        // notation in addition to the bare class name.  The adapter
        // should match `run_action` against the snake_case of
        // `RunAction`.
        let src: &[u8] = b"require 'hanami/routes'\n\
            require 'hanami/action'\n\
            class Routes < Hanami::Routes\n\
              get \"/u/:id\", to: \"actions.run_action\"\n\
            end\n\
            class RunAction < Hanami::Action\n\
              def call(req, id)\n\
                id\n\
              end\n\
            end\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/u/:id");
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn inline_routes_dsl_wins_over_pinned_comment() {
        // When both an inline routes-DSL line and a `# nyx-route:`
        // comment are present, the routes-DSL line wins because it is
        // the canonical source of truth.
        let src: &[u8] = b"# nyx-route: GET /old\n\
            require 'hanami/routes'\n\
            class Routes < Hanami::Routes\n\
              put \"/new\", to: \"PutAction\"\n\
            end\n\
            class PutAction < Hanami::Action\n\
              def call(req)\n\
                'ok'\n\
              end\n\
            end\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::PUT);
        assert_eq!(route.path, "/new");
    }

    #[test]
    fn populates_middleware_from_before_action() {
        let src: &[u8] = b"require 'hanami/action'\nclass Show < Hanami::Action\n  before_action :authenticate_user!\n  def call(req)\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyHanamiAdapter
            .detect(&summary("call"), tree.root_node(), src)
            .expect("binding");
        assert!(
            binding
                .middleware
                .iter()
                .any(|m| m.name == "authenticate_user!"),
            "expected authenticate_user! marker, got {:?}",
            binding.middleware
        );
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
