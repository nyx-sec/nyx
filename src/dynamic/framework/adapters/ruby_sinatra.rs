//! Ruby Sinatra [`super::super::FrameworkAdapter`] (Phase 15 — Track L.13).
//!
//! Recognises two Sinatra route shapes:
//!
//!   - Top-level block form:  `get '/run' do |payload| ... end`
//!   - Class-form modular:    `class App < Sinatra::Base\n  get '/x' do ... end\nend`
//!
//! Sinatra blocks are anonymous, so the adapter maps `summary.name`
//! to the route by treating the last path segment (with any leading
//! `:` placeholder sigil stripped) as the function name.  When that
//! deterministic match fails the adapter falls back to the first
//! route declared in the file so a single-route Sinatra script still
//! lights up the binding.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::ruby_routes::{
    bind_path_params, first_string_arg, source_imports_sinatra, verb_from_ident,
};

pub struct RubySinatraAdapter;

const ADAPTER_NAME: &str = "ruby-sinatra";

/// One route declaration extracted from the file.
struct SinatraRoute {
    method: HttpMethod,
    path: String,
    block_params: Vec<String>,
}

fn collect_routes(root: Node<'_>, bytes: &[u8]) -> Vec<SinatraRoute> {
    let mut out = Vec::new();
    visit(root, bytes, &mut out);
    out
}

fn visit(node: Node<'_>, bytes: &[u8], out: &mut Vec<SinatraRoute>) {
    if node.kind() == "call" {
        if let Some(route) = try_route(node, bytes) {
            out.push(route);
            return;
        }
    }
    // Sinatra routes live at top level or directly under a `class App <
    // Sinatra::Base` body — never inside a helper method's body.  Skip
    // descent through `method` / `singleton_method` so a stray `get '/x'
    // do ... end` nested inside `def helper ... end` (allowed by the
    // AST, never by Sinatra) is not collected as a route.
    if matches!(node.kind(), "method" | "singleton_method") {
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        visit(child, bytes, out);
    }
}

fn try_route(call: Node<'_>, bytes: &[u8]) -> Option<SinatraRoute> {
    let mut cur = call.walk();
    let mut verb: Option<HttpMethod> = None;
    let mut args: Option<Node<'_>> = None;
    let mut block: Option<Node<'_>> = None;
    for child in call.named_children(&mut cur) {
        match child.kind() {
            "identifier" => {
                if let Ok(name) = child.utf8_text(bytes) {
                    verb = verb_from_ident(name);
                }
            }
            "argument_list" => args = Some(child),
            "do_block" | "block" => block = Some(child),
            _ => {}
        }
    }
    let verb = verb?;
    let args = args?;
    // The block argument is mandatory — a route without an attached
    // block is a `routes.draw` mapping (handled by ruby_rails) and
    // must not be claimed by the Sinatra adapter.
    let block = block?;
    let path = first_string_arg(args, bytes)?;
    let block_params = block_parameter_names(block, bytes);
    Some(SinatraRoute {
        method: verb,
        path,
        block_params,
    })
}

fn block_parameter_names(block: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = block.walk();
    for child in block.named_children(&mut cur) {
        if child.kind() != "block_parameters" {
            continue;
        }
        let mut bc = child.walk();
        for p in child.named_children(&mut bc) {
            if p.kind() == "identifier" {
                if let Ok(t) = p.utf8_text(bytes) {
                    out.push(t.to_owned());
                }
            }
        }
    }
    out
}

/// Strip leading `/` and any `:` placeholder sigil, then return the
/// last path segment.  `/users/:id` → `id`, `/run` → `run`.
fn path_stem(path: &str) -> String {
    let last = path.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
    last.trim_start_matches(':')
        .trim_start_matches('*')
        .to_owned()
}

impl FrameworkAdapter for RubySinatraAdapter {
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
        if !source_imports_sinatra(file_bytes) {
            return None;
        }
        let routes = collect_routes(ast, file_bytes);
        if routes.is_empty() {
            return None;
        }
        let target = summary.name.as_str();
        let route = routes
            .iter()
            .find(|r| path_stem(&r.path) == target)
            .or_else(|| routes.first())?;
        let request_params = bind_path_params(&route.block_params, &route.path);
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape {
                method: route.method,
                path: route.path.clone(),
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
    fn fires_on_top_level_get_block() {
        let src: &[u8] = b"require 'sinatra'\nget '/run' do |payload|\n  payload\nend\n";
        let tree = parse(src);
        let binding = RubySinatraAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "ruby-sinatra");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/run");
    }

    #[test]
    fn fires_on_marker_comment() {
        let src: &[u8] =
            b"# nyx-shape: sinatra\nget '/run' do |payload|\n  payload\nend\n";
        let tree = parse(src);
        let binding = RubySinatraAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "ruby-sinatra");
    }

    #[test]
    fn binds_path_placeholder() {
        let src: &[u8] =
            b"require 'sinatra'\nget '/u/:id' do |id|\n  id\nend\n";
        let tree = parse(src);
        let binding = RubySinatraAdapter
            .detect(&summary("id"), tree.root_node(), src)
            .expect("binding");
        let id = binding.request_params.iter().find(|p| p.name == "id").unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn skips_routes_draw_without_block() {
        let src: &[u8] = b"require 'sinatra'\nget '/run', to: 'users#index'\n";
        let tree = parse(src);
        // No do/end block — the Sinatra adapter must not claim a
        // Rails-style `routes.draw` mapping.
        assert!(RubySinatraAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn falls_back_to_first_route_when_name_does_not_match_stem() {
        let src: &[u8] =
            b"require 'sinatra'\nget '/alpha' do |p|\n  p\nend\nget '/beta' do |p|\n  p\nend\n";
        let tree = parse(src);
        let binding = RubySinatraAdapter
            .detect(&summary("gamma"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().path, "/alpha");
    }

    #[test]
    fn skips_when_sinatra_not_imported() {
        let src: &[u8] = b"get '/run' do |p|\n  p\nend\n";
        let tree = parse(src);
        assert!(RubySinatraAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn post_verb_recognised() {
        let src: &[u8] = b"require 'sinatra'\npost '/save' do |body|\n  body\nend\n";
        let tree = parse(src);
        let binding = RubySinatraAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn fires_on_modular_class_form() {
        let src: &[u8] = b"require 'sinatra/base'\nclass App < Sinatra::Base\n  get '/run' do |payload|\n    payload\n  end\nend\n";
        let tree = parse(src);
        let binding = RubySinatraAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .expect("modular class-form binding");
        assert_eq!(binding.adapter, "ruby-sinatra");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/run");
    }

    #[test]
    fn skips_route_nested_in_method_body() {
        // A `get` call hidden inside a helper method's body is not a
        // Sinatra route declaration; the depth filter must reject it
        // even though `require 'sinatra'` is in scope.
        let src: &[u8] =
            b"require 'sinatra'\ndef helper\n  get '/run' do |payload|\n    payload\n  end\nend\n";
        let tree = parse(src);
        assert!(RubySinatraAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn path_stem_strips_sigils() {
        assert_eq!(path_stem("/run"), "run");
        assert_eq!(path_stem("/u/:id"), "id");
        assert_eq!(path_stem("/files/*rest"), "rest");
        assert_eq!(path_stem("/"), "");
    }
}
