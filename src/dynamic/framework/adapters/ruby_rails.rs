//! Ruby Rails [`super::super::FrameworkAdapter`] (Phase 15 — Track L.13).
//!
//! Recognises controller-style action methods declared inside a
//! class that inherits from `ApplicationController` /
//! `ActionController::Base` / `ActionController::API`.  When the
//! same file (or, in the Phase 15 fixture path, the same
//! `routes.draw` block we can see at top level) declares a matching
//! `get '/path', to: 'controller#action'` mapping the adapter pulls
//! the explicit path; otherwise the binding falls back to the
//! conventional `/{action}` route + `GET` method so harness
//! emitters still have a usable [`super::super::RouteShape`].

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::ruby_routes::{
    bind_path_params, class_extends, class_name, find_class_with_method, first_string_arg,
    kwarg_string, method_formal_names, source_imports_rails, verb_from_ident,
};

pub struct RubyRailsAdapter;

const ADAPTER_NAME: &str = "ruby-rails";

fn class_is_rails_controller(class: Node<'_>, bytes: &[u8]) -> bool {
    [
        "ApplicationController",
        "ActionController::Base",
        "ActionController::API",
        "Base",
        "API",
    ]
    .iter()
    .any(|t| class_extends(class, bytes, t))
}

/// Walk the file's top-level `call` nodes looking for a
/// `Rails.application.routes.draw` block or bare `get / post / ...`
/// dispatch lines, and return the first `(method, path)` whose
/// `to: 'controller#action'` kwarg references the target.  Returns
/// `None` when no route mapping is present (the caller then falls
/// back to the conventional `/{action}` shape).
fn find_route_mapping<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    controller: &str,
    action: &str,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    visit_routes(root, bytes, controller, action, &mut hit);
    hit
}

fn visit_routes<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    controller: &str,
    action: &str,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call" {
        if let Some(found) = try_route_mapping(node, bytes, controller, action) {
            *out = Some(found);
            return;
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        visit_routes(child, bytes, controller, action, out);
    }
}

fn try_route_mapping<'a>(
    call: Node<'a>,
    bytes: &'a [u8],
    controller: &str,
    action: &str,
) -> Option<(HttpMethod, String)> {
    let mut cur = call.walk();
    let mut verb: Option<HttpMethod> = None;
    let mut args: Option<Node<'a>> = None;
    for child in call.named_children(&mut cur) {
        match child.kind() {
            "identifier" => {
                if let Ok(name) = child.utf8_text(bytes) {
                    verb = verb_from_ident(name);
                }
            }
            "argument_list" => args = Some(child),
            _ => {}
        }
    }
    let verb = verb?;
    let args = args?;
    let path = first_string_arg(args, bytes)?;
    let to = kwarg_string(args, bytes, "to")?;
    let (ctrl, act) = to.split_once('#')?;
    if controller_matches(ctrl, controller) && act == action {
        return Some((verb, path));
    }
    None
}

/// Match a routes-DSL `controller` name against the Ruby controller
/// class.  Rails convention strips the trailing `Controller` suffix
/// and snake-cases:
///   - `UsersController`         → `users`
///   - `Api::UsersController`    → `api/users`
fn controller_matches(routes_ctrl: &str, controller_class: &str) -> bool {
    let expected = rails_controller_path(controller_class);
    routes_ctrl == expected
}

fn rails_controller_path(class_name: &str) -> String {
    let stripped = class_name
        .strip_suffix("Controller")
        .unwrap_or(class_name);
    // Rails routes use the singular-segment lower form joined by `/`
    // for module-namespaced controllers (`Api::Users` → `api/users`).
    let segments: Vec<String> = stripped
        .split("::")
        .map(|seg| snake_case(seg))
        .filter(|s| !s.is_empty())
        .collect();
    segments.join("/")
}

fn snake_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    for (i, ch) in input.char_indices() {
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

impl FrameworkAdapter for RubyRailsAdapter {
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
        if !source_imports_rails(file_bytes) {
            return None;
        }
        let (class, method) = find_class_with_method(ast, file_bytes, &summary.name)?;
        if !class_is_rails_controller(class, file_bytes) {
            return None;
        }
        let controller = class_name(class, file_bytes)?;

        let (http_method, path) = find_route_mapping(ast, file_bytes, controller, &summary.name)
            .unwrap_or_else(|| (HttpMethod::GET, format!("/{}", summary.name)));

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
    fn fires_on_application_controller_subclass() {
        let src: &[u8] =
            b"class UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "ruby-rails");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/index");
    }

    #[test]
    fn fires_on_action_controller_base_subclass() {
        let src: &[u8] =
            b"class UsersController < ActionController::Base\n  def show\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "ruby-rails");
    }

    #[test]
    fn picks_up_routes_draw_mapping() {
        let src: &[u8] = b"Rails.application.routes.draw do\n  get '/run', to: 'users#index'\nend\n\nclass UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/run");
        assert_eq!(route.method, HttpMethod::GET);
    }

    #[test]
    fn routes_draw_post_picks_post_verb() {
        let src: &[u8] = b"Rails.application.routes.draw do\n  post '/save', to: 'users#save'\nend\n\nclass UsersController < ApplicationController\n  def save\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn routes_draw_with_path_placeholder_binds_segment() {
        let src: &[u8] = b"Rails.application.routes.draw do\n  get '/u/:id', to: 'users#show'\nend\n\nclass UsersController < ApplicationController\n  def show(id)\n    id\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/u/:id");
        let id = binding.request_params.iter().find(|p| p.name == "id").unwrap();
        assert!(matches!(id.source, crate::dynamic::framework::ParamSource::PathSegment(_)));
    }

    #[test]
    fn skips_when_class_is_not_a_controller() {
        let src: &[u8] = b"class Foo\n  def bar\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        assert!(RubyRailsAdapter
            .detect(&summary("bar"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_when_target_method_not_present() {
        let src: &[u8] =
            b"class UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        assert!(RubyRailsAdapter
            .detect(&summary("missing"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_files_without_rails_marker() {
        let src: &[u8] =
            b"class UsersController < Object\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        assert!(RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn rails_controller_path_drops_suffix_and_snake_cases() {
        assert_eq!(rails_controller_path("UsersController"), "users");
        assert_eq!(rails_controller_path("UserPostsController"), "user_posts");
        assert_eq!(
            rails_controller_path("Api::UsersController"),
            "api/users"
        );
        assert_eq!(rails_controller_path("Foo"), "foo");
    }
}
