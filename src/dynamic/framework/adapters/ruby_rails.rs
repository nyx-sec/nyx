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
    bind_path_params, class_extends, class_name, collect_ruby_middleware, find_class_with_method,
    first_string_arg, first_symbol_arg, kwarg_string, method_formal_names, source_imports_rails,
    verb_from_ident,
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
/// `to: 'controller#action'` kwarg references the target.  Respects
/// `namespace :api do ... end` and `scope :v1 do ... end` /
/// `scope path: '/v1' do ... end` nesting so a route declared inside
/// such a block resolves against the prefixed path + controller name
/// Rails actually mounts it under.  Returns `None` when no mapping
/// is present (the caller then falls back to the conventional
/// `/{action}` shape).
fn find_route_mapping<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    controller: &str,
    action: &str,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    visit_routes(root, bytes, controller, action, "", "", &mut hit);
    hit
}

fn visit_routes<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    controller: &str,
    action: &str,
    path_prefix: &str,
    ctrl_prefix: &str,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call" {
        if let Some((kind, ident)) = route_nesting_kind(node, bytes) {
            let (path_pfx, ctrl_pfx) = match kind {
                NestingKind::Namespace => (
                    format!("{path_prefix}/{ident}"),
                    format!("{ctrl_prefix}{ident}/"),
                ),
                NestingKind::ScopeSymbol => (
                    format!("{path_prefix}/{ident}"),
                    format!("{ctrl_prefix}{ident}/"),
                ),
                NestingKind::ScopePath => {
                    (format!("{path_prefix}/{ident}"), ctrl_prefix.to_owned())
                }
            };
            recurse_into_block(node, bytes, controller, action, &path_pfx, &ctrl_pfx, out);
            return;
        }
        if let Some(found) =
            try_route_mapping(node, bytes, controller, action, path_prefix, ctrl_prefix)
        {
            *out = Some(found);
            return;
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        visit_routes(
            child,
            bytes,
            controller,
            action,
            path_prefix,
            ctrl_prefix,
            out,
        );
    }
}

enum NestingKind {
    Namespace,
    ScopeSymbol,
    ScopePath,
}

/// If `call` is a routes-DSL nesting block (`namespace :api do ... end`,
/// `scope :v1 do ... end`, or `scope path: '/v1' do ... end`) return
/// the kind + the extracted identifier (a bare token for namespace /
/// symbol-scope, a leading-slash-stripped path for path-scope).
fn route_nesting_kind<'a>(call: Node<'a>, bytes: &'a [u8]) -> Option<(NestingKind, String)> {
    let mut cur = call.walk();
    let mut ident: Option<&str> = None;
    let mut args: Option<Node<'a>> = None;
    for child in call.named_children(&mut cur) {
        match child.kind() {
            "identifier" => ident = child.utf8_text(bytes).ok(),
            "argument_list" => args = Some(child),
            _ => {}
        }
    }
    let ident = ident?;
    let args = args?;
    match ident {
        "namespace" => {
            let sym = first_symbol_arg(args, bytes)?;
            Some((NestingKind::Namespace, sym))
        }
        "scope" => {
            if let Some(sym) = first_symbol_arg(args, bytes) {
                Some((NestingKind::ScopeSymbol, sym))
            } else {
                let path = kwarg_string(args, bytes, "path")?;
                let trimmed = path.trim_start_matches('/').to_owned();
                if trimmed.is_empty() {
                    return None;
                }
                Some((NestingKind::ScopePath, trimmed))
            }
        }
        _ => None,
    }
}

fn recurse_into_block<'a>(
    call: Node<'a>,
    bytes: &'a [u8],
    controller: &str,
    action: &str,
    path_prefix: &str,
    ctrl_prefix: &str,
    out: &mut Option<(HttpMethod, String)>,
) {
    let mut cur = call.walk();
    for child in call.named_children(&mut cur) {
        if child.kind() == "do_block" || child.kind() == "block" {
            visit_routes(
                child,
                bytes,
                controller,
                action,
                path_prefix,
                ctrl_prefix,
                out,
            );
        }
    }
}

fn try_route_mapping<'a>(
    call: Node<'a>,
    bytes: &'a [u8],
    controller: &str,
    action: &str,
    path_prefix: &str,
    ctrl_prefix: &str,
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
    let full_ctrl = format!("{ctrl_prefix}{ctrl}");
    if controller_matches(&full_ctrl, controller) && act == action {
        let full_path = if path_prefix.is_empty() {
            path
        } else {
            format!("{}/{}", path_prefix, path.trim_start_matches('/'))
        };
        return Some((verb, full_path));
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
    let stripped = class_name.strip_suffix("Controller").unwrap_or(class_name);
    // Rails routes use the singular-segment lower form joined by `/`
    // for module-namespaced controllers (`Api::Users` → `api/users`).
    let segments: Vec<String> = stripped
        .split("::")
        .map(snake_case)
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
        let middleware = collect_ruby_middleware(ast, file_bytes);

        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape::single(http_method, path)),
            request_params,
            response_writer: None,
            middleware,
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
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(
            id.source,
            crate::dynamic::framework::ParamSource::PathSegment(_)
        ));
    }

    #[test]
    fn routes_draw_namespace_applies_prefix_to_path_and_controller() {
        let src: &[u8] = b"Rails.application.routes.draw do\n  namespace :api do\n    get '/users', to: 'users#index'\n  end\nend\n\nclass Api::UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/api/users");
        assert_eq!(route.method, HttpMethod::GET);
    }

    #[test]
    fn routes_draw_scope_path_prefixes_path_only() {
        let src: &[u8] = b"Rails.application.routes.draw do\n  scope path: '/v1' do\n    get '/users', to: 'users#index'\n  end\nend\n\nclass UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/v1/users");
    }

    #[test]
    fn routes_draw_scope_symbol_prefixes_path_and_controller() {
        let src: &[u8] = b"Rails.application.routes.draw do\n  scope :admin do\n    get '/users', to: 'users#index'\n  end\nend\n\nclass Admin::UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/admin/users");
    }

    #[test]
    fn routes_draw_nested_namespaces_compose_prefixes() {
        let src: &[u8] = b"Rails.application.routes.draw do\n  namespace :api do\n    namespace :v1 do\n      get '/users', to: 'users#index'\n    end\n  end\nend\n\nclass Api::V1::UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/api/v1/users");
    }

    #[test]
    fn skips_when_class_is_not_a_controller() {
        let src: &[u8] = b"class Foo\n  def bar\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        assert!(
            RubyRailsAdapter
                .detect(&summary("bar"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_target_method_not_present() {
        let src: &[u8] =
            b"class UsersController < ApplicationController\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        assert!(
            RubyRailsAdapter
                .detect(&summary("missing"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_files_without_rails_marker() {
        let src: &[u8] = b"class UsersController < Object\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        assert!(
            RubyRailsAdapter
                .detect(&summary("index"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn populates_middleware_from_before_action() {
        let src: &[u8] = b"class UsersController < ApplicationController\n  before_action :authenticate_user!\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.middleware.len(), 1);
        assert_eq!(binding.middleware[0].name, "authenticate_user!");
    }

    #[test]
    fn populates_middleware_from_protect_from_forgery() {
        let src: &[u8] = b"class A < ApplicationController\n  protect_from_forgery with: :exception\n  def index\n    'ok'\n  end\nend\n";
        let tree = parse(src);
        let binding = RubyRailsAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        assert!(
            binding
                .middleware
                .iter()
                .any(|m| m.name == "protect_from_forgery"),
            "expected protect_from_forgery marker, got {:?}",
            binding.middleware
        );
    }

    #[test]
    fn rails_controller_path_drops_suffix_and_snake_cases() {
        assert_eq!(rails_controller_path("UsersController"), "users");
        assert_eq!(rails_controller_path("UserPostsController"), "user_posts");
        assert_eq!(rails_controller_path("Api::UsersController"), "api/users");
        assert_eq!(rails_controller_path("Foo"), "foo");
    }
}
