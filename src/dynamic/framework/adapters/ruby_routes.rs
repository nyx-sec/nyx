//! Shared Ruby-route adapter helpers (Phase 15 — Track L.13).
//!
//! The Rails / Sinatra / Hanami adapters all need the same handful
//! of tree-sitter helpers: locate a `class` node by name, locate a
//! `method` inside a class body, enumerate method formal names,
//! extract the path placeholders Rails / Sinatra use (`:id`,
//! `*splat`), and bind formals to request slots.  Centralising the
//! helpers here keeps the three adapters terse and lets every
//! framework share the same placeholder-binding semantics.

use crate::dynamic::framework::{HttpMethod, ParamBinding, ParamSource};
use tree_sitter::Node;

/// True when `bytes` carries any of the well-known Rails import
/// stanzas — full framework markers (`require 'rails'`,
/// `ActionController::Base`) plus the convention-based
/// `ApplicationController` superclass the Phase 15 fixture uses.
pub fn source_imports_rails(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"require 'rails'",
            b"require \"rails\"",
            b"ActionController::Base",
            b"ActionController::API",
            b"ApplicationController",
            b"Rails.application",
            b"# nyx-shape: rails",
        ],
    )
}

/// True when `bytes` carries any of the well-known Sinatra markers
/// — `require 'sinatra'`, `Sinatra::Base` subclass, or a top-level
/// `# nyx-shape: sinatra` annotation.
pub fn source_imports_sinatra(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"require 'sinatra'",
            b"require \"sinatra\"",
            b"require 'sinatra/base'",
            b"require \"sinatra/base\"",
            b"Sinatra::Base",
            b"Sinatra::Application",
            b"# nyx-shape: sinatra",
        ],
    )
}

/// True when `bytes` carries any of the well-known Hanami markers —
/// `require 'hanami'`, `Hanami::Action` superclass / include, or a
/// `# nyx-shape: hanami` annotation.
pub fn source_imports_hanami(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"require 'hanami'",
            b"require \"hanami\"",
            b"require 'hanami/action'",
            b"require \"hanami/action\"",
            b"Hanami::Action",
            b"Hanami::Controller",
            b"# nyx-shape: hanami",
        ],
    )
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| haystack.windows(n.len()).any(|w| w == *n))
}

/// Locate the `(class_node, method_node)` pair whose method's
/// identifier equals `target`.  Returns the outermost matching class
/// so the caller can read the class superclass + class-level
/// annotations without re-walking.
pub fn find_class_with_method<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(Node<'a>, Node<'a>)> {
    let mut hit: Option<(Node<'a>, Node<'a>)> = None;
    walk_class(root, bytes, target, &mut hit);
    hit
}

fn walk_class<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    out: &mut Option<(Node<'a>, Node<'a>)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "class"
        && let Some(method) = find_method_in_class(node, bytes, target) {
            *out = Some((node, method));
            return;
        }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_class(child, bytes, target, out);
    }
}

/// Find a `method` node named `target` directly inside a `class`
/// body.  Returns `None` when the class has no body or no method of
/// that name.
pub fn find_method_in_class<'a>(class: Node<'a>, bytes: &'a [u8], target: &str) -> Option<Node<'a>> {
    let body = named_child_of_kind(class, "body_statement")?;
    let mut cur = body.walk();
    for member in body.named_children(&mut cur) {
        if member.kind() != "method" {
            continue;
        }
        if let Some(name) = method_identifier(member, bytes)
            && name == target {
                return Some(member);
            }
    }
    None
}

/// Read the leaf identifier of a `method` node.
pub fn method_identifier<'a>(method: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    let mut cur = method.walk();
    for c in method.named_children(&mut cur) {
        if c.kind() == "identifier" {
            return c.utf8_text(bytes).ok();
        }
    }
    None
}

fn named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cur = node.walk();
    node.named_children(&mut cur).find(|c| c.kind() == kind)
}

/// Read the simple name of the class declaration: the first
/// `constant` named child.
pub fn class_name<'a>(class: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    let mut cur = class.walk();
    for c in class.named_children(&mut cur) {
        if c.kind() == "constant" || c.kind() == "scope_resolution" {
            return c.utf8_text(bytes).ok();
        }
    }
    None
}

/// Read the superclass text (with `< ` prefix dropped) and reduce
/// scope-resolution chains to their leaf segment.  Returns `None`
/// when the class has no superclass.
///
/// Examples:
///   - `class Foo < Bar`                  → `Some("Bar")`
///   - `class Foo < Hanami::Action`       → `Some("Hanami::Action")`
///   - `class Foo`                        → `None`
pub fn class_superclass_text<'a>(class: Node<'a>, bytes: &'a [u8]) -> Option<String> {
    let sc = named_child_of_kind(class, "superclass")?;
    let mut cur = sc.walk();
    for c in sc.named_children(&mut cur) {
        let txt = c.utf8_text(bytes).ok()?;
        let trimmed = txt.trim();
        if !trimmed.is_empty() && trimmed != "<" {
            return Some(trimmed.to_owned());
        }
    }
    None
}

/// True when the class's superclass leaf or qualified form equals
/// `target`.  Matches both `class A < Hanami::Action` and `class A <
/// Action` when `target == "Hanami::Action"` or `"Action"`.
pub fn class_extends(class: Node<'_>, bytes: &[u8], target: &str) -> bool {
    let Some(text) = class_superclass_text(class, bytes) else {
        return false;
    };
    if text == target {
        return true;
    }
    text.rsplit("::").next().unwrap_or(text.as_str()) == target
}

/// True when the class body contains an `include` call referencing
/// `target` (Hanami v2 idiom: `include Hanami::Action`).
pub fn class_includes(class: Node<'_>, bytes: &[u8], target: &str) -> bool {
    let Some(body) = named_child_of_kind(class, "body_statement") else {
        return false;
    };
    let mut cur = body.walk();
    for member in body.named_children(&mut cur) {
        if member.kind() != "call" && member.kind() != "method_call" {
            continue;
        }
        let mut cc = member.walk();
        let mut saw_include = false;
        let mut saw_target = false;
        for child in member.named_children(&mut cc) {
            if child.kind() == "identifier" {
                if child.utf8_text(bytes).ok() == Some("include") {
                    saw_include = true;
                }
                continue;
            }
            if child.kind() == "argument_list" {
                let raw = child.utf8_text(bytes).ok().unwrap_or("");
                if raw.contains(target) {
                    saw_target = true;
                }
            }
        }
        if saw_include && saw_target {
            return true;
        }
    }
    false
}

/// Enumerate formal parameter names from a `method` node.  Skips the
/// implicit `self` receiver (Ruby methods never declare it).  Drops
/// splat / block parameters' sigil so `*args` → `args` and `&blk` →
/// `blk`.
pub fn method_formal_names(method: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(params) = named_child_of_kind(method, "method_parameters") else {
        return out;
    };
    let mut cur = params.walk();
    for fp in params.named_children(&mut cur) {
        if let Some(name) = parameter_name(fp, bytes) {
            out.push(name);
        }
    }
    out
}

fn parameter_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(bytes).ok().map(str::to_owned),
        "optional_parameter"
        | "keyword_parameter"
        | "splat_parameter"
        | "hash_splat_parameter"
        | "block_parameter"
        | "destructured_parameter" => {
            let mut cur = node.walk();
            for c in node.named_children(&mut cur) {
                if c.kind() == "identifier" {
                    return c.utf8_text(bytes).ok().map(str::to_owned);
                }
                if let Some(n) = parameter_name(c, bytes) {
                    return Some(n);
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract placeholder names from a Ruby route path template.
///
/// Supports:
///   - Rails / Sinatra `:id` style: `/u/:id`  → `id`
///   - Hanami `{id}` style:         `/u/{id}` → `id`
///   - Splat:                       `/u/*rest` → `rest`
pub fn extract_path_placeholders(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |name: String| {
        if !name.is_empty() && !out.iter().any(|n| n == &name) {
            out.push(name);
        }
    };
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b':' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > start {
                    push(path[start..j].to_owned());
                    i = j;
                    continue;
                }
            }
            b'{' => {
                if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'}') {
                    let inner = &path[i + 1..i + 1 + end];
                    let name = inner.split(':').next().unwrap_or(inner);
                    push(name.to_owned());
                    i += end + 2;
                    continue;
                }
            }
            b'*' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > start {
                    push(path[start..j].to_owned());
                    i = j;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Bind formals to request slots given a Ruby route path template.
///
/// Names matching the path placeholder list become a
/// [`ParamSource::PathSegment`]; `env`, `request`, `req`, `params`
/// formals become [`ParamSource::Implicit`]; every other formal
/// falls back to a [`ParamSource::QueryParam`] of the same name.
pub fn bind_path_params(formals: &[String], path: &str) -> Vec<ParamBinding> {
    let placeholders = extract_path_placeholders(path);
    formals
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let source = if is_implicit_formal(name) {
                ParamSource::Implicit
            } else if placeholders.iter().any(|p| p == name) {
                ParamSource::PathSegment(name.clone())
            } else {
                ParamSource::QueryParam(name.clone())
            };
            ParamBinding {
                index: idx,
                name: name.clone(),
                source,
            }
        })
        .collect()
}

fn is_implicit_formal(name: &str) -> bool {
    matches!(name, "env" | "request" | "req" | "params" | "response" | "res")
}

/// Read the first positional symbol argument (`:foo`) from an
/// `argument_list` child.  Used by the Rails router DSL to pull the
/// namespace name out of `namespace :api do ... end` and the
/// positional form of `scope :v1 do ... end`.  The returned string
/// is the symbol's identifier portion without the leading colon.
pub fn first_symbol_arg<'a>(args: Node<'a>, bytes: &'a [u8]) -> Option<String> {
    let mut cur = args.walk();
    for c in args.named_children(&mut cur) {
        if c.kind() == "simple_symbol" {
            let raw = c.utf8_text(bytes).ok()?;
            return Some(raw.trim_start_matches(':').to_owned());
        }
    }
    None
}

/// Read the first positional string-literal argument from an
/// `argument_list` child.  Used by every Ruby route adapter to pull
/// a path template out of `get '/run' do ... end` and the Rails
/// router DSL `get '/run', to: 'users#index'`.
pub fn first_string_arg<'a>(args: Node<'a>, bytes: &'a [u8]) -> Option<String> {
    let mut cur = args.walk();
    for c in args.named_children(&mut cur) {
        if c.kind() == "string" {
            return Some(string_content(c, bytes));
        }
    }
    None
}

/// Read the string content of a Ruby `string` node, stripping the
/// surrounding quote children.
pub fn string_content(node: Node<'_>, bytes: &[u8]) -> String {
    let mut cur = node.walk();
    for c in node.named_children(&mut cur) {
        if c.kind() == "string_content" {
            return c.utf8_text(bytes).unwrap_or("").to_owned();
        }
    }
    // Fall back to raw text with the outer quotes trimmed.
    let raw = node.utf8_text(bytes).unwrap_or("").trim();
    raw.trim_matches(['\'', '"']).to_owned()
}

/// Look up a keyword argument (`key: value`) inside an
/// `argument_list` and return the string content of its value.
/// Returns `None` when the kwarg is missing or its value is not a
/// string literal.
pub fn kwarg_string<'a>(args: Node<'a>, bytes: &'a [u8], key: &str) -> Option<String> {
    let mut cur = args.walk();
    for arg in args.named_children(&mut cur) {
        if arg.kind() != "pair" {
            continue;
        }
        let mut pc = arg.walk();
        let mut key_match = false;
        for child in arg.named_children(&mut pc) {
            if child.kind() == "hash_key_symbol" || child.kind() == "simple_symbol" {
                if child.utf8_text(bytes).ok() == Some(key) {
                    key_match = true;
                }
                continue;
            }
            if key_match && child.kind() == "string" {
                return Some(string_content(child, bytes));
            }
        }
    }
    None
}

/// Parse Rails-style verb names (`get`, `post`, `put`, `patch`,
/// `delete`, `head`, `options`).  Returns `None` for unrelated
/// identifiers.
pub fn verb_from_ident(ident: &str) -> Option<HttpMethod> {
    match ident {
        "get" => Some(HttpMethod::GET),
        "post" => Some(HttpMethod::POST),
        "put" => Some(HttpMethod::PUT),
        "patch" => Some(HttpMethod::PATCH),
        "delete" => Some(HttpMethod::DELETE),
        "head" => Some(HttpMethod::HEAD),
        "options" => Some(HttpMethod::OPTIONS),
        _ => None,
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

    #[test]
    fn finds_class_and_method() {
        let src: &[u8] = b"class V\n  def run(x)\n    x\n  end\nend\n";
        let tree = parse(src);
        let (class, method) = find_class_with_method(tree.root_node(), src, "run").unwrap();
        assert_eq!(class.kind(), "class");
        assert_eq!(method.kind(), "method");
    }

    #[test]
    fn class_name_reads_constant() {
        let src: &[u8] = b"class UsersController < Base\nend\n";
        let tree = parse(src);
        let mut cur = tree.root_node().walk();
        let class = tree
            .root_node()
            .children(&mut cur)
            .find(|c| c.kind() == "class")
            .unwrap();
        assert_eq!(class_name(class, src), Some("UsersController"));
    }

    #[test]
    fn class_extends_handles_scope_resolution() {
        let src: &[u8] = b"class A < Hanami::Action\nend\n";
        let tree = parse(src);
        let mut cur = tree.root_node().walk();
        let class = tree
            .root_node()
            .children(&mut cur)
            .find(|c| c.kind() == "class")
            .unwrap();
        assert!(class_extends(class, src, "Hanami::Action"));
        assert!(class_extends(class, src, "Action"));
        assert!(!class_extends(class, src, "ApplicationController"));
    }

    #[test]
    fn class_includes_detects_hanami_v2() {
        let src: &[u8] =
            b"class A\n  include Hanami::Action\n  def call(req)\n  end\nend\n";
        let tree = parse(src);
        let mut cur = tree.root_node().walk();
        let class = tree
            .root_node()
            .children(&mut cur)
            .find(|c| c.kind() == "class")
            .unwrap();
        assert!(class_includes(class, src, "Hanami::Action"));
    }

    #[test]
    fn extracts_rails_placeholders() {
        assert_eq!(extract_path_placeholders("/u/:id"), vec!["id"]);
        assert_eq!(
            extract_path_placeholders("/u/:id/posts/:slug"),
            vec!["id", "slug"]
        );
        assert_eq!(extract_path_placeholders("/files/*rest"), vec!["rest"]);
    }

    #[test]
    fn extracts_hanami_placeholders() {
        assert_eq!(extract_path_placeholders("/u/{id}"), vec!["id"]);
    }

    #[test]
    fn binds_known_placeholder_as_path_segment() {
        let formals = vec!["id".to_string(), "extra".to_string()];
        let bindings = bind_path_params(&formals, "/u/:id");
        assert!(matches!(bindings[0].source, ParamSource::PathSegment(_)));
        assert!(matches!(bindings[1].source, ParamSource::QueryParam(_)));
    }

    #[test]
    fn binds_env_request_as_implicit() {
        let formals = vec!["env".to_string(), "request".to_string(), "req".to_string()];
        let bindings = bind_path_params(&formals, "/run");
        for b in &bindings {
            assert!(matches!(b.source, ParamSource::Implicit));
        }
    }

    #[test]
    fn method_formal_names_skip_splat_sigils() {
        let src: &[u8] = b"class V\n  def run(req, *rest, &blk)\n    req\n  end\nend\n";
        let tree = parse(src);
        let (_, method) = find_class_with_method(tree.root_node(), src, "run").unwrap();
        let names = method_formal_names(method, src);
        assert_eq!(names, vec!["req", "rest", "blk"]);
    }

    #[test]
    fn kwarg_string_pulls_value() {
        let src: &[u8] = b"get '/run', to: 'users#index'\n";
        let tree = parse(src);
        let mut cur = tree.root_node().walk();
        let call = tree
            .root_node()
            .children(&mut cur)
            .find(|c| c.kind() == "call")
            .unwrap();
        let args = call.child_by_field_name("arguments").unwrap();
        assert_eq!(kwarg_string(args, src, "to"), Some("users#index".into()));
    }

    #[test]
    fn first_string_arg_pulls_literal() {
        let src: &[u8] = b"get '/run' do |p|\n  p\nend\n";
        let tree = parse(src);
        let mut cur = tree.root_node().walk();
        let call = tree
            .root_node()
            .children(&mut cur)
            .find(|c| c.kind() == "call")
            .unwrap();
        let args = call.child_by_field_name("arguments").unwrap();
        assert_eq!(first_string_arg(args, src), Some("/run".into()));
    }
}
