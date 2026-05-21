//! Python Django [`super::super::FrameworkAdapter`] (Phase 12 — Track L.10).
//!
//! Two recognition shapes:
//!
//!   - `urls.py` registrations: `path("…", view)`, `re_path(r"…", view)`,
//!     `url(r"…", view)`.  Adapter matches the second argument's last
//!     identifier segment (so `views.list_users`, `MyView.as_view()`,
//!     and bare `list_users` all hit the same predicate) against
//!     `summary.name`.
//!   - Class-based views: a method named `get` / `post` / `put` /
//!     `patch` / `delete` / `head` / `options` on a class extending
//!     `View` / `APIView` / `ViewSet` / `TemplateView`.  The route
//!     path is left as `"/"` when no matching `urls.py` entry can be
//!     found in the same file — the runner is still able to drive
//!     the view through `RequestFactory`, which does not require a
//!     real URL conf.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::python_routes::{
    bind_path_params, find_python_function, first_string_arg, function_formal_names,
    source_imports_django,
};

pub struct PythonDjangoAdapter;

const ADAPTER_NAME: &str = "python-django";

fn http_method_from_method_name(name: &str) -> Option<HttpMethod> {
    HttpMethod::from_ident(name)
}

fn class_super_looks_like_view(text: &str) -> bool {
    text.contains("View")
        || text.contains("APIView")
        || text.contains("ViewSet")
        || text.contains("TemplateView")
        || text.contains("ListView")
        || text.contains("DetailView")
        || text.contains("CreateView")
        || text.contains("UpdateView")
        || text.contains("DeleteView")
}

fn enclosing_class<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == "class_definition" {
            return Some(p);
        }
        cur = p.parent();
    }
    None
}

/// Walk `urls.py`-style registrations (`path(...)`, `re_path(...)`,
/// `url(...)`) and return `Some(path_template)` when one of them
/// references `target` as the second positional argument.  When
/// `class_target` is `Some`, an `as_view`-based registration whose
/// receiver class matches is also accepted (so `path("users/<id>",
/// UserView.as_view())` binds the class's method-as-view).
fn url_template_for(
    root: Node<'_>,
    bytes: &[u8],
    target: &str,
    class_target: Option<&str>,
) -> Option<String> {
    let mut hit: Option<String> = None;
    walk_url_registrations(root, bytes, target, class_target, &mut hit);
    hit
}

fn walk_url_registrations(
    node: Node<'_>,
    bytes: &[u8],
    target: &str,
    class_target: Option<&str>,
    out: &mut Option<String>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "call"
        && let Some(callee) = node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(bytes).ok())
    {
        let last = callee.rsplit_once('.').map(|(_, s)| s).unwrap_or(callee);
        if matches!(last, "path" | "re_path" | "url")
            && let Some(args) = node.child_by_field_name("arguments") {
                let positional = positional_args(args);
                if positional.len() >= 2 {
                    let view_arg = positional[1];
                    if view_arg_references(view_arg, bytes, target, class_target)
                        && let Some(template) = first_string_arg(args, bytes) {
                            *out = Some(template);
                            return;
                        }
                }
            }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_url_registrations(child, bytes, target, class_target, out);
    }
}

fn positional_args(args: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut cur = args.walk();
    for c in args.named_children(&mut cur) {
        if c.kind() != "keyword_argument" {
            out.push(c);
        }
    }
    out
}

fn view_arg_references(
    node: Node<'_>,
    bytes: &[u8],
    target: &str,
    class_target: Option<&str>,
) -> bool {
    let Ok(text) = node.utf8_text(bytes) else {
        return false;
    };
    let trimmed = text.trim();
    // `MyView.as_view()` (with or without args) → strip trailing `()`
    // and `.as_view` so the residual is the class name.
    if let Some(class) = trimmed
        .strip_suffix(')')
        .and_then(|s| s.rfind('(').map(|i| &s[..i]))
        .and_then(|s| s.strip_suffix(".as_view"))
        && let Some(ct) = class_target
            && class.rsplit_once('.').map(|(_, s)| s).unwrap_or(class) == ct
        {
            return true;
        }
    let stripped = trimmed.trim_end_matches("()");
    let last = stripped.rsplit_once('.').map(|(_, s)| s).unwrap_or(stripped);
    last == target || stripped == target
}

impl FrameworkAdapter for PythonDjangoAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Python
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_django(file_bytes) {
            return None;
        }
        let (func_node, _) = find_python_function(ast, file_bytes, &summary.name)?;

        // Class-based view: method named after an HTTP verb inside a
        // View-derived class.
        let enclosing = enclosing_class(func_node);
        let cbv_class_name = enclosing
            .and_then(|c| c.child_by_field_name("name"))
            .and_then(|n| n.utf8_text(file_bytes).ok())
            .map(str::to_owned);
        let cbv_method = http_method_from_method_name(&summary.name).filter(|_| {
            enclosing
                .and_then(|c| c.child_by_field_name("superclasses"))
                .map(|supers| {
                    let mut cur = supers.walk();
                    supers.named_children(&mut cur).any(|sup| {
                        sup.utf8_text(file_bytes)
                            .map(class_super_looks_like_view)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });

        // Pick (method, path) from one of:
        //   - urls.py registration referencing the function
        //   - urls.py `ClassName.as_view()` registration referencing the enclosing class
        //   - class-based view method name (path falls back to `/`)
        let url_template = url_template_for(
            ast,
            file_bytes,
            &summary.name,
            cbv_class_name.as_deref(),
        );

        let (method, path) = if let Some(m) = cbv_method {
            (m, url_template.unwrap_or_else(|| "/".to_owned()))
        } else if let Some(template) = url_template {
            (HttpMethod::GET, template)
        } else {
            return None;
        };

        let formals = function_formal_names(func_node, file_bytes);
        let request_params = bind_path_params(&formals, &path);

        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape { method, path }),
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
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "python".into(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_function_view_with_path_registration() {
        let src: &[u8] = b"from django.http import HttpResponse\nfrom django.urls import path\ndef list_users(request):\n    return HttpResponse(\"ok\")\nurlpatterns = [path(\"users/\", list_users)]\n";
        let tree = parse(src);
        let binding = PythonDjangoAdapter
            .detect(&summary("list_users"), tree.root_node(), src)
            .unwrap();
        assert_eq!(binding.route.as_ref().unwrap().path, "users/");
        assert_eq!(binding.route.as_ref().unwrap().method, HttpMethod::GET);
        let request_arg = binding
            .request_params
            .iter()
            .find(|p| p.name == "request")
            .unwrap();
        assert!(matches!(request_arg.source, ParamSource::Implicit));
    }

    #[test]
    fn fires_on_class_based_view_get_method() {
        let src: &[u8] = b"from django.views import View\nfrom django.http import HttpResponse\nclass UserView(View):\n    def get(self, request, id):\n        return HttpResponse(id)\n";
        let tree = parse(src);
        let binding = PythonDjangoAdapter
            .detect(&summary("get"), tree.root_node(), src)
            .unwrap();
        assert_eq!(binding.route.as_ref().unwrap().method, HttpMethod::GET);
    }

    #[test]
    fn fires_on_as_view_registration() {
        let src: &[u8] = b"from django.views import View\nfrom django.urls import path\nclass UserView(View):\n    def get(self, request, id):\n        return None\nurlpatterns = [path(\"users/<int:id>/\", UserView.as_view())]\n";
        let tree = parse(src);
        let binding = PythonDjangoAdapter
            .detect(&summary("get"), tree.root_node(), src)
            .unwrap();
        let route = binding.route.unwrap();
        assert_eq!(route.path, "users/<int:id>/");
        let id_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id_binding.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn skips_when_django_not_imported() {
        let src: &[u8] = b"def list_users(request):\n    return None\n";
        let tree = parse(src);
        assert!(PythonDjangoAdapter
            .detect(&summary("list_users"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_plain_helper_function() {
        let src: &[u8] = b"from django.http import HttpResponse\ndef helper(x):\n    return HttpResponse(x)\n";
        let tree = parse(src);
        assert!(PythonDjangoAdapter
            .detect(&summary("helper"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_request_first_formal_without_url_registration() {
        // Regression guard: an earlier revision stamped any function
        // whose first formal was `request` as `(GET, "/")`.  The
        // brief never prescribed that fallback and it fires on
        // utility helpers (`def authenticated(request, perm): ...`,
        // decorator wrappers, middleware-shaped helpers) that are not
        // routes.  Without a matching `urls.py` registration or a
        // CBV-method shape, the adapter must return `None` so the
        // pipeline surfaces `SpecDerivationFailed`.
        let src: &[u8] = b"from django.http import HttpResponse\ndef authenticated(request, perm):\n    return HttpResponse(perm)\n";
        let tree = parse(src);
        assert!(PythonDjangoAdapter
            .detect(&summary("authenticated"), tree.root_node(), src)
            .is_none());
    }
}
