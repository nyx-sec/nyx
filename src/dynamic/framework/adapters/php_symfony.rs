//! Symfony [`super::super::FrameworkAdapter`] (Phase 16 — Track L.14).
//!
//! Recognises `#[Route('/path', methods: ['GET'])]` PHP attributes on
//! controller methods or top-level functions.  Class-level
//! `#[Route('/api')]` prefix is concatenated with the method-level
//! path so `#[Route('/api')] + #[Route('/x')]` produces `"/api/x"`.
//!
//! YAML routing (`config/routes.yaml`) is not handled in v1 — the
//! attribute path covers >90% of modern Symfony 5/6/7 controller
//! declarations and is the only path the harness needs to bind a
//! single route inside a single source file.  YAML lookup belongs to
//! a later phase once the framework adapter trait gains access to
//! the project-level config file list.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::php_routes::{
    bind_php_path_params, collect_php_middleware, find_php_function, first_php_string_arg,
    iter_php_attributes, methods_named_arg, php_formal_names, source_imports_symfony,
};

pub struct PhpSymfonyAdapter;

const ADAPTER_NAME: &str = "php-symfony";

fn route_attribute_shape(node: Node<'_>, bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    iter_php_attributes(node, bytes, |ann, name| {
        if hit.is_some() || name != "Route" {
            return;
        }
        let Some(args) = ann.child_by_field_name("parameters") else {
            return;
        };
        let path = first_php_string_arg(args, bytes).unwrap_or_default();
        let method = methods_named_arg(args, bytes).unwrap_or(HttpMethod::GET);
        hit = Some((method, path));
    });
    hit
}

fn join_route_path(class_path: &str, method_path: &str) -> String {
    if class_path.is_empty() {
        return method_path.to_owned();
    }
    if method_path.is_empty() {
        return class_path.to_owned();
    }
    format!(
        "{}/{}",
        class_path.trim_end_matches('/'),
        method_path.trim_start_matches('/')
    )
}

impl FrameworkAdapter for PhpSymfonyAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Php
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_symfony(file_bytes) {
            return None;
        }
        let (func_node, class) = find_php_function(ast, file_bytes, &summary.name)?;
        let (http_method, method_path) = route_attribute_shape(func_node, file_bytes)?;
        let class_prefix = class
            .and_then(|c| route_attribute_shape(c, file_bytes))
            .map(|(_, p)| p)
            .unwrap_or_default();
        let path = join_route_path(&class_prefix, &method_path);
        let formals = php_formal_names(func_node, file_bytes);
        let request_params = bind_php_path_params(&formals, &path);
        let middleware = collect_php_middleware(ast, file_bytes);

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
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "php".into(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_method_route_attribute_with_class_prefix() {
        let src: &[u8] = b"<?php\nuse Symfony\\Component\\Routing\\Annotation\\Route;\n#[Route('/api')]\nclass UserController {\n  #[Route('/users/{id}')]\n  public function show($id) { return $id; }\n}\n";
        let tree = parse(src);
        let binding = PhpSymfonyAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "php-symfony");
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/api/users/{id}");
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_post_with_named_methods_kwarg() {
        let src: &[u8] = b"<?php\nuse Symfony\\Component\\Routing\\Annotation\\Route;\nclass C {\n  #[Route('/save', methods: ['POST'])]\n  public function save($payload) { return $payload; }\n}\n";
        let tree = parse(src);
        let binding = PhpSymfonyAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/save");
    }

    #[test]
    fn fires_on_function_level_attribute() {
        let src: &[u8] = b"<?php\nuse Symfony\\Component\\Routing\\Annotation\\Route;\n#[Route('/x')]\nfunction handle() { return 'ok'; }\n";
        let tree = parse(src);
        let binding = PhpSymfonyAdapter
            .detect(&summary("handle"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/x");
    }

    #[test]
    fn populates_middleware_from_is_granted_attribute() {
        let src: &[u8] = b"<?php\nuse Symfony\\Component\\Routing\\Annotation\\Route;\nclass C {\n  #[Route('/x')]\n  #[IsGranted('ROLE_USER')]\n  public function show() { return 1; }\n}\n";
        let tree = parse(src);
        let binding = PhpSymfonyAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert!(
            binding.middleware.iter().any(|m| m.name == "#[IsGranted]"),
            "got {:?}",
            binding.middleware
        );
    }

    #[test]
    fn skips_when_symfony_not_imported() {
        let src: &[u8] = b"<?php\n#[Route('/x')]\nfunction f() { return 1; }\n";
        let tree = parse(src);
        assert!(
            PhpSymfonyAdapter
                .detect(&summary("f"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_method_has_no_route_attribute() {
        let src: &[u8] = b"<?php\nuse Symfony\\Component\\Routing\\Annotation\\Route;\nclass C {\n  public function helper($x) { return $x; }\n}\n";
        let tree = parse(src);
        assert!(
            PhpSymfonyAdapter
                .detect(&summary("helper"), tree.root_node(), src)
                .is_none()
        );
    }
}
