//! Symfony [`super::super::FrameworkAdapter`] (Phase 16 — Track L.14).
//!
//! Recognises `#[Route('/path', methods: ['GET'])]` PHP attributes on
//! controller methods or top-level functions.  Class-level
//! `#[Route('/api')]` prefix is concatenated with the method-level
//! path so `#[Route('/api')] + #[Route('/x')]` produces `"/api/x"`.
//!
//! The adapter also recognises project `config/routes.yaml` /
//! `config/routes.yml` entries when detection receives a project-file
//! context.

use crate::dynamic::framework::{
    FrameworkAdapter, FrameworkBinding, FrameworkDetectionContext, HttpMethod, ProjectFileIndex,
    RouteShape,
};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::php_routes::{
    bind_php_path_params, collect_php_middleware, find_php_function, first_php_string_arg,
    iter_php_attributes, methods_named_arg, php_class_name, php_formal_names,
    source_imports_symfony,
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
        detect_symfony(summary, ast, file_bytes, None)
    }

    fn detect_with_project_context(
        &self,
        summary: &FuncSummary,
        context: FrameworkDetectionContext<'_>,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_symfony(summary, ast, file_bytes, Some(context.project_files))
    }
}

fn detect_symfony(
    summary: &FuncSummary,
    ast: Node<'_>,
    file_bytes: &[u8],
    project_files: Option<&ProjectFileIndex>,
) -> Option<FrameworkBinding> {
    let (func_node, class) = find_php_function(ast, file_bytes, &summary.name)?;
    let controller = class.and_then(|c| php_class_name(c, file_bytes));
    let (route, from_project_config) =
        if let Some((http_method, method_path)) = route_attribute_shape(func_node, file_bytes) {
            let class_prefix = class
                .and_then(|c| route_attribute_shape(c, file_bytes))
                .map(|(_, p)| p)
                .unwrap_or_default();
            (
                Some(RouteShape::single(
                    http_method,
                    join_route_path(&class_prefix, &method_path),
                )),
                false,
            )
        } else {
            (
                project_files.and_then(|files| yaml_route_shape(files, &summary.name, controller)),
                true,
            )
        };

    let route = route?;
    if !source_imports_symfony(file_bytes) && !from_project_config {
        return None;
    }

    let formals = php_formal_names(func_node, file_bytes);
    let request_params = bind_php_path_params(&formals, &route.path);
    let middleware = collect_php_middleware(ast, file_bytes);

    Some(FrameworkBinding {
        adapter: ADAPTER_NAME.to_owned(),
        kind: EntryKind::HttpRoute,
        route: Some(route),
        request_params,
        response_writer: None,
        middleware,
    })
}

fn yaml_route_shape(
    project_files: &ProjectFileIndex,
    method_name: &str,
    controller: Option<&str>,
) -> Option<RouteShape> {
    for rel in ["config/routes.yaml", "config/routes.yml"] {
        if let Some(bytes) = project_files.get(rel)
            && let Some(shape) = parse_symfony_yaml_routes(bytes, method_name, controller)
        {
            return Some(shape);
        }
    }
    None
}

#[derive(Default)]
struct SymfonyYamlRoute {
    path: Option<String>,
    controller: Option<String>,
    method: Option<HttpMethod>,
}

fn parse_symfony_yaml_routes(
    bytes: &[u8],
    method_name: &str,
    class_name: Option<&str>,
) -> Option<RouteShape> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut current: Option<SymfonyYamlRoute> = None;
    for raw in text.lines() {
        let line = raw.trim_end();
        let trim = line.trim_start();
        if trim.is_empty() || trim.starts_with('#') {
            continue;
        }
        let indent = line.len().saturating_sub(trim.len());
        if indent == 0 && trim.ends_with(':') {
            if let Some(shape) = finish_yaml_route(current.take(), method_name, class_name) {
                return Some(shape);
            }
            current = Some(SymfonyYamlRoute::default());
            continue;
        }
        let Some(route) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = trim.split_once(':') else {
            continue;
        };
        let value = yaml_scalar(value);
        match key.trim() {
            "path" => route.path = Some(value),
            "controller" | "_controller" => route.controller = Some(value),
            "methods" => route.method = yaml_method(&value),
            "defaults" => {
                if let Some(controller) = inline_yaml_value(&value, "_controller") {
                    route.controller = Some(controller);
                }
            }
            _ => {}
        }
    }
    finish_yaml_route(current, method_name, class_name)
}

fn finish_yaml_route(
    route: Option<SymfonyYamlRoute>,
    method_name: &str,
    class_name: Option<&str>,
) -> Option<RouteShape> {
    let route = route?;
    let path = route.path?;
    let controller = route.controller?;
    if !controller_matches(&controller, method_name, class_name) {
        return None;
    }
    Some(RouteShape::single(
        route.method.unwrap_or(HttpMethod::GET),
        path,
    ))
}

fn yaml_scalar(value: &str) -> String {
    value.trim().trim_matches('"').trim_matches('\'').to_owned()
}

fn inline_yaml_value(value: &str, key: &str) -> Option<String> {
    let trimmed = value.trim().trim_start_matches('{').trim_end_matches('}');
    for part in trimmed.split(',') {
        let (k, v) = part.split_once(':')?;
        if k.trim() == key {
            return Some(yaml_scalar(v));
        }
    }
    None
}

fn yaml_method(value: &str) -> Option<HttpMethod> {
    for raw in value.trim_matches('[').trim_matches(']').split([',', ' ']) {
        let token = raw.trim().trim_matches('"').trim_matches('\'');
        if let Some(method) = HttpMethod::from_ident(token) {
            return Some(method);
        }
    }
    None
}

fn controller_matches(controller: &str, method_name: &str, class_name: Option<&str>) -> bool {
    let controller = controller.trim();
    let Some((class, method)) = controller.rsplit_once("::") else {
        return false;
    };
    if method != method_name {
        return false;
    }
    match class_name {
        Some(expected) => class.rsplit('\\').next().unwrap_or(class) == expected,
        None => true,
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

    fn summary_at(name: &str, file_path: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            file_path: file_path.into(),
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
    fn resolves_project_yaml_route_config() {
        let src: &[u8] = b"<?php\nnamespace App\\Controller;\nuse Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController;\nclass ReportController extends AbstractController {\n  public function show($id) { return $id; }\n}\n";
        let tree = parse(src);
        let mut project_files = ProjectFileIndex::new();
        project_files.insert(
            "config/routes.yaml",
            b"report_show:\n  path: /reports/{id}\n  controller: App\\Controller\\ReportController::show\n  methods: [POST]\n".to_vec(),
        );
        let context = FrameworkDetectionContext {
            ssa_summary: None,
            project_files: &project_files,
        };
        let binding = PhpSymfonyAdapter
            .detect_with_project_context(
                &summary_at("show", "/tmp/app/src/Controller/ReportController.php"),
                context,
                tree.root_node(),
                src,
            )
            .expect("binding from config/routes.yaml");
        let route = binding.route.unwrap();
        assert_eq!(route.path, "/reports/{id}");
        assert_eq!(route.method, HttpMethod::POST);
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
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
    fn skips_custom_abstract_controller_without_symfony_import() {
        let src: &[u8] = b"<?php\nclass AbstractController {}\nclass Route { public function __construct($path) {} }\nclass C extends AbstractController {\n  #[Route('/x')]\n  public function show() { return 1; }\n}\n";
        let tree = parse(src);
        assert!(
            PhpSymfonyAdapter
                .detect(&summary("show"), tree.root_node(), src)
                .is_none(),
            "bare custom AbstractController / Route aliases are not enough for Symfony binding",
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
