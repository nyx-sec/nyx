//! Laravel [`super::super::FrameworkAdapter`] (Phase 16 — Track L.14).
//!
//! Two recognition shapes:
//!
//!   - Closure route: `Route::get('/path', function ($payload) {…})`
//!     declared at top level — the closure's function name is the
//!     enclosing summary's name (the static-analysis side already
//!     stamps anonymous closures with a synthetic name slot).
//!   - Controller-method route:
//!     `Route::get('/path', 'UserController@show')` /
//!     `Route::post('/path', [UserController::class, 'save'])` plus
//!     a `class UserController { public function show($id) {…} }`
//!     declaration in the same file.

#[cfg(test)]
use crate::dynamic::framework::HttpMethod;
use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::php_routes::{
    bind_php_path_params, collect_php_middleware, find_laravel_static_route, find_php_function,
    php_class_name, php_formal_names, source_imports_laravel,
};

pub struct PhpLaravelAdapter;

const ADAPTER_NAME: &str = "php-laravel";

impl FrameworkAdapter for PhpLaravelAdapter {
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
        if !source_imports_laravel(file_bytes) {
            return None;
        }
        let (func_node, class) = find_php_function(ast, file_bytes, &summary.name)?;
        let controller = class.and_then(|c| php_class_name(c, file_bytes));

        let (method, path) = find_laravel_static_route(ast, file_bytes, &summary.name, controller)?;

        let formals = php_formal_names(func_node, file_bytes);
        let request_params = bind_php_path_params(&formals, &path);
        let middleware = collect_php_middleware(ast, file_bytes);

        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape { method, path }),
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
    fn fires_on_route_get_with_controller_method() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/users/{id}', 'UserController@show');\nclass UserController {\n  public function show($id) { return $id; }\n}\n";
        let tree = parse(src);
        let binding = PhpLaravelAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "php-laravel");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users/{id}");
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_post_with_closure() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/save', function ($payload) { return $payload; });\nfunction save($payload) { return $payload; }\n";
        let tree = parse(src);
        let binding = PhpLaravelAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/save");
    }

    #[test]
    fn fires_on_array_callable() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::put('/users/{id}', [UserController::class, 'update']);\nclass UserController {\n  public function update($id) { return $id; }\n}\n";
        let tree = parse(src);
        let binding = PhpLaravelAdapter
            .detect(&summary("update"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::PUT);
    }

    #[test]
    fn fires_on_double_colon_callable() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::delete('/users/{id}', 'UserController::destroy');\nclass UserController {\n  public function destroy($id) { return $id; }\n}\n";
        let tree = parse(src);
        let binding = PhpLaravelAdapter
            .detect(&summary("destroy"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::DELETE);
    }

    #[test]
    fn populates_middleware_from_chained_call() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/users/{id}', 'UserController@show')->middleware('auth');\nclass UserController {\n  public function show($id) { return $id; }\n}\n";
        let tree = parse(src);
        let binding = PhpLaravelAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert!(
            binding.middleware.iter().any(|m| m.name == "auth"),
            "got {:?}",
            binding.middleware
        );
    }

    #[test]
    fn populates_middleware_from_constructor_call() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/users', 'UserController@index');\nclass UserController {\n  public function __construct() { $this->middleware('auth:sanctum'); }\n  public function index() { return 1; }\n}\n";
        let tree = parse(src);
        let binding = PhpLaravelAdapter
            .detect(&summary("index"), tree.root_node(), src)
            .expect("binding");
        assert!(
            binding.middleware.iter().any(|m| m.name == "auth:sanctum"),
            "got {:?}",
            binding.middleware
        );
    }

    #[test]
    fn skips_when_laravel_not_imported() {
        let src: &[u8] = b"<?php\nfunction f($x) { return $x; }\n";
        let tree = parse(src);
        assert!(
            PhpLaravelAdapter
                .detect(&summary("f"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_route_mapping_does_not_reference_function() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/users', 'UserController@show');\nfunction helper($x) { return $x; }\n";
        let tree = parse(src);
        assert!(
            PhpLaravelAdapter
                .detect(&summary("helper"), tree.root_node(), src)
                .is_none()
        );
    }
}
