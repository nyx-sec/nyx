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
use crate::dynamic::framework::{
    FrameworkAdapter, FrameworkBinding, FrameworkDetectionContext, ProjectFileIndex, RouteShape,
};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::php_routes::{
    bind_php_path_params, collect_php_middleware, find_laravel_static_route_shape,
    find_php_function, php_class_name, php_formal_names, source_imports_laravel,
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
        detect_laravel(summary, ast, file_bytes, None)
    }

    fn detect_with_project_context(
        &self,
        summary: &FuncSummary,
        context: FrameworkDetectionContext<'_>,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_laravel(summary, ast, file_bytes, Some(context.project_files))
    }
}

fn detect_laravel(
    summary: &FuncSummary,
    ast: Node<'_>,
    file_bytes: &[u8],
    project_files: Option<&ProjectFileIndex>,
) -> Option<FrameworkBinding> {
    let (func_node, class) = find_php_function(ast, file_bytes, &summary.name)?;
    let controller = class.and_then(|c| php_class_name(c, file_bytes));

    let (route, from_project_config) = if let Some(route) =
        find_laravel_static_route_shape(ast, file_bytes, &summary.name, controller)
    {
        (route, false)
    } else {
        (
            project_files
                .and_then(|files| laravel_config_route_shape(files, &summary.name, controller))?,
            true,
        )
    };

    if !source_imports_laravel(file_bytes) && !from_project_config {
        return None;
    }

    let formals = php_formal_names(func_node, file_bytes);
    let request_params = bind_php_path_params(&formals, &route.path);
    let mut middleware = collect_php_middleware(ast, file_bytes);
    if from_project_config && let Some(files) = project_files {
        middleware.extend(laravel_config_middleware(files));
    }

    Some(FrameworkBinding {
        adapter: ADAPTER_NAME.to_owned(),
        kind: EntryKind::HttpRoute,
        route: Some(route),
        request_params,
        response_writer: None,
        middleware,
    })
}

fn laravel_config_route_shape(
    project_files: &ProjectFileIndex,
    method_name: &str,
    controller: Option<&str>,
) -> Option<RouteShape> {
    for rel in ["routes/web.php", "routes/api.php"] {
        if let Some(bytes) = project_files.get(rel)
            && let Some(tree) = parse_php(bytes)
            && let Some(route) =
                find_laravel_static_route_shape(tree.root_node(), bytes, method_name, controller)
        {
            return Some(route);
        }
    }
    None
}

fn laravel_config_middleware(
    project_files: &ProjectFileIndex,
) -> Vec<crate::dynamic::framework::MiddlewareShape> {
    let mut out = Vec::new();
    for rel in ["routes/web.php", "routes/api.php"] {
        if let Some(bytes) = project_files.get(rel)
            && let Some(tree) = parse_php(bytes)
        {
            out.extend(collect_php_middleware(tree.root_node(), bytes));
        }
    }
    out
}

fn parse_php(bytes: &[u8]) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    parser.set_language(&lang).ok()?;
    parser.parse(bytes, None)
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
    fn resolves_project_route_file_for_controller_method() {
        let src: &[u8] = b"<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n  public function show($id) { return $id; }\n}\n";
        let tree = parse(src);
        let mut project_files = ProjectFileIndex::new();
        project_files.insert(
            "routes/web.php",
            b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\UserController;\nRoute::get('/users/{id}', [UserController::class, 'show'])->middleware('auth');\n".to_vec(),
        );
        let context = FrameworkDetectionContext {
            ssa_summary: None,
            project_files: &project_files,
        };
        let binding = PhpLaravelAdapter
            .detect_with_project_context(
                &summary_at("show", "/tmp/app/app/Http/Controllers/UserController.php"),
                context,
                tree.root_node(),
                src,
            )
            .expect("binding from routes/web.php");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/users/{id}");
        assert!(
            binding.middleware.iter().any(|m| m.name == "auth"),
            "expected auth middleware from routes/web.php, got {:?}",
            binding.middleware
        );
    }

    #[test]
    fn preserves_match_route_methods() {
        let src: &[u8] = b"<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::match(['POST', 'PATCH'], '/jobs/{id}', [JobController::class, 'run']);\nclass JobController {\n  public function run($id) { return $id; }\n}\n";
        let tree = parse(src);
        let binding = PhpLaravelAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(
            route.reachable_methods(),
            vec![HttpMethod::POST, HttpMethod::PATCH]
        );
        assert_eq!(route.path, "/jobs/{id}");
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
