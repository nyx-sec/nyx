//! CodeIgniter [`super::super::FrameworkAdapter`] (Phase 16 — Track L.14).
//!
//! Recognises `$routes->get('users/(:num)', 'UserController::show')` /
//! `$routes->post(...)` route declarations declared inside the
//! conventional `app/Config/Routes.php` plus the matching controller
//! method declared inside an `extends BaseController` class.
//!
//! CodeIgniter 4's placeholder vocabulary covers `(:num)`,
//! `(:alpha)`, `(:alphanum)`, `(:any)`, `(:segment)`, `(:hash)` —
//! [`super::php_routes::extract_php_path_placeholders`] returns the
//! inner name (after the `:`) for each so a `$id` formal whose name
//! matches the placeholder binds as [`super::super::ParamSource::PathSegment`].

#[cfg(test)]
use crate::dynamic::framework::HttpMethod;
use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::php_routes::{
    bind_php_path_params, find_codeigniter_route, find_php_function, php_class_name,
    php_formal_names, source_imports_codeigniter,
};

pub struct PhpCodeIgniterAdapter;

const ADAPTER_NAME: &str = "php-codeigniter";

impl FrameworkAdapter for PhpCodeIgniterAdapter {
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
        if !source_imports_codeigniter(file_bytes) {
            return None;
        }
        let (func_node, class) = find_php_function(ast, file_bytes, &summary.name)?;
        let controller = class.and_then(|c| php_class_name(c, file_bytes));

        let (method, path) = find_codeigniter_route(ast, file_bytes, &summary.name, controller)?;

        let formals = php_formal_names(func_node, file_bytes);
        let request_params = bind_php_path_params(&formals, &path);

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
    fn fires_on_get_route_with_double_colon_callable() {
        let src: &[u8] = b"<?php\nuse CodeIgniter\\Router\\RouteCollection;\n$routes->get('users/(:num)', 'UserController::show');\nclass UserController extends BaseController {\n  public function show($num) { return $num; }\n}\n";
        let tree = parse(src);
        let binding = PhpCodeIgniterAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "php-codeigniter");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "users/(:num)");
        let num = binding
            .request_params
            .iter()
            .find(|p| p.name == "num")
            .unwrap();
        assert!(matches!(num.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_post_with_closure_callable() {
        let src: &[u8] = b"<?php\nuse CodeIgniter\\Router\\RouteCollection;\n$routes->post('save', function ($payload) { return $payload; });\nfunction save($payload) { return $payload; }\n";
        let tree = parse(src);
        let binding = PhpCodeIgniterAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn skips_when_codeigniter_not_imported() {
        let src: &[u8] = b"<?php\n$routes->get('users/(:num)', 'UserController::show');\n";
        let tree = parse(src);
        assert!(
            PhpCodeIgniterAdapter
                .detect(&summary("show"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_callable_does_not_reference_method() {
        let src: &[u8] = b"<?php\nuse CodeIgniter\\Router\\RouteCollection;\n$routes->get('users/(:num)', 'UserController::show');\nclass UserController extends BaseController {\n  public function helper($x) { return $x; }\n}\n";
        let tree = parse(src);
        assert!(
            PhpCodeIgniterAdapter
                .detect(&summary("helper"), tree.root_node(), src)
                .is_none()
        );
    }
}
