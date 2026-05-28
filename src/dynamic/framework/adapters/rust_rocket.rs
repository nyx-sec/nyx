//! Rocket [`super::super::FrameworkAdapter`] (Phase 17 — Track L.15).
//!
//! Recognises rocket's `#[get("/path")]` / `#[post("/path")]`
//! attribute macros plus the `routes![handler]` macro:
//!
//! ```rust,ignore
//! #[get("/users/<id>")]
//! fn show(id: String) -> String { id }
//!
//! #[launch]
//! fn rocket() -> _ { rocket::build().mount("/", routes![show]) }
//! ```
//!
//! Rocket's placeholder syntax `<id>` plus brace syntax `<id..>`
//! resolve via [`super::rust_routes::extract_rust_path_placeholders`].
//! The adapter shares the attribute-walk path with actix; the only
//! difference is the source-import discriminator.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::rust_routes::{
    RustRouteAttributeFramework, bind_rust_path_params, collect_rust_middleware,
    find_method_attribute_for_framework, find_rust_function, rust_formal_names,
    source_imports_rocket,
};

pub struct RustRocketAdapter;

const ADAPTER_NAME: &str = "rust-rocket";

impl FrameworkAdapter for RustRocketAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Rust
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if !source_imports_rocket(file_bytes) {
            return None;
        }
        let func = find_rust_function(ast, file_bytes, &summary.name)?;
        let (method, path) = find_method_attribute_for_framework(
            func,
            file_bytes,
            RustRouteAttributeFramework::Rocket,
        )?;
        let formals = rust_formal_names(func, file_bytes);
        let request_params = bind_rust_path_params(&formals, &path);
        let middleware = collect_rust_middleware(ast, file_bytes);
        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape::single(method, path)),
            request_params,
            response_writer: None,
            middleware,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::{HttpMethod, ParamSource};

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "rust".into(),
            ..Default::default()
        }
    }

    #[test]
    fn fires_on_get_with_angle_placeholder() {
        let src: &[u8] =
            b"use rocket::get;\n#[get(\"/u/<id>\")]\nfn show(id: String) -> String { id }\n";
        let tree = parse(src);
        let binding = RustRocketAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "rust-rocket");
        let route = binding.route.expect("route");
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/u/<id>");
        let id = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_post_with_data_param() {
        let src: &[u8] =
            b"use rocket::post;\n#[post(\"/save\", data = \"<body>\")]\nfn save(body: String) {}\n";
        let tree = parse(src);
        let binding = RustRocketAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn populates_middleware_from_attach_fairing() {
        let src: &[u8] = b"use rocket::get;\n#[get(\"/u\")]\nfn show() -> &'static str { \"ok\" }\n\
            #[launch]\nfn rocket() -> _ { rocket::build().attach(CsrfLayer).mount(\"/\", routes![show]) }\n";
        let tree = parse(src);
        let binding = RustRocketAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.middleware.len(), 1);
        assert_eq!(binding.middleware[0].name, "CsrfLayer");
    }

    #[test]
    fn skips_when_rocket_not_imported() {
        let src: &[u8] = b"#[get(\"/u\")]\nfn show() {}\n";
        let tree = parse(src);
        assert!(
            RustRocketAdapter
                .detect(&summary("show"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_actix_get_macro_in_rocket_file() {
        let src: &[u8] = b"use rocket::routes;\nuse actix_web::get;\n#[get(\"/u\")]\nfn show() -> &'static str { \"ok\" }\n";
        let tree = parse(src);
        assert!(
            RustRocketAdapter
                .detect(&summary("show"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn accepts_scoped_rocket_get_macro() {
        let src: &[u8] =
            b"use rocket::routes;\n#[rocket::get(\"/u\")]\nfn show() -> &'static str { \"ok\" }\n";
        let tree = parse(src);
        let binding = RustRocketAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().path, "/u");
    }
}
