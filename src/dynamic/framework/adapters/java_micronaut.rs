//! Java Micronaut [`super::super::FrameworkAdapter`] (Phase 14 — Track L.12).
//!
//! Recognises Micronaut `@Controller("/path")` on a class plus a
//! handler method annotated with `@Get("/sub")` / `@Post` / `@Put` /
//! `@Delete` / `@Patch` / `@Head` / `@Options` (mixed-case, distinct
//! from JAX-RS all-caps verbs).  Fires only when the source carries
//! a Micronaut import stanza so a Spring `@Controller` + Spring
//! `@GetMapping` file does not collide with this adapter.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::java_routes::{
    annotation_string_arg, bind_java_params, collect_security_annotations, find_class_with_method,
    iter_annotations, java_receiver_facts_allow_formals, join_route_path, method_formal_types,
    source_imports_micronaut,
};

pub struct JavaMicronautAdapter;

const ADAPTER_NAME: &str = "java-micronaut";

fn verb_for(name: &str) -> Option<HttpMethod> {
    match name {
        "Get" => Some(HttpMethod::GET),
        "Post" => Some(HttpMethod::POST),
        "Put" => Some(HttpMethod::PUT),
        "Delete" => Some(HttpMethod::DELETE),
        "Patch" => Some(HttpMethod::PATCH),
        "Head" => Some(HttpMethod::HEAD),
        "Options" => Some(HttpMethod::OPTIONS),
        _ => None,
    }
}

fn class_path_prefix(class: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut hit: Option<String> = None;
    iter_annotations(class, bytes, |ann, name| {
        if name == "Controller" {
            hit = Some(annotation_string_arg(ann, bytes).unwrap_or_default());
        }
    });
    hit
}

fn method_verb_and_path(method: Node<'_>, bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    iter_annotations(method, bytes, |ann, name| {
        if hit.is_some() {
            return;
        }
        if let Some(v) = verb_for(name) {
            let path = annotation_string_arg(ann, bytes).unwrap_or_default();
            hit = Some((v, path));
        }
    });
    hit
}

fn detect_micronaut(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    ast: Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_micronaut(file_bytes) {
        return None;
    }
    let (class, method) = find_class_with_method(ast, file_bytes, &summary.name)?;
    let class_prefix = class_path_prefix(class, file_bytes)?;
    let (http_method, method_path) = method_verb_and_path(method, file_bytes)?;
    let path = join_route_path(&class_prefix, &method_path);
    let formals = method_formal_types(method, file_bytes);
    if !java_receiver_facts_allow_formals(summary, ssa_summary, &formals) {
        return None;
    }
    let request_params = bind_java_params(&formals, &path);
    let middleware = collect_security_annotations(class, method, file_bytes);
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

impl FrameworkAdapter for JavaMicronautAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_micronaut(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_micronaut(summary, ssa_summary, ast, file_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::framework::ParamSource;
    use crate::summary::CalleeSite;

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn summary(name: &str) -> FuncSummary {
        FuncSummary {
            name: name.into(),
            lang: "java".into(),
            ..Default::default()
        }
    }

    fn summary_with_receiver(name: &str, receiver: &str, callee: &str) -> FuncSummary {
        let mut s = summary(name);
        s.callees.push(CalleeSite {
            name: callee.into(),
            receiver: Some(receiver.into()),
            ordinal: 0,
            ..Default::default()
        });
        s
    }

    #[test]
    fn fires_on_controller_plus_get() {
        let src: &[u8] = b"import io.micronaut.http.annotation.Controller;\nimport io.micronaut.http.annotation.Get;\n@Controller(\"/api\")\npublic class V {\n  @Get(\"/{id}\")\n  public String show(String id) { return id; }\n}\n";
        let tree = parse(src);
        let binding = JavaMicronautAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "java-micronaut");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/api/{id}");
        let id_binding = binding
            .request_params
            .iter()
            .find(|p| p.name == "id")
            .unwrap();
        assert!(matches!(id_binding.source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn fires_on_post_with_empty_prefix() {
        let src: &[u8] = b"import io.micronaut.http.annotation.Controller;\nimport io.micronaut.http.annotation.Post;\n@Controller\npublic class V {\n  @Post(\"/save\")\n  public String save(String body) { return body; }\n}\n";
        let tree = parse(src);
        let binding = JavaMicronautAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/save");
    }

    #[test]
    fn skips_non_micronaut_file() {
        let src: &[u8] = b"@Controller\npublic class C {\n  @GetMapping(\"/x\")\n  public String x() { return \"\"; }\n}\n";
        let tree = parse(src);
        assert!(
            JavaMicronautAdapter
                .detect(&summary("x"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_method_without_micronaut_verb() {
        let src: &[u8] = b"import io.micronaut.http.annotation.Controller;\n@Controller(\"/api\")\npublic class V {\n  public String helper() { return \"\"; }\n}\n";
        let tree = parse(src);
        assert!(
            JavaMicronautAdapter
                .detect(&summary("helper"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn collects_secured_middleware() {
        let src: &[u8] = b"import io.micronaut.http.annotation.Controller;\nimport io.micronaut.http.annotation.Get;\n@Controller(\"/api\")\npublic class V {\n  @Secured(\"USER\")\n  @Get(\"/x\")\n  public String run() { return \"\"; }\n}\n";
        let tree = parse(src);
        let binding = JavaMicronautAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .expect("binding");
        assert!(binding.middleware.iter().any(|m| m.name == "@Secured"));
    }

    #[test]
    fn ssa_rejects_incompatible_request_receiver() {
        let src: &[u8] = b"import io.micronaut.http.annotation.Controller;\nimport io.micronaut.http.annotation.Get;\n@Controller(\"/api\")\npublic class V {\n  @Get(\"/x\")\n  public String run(HttpRequest req) { return req.getPath(); }\n}\n";
        let tree = parse(src);
        let summary = summary_with_receiver("run", "req", "getPath");
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, "HttpClient".into()));
        assert!(
            JavaMicronautAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }
}
