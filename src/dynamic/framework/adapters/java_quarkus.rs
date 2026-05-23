//! Java Quarkus / Jakarta REST [`super::super::FrameworkAdapter`]
//! (Phase 14 — Track L.12).
//!
//! Recognises `@Path("/path")` on a class plus a handler method
//! annotated with `@GET` / `@POST` / `@PUT` / `@DELETE` / `@PATCH` /
//! `@HEAD` / `@OPTIONS` (all-caps JAX-RS verb annotations, distinct
//! from Micronaut's mixed-case `@Get` / `@Post`).  Method-level
//! `@Path("/sub")` is concatenated with the class-level prefix.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::java_routes::{
    annotation_string_arg, bind_java_params, collect_security_annotations, find_class_with_method,
    iter_annotations, java_receiver_facts_allow_formals, join_route_path, method_formal_types,
    source_imports_quarkus,
};

pub struct JavaQuarkusAdapter;

const ADAPTER_NAME: &str = "java-quarkus";

fn verb_for(name: &str) -> Option<HttpMethod> {
    match name {
        "GET" => Some(HttpMethod::GET),
        "POST" => Some(HttpMethod::POST),
        "PUT" => Some(HttpMethod::PUT),
        "DELETE" => Some(HttpMethod::DELETE),
        "PATCH" => Some(HttpMethod::PATCH),
        "HEAD" => Some(HttpMethod::HEAD),
        "OPTIONS" => Some(HttpMethod::OPTIONS),
        _ => None,
    }
}

fn class_path_prefix(class: Node<'_>, bytes: &[u8]) -> String {
    let mut prefix = String::new();
    iter_annotations(class, bytes, |ann, name| {
        if name == "Path"
            && let Some(p) = annotation_string_arg(ann, bytes)
        {
            prefix = p;
        }
    });
    prefix
}

fn method_verb_and_path(method: Node<'_>, bytes: &[u8]) -> Option<(HttpMethod, String)> {
    let mut verb: Option<HttpMethod> = None;
    let mut path = String::new();
    iter_annotations(method, bytes, |ann, name| {
        if let Some(v) = verb_for(name) {
            verb = Some(v);
        }
        if name == "Path"
            && let Some(p) = annotation_string_arg(ann, bytes)
        {
            path = p;
        }
    });
    Some((verb?, path))
}

fn detect_quarkus(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    ast: Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_quarkus(file_bytes) {
        return None;
    }
    let (class, method) = find_class_with_method(ast, file_bytes, &summary.name)?;
    let (http_method, method_path) = method_verb_and_path(method, file_bytes)?;
    let class_prefix = class_path_prefix(class, file_bytes);
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

impl FrameworkAdapter for JavaQuarkusAdapter {
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
        detect_quarkus(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_quarkus(summary, ssa_summary, ast, file_bytes)
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
    fn fires_on_class_path_plus_method_get() {
        let src: &[u8] = b"import jakarta.ws.rs.GET;\nimport jakarta.ws.rs.Path;\n@Path(\"/api\")\npublic class V {\n  @GET\n  @Path(\"/{id}\")\n  public String show(String id) { return id; }\n}\n";
        let tree = parse(src);
        let binding = JavaQuarkusAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "java-quarkus");
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
    fn fires_on_post_without_class_prefix() {
        let src: &[u8] = b"import io.quarkus.runtime.Quarkus;\nimport jakarta.ws.rs.POST;\n@Path(\"/save\")\npublic class V {\n  @POST\n  public String save(String body) { return body; }\n}\n";
        let tree = parse(src);
        let binding = JavaQuarkusAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/save");
    }

    #[test]
    fn skips_non_quarkus_file() {
        let src: &[u8] = b"@RestController\npublic class C {\n  @GetMapping(\"/x\")\n  public String x() { return \"\"; }\n}\n";
        let tree = parse(src);
        assert!(
            JavaQuarkusAdapter
                .detect(&summary("x"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_method_without_verb_annotation() {
        let src: &[u8] = b"import jakarta.ws.rs.Path;\n@Path(\"/api\")\npublic class V {\n  public String helper() { return \"\"; }\n}\n";
        let tree = parse(src);
        assert!(
            JavaQuarkusAdapter
                .detect(&summary("helper"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn collects_rolesallowed_middleware() {
        let src: &[u8] = b"import jakarta.ws.rs.GET;\nimport jakarta.ws.rs.Path;\n@Path(\"/api\")\npublic class V {\n  @RolesAllowed(\"ADMIN\")\n  @GET\n  public String run() { return \"\"; }\n}\n";
        let tree = parse(src);
        let binding = JavaQuarkusAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .expect("binding");
        assert!(binding.middleware.iter().any(|m| m.name == "@RolesAllowed"));
    }

    #[test]
    fn ssa_rejects_incompatible_request_receiver() {
        let src: &[u8] = b"import jakarta.ws.rs.GET;\nimport jakarta.ws.rs.Path;\n@Path(\"/api\")\npublic class V {\n  @GET\n  public String run(HttpServletRequest req) { return req.getParameter(\"q\"); }\n}\n";
        let tree = parse(src);
        let summary = summary_with_receiver("run", "req", "getParameter");
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers
            .push((0, "DatabaseConnection".into()));
        assert!(
            JavaQuarkusAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }
}
