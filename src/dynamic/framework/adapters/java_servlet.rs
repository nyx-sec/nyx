//! Java Servlet [`super::super::FrameworkAdapter`] (Phase 14 — Track L.12).
//!
//! Recognises a `doGet` / `doPost` / `doPut` / `doDelete` / `doHead`
//! / `doOptions` method on a class that either extends `HttpServlet`
//! or accepts a `(HttpServletRequest, HttpServletResponse)` pair as
//! its formal parameters — the Phase 14 servlet fixture uses the
//! second shape because its stubs live in the default package.
//!
//! The route path is sourced from a class-level `@WebServlet("/x")`
//! annotation when present; otherwise it defaults to `"/"` so the
//! harness has a deterministic slot to drive.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::java_routes::{
    annotation_string_arg, bind_java_params, class_extends, collect_security_annotations,
    find_class_with_method, iter_annotations, java_receiver_facts_allow_formals,
    method_formal_types, source_imports_servlet,
};

pub struct JavaServletAdapter;

const ADAPTER_NAME: &str = "java-servlet";

fn servlet_method_for(name: &str) -> Option<HttpMethod> {
    match name {
        "doGet" => Some(HttpMethod::GET),
        "doPost" => Some(HttpMethod::POST),
        "doPut" => Some(HttpMethod::PUT),
        "doDelete" => Some(HttpMethod::DELETE),
        "doHead" => Some(HttpMethod::HEAD),
        "doOptions" => Some(HttpMethod::OPTIONS),
        _ => None,
    }
}

fn web_servlet_path(class: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut hit: Option<String> = None;
    iter_annotations(class, bytes, |ann, name| {
        if name == "WebServlet" {
            hit = annotation_string_arg(ann, bytes);
        }
    });
    hit
}

fn formals_look_like_servlet(formals: &[(String, String)]) -> bool {
    formals
        .iter()
        .any(|(ty, _)| ty == "HttpServletRequest" || ty == "ServletRequest")
}

fn detect_servlet(
    summary: &FuncSummary,
    ssa_summary: Option<&SsaFuncSummary>,
    ast: Node<'_>,
    file_bytes: &[u8],
) -> Option<FrameworkBinding> {
    if !source_imports_servlet(file_bytes) {
        return None;
    }
    let http_method = servlet_method_for(&summary.name)?;
    let (class, method) = find_class_with_method(ast, file_bytes, &summary.name)?;
    let formals = method_formal_types(method, file_bytes);
    let extends_servlet = class_extends(class, file_bytes, "HttpServlet")
        || class_extends(class, file_bytes, "GenericServlet");
    if !extends_servlet && !formals_look_like_servlet(&formals) {
        return None;
    }
    if !java_receiver_facts_allow_formals(summary, ssa_summary, &formals) {
        return None;
    }
    let path = web_servlet_path(class, file_bytes).unwrap_or_else(|| "/".to_owned());
    let request_params = bind_java_params(&formals, &path);
    let middleware = collect_security_annotations(class, method, file_bytes);
    Some(FrameworkBinding {
        adapter: ADAPTER_NAME.to_owned(),
        kind: EntryKind::HttpRoute,
        route: Some(RouteShape::single(http_method, path)),
        request_params,
        response_writer: None,
        middleware,
    })
}

impl FrameworkAdapter for JavaServletAdapter {
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
        detect_servlet(summary, None, ast, file_bytes)
    }

    fn detect_with_context(
        &self,
        summary: &FuncSummary,
        ssa_summary: Option<&SsaFuncSummary>,
        ast: Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        detect_servlet(summary, ssa_summary, ast, file_bytes)
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

    fn ssa_receiver(container: &str) -> SsaFuncSummary {
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((0, container.to_owned()));
        ssa
    }

    #[test]
    fn fires_on_extends_http_servlet_doget() {
        let src: &[u8] = b"import jakarta.servlet.http.HttpServlet;\nimport jakarta.servlet.http.HttpServletRequest;\nimport jakarta.servlet.http.HttpServletResponse;\n@WebServlet(\"/admin\")\npublic class Admin extends HttpServlet {\n  public void doGet(HttpServletRequest req, HttpServletResponse resp) {}\n}\n";
        let tree = parse(src);
        let binding = JavaServletAdapter
            .detect(&summary("doGet"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "java-servlet");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::GET);
        assert_eq!(route.path, "/admin");
        assert!(
            binding
                .request_params
                .iter()
                .all(|p| matches!(p.source, ParamSource::Implicit))
        );
    }

    #[test]
    fn fires_on_dopost_with_servlet_request_param() {
        // Default-package fixture path: no `extends HttpServlet`, but
        // the method's formal parameters carry the canonical types so
        // the harness can still wire a stub.
        let src: &[u8] = b"public class V {\n  public void doPost(HttpServletRequest req, HttpServletResponse resp) {}\n}\n";
        let tree = parse(src);
        let binding = JavaServletAdapter
            .detect(&summary("doPost"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().method, HttpMethod::POST);
    }

    #[test]
    fn defaults_path_to_slash_without_webservlet() {
        let src: &[u8] = b"public class V extends HttpServlet {\n  public void doGet(HttpServletRequest req, HttpServletResponse resp) {}\n}\n";
        let tree = parse(src);
        let binding = JavaServletAdapter
            .detect(&summary("doGet"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().path, "/");
    }

    #[test]
    fn skips_when_method_name_is_not_a_servlet_verb() {
        let src: &[u8] =
            b"public class V extends HttpServlet { public void run(HttpServletRequest req) {} }\n";
        let tree = parse(src);
        assert!(
            JavaServletAdapter
                .detect(&summary("run"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_when_no_servlet_signature_markers() {
        let src: &[u8] = b"public class V {\n  public void doGet(String x) {}\n}\n";
        let tree = parse(src);
        assert!(
            JavaServletAdapter
                .detect(&summary("doGet"), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn collects_class_level_preauthorize_middleware() {
        let src: &[u8] = b"import jakarta.servlet.http.HttpServlet;\nimport jakarta.servlet.http.HttpServletRequest;\nimport jakarta.servlet.http.HttpServletResponse;\n@PreAuthorize(\"hasRole('USER')\")\n@WebServlet(\"/x\")\npublic class V extends HttpServlet {\n  public void doGet(HttpServletRequest req, HttpServletResponse resp) {}\n}\n";
        let tree = parse(src);
        let binding = JavaServletAdapter
            .detect(&summary("doGet"), tree.root_node(), src)
            .expect("binding");
        assert!(binding.middleware.iter().any(|m| m.name == "@PreAuthorize"));
    }

    #[test]
    fn ssa_rejects_incompatible_response_receiver() {
        let src: &[u8] = b"public class V {\n  public void doGet(HttpServletRequest req, HttpServletResponse resp) { resp.setHeader(\"X\", \"y\"); }\n}\n";
        let tree = parse(src);
        let summary = summary_with_receiver("doGet", "resp", "setHeader");
        let ssa = ssa_receiver("LocalCollection");
        assert!(
            JavaServletAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn ssa_allows_matching_response_receiver() {
        let src: &[u8] = b"public class V {\n  public void doGet(HttpServletRequest req, HttpServletResponse resp) { resp.setHeader(\"X\", \"y\"); }\n}\n";
        let tree = parse(src);
        let summary = summary_with_receiver("doGet", "resp", "setHeader");
        let ssa = ssa_receiver("HttpResponse");
        assert!(
            JavaServletAdapter
                .detect_with_context(&summary, Some(&ssa), tree.root_node(), src)
                .is_some()
        );
    }
}
