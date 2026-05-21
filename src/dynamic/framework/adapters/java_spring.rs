//! Java Spring [`super::super::FrameworkAdapter`] (Phase 14 — Track L.12).
//!
//! Recognises `@RestController` / `@Controller` on a class plus a
//! handler method annotated with `@GetMapping("/path")` /
//! `@PostMapping` / `@PutMapping` / `@PatchMapping` / `@DeleteMapping`
//! / `@RequestMapping(value="/path", method=RequestMethod.POST)`.
//! Class-level `@RequestMapping(prefix)` is concatenated with the
//! method-level path so `@RequestMapping("/api") + @GetMapping("/x")`
//! produces `"/api/x"`.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding, HttpMethod, RouteShape};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;
use tree_sitter::Node;

use super::java_routes::{
    annotation_string_arg, bind_java_params, find_class_with_method, iter_annotations,
    join_route_path, method_formal_types, request_method_from_args, source_imports_quarkus,
    source_imports_spring,
};

pub struct JavaSpringAdapter;

const ADAPTER_NAME: &str = "java-spring";

fn mapping_method(name: &str) -> Option<HttpMethod> {
    match name {
        "GetMapping" => Some(HttpMethod::GET),
        "PostMapping" => Some(HttpMethod::POST),
        "PutMapping" => Some(HttpMethod::PUT),
        "PatchMapping" => Some(HttpMethod::PATCH),
        "DeleteMapping" => Some(HttpMethod::DELETE),
        _ => None,
    }
}

fn class_is_controller(class: Node<'_>, bytes: &[u8]) -> bool {
    let mut hit = false;
    iter_annotations(class, bytes, |_ann, name| {
        if matches!(name, "RestController" | "Controller") {
            hit = true;
        }
    });
    hit
}

fn class_route_prefix(class: Node<'_>, bytes: &[u8]) -> String {
    let mut prefix = String::new();
    iter_annotations(class, bytes, |ann, name| {
        if name == "RequestMapping"
            && let Some(p) = annotation_string_arg(ann, bytes) {
                prefix = p;
            }
    });
    prefix
}

fn method_route(
    method: Node<'_>,
    bytes: &[u8],
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    iter_annotations(method, bytes, |ann, name| {
        if hit.is_some() {
            return;
        }
        if let Some(m) = mapping_method(name) {
            let path = annotation_string_arg(ann, bytes).unwrap_or_default();
            hit = Some((m, path));
            return;
        }
        if name == "RequestMapping" {
            let path = annotation_string_arg(ann, bytes).unwrap_or_default();
            let m = request_method_from_args(ann, bytes).unwrap_or(HttpMethod::GET);
            hit = Some((m, path));
        }
    });
    hit
}

impl FrameworkAdapter for JavaSpringAdapter {
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
        if !source_imports_spring(file_bytes) {
            return None;
        }
        // Quarkus / JAX-RS files often re-use `@Path` but the brief
        // routes those through `java-quarkus`; skip when the file
        // looks like Quarkus and is not also a Spring controller.
        if source_imports_quarkus(file_bytes) && !file_bytes.windows(15).any(|w| w == b"@RestController") && !file_bytes.windows(11).any(|w| w == b"@Controller") {
            return None;
        }
        let (class, method) = find_class_with_method(ast, file_bytes, &summary.name)?;
        if !class_is_controller(class, file_bytes) {
            return None;
        }
        let class_prefix = class_route_prefix(class, file_bytes);
        // Method-level mapping wins.  Falls back to (GET, "") when
        // the method has no mapping annotation but the enclosing
        // class has a `@RequestMapping(prefix)` — Spring routes the
        // public method under the class prefix.  Skip the binding
        // when neither the method nor the class declares a route
        // path so a plain `@Controller` helper class does not
        // hijack the registry.
        let (http_method, method_path) = match method_route(method, file_bytes) {
            Some(r) => r,
            None => {
                if class_prefix.is_empty() {
                    return None;
                }
                (HttpMethod::GET, String::new())
            }
        };
        let path = join_route_path(&class_prefix, &method_path);
        let formals = method_formal_types(method, file_bytes);
        let request_params = bind_java_params(&formals, &path);

        Some(FrameworkBinding {
            adapter: ADAPTER_NAME.to_owned(),
            kind: EntryKind::HttpRoute,
            route: Some(RouteShape {
                method: http_method,
                path,
            }),
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

    #[test]
    fn fires_on_get_mapping_with_class_prefix() {
        let src: &[u8] = b"@RestController\n@RequestMapping(\"/api\")\npublic class Users {\n  @GetMapping(\"/{id}\")\n  public String show(String id) { return id; }\n}\n";
        let tree = parse(src);
        let binding = JavaSpringAdapter
            .detect(&summary("show"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.adapter, "java-spring");
        assert_eq!(binding.kind, EntryKind::HttpRoute);
        let route = binding.route.expect("route");
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
    fn fires_on_request_mapping_with_explicit_method() {
        let src: &[u8] = b"@Controller\npublic class C {\n  @RequestMapping(value=\"/save\", method=RequestMethod.POST)\n  public String save(String payload) { return payload; }\n}\n";
        let tree = parse(src);
        let binding = JavaSpringAdapter
            .detect(&summary("save"), tree.root_node(), src)
            .expect("binding");
        let route = binding.route.unwrap();
        assert_eq!(route.method, HttpMethod::POST);
        assert_eq!(route.path, "/save");
    }

    #[test]
    fn fires_on_bare_controller_without_prefix() {
        let src: &[u8] =
            b"@RestController\npublic class C {\n  @GetMapping(\"/x\")\n  public String x() { return \"\"; }\n}\n";
        let tree = parse(src);
        let binding = JavaSpringAdapter
            .detect(&summary("x"), tree.root_node(), src)
            .expect("binding");
        assert_eq!(binding.route.unwrap().path, "/x");
    }

    #[test]
    fn skips_when_class_is_not_controller() {
        let src: &[u8] =
            b"@RequestMapping(\"/api\")\npublic class C {\n  @GetMapping(\"/x\")\n  public String x() { return \"\"; }\n}\n";
        let tree = parse(src);
        assert!(JavaSpringAdapter
            .detect(&summary("x"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_quarkus_file() {
        let src: &[u8] = b"import io.quarkus.runtime.Quarkus;\nimport jakarta.ws.rs.GET;\nimport jakarta.ws.rs.Path;\n@Path(\"/run\")\npublic class Q {\n  @GET\n  public String run() { return \"\"; }\n}\n";
        let tree = parse(src);
        assert!(JavaSpringAdapter
            .detect(&summary("run"), tree.root_node(), src)
            .is_none());
    }

    #[test]
    fn skips_plain_function() {
        let src: &[u8] = b"public class C { public int add(int a, int b) { return a + b; } }\n";
        let tree = parse(src);
        assert!(JavaSpringAdapter
            .detect(&summary("add"), tree.root_node(), src)
            .is_none());
    }
}
