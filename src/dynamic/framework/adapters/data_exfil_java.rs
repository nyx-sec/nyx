//! Java [`super::super::FrameworkAdapter`] matching outbound-HTTP
//! sink constructions (`java.net.HttpURLConnection`, the modern
//! `java.net.http.HttpClient`, OkHttp, Apache HttpClient).
//!
//! Phase 11 (Track L.9).  Fires when the function body invokes one
//! of the canonical Java HTTP-client entry points and the surrounding
//! source imports the matching stdlib / third-party module.
//!
//! See sibling adapters
//! [`super::data_exfil_python::DataExfilPythonAdapter`],
//! [`super::data_exfil_js::DataExfilJsAdapter`],
//! [`super::data_exfil_go::DataExfilGoAdapter`], and
//! [`super::data_exfil_ruby::DataExfilRubyAdapter`] for the same
//! shape on other languages.

use crate::dynamic::framework::{FrameworkAdapter, FrameworkBinding};
use crate::evidence::EntryKind;
use crate::summary::FuncSummary;
use crate::symbol::Lang;

pub struct DataExfilJavaAdapter;

const ADAPTER_NAME: &str = "data-exfil-java";

fn callee_is_outbound_http(name: &str) -> bool {
    let last = name.rsplit_once('.').map(|(_, s)| s).unwrap_or(name);
    matches!(
        last,
        "openConnection"
            | "openStream"
            | "send"
            | "sendAsync"
            | "execute"
            | "newCall"
            | "newBuilder"
            | "build"
            | "connect"
    ) || matches!(
        name,
        "java.net.URL.openConnection"
            | "java.net.URL.openStream"
            | "URL.openConnection"
            | "URL.openStream"
            | "HttpClient.send"
            | "HttpClient.sendAsync"
            | "HttpClient.newHttpClient"
            | "HttpRequest.newBuilder"
            | "OkHttpClient.newCall"
            | "Call.execute"
            | "HttpClients.createDefault"
            | "CloseableHttpClient.execute"
            | "Request.Builder.url"
    )
}

fn source_imports_java_http_client(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"java.net.HttpURLConnection",
        b"java.net.URL",
        b"java.net.http.HttpClient",
        b"java.net.http.HttpRequest",
        b"okhttp3.OkHttpClient",
        b"okhttp3.Request",
        b"okhttp3.Call",
        b"org.apache.http.client.HttpClient",
        b"org.apache.http.impl.client.HttpClients",
        b"org.apache.http.impl.client.CloseableHttpClient",
        b"org.apache.hc.client5.http",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

/// Returns `true` when the surrounding source visibly routes the
/// outbound URL through a host-allowlist / network-policy gate.
fn host_routed_through_allowlist(file_bytes: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[
        b"ALLOWLIST",
        b"ALLOWED_HOSTS",
        b"allowedHosts",
        b"allowlist",
        b"\"127.0.0.1\"",
        b"\"localhost\"",
        b".equals(\"localhost\")",
        b".contains(host)",
        b".containsKey(host)",
    ];
    NEEDLES
        .iter()
        .any(|n| file_bytes.windows(n.len()).any(|w| w == *n))
}

impl FrameworkAdapter for DataExfilJavaAdapter {
    fn name(&self) -> &'static str {
        ADAPTER_NAME
    }

    fn lang(&self) -> Lang {
        Lang::Java
    }

    fn detect(
        &self,
        summary: &FuncSummary,
        _ast: tree_sitter::Node<'_>,
        file_bytes: &[u8],
    ) -> Option<FrameworkBinding> {
        if host_routed_through_allowlist(file_bytes) {
            return None;
        }
        let matches_call = super::any_callee_matches(summary, callee_is_outbound_http);
        let matches_source = source_imports_java_http_client(file_bytes);
        if matches_call && matches_source {
            Some(FrameworkBinding {
                adapter: ADAPTER_NAME.to_owned(),
                kind: EntryKind::Function,
                route: None,
                request_params: Vec::new(),
                response_writer: None,
                middleware: Vec::new(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_java(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn fires_on_url_open_connection() {
        let src: &[u8] = b"import java.net.HttpURLConnection;\nimport java.net.URL;\n\
            public class Vuln {\n    public static void run(String host) throws Exception {\n        URL u = new URL(\"http://\" + host + \"/exfil\");\n        HttpURLConnection conn = (HttpURLConnection) u.openConnection();\n        conn.connect();\n    }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("URL.openConnection")],
            ..Default::default()
        };
        assert!(
            DataExfilJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_httpclient_send() {
        let src: &[u8] = b"import java.net.http.HttpClient;\nimport java.net.http.HttpRequest;\nimport java.net.URI;\n\
            public class Vuln {\n    public static void run(String host) throws Exception {\n        HttpClient c = HttpClient.newHttpClient();\n        HttpRequest r = HttpRequest.newBuilder(URI.create(\"http://\" + host)).build();\n        c.send(r, java.net.http.HttpResponse.BodyHandlers.discarding());\n    }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("HttpRequest.newBuilder"),
                crate::summary::CalleeSite::bare("HttpClient.send"),
            ],
            ..Default::default()
        };
        assert!(
            DataExfilJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn fires_on_okhttp_newcall_execute() {
        let src: &[u8] = b"import okhttp3.OkHttpClient;\nimport okhttp3.Request;\n\
            public class Vuln {\n    public static void run(String host) throws Exception {\n        OkHttpClient c = new OkHttpClient();\n        Request r = new Request.Builder().url(\"http://\" + host).build();\n        c.newCall(r).execute();\n    }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![
                crate::summary::CalleeSite::bare("OkHttpClient.newCall"),
                crate::summary::CalleeSite::bare("Call.execute"),
            ],
            ..Default::default()
        };
        assert!(
            DataExfilJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_some()
        );
    }

    #[test]
    fn skips_when_host_in_allowlist_literal() {
        let src: &[u8] = b"import java.net.HttpURLConnection;\nimport java.net.URL;\n\
            public class Vuln {\n    public static void run(String host) throws Exception {\n        if (!host.equals(\"127.0.0.1\")) { return; }\n        URL u = new URL(\"http://\" + host + \"/exfil\");\n        ((HttpURLConnection) u.openConnection()).connect();\n    }\n}\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "run".into(),
            callees: vec![crate::summary::CalleeSite::bare("URL.openConnection")],
            ..Default::default()
        };
        assert!(
            DataExfilJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }

    #[test]
    fn skips_plain_method() {
        let src: &[u8] = b"public class Plain { public static int add(int a, int b) { return a + b; } }\n";
        let tree = parse_java(src);
        let summary = FuncSummary {
            name: "add".into(),
            ..Default::default()
        };
        assert!(
            DataExfilJavaAdapter
                .detect(&summary, tree.root_node(), src)
                .is_none()
        );
    }
}
