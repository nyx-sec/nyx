//! External-service detection.
//!
//! Walks the post-pass-2 [`GlobalSummaries`] looking for callees that
//! launch outbound network requests (HTTP, gRPC, SMTP, DNS) and emits
//! one [`SurfaceNode::ExternalService`] per call.  Detection is by
//! callee leaf name + `sink_caps & SSRF` heuristic — both signals are
//! consulted so a probe with no SSRF cap (DNS resolver, SMTP sender)
//! still surfaces as an external service.

use super::{ExternalService, ExternalServiceKind, SourceLocation, SurfaceNode};
use crate::labels::Cap;
use crate::summary::{CalleeSite, FuncSummary, GlobalSummaries};

struct ClientRule {
    leaf: &'static str,
    kind: ExternalServiceKind,
    label: &'static str,
}

const CLIENT_RULES: &[ClientRule] = &[
    // HTTP
    ClientRule { leaf: "requests.get",         kind: ExternalServiceKind::HttpApi, label: "requests (Python)" },
    ClientRule { leaf: "requests.post",        kind: ExternalServiceKind::HttpApi, label: "requests (Python)" },
    ClientRule { leaf: "httpx.get",            kind: ExternalServiceKind::HttpApi, label: "httpx (Python)" },
    ClientRule { leaf: "httpx.post",           kind: ExternalServiceKind::HttpApi, label: "httpx (Python)" },
    ClientRule { leaf: "urllib.request.urlopen", kind: ExternalServiceKind::HttpApi, label: "urllib" },
    ClientRule { leaf: "fetch",                kind: ExternalServiceKind::HttpApi, label: "fetch (JS)" },
    ClientRule { leaf: "axios.get",            kind: ExternalServiceKind::HttpApi, label: "axios" },
    ClientRule { leaf: "axios.post",           kind: ExternalServiceKind::HttpApi, label: "axios" },
    ClientRule { leaf: "http.request",         kind: ExternalServiceKind::HttpApi, label: "node http" },
    ClientRule { leaf: "got",                  kind: ExternalServiceKind::HttpApi, label: "got (JS)" },
    ClientRule { leaf: "HttpClient.send",      kind: ExternalServiceKind::HttpApi, label: "Java HttpClient" },
    ClientRule { leaf: "HttpClient.execute",   kind: ExternalServiceKind::HttpApi, label: "Java HttpClient" },
    ClientRule { leaf: "RestTemplate.exchange", kind: ExternalServiceKind::HttpApi, label: "Spring RestTemplate" },
    ClientRule { leaf: "RestTemplate.getForObject", kind: ExternalServiceKind::HttpApi, label: "Spring RestTemplate" },
    ClientRule { leaf: "OkHttpClient.newCall", kind: ExternalServiceKind::HttpApi, label: "OkHttp" },
    ClientRule { leaf: "http.Get",             kind: ExternalServiceKind::HttpApi, label: "net/http (Go)" },
    ClientRule { leaf: "http.Post",            kind: ExternalServiceKind::HttpApi, label: "net/http (Go)" },
    ClientRule { leaf: "http.NewRequest",      kind: ExternalServiceKind::HttpApi, label: "net/http (Go)" },
    ClientRule { leaf: "client.Do",            kind: ExternalServiceKind::HttpApi, label: "go http client" },
    ClientRule { leaf: "reqwest::get",         kind: ExternalServiceKind::HttpApi, label: "reqwest (Rust)" },
    ClientRule { leaf: "reqwest::Client",      kind: ExternalServiceKind::HttpApi, label: "reqwest (Rust)" },
    ClientRule { leaf: "Net::HTTP",            kind: ExternalServiceKind::HttpApi, label: "Net::HTTP (Ruby)" },
    ClientRule { leaf: "HTTParty.get",         kind: ExternalServiceKind::HttpApi, label: "HTTParty" },
    ClientRule { leaf: "Faraday",              kind: ExternalServiceKind::HttpApi, label: "Faraday (Ruby)" },
    ClientRule { leaf: "curl_exec",            kind: ExternalServiceKind::HttpApi, label: "PHP curl" },
    ClientRule { leaf: "file_get_contents",    kind: ExternalServiceKind::HttpApi, label: "PHP file_get_contents" },
    ClientRule { leaf: "Guzzle",               kind: ExternalServiceKind::HttpApi, label: "Guzzle (PHP)" },

    // Message brokers
    ClientRule { leaf: "kafka.send",           kind: ExternalServiceKind::MessageBroker, label: "Kafka" },
    ClientRule { leaf: "KafkaProducer.send",   kind: ExternalServiceKind::MessageBroker, label: "Kafka" },
    ClientRule { leaf: "rabbitmq.publish",     kind: ExternalServiceKind::MessageBroker, label: "RabbitMQ" },
    ClientRule { leaf: "amqp.publish",         kind: ExternalServiceKind::MessageBroker, label: "AMQP" },
    ClientRule { leaf: "sqs.send_message",     kind: ExternalServiceKind::MessageBroker, label: "AWS SQS" },
    ClientRule { leaf: "sns.publish",          kind: ExternalServiceKind::MessageBroker, label: "AWS SNS" },

    // Search indices
    ClientRule { leaf: "Elasticsearch",        kind: ExternalServiceKind::SearchIndex, label: "Elasticsearch" },
    ClientRule { leaf: "elasticsearch.search", kind: ExternalServiceKind::SearchIndex, label: "Elasticsearch" },
    ClientRule { leaf: "OpenSearch",           kind: ExternalServiceKind::SearchIndex, label: "OpenSearch" },
    ClientRule { leaf: "Algolia",              kind: ExternalServiceKind::SearchIndex, label: "Algolia" },

    // Auth providers
    ClientRule { leaf: "auth0",                kind: ExternalServiceKind::AuthProvider, label: "Auth0" },
    ClientRule { leaf: "passport.authenticate", kind: ExternalServiceKind::AuthProvider, label: "Passport.js" },
    ClientRule { leaf: "OAuth2Client",         kind: ExternalServiceKind::AuthProvider, label: "OAuth2 client" },
    ClientRule { leaf: "google.oauth2",        kind: ExternalServiceKind::AuthProvider, label: "Google OAuth2" },

    // SMTP
    ClientRule { leaf: "smtplib.SMTP",         kind: ExternalServiceKind::HttpApi, label: "SMTP (Python)" },
    ClientRule { leaf: "Mail::send",           kind: ExternalServiceKind::HttpApi, label: "Laravel Mail" },
    ClientRule { leaf: "ActionMailer",         kind: ExternalServiceKind::HttpApi, label: "Rails ActionMailer" },

    // DNS
    ClientRule { leaf: "socket.gethostbyname", kind: ExternalServiceKind::HttpApi, label: "DNS resolver" },
    ClientRule { leaf: "dns.lookup",           kind: ExternalServiceKind::HttpApi, label: "DNS resolver" },
    ClientRule { leaf: "net.LookupIP",         kind: ExternalServiceKind::HttpApi, label: "DNS resolver" },
];

pub fn detect_external_services(summaries: &GlobalSummaries) -> Vec<SurfaceNode> {
    let mut out: Vec<SurfaceNode> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    for (_key, summary) in summaries.iter() {
        for callee in &summary.callees {
            let Some(rule) = match_rule(&callee.name) else {
                continue;
            };
            let location = call_site_location(summary, Some(callee));
            if !seen.insert((location.file.clone(), rule.label.to_string())) {
                continue;
            }
            out.push(SurfaceNode::ExternalService(ExternalService {
                location,
                kind: rule.kind,
                label: rule.label.to_string(),
            }));
        }
    }
    // Also surface any function whose own sink_caps include SSRF — the
    // function itself is an outbound network call site even if the
    // direct callee did not match the rule list.  Use the function's
    // file as the location and synthesise a generic label.
    for (_key, summary) in summaries.iter() {
        if summary.sink_caps().contains(Cap::SSRF) {
            let loc = call_site_location(summary, None);
            let dedup = (loc.file.clone(), "Outbound HTTP".to_string());
            if seen.insert(dedup) {
                out.push(SurfaceNode::ExternalService(ExternalService {
                    location: loc,
                    kind: ExternalServiceKind::HttpApi,
                    label: "Outbound HTTP".to_string(),
                }));
            }
        }
    }
    out
}

fn match_rule(callee: &str) -> Option<&'static ClientRule> {
    let cl = callee.trim().to_ascii_lowercase();
    let cl_segments = cl.replace("::", ".");
    CLIENT_RULES.iter().find(|r| {
        let rl = r.leaf.to_ascii_lowercase();
        if r.leaf.contains('.') || r.leaf.contains("::") {
            // Qualified pattern: substring on full callee text.
            cl.contains(&rl)
        } else {
            // Bare leaf: whole-segment match only.  Stops `prefetch` from
            // matching `fetch`, `Faraday` substrings, etc.
            cl_segments.split('.').any(|seg| seg == rl)
        }
    })
}

/// Source location of an external-service call site.  Reads the 1-based
/// `(line, col)` recorded on the [`CalleeSite`] at CFG-build time when
/// available; otherwise (sink-cap–only fallback path, or legacy summaries
/// loaded from SQLite) returns the function's host file with line 0.
fn call_site_location(summary: &FuncSummary, callee: Option<&CalleeSite>) -> SourceLocation {
    let (line, col) = callee.and_then(|c| c.span).unwrap_or((0, 0));
    SourceLocation {
        file: summary.file_path.clone(),
        line,
        col,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::CalleeSite;
    use crate::symbol::{FuncKey, Lang};

    #[test]
    fn detects_requests_get() {
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "client.py", "fetch_user", None);
        let summary = FuncSummary {
            name: "fetch_user".to_string(),
            file_path: "client.py".to_string(),
            lang: "python".to_string(),
            param_count: 0,
            callees: vec![CalleeSite::bare("requests.get".to_string())],
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_external_services(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::ExternalService(es) = &nodes[0] else {
            panic!()
        };
        assert_eq!(es.label, "requests (Python)");
    }

    #[test]
    fn bare_fetch_rule_does_not_match_prefetch_or_cachekey() {
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::JavaScript, "client.js", "load", None);
        let summary = FuncSummary {
            name: "load".to_string(),
            file_path: "client.js".to_string(),
            lang: "javascript".to_string(),
            param_count: 0,
            callees: vec![
                CalleeSite::bare("prefetch".to_string()),
                CalleeSite::bare("cacheKeyFetch".to_string()),
                CalleeSite::bare("Faraday_token".to_string()),
            ],
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_external_services(&gs);
        assert!(nodes.is_empty(), "bare rules FP-matched on {nodes:?}");
    }

    #[test]
    fn bare_got_rule_matches_segmented_callee() {
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::JavaScript, "client.js", "load", None);
        let summary = FuncSummary {
            name: "load".to_string(),
            file_path: "client.js".to_string(),
            lang: "javascript".to_string(),
            param_count: 0,
            callees: vec![CalleeSite::bare("got.post".to_string())],
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_external_services(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::ExternalService(es) = &nodes[0] else {
            panic!()
        };
        assert_eq!(es.label, "got (JS)");
    }
}
