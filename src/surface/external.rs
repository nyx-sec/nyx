//! External-service detection.
//!
//! Walks the post-pass-2 [`GlobalSummaries`] looking for callees that
//! launch outbound network requests (HTTP, gRPC, SMTP, DNS) and emits
//! one [`SurfaceNode::ExternalService`] per call.  Detection is by
//! callee leaf name + `sink_caps & SSRF` heuristic — both signals are
//! consulted so a probe with no SSRF cap (DNS resolver, SMTP sender)
//! still surfaces as an external service.

use super::{ExternalService, ExternalServiceKind, SourceLocation, SurfaceNode, namespace_file};
use crate::labels::Cap;
use crate::summary::GlobalSummaries;

struct ClientRule {
    leaf: &'static str,
    kind: ExternalServiceKind,
    label: &'static str,
}

const CLIENT_RULES: &[ClientRule] = &[
    // HTTP
    ClientRule {
        leaf: "requests.get",
        kind: ExternalServiceKind::HttpApi,
        label: "requests (Python)",
    },
    ClientRule {
        leaf: "requests.post",
        kind: ExternalServiceKind::HttpApi,
        label: "requests (Python)",
    },
    ClientRule {
        leaf: "httpx.get",
        kind: ExternalServiceKind::HttpApi,
        label: "httpx (Python)",
    },
    ClientRule {
        leaf: "httpx.post",
        kind: ExternalServiceKind::HttpApi,
        label: "httpx (Python)",
    },
    ClientRule {
        leaf: "urllib.request.urlopen",
        kind: ExternalServiceKind::HttpApi,
        label: "urllib",
    },
    ClientRule {
        leaf: "fetch",
        kind: ExternalServiceKind::HttpApi,
        label: "fetch (JS)",
    },
    ClientRule {
        leaf: "axios.get",
        kind: ExternalServiceKind::HttpApi,
        label: "axios",
    },
    ClientRule {
        leaf: "axios.post",
        kind: ExternalServiceKind::HttpApi,
        label: "axios",
    },
    ClientRule {
        leaf: "http.request",
        kind: ExternalServiceKind::HttpApi,
        label: "node http",
    },
    ClientRule {
        leaf: "got",
        kind: ExternalServiceKind::HttpApi,
        label: "got (JS)",
    },
    ClientRule {
        leaf: "HttpClient.send",
        kind: ExternalServiceKind::HttpApi,
        label: "Java HttpClient",
    },
    ClientRule {
        leaf: "HttpClient.execute",
        kind: ExternalServiceKind::HttpApi,
        label: "Java HttpClient",
    },
    ClientRule {
        leaf: "RestTemplate.exchange",
        kind: ExternalServiceKind::HttpApi,
        label: "Spring RestTemplate",
    },
    ClientRule {
        leaf: "RestTemplate.getForObject",
        kind: ExternalServiceKind::HttpApi,
        label: "Spring RestTemplate",
    },
    ClientRule {
        leaf: "OkHttpClient.newCall",
        kind: ExternalServiceKind::HttpApi,
        label: "OkHttp",
    },
    ClientRule {
        leaf: "http.Get",
        kind: ExternalServiceKind::HttpApi,
        label: "net/http (Go)",
    },
    ClientRule {
        leaf: "http.Post",
        kind: ExternalServiceKind::HttpApi,
        label: "net/http (Go)",
    },
    ClientRule {
        leaf: "http.NewRequest",
        kind: ExternalServiceKind::HttpApi,
        label: "net/http (Go)",
    },
    ClientRule {
        leaf: "client.Do",
        kind: ExternalServiceKind::HttpApi,
        label: "go http client",
    },
    ClientRule {
        leaf: "reqwest::get",
        kind: ExternalServiceKind::HttpApi,
        label: "reqwest (Rust)",
    },
    ClientRule {
        leaf: "reqwest::Client",
        kind: ExternalServiceKind::HttpApi,
        label: "reqwest (Rust)",
    },
    ClientRule {
        leaf: "Net::HTTP",
        kind: ExternalServiceKind::HttpApi,
        label: "Net::HTTP (Ruby)",
    },
    ClientRule {
        leaf: "HTTParty.get",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTParty",
    },
    ClientRule {
        leaf: "Faraday",
        kind: ExternalServiceKind::HttpApi,
        label: "Faraday (Ruby)",
    },
    ClientRule {
        leaf: "curl_exec",
        kind: ExternalServiceKind::HttpApi,
        label: "PHP curl",
    },
    ClientRule {
        leaf: "file_get_contents",
        kind: ExternalServiceKind::HttpApi,
        label: "PHP file_get_contents",
    },
    ClientRule {
        leaf: "Guzzle",
        kind: ExternalServiceKind::HttpApi,
        label: "Guzzle (PHP)",
    },
    // Message brokers
    ClientRule {
        leaf: "kafka.send",
        kind: ExternalServiceKind::MessageBroker,
        label: "Kafka",
    },
    ClientRule {
        leaf: "KafkaProducer.send",
        kind: ExternalServiceKind::MessageBroker,
        label: "Kafka",
    },
    ClientRule {
        leaf: "rabbitmq.publish",
        kind: ExternalServiceKind::MessageBroker,
        label: "RabbitMQ",
    },
    ClientRule {
        leaf: "amqp.publish",
        kind: ExternalServiceKind::MessageBroker,
        label: "AMQP",
    },
    ClientRule {
        leaf: "sqs.send_message",
        kind: ExternalServiceKind::MessageBroker,
        label: "AWS SQS",
    },
    ClientRule {
        leaf: "sns.publish",
        kind: ExternalServiceKind::MessageBroker,
        label: "AWS SNS",
    },
    // Search indices
    ClientRule {
        leaf: "Elasticsearch",
        kind: ExternalServiceKind::SearchIndex,
        label: "Elasticsearch",
    },
    ClientRule {
        leaf: "elasticsearch.search",
        kind: ExternalServiceKind::SearchIndex,
        label: "Elasticsearch",
    },
    ClientRule {
        leaf: "OpenSearch",
        kind: ExternalServiceKind::SearchIndex,
        label: "OpenSearch",
    },
    ClientRule {
        leaf: "Algolia",
        kind: ExternalServiceKind::SearchIndex,
        label: "Algolia",
    },
    // Auth providers
    ClientRule {
        leaf: "auth0",
        kind: ExternalServiceKind::AuthProvider,
        label: "Auth0",
    },
    ClientRule {
        leaf: "passport.authenticate",
        kind: ExternalServiceKind::AuthProvider,
        label: "Passport.js",
    },
    ClientRule {
        leaf: "OAuth2Client",
        kind: ExternalServiceKind::AuthProvider,
        label: "OAuth2 client",
    },
    ClientRule {
        leaf: "google.oauth2",
        kind: ExternalServiceKind::AuthProvider,
        label: "Google OAuth2",
    },
    // SMTP
    ClientRule {
        leaf: "smtplib.SMTP",
        kind: ExternalServiceKind::HttpApi,
        label: "SMTP (Python)",
    },
    ClientRule {
        leaf: "Mail::send",
        kind: ExternalServiceKind::HttpApi,
        label: "Laravel Mail",
    },
    ClientRule {
        leaf: "ActionMailer",
        kind: ExternalServiceKind::HttpApi,
        label: "Rails ActionMailer",
    },
    // DNS
    ClientRule {
        leaf: "socket.gethostbyname",
        kind: ExternalServiceKind::HttpApi,
        label: "DNS resolver",
    },
    ClientRule {
        leaf: "dns.lookup",
        kind: ExternalServiceKind::HttpApi,
        label: "DNS resolver",
    },
    ClientRule {
        leaf: "net.LookupIP",
        kind: ExternalServiceKind::HttpApi,
        label: "DNS resolver",
    },
    // Type-qualified — fires when the SSA type-fact engine resolves a
    // receiver to `TypeKind::HttpClient` regardless of the bare callee
    // name (`session = requests.Session(); session.get(url)` →
    // typed_call_receivers maps the `.get` ordinal to "HttpClient", so
    // the bound-receiver call surfaces as an outbound HTTP node even
    // though `requests.get` is the only direct-import rule above).
    ClientRule {
        leaf: "HttpClient.get",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP client",
    },
    ClientRule {
        leaf: "HttpClient.post",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP client",
    },
    ClientRule {
        leaf: "HttpClient.put",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP client",
    },
    ClientRule {
        leaf: "HttpClient.delete",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP client",
    },
    ClientRule {
        leaf: "HttpClient.patch",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP client",
    },
    ClientRule {
        leaf: "HttpClient.request",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP client",
    },
    ClientRule {
        leaf: "HttpClient.head",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP client",
    },
    ClientRule {
        leaf: "HttpClient.options",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP client",
    },
    ClientRule {
        leaf: "RequestBuilder.send",
        kind: ExternalServiceKind::HttpApi,
        label: "HTTP request builder",
    },
    ClientRule {
        leaf: "URL.openConnection",
        kind: ExternalServiceKind::HttpApi,
        label: "URL connection",
    },
    ClientRule {
        leaf: "URL.openStream",
        kind: ExternalServiceKind::HttpApi,
        label: "URL connection",
    },
];

/// Walk every function summary's callee list and emit one
/// [`SurfaceNode::ExternalService`] per matched outbound-client call.
///
/// When the bare callee name does not hit a rule, the type-fact engine's
/// per-call `typed_call_receivers` map (read off the matching
/// [`crate::summary::ssa_summary::SsaFuncSummary`]) is consulted: a callee whose
/// receiver was resolved to `TypeKind::HttpClient` /
/// `TypeKind::RequestBuilder` / `TypeKind::Url` is retried under the
/// type-qualified name `"{container}.<method>"`, picking up the
/// bound-receiver call shapes (`client = requests.Session();
/// client.get(url)`) that the name-only matcher misses.
pub fn detect_external_services(summaries: &GlobalSummaries) -> Vec<SurfaceNode> {
    let mut out: Vec<SurfaceNode> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for (key, summary) in summaries.iter() {
        // Project-relative POSIX file, keyed off the FuncKey namespace so an
        // external-service node and the entry-point that reaches it agree on
        // file identity (FuncSummary.file_path is an absolute path).
        let file = namespace_file(&key.namespace).to_string();
        let owner = key.qualified_name();
        let typed = summaries
            .get_ssa(key)
            .map(|s| s.typed_call_receivers.as_slice());
        let mut matched_for_fn = false;
        for callee in &summary.callees {
            let rule = match_rule(&callee.name).or_else(|| {
                typed
                    .and_then(|t| container_for_ordinal(t, callee.ordinal))
                    .and_then(|c| match_rule(&qualify(c, &callee.name)))
            });
            let Some(rule) = rule else { continue };
            matched_for_fn = true;
            let location = call_site_location(&file, callee.span);
            if !seen.insert((location.file.clone(), rule.label.to_string())) {
                continue;
            }
            out.push(SurfaceNode::ExternalService(ExternalService {
                location,
                kind: rule.kind,
                label: rule.label.to_string(),
                owner: owner.clone(),
            }));
        }

        // Cap-driven fallback: a function whose own sink_caps include SSRF
        // (outbound request) or DATA_EXFIL (data leaving the system) is an
        // egress site even when the direct callee did not match the rule
        // list.  Skipped when a named client already fired for this function
        // so the precise label wins and the generic node does not
        // double-count the same egress.
        if matched_for_fn {
            continue;
        }
        let caps = summary.sink_caps();
        let fallback = if caps.contains(Cap::SSRF) {
            Some(("Outbound HTTP", ExternalServiceKind::HttpApi))
        } else if caps.contains(Cap::DATA_EXFIL) {
            Some(("Data egress", ExternalServiceKind::Unknown))
        } else {
            None
        };
        if let Some((label, kind)) = fallback {
            let dedup = (file.clone(), label.to_string());
            if seen.insert(dedup) {
                out.push(SurfaceNode::ExternalService(ExternalService {
                    location: call_site_location(&file, None),
                    kind,
                    label: label.to_string(),
                    owner: owner.clone(),
                }));
            }
        }
    }
    out
}

fn leaf_segment(name: &str) -> &str {
    let after_colon = name.rsplit("::").next().unwrap_or(name);
    after_colon.rsplit('.').next().unwrap_or(after_colon)
}

fn qualify(container: &str, callee_name: &str) -> String {
    format!("{}.{}", container, leaf_segment(callee_name))
}

fn container_for_ordinal(typed: &[(u32, String)], ordinal: u32) -> Option<&str> {
    typed
        .iter()
        .find(|(o, _)| *o == ordinal)
        .map(|(_, c)| c.as_str())
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

/// Source location of an external-service call site in the
/// project-relative `file`.  Reads the 1-based `(line, col)` recorded on
/// the [`crate::summary::CalleeSite`] at CFG-build time when `span` is
/// `Some`; otherwise (sink-cap–only fallback path, or legacy summaries
/// loaded from SQLite) returns the file with line 0.
fn call_site_location(file: &str, span: Option<(u32, u32)>) -> SourceLocation {
    let (line, col) = span.unwrap_or((0, 0));
    SourceLocation {
        file: file.to_string(),
        line,
        col,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::{CalleeSite, FuncSummary};
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
    fn ssrf_cap_fallback_carries_owner() {
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "proxy.py", "forward", None);
        let summary = FuncSummary {
            name: "forward".into(),
            file_path: "/abs/proxy.py".into(),
            lang: "python".into(),
            sink_caps: Cap::SSRF.bits(),
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_external_services(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::ExternalService(es) = &nodes[0] else {
            panic!()
        };
        assert_eq!(es.label, "Outbound HTTP");
        assert_eq!(es.owner, "forward");
        assert_eq!(es.location.file, "proxy.py");
    }

    #[test]
    fn data_exfil_cap_emits_egress_node() {
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "leak.py", "dump", None);
        let summary = FuncSummary {
            name: "dump".into(),
            file_path: "leak.py".into(),
            lang: "python".into(),
            sink_caps: Cap::DATA_EXFIL.bits(),
            ..Default::default()
        };
        gs.insert(key, summary);
        let nodes = detect_external_services(&gs);
        assert_eq!(nodes.len(), 1);
        let SurfaceNode::ExternalService(es) = &nodes[0] else {
            panic!()
        };
        assert_eq!(es.label, "Data egress");
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
    fn typed_receiver_http_client_resolves_bound_session_get() {
        // `client = requests.Session(); client.get(url)` — the bare
        // callee `client.get` is not in CLIENT_RULES, but the SSA type
        // engine resolves the receiver to `TypeKind::HttpClient`. The
        // detector retries under `HttpClient.get` and emits an HTTP
        // external-service node.
        use crate::summary::ssa_summary::SsaFuncSummary;
        let mut gs = GlobalSummaries::new();
        let key = FuncKey::new_function(Lang::Python, "client.py", "fetch", None);
        let summary = FuncSummary {
            name: "fetch".into(),
            file_path: "client.py".into(),
            lang: "python".into(),
            param_count: 0,
            callees: vec![{
                let mut c = CalleeSite::bare("client.get");
                c.ordinal = 3;
                c.span = Some((9, 5));
                c
            }],
            ..Default::default()
        };
        gs.insert(key.clone(), summary);
        let mut ssa = SsaFuncSummary::default();
        ssa.typed_call_receivers.push((3, "HttpClient".into()));
        gs.insert_ssa(key, ssa);
        let nodes = detect_external_services(&gs);
        assert_eq!(nodes.len(), 1, "expected typed retry to hit; got {nodes:?}");
        let SurfaceNode::ExternalService(es) = &nodes[0] else {
            panic!()
        };
        assert_eq!(es.label, "HTTP client");
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
