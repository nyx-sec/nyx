use super::dominators::{self, dominates};
use super::{
    AnalysisContext, CfgAnalysis, CfgFinding, Confidence, is_auth_call, is_entry_point_func,
    is_sink,
};
use crate::cfg::StmtKind;
use crate::labels::DataLabel;
use crate::patterns::Severity;
use crate::symbol::Lang;
use petgraph::graph::NodeIndex;

pub struct AuthGap;

/// Privileged sink capabilities that warrant auth-gap checking.
/// Shell execution, file I/O, and similar sensitive operations.
fn is_privileged_sink(info: &crate::cfg::NodeInfo) -> bool {
    use crate::labels::Cap;
    info.taint.labels.iter().any(|l| {
        if let DataLabel::Sink(caps) = l {
            caps.intersects(Cap::SHELL_ESCAPE | Cap::FILE_IO)
        } else {
            false
        }
    })
}

/// Web handler parameter patterns by language.
/// Returns true if the function's parameters suggest it handles HTTP requests.
fn has_web_handler_params(ctx: &AnalysisContext, func_name: &str) -> bool {
    // Find parameter names for this function from FuncSummaries
    let param_names: Vec<&str> = ctx
        .func_summaries
        .values()
        .filter(|s| ctx.cfg[s.entry].ast.enclosing_func.as_deref() == Some(func_name))
        .flat_map(|s| s.param_names.iter().map(|p| p.as_str()))
        .collect();

    match ctx.lang {
        Lang::Rust => {
            // Rust web frameworks: actix-web, axum, rocket, warp
            // Look for parameter type-like names: request, req, http_request, json, query, form, etc.
            let web_params = [
                "request",
                "req",
                "http_request",
                "httprequest",
                "json",
                "query",
                "form",
                "payload",
                "body",
                "web",
            ];
            param_names
                .iter()
                .any(|p| web_params.contains(&p.to_ascii_lowercase().as_str()))
        }
        Lang::JavaScript | Lang::TypeScript => {
            // Express.js / Node.js: (req, res), (request, response), (ctx)
            let lower: Vec<String> = param_names.iter().map(|p| p.to_ascii_lowercase()).collect();
            let has_req = lower
                .iter()
                .any(|p| p == "req" || p == "request" || p == "ctx");
            let has_res = lower.iter().any(|p| p == "res" || p == "response");
            // req+res pattern or ctx pattern
            (has_req && has_res) || lower.iter().any(|p| p == "ctx")
        }
        Lang::Python => {
            // Django/Flask: request, self+request
            let lower: Vec<String> = param_names.iter().map(|p| p.to_ascii_lowercase()).collect();
            lower.iter().any(|p| p == "request" || p == "req")
        }
        Lang::Go => {
            // net/http: (w http.ResponseWriter, r *http.Request)
            // At AST level we see parameter names, not types. Look for w+r or writer+request patterns.
            let lower: Vec<String> = param_names.iter().map(|p| p.to_ascii_lowercase()).collect();
            let has_writer = lower.iter().any(|p| p == "w" || p == "writer" || p == "rw");
            let has_request = lower
                .iter()
                .any(|p| p == "r" || p == "req" || p == "request");
            has_writer && has_request
        }
        Lang::Java => {
            // Servlet: HttpServletRequest, Spring: @RequestMapping params
            let lower: Vec<String> = param_names.iter().map(|p| p.to_ascii_lowercase()).collect();
            lower
                .iter()
                .any(|p| p == "request" || p == "req" || p.contains("httpservlet"))
        }
        Lang::Ruby => {
            // Rails controllers use params implicitly; Sinatra uses request
            let lower: Vec<String> = param_names.iter().map(|p| p.to_ascii_lowercase()).collect();
            lower
                .iter()
                .any(|p| p == "request" || p == "req" || p == "params")
        }
        Lang::Php => {
            let lower: Vec<String> = param_names.iter().map(|p| p.to_ascii_lowercase()).collect();
            lower
                .iter()
                .any(|p| p == "$request" || p == "request" || p == "$req")
        }
        _ => false,
    }
}

/// Determine if a function qualifies as a web entrypoint (not just any entrypoint).
///
/// A web entrypoint must:
/// 1. Match entrypoint naming rules (handle_*, route_*, api_*, etc.), but NOT bare `main`
///    unless it has web-like parameters
/// 2. Have parameters resembling HTTP handler signatures
fn is_web_entrypoint(ctx: &AnalysisContext, func_name: &str) -> bool {
    // "main" without web params is a CLI entrypoint, skip
    if func_name == "main" {
        return has_web_handler_params(ctx, func_name);
    }

    // Must match entrypoint naming patterns
    if !is_entry_point_func(func_name, ctx.lang) {
        return false;
    }

    // For named handlers (handle_*, route_*, api_*), check if they have web params.
    // If we can't determine params (e.g. no summary), fall back to name-only heuristic
    // for handler-style names (but NOT process_* or serve_* without params).
    let has_params = has_web_handler_params(ctx, func_name);
    let name_lower = func_name.to_ascii_lowercase();
    let strong_handler_name = name_lower.starts_with("handle_")
        || name_lower.starts_with("route_")
        || name_lower.starts_with("api_")
        || name_lower == "handler";

    has_params || strong_handler_name
}

/// Find functions that qualify as web entrypoints.
fn find_web_entry_point_functions(ctx: &AnalysisContext) -> Vec<String> {
    let mut entry_funcs = Vec::new();
    for idx in ctx.cfg.node_indices() {
        if let Some(func_name) = &ctx.cfg[idx].ast.enclosing_func
            && is_web_entrypoint(ctx, func_name)
            && !entry_funcs.contains(func_name)
        {
            entry_funcs.push(func_name.clone());
        }
    }
    entry_funcs
}

/// Find all auth check nodes in the CFG.
fn find_auth_nodes(ctx: &AnalysisContext) -> Vec<NodeIndex> {
    ctx.cfg
        .node_indices()
        .filter(|&idx| is_auth_call(&ctx.cfg[idx], ctx.lang))
        .collect()
}

impl CfgAnalysis for AuthGap {
    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        // Decorator/annotation/attribute auth on the body declaration
        // already gates every sink in the body, skip the
        // structural-call dominance check entirely when the framework
        // enforces auth at the declaration level.  Mirrors the
        // `classify_auth_decorators` lookup the state engine uses to
        // seed the AuthLevel of the body's initial state, so both
        // analyses agree on which decorators count.
        let body_auth_level = crate::state::classify_auth_decorators(ctx.lang, ctx.auth_decorators);
        if body_auth_level >= crate::state::domain::AuthLevel::Authed {
            return Vec::new();
        }

        let doms = dominators::compute_dominators(ctx.cfg, ctx.entry);
        let entry_funcs = find_web_entry_point_functions(ctx);
        let auth_nodes = find_auth_nodes(ctx);

        if entry_funcs.is_empty() {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // Find sink nodes that are inside web entry point functions
        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];

            if !is_sink(info) && info.kind != StmtKind::Call {
                continue;
            }

            // Only check nodes inside web entry point functions
            let func_name = match &info.ast.enclosing_func {
                Some(name) if entry_funcs.contains(name) => name.clone(),
                _ => continue,
            };

            // Skip if not a sink
            if !is_sink(info) {
                continue;
            }

            // Only flag privileged sinks (shell, file I/O), not all sinks
            if !is_privileged_sink(info) {
                continue;
            }

            // Check: does any auth call dominate this sink?
            let has_auth = auth_nodes
                .iter()
                .any(|&auth_idx| dominates(&doms, auth_idx, idx));

            if !has_auth {
                let callee_desc = info.call.callee.as_deref().unwrap_or("(sensitive op)");

                findings.push(CfgFinding {
                    rule_id: "cfg-auth-gap".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    span: info.ast.span,
                    message: format!(
                        "Sensitive operation `{callee_desc}` in web handler `{func_name}` \
                         has no dominating authentication check"
                    ),
                    evidence: vec![idx],
                    score: None,
                });
            }
        }

        findings
    }
}
