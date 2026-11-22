use super::dominators::{self, dominates};
use super::{
    AnalysisContext, CfgAnalysis, CfgFinding, Confidence, is_auth_call, is_entry_point_func,
    is_sink,
};
use crate::cfg::{EdgeKind, StmtKind};
use crate::labels::DataLabel;
use crate::patterns::Severity;
use crate::symbol::Lang;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

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
/// Returns true if the parameters of the body under analysis suggest it
/// handles HTTP requests.  Every node of a per-body CFG belongs to that one
/// function, so its own parameter list is the one to check.
fn has_web_handler_params(ctx: &AnalysisContext) -> bool {
    let param_names: Vec<&str> = ctx.body_params.iter().map(String::as_str).collect();

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
        return has_web_handler_params(ctx);
    }

    // Must match entrypoint naming patterns
    if !is_entry_point_func(func_name, ctx.lang) {
        return false;
    }

    // For named handlers (handle_*, route_*, api_*), check if they have web params.
    // If we can't determine params (e.g. no summary), fall back to name-only heuristic
    // for handler-style names (but NOT process_* or serve_* without params).
    let has_params = has_web_handler_params(ctx);
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

/// Entry nodes of the branches an authentication test lets through.
///
/// `if (!req.isAuthenticated()) return res.status(401).end();` and
/// `if request.user.is_authenticated: ...` carry the check in the condition of
/// an `If` node, not in a call statement of their own, so `find_auth_nodes`
/// never sees them.  The state engine reads the same conditions with
/// [`condition_contains_auth_token`]; this applies its polarity rule: the
/// test passed on the False edge of a negated condition and on the True edge
/// of a plain one.
///
/// The first node of the passing branch counts as a guard only when the If node
/// is its sole predecessor.  When the rejecting branch does not end the
/// handler (`if (!authed) { res.redirect('/login') } fs.unlink(..)`), the two
/// branches meet again before the sink, the join has other predecessors, and
/// the test guards nothing.
///
/// Only a bare truth test counts.  A comparison (`req.isAuthenticated() ===
/// false`) or a negated compound (`!(authed || isPublic)`) moves the passing
/// side to a branch the polarity rule does not predict.
///
/// [`condition_contains_auth_token`]: crate::state::transfer::condition_contains_auth_token
fn find_auth_condition_guards(ctx: &AnalysisContext) -> Vec<NodeIndex> {
    let mut guards = Vec::new();
    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.kind != StmtKind::If {
            continue;
        }
        let Some(condition) = &info.condition_text else {
            continue;
        };
        let lower = condition.to_ascii_lowercase();
        // Remove the one negation the CFG recorded, and the parentheses the
        // grammar keeps around an `if` condition.  Anything left over
        // (`!!x`) fails the bare-truth-test check below.
        let outer = strip_outer_parens(&lower);
        let inner = if info.condition_negated {
            strip_outer_parens(
                outer
                    .strip_prefix('!')
                    .or_else(|| outer.strip_prefix("not "))
                    .unwrap_or(outer),
            )
        } else {
            outer
        };
        if !is_bare_truth_test(inner) {
            continue;
        }
        let is_auth_test = crate::state::transfer::condition_is_auth_test(inner, ctx.lang);
        if !is_auth_test {
            continue;
        }
        let passing_edge = if info.condition_negated {
            EdgeKind::False
        } else {
            EdgeKind::True
        };
        for edge in ctx.cfg.edges(idx) {
            if *edge.weight() != passing_edge {
                continue;
            }
            let target = edge.target();
            let only_from_test = ctx
                .cfg
                .edges_directed(target, petgraph::Direction::Incoming)
                .all(|incoming| incoming.source() == idx);
            if only_from_test {
                guards.push(target);
            }
        }
    }
    guards
}

/// `(x)` -> `x`, `((x))` -> `x`.  Parentheses that do not wrap the whole text
/// (`(a) && (b)`, `f(x)`) are kept.
fn strip_outer_parens(text: &str) -> &str {
    let mut text = text.trim();
    while text.starts_with('(') && text.ends_with(')') {
        let mut depth = 0usize;
        let wraps = text.bytes().enumerate().all(|(idx, byte)| {
            match byte {
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                _ => {}
            }
            depth > 0 || idx + 1 == text.len()
        });
        if !wraps {
            break;
        }
        text = text[1..text.len() - 1].trim();
    }
    text
}

/// True when the lowercased condition, with its negation already removed, is
/// a call or a member read with no comparison, boolean operator or negation
/// left in it: `req.isauthenticated()`, `request.user.is_authenticated`.
fn is_bare_truth_test(condition: &str) -> bool {
    const OPERATORS: &[&str] = &[
        "=", "<", ">", "!", "&&", "||", " and ", " or ", " is ", " in ", "not ",
    ];
    !OPERATORS.iter().any(|op| condition.contains(op))
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
        let mut auth_nodes = find_auth_nodes(ctx);
        auth_nodes.extend(find_auth_condition_guards(ctx));

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
