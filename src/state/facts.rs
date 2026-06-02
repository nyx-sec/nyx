#![allow(clippy::unnecessary_map_or)]

use super::domain::{AuthLevel, ProductState, ResourceLifecycle};
use super::engine::DataflowResult;
use super::symbol::SymbolInterner;
use super::transfer::{TransferEvent, TransferEventKind};
use crate::cfg::{Cfg, StmtKind};
use crate::labels::{Cap, DataLabel};
use crate::patterns::Severity;
use crate::symbol::Lang;
use petgraph::visit::IntoNodeReferences;

/// Normalize a callee description for display.
fn sanitize_desc(s: &str) -> String {
    crate::fmt::normalize_snippet(s)
}

/// Returns true if `idx` is the terminal exit of a function body, the
/// convergence node where all execution paths join before leaving the function.
///
/// **Invariant:** Only terminal exits carry the complete merged lifecycle state
/// needed for leak analysis.  Return nodes are intermediate in per-body graphs
/// (they flow into the synthetic Exit node) but become terminal in legacy
/// supergraphs (their successor is the file-level Exit with
/// `enclosing_func = None`).
///
/// Detection combines a kind filter with a topological check.  Only nodes
/// whose `StmtKind` actually terminates execution (`Exit`, `Return`, `Throw`)
/// are considered, then we require that they have no successor in the same
/// function scope.  Without the kind filter, dangling Seq nodes left behind
/// when nested function literals (e.g. `obj.fn = () => {...}`) get a
/// placeholder in the parent graph would be misclassified as terminal exits
/// and produce spurious resource-leak findings at the function-literal span.
fn is_terminal_function_exit(
    idx: petgraph::graph::NodeIndex,
    info: &crate::cfg::NodeInfo,
    cfg: &Cfg,
) -> bool {
    if !matches!(
        info.kind,
        StmtKind::Exit | StmtKind::Return | StmtKind::Throw
    ) {
        return false;
    }
    info.ast.enclosing_func.is_some()
        && !cfg
            .neighbors_directed(idx, petgraph::Direction::Outgoing)
            .any(|succ| cfg[succ].ast.enclosing_func == info.ast.enclosing_func)
}

/// A finding produced by state analysis.
#[derive(Debug, Clone)]
pub struct StateFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub span: (usize, usize),
    pub message: String,
    /// State machine that produced this finding: `"resource"` or `"auth"`.
    pub machine: &'static str,
    /// Variable name involved, if available.
    pub subject: Option<String>,
    /// State before the event (e.g. `"closed"`, `"open"`, `"unauthed"`).
    pub from_state: &'static str,
    /// State after the event (e.g. `"used"`, `"closed"`, `"leaked"`, `"access"`).
    pub to_state: &'static str,
}

/// Extract findings from converged dataflow state + transfer events.
///
/// `path_safe_suppressed_sink_spans` lists CFG sink spans whose tainted
/// inputs were proved path-safe by the SSA taint engine; the privileged
/// `state-unauthed-access` finding is suppressed on those spans because
/// the user-controlled input has already been proved unable to escape
/// into a privileged location.
#[allow(clippy::too_many_arguments)]
pub fn extract_findings(
    result: &DataflowResult<ProductState, TransferEvent>,
    cfg: &Cfg,
    interner: &SymbolInterner,
    lang: Lang,
    func_summaries: &crate::cfg::FuncSummaries,
    enable_auth: bool,
    path_safe_suppressed_sink_spans: &std::collections::HashSet<(usize, usize)>,
    closure_released_var_names: Option<&std::collections::HashSet<String>>,
) -> Vec<StateFinding> {
    let mut findings = Vec::new();

    // ── 1. Use-after-close from transfer events ──────────────────────────
    for event in &result.events {
        let info = &cfg[event.node];
        let var_name = interner.resolve(event.var);
        match event.kind {
            TransferEventKind::UseAfterClose => {
                findings.push(StateFinding {
                    rule_id: "state-use-after-close".into(),
                    severity: Severity::High,
                    span: info.ast.span,
                    message: format!("variable `{var_name}` used after close"),
                    machine: "resource",
                    subject: Some(var_name.to_string()),
                    from_state: "closed",
                    to_state: "used",
                });
            }
            TransferEventKind::DoubleClose => {
                findings.push(StateFinding {
                    rule_id: "state-double-close".into(),
                    severity: Severity::Medium,
                    span: info.ast.span,
                    message: format!("variable `{var_name}` closed twice"),
                    machine: "resource",
                    subject: Some(var_name.to_string()),
                    from_state: "closed",
                    to_state: "closed",
                });
            }
        }
    }

    // ── 2. Resource leaks at Exit and function-Return nodes ──────────────

    // Collect variables with a deferred release call (Go `defer f.Close()`).
    // These remain OPEN at function exit because transfer skips deferred
    // releases, but the runtime guarantees cleanup.
    let deferred_close_vars: std::collections::HashSet<super::symbol::SymbolId> = {
        let pairs = crate::cfg_analysis::rules::resource_pairs(lang);
        cfg.node_references()
            .filter(|(_, ni)| {
                ni.in_defer
                    && ni.kind == StmtKind::Call
                    && ni.call.callee.as_ref().is_some_and(|c| {
                        let cl = c.to_ascii_lowercase();
                        pairs.iter().any(|p| {
                            p.release.iter().any(|r| {
                                let rl = r.to_ascii_lowercase();
                                if rl.starts_with('.') {
                                    cl.ends_with(&rl)
                                } else {
                                    cl.ends_with(&rl) || cl == rl
                                }
                            })
                        })
                    })
            })
            .flat_map(|(_, ni)| {
                let scope = ni.ast.enclosing_func.clone();
                ni.taint
                    .uses
                    .iter()
                    .filter_map(move |v| interner.get_scoped(scope.as_deref(), v))
            })
            .collect()
    };

    // Collect variables released via inner-call-in-arg shape (Go testify
    // `require.NoError(t, f.Close())`, `errs = append(errs, f.Close())`,
    // JUnit `assertEquals(0, in.read())`).  The transfer flips the
    // lifecycle to CLOSED on the success branch, but the err-return
    // predecessor that ran after the bare acquire (`f, err := os.Open(...)`)
    // still merges OPEN at the function-exit join.  Mirror the
    // `deferred_close_vars` suppression so the OPEN|CLOSED join doesn't
    // emit a leak-possible for a resource that has a real release site.
    let inner_arg_close_vars: std::collections::HashSet<super::symbol::SymbolId> = {
        let pairs = crate::cfg_analysis::rules::resource_pairs(lang);
        let mut set = std::collections::HashSet::new();
        for (_, ni) in cfg.node_references() {
            if ni.in_defer || ni.arg_callees.is_empty() {
                continue;
            }
            let scope = ni.ast.enclosing_func.as_deref();
            for arg_callee in &ni.arg_callees {
                let Some(arg_callee_text) = arg_callee.as_deref() else {
                    continue;
                };
                let Some(dot_idx) = arg_callee_text.rfind('.') else {
                    continue;
                };
                let recv_text = &arg_callee_text[..dot_idx];
                if recv_text.contains('.') {
                    continue;
                }
                let arg_callee_lower = arg_callee_text.to_ascii_lowercase();
                let matches_release = pairs.iter().any(|p| {
                    p.release.iter().any(|r| {
                        let rl = r.to_ascii_lowercase();
                        if rl.starts_with('.') {
                            arg_callee_lower.ends_with(&rl)
                        } else {
                            arg_callee_lower.ends_with(&rl) || arg_callee_lower == rl
                        }
                    })
                });
                if !matches_release {
                    continue;
                }
                if let Some(sym) = interner.get_scoped(scope, recv_text) {
                    set.insert(sym);
                }
            }
        }
        set
    };

    for (idx, info) in cfg.node_references() {
        // File-level Exit (program termination, no enclosing function).
        let is_file_exit = info.kind == StmtKind::Exit && info.ast.enclosing_func.is_none();
        // Terminal function exit, the convergence node where all paths join.
        // Return nodes are intermediate and carry only path-specific state;
        // only the terminal exit carries the complete merged lifecycle.
        let is_func_terminal = is_terminal_function_exit(idx, info, cfg);
        if !is_file_exit && !is_func_terminal {
            continue;
        }
        let Some(state) = result.states.get(&idx) else {
            continue;
        };

        for (&sym, &lifecycle) in &state.resource.vars {
            if !lifecycle.contains(ResourceLifecycle::OPEN) {
                continue;
            }
            let var_name = interner.resolve(sym);
            let scope = if is_func_terminal {
                info.ast.enclosing_func.as_deref()
            } else {
                None
            };
            let acquire_node = find_acquire_node(cfg, sym, interner, scope);

            // At the file-level Exit, skip variables whose acquire site is
            // inside a function, those are already handled by the per-
            // function exit checks above.  Without this, the file-level Exit
            // would duplicate leak findings with a misleading acquire span
            // (the first global match instead of the correct function-local one).
            if is_file_exit {
                if let Some(acq) = acquire_node {
                    if cfg[acq].ast.enclosing_func.is_some() {
                        continue;
                    }
                }
            }

            // Suppress leaks for resources acquired inside managed scopes
            // (Python `with`, Java try-with-resources). The suppression is
            // tied to the specific acquire site, not the variable name.
            if let Some(acq) = acquire_node {
                if cfg[acq].managed_resource {
                    continue;
                }
            }

            // Suppress leaks for variables with a deferred close call
            // (Go `defer f.Close()`). The deferred call guarantees cleanup
            // at function exit even though transfer didn't mark it CLOSED.
            if deferred_close_vars.contains(&sym) {
                continue;
            }

            // Suppress leaks for variables released via inner-call-in-arg
            // shape.  Mirrors the deferred-close suppression so the
            // OPEN-on-err-return / CLOSED-on-success-branch merge at
            // function exit does not surface as leak-possible.
            if inner_arg_close_vars.contains(&sym) {
                continue;
            }

            // Suppress leaks for variables whose release call lives in a
            // nested closure (callback / event handler) outside this
            // body's CFG.  Common JS/TS shape:
            //   const ws = new WebSocket(url);
            //   socket.on("close", () => ws.close());
            // The per-body resource analysis cannot observe the close
            // inside the registered handler body; without this gate the
            // handle reads as a definite leak.  Match by variable name —
            // closure-captured handles share the binding name with the
            // handle in the outer scope.
            if closure_released_var_names
                .map(|s| s.contains(var_name))
                .unwrap_or(false)
            {
                continue;
            }

            // Prefer direct acquire node span; fall back to proxy span
            // from ResourceMethodSummary (cross-body resource tracking).
            let acquire_span = acquire_node
                .map(|n| cfg[n].ast.span)
                .or_else(|| state.proxy_acquire_spans.get(&sym).copied());

            // Suppress/downgrade leaks for variables returned from the
            // function (factory pattern).  Only suppress when ALL
            // predecessors that have the variable OPEN also return it.
            // Mixed cases (some paths return, some leak) are downgraded
            // to state-resource-leak-possible.
            if is_func_terminal {
                let scope = info.ast.enclosing_func.as_deref();
                let mut returned_open = 0u32;
                let mut non_returned_open = 0u32;
                for pred in cfg.neighbors_directed(idx, petgraph::Direction::Incoming) {
                    let Some(ps) = result.states.get(&pred) else {
                        continue;
                    };
                    let pred_has_open = ps
                        .resource
                        .vars
                        .get(&sym)
                        .map_or(false, |lc| lc.contains(ResourceLifecycle::OPEN));
                    if !pred_has_open {
                        continue;
                    }
                    // Only Return nodes can transfer resource ownership to the
                    // caller.  Non-Return predecessors (exception edges, implicit
                    // fallthrough) with OPEN resources represent genuine leaks.
                    let returns_var = cfg[pred].kind == StmtKind::Return
                        && cfg[pred]
                            .taint
                            .uses
                            .iter()
                            .any(|u| interner.get_scoped(scope, u) == Some(sym));
                    if returns_var {
                        returned_open += 1;
                    } else {
                        non_returned_open += 1;
                    }
                }
                if returned_open > 0 && non_returned_open == 0 {
                    continue; // all OPEN paths transfer ownership to caller
                }
                if returned_open > 0 && non_returned_open > 0 {
                    // Mixed: some paths return resource, some leak it.
                    findings.push(StateFinding {
                        rule_id: "state-resource-leak-possible".into(),
                        severity: Severity::Low,
                        span: acquire_span.unwrap_or(info.ast.span),
                        message: format!("resource `{var_name}` may not be closed on all paths"),
                        machine: "resource",
                        subject: Some(var_name.to_string()),
                        from_state: "open",
                        to_state: "possibly_leaked",
                    });
                    continue;
                }
                // returned_open == 0: fall through to normal leak detection
            }

            if !lifecycle.contains(ResourceLifecycle::CLOSED)
                && !lifecycle.contains(ResourceLifecycle::MOVED)
            {
                // Definite leak: open on all paths, never closed
                findings.push(StateFinding {
                    rule_id: "state-resource-leak".into(),
                    severity: Severity::Medium,
                    span: acquire_span.unwrap_or(info.ast.span),
                    message: format!("resource `{var_name}` is never closed"),
                    machine: "resource",
                    subject: Some(var_name.to_string()),
                    from_state: "open",
                    to_state: "leaked",
                });
            } else if lifecycle.contains(ResourceLifecycle::CLOSED) {
                // May-leak: open on some paths, closed on others
                findings.push(StateFinding {
                    rule_id: "state-resource-leak-possible".into(),
                    severity: Severity::Low,
                    span: acquire_span.unwrap_or(info.ast.span),
                    message: format!("resource `{var_name}` may not be closed on all paths"),
                    machine: "resource",
                    subject: Some(var_name.to_string()),
                    from_state: "open",
                    to_state: "possibly_leaked",
                });
            }
        }
    }

    // ── 2b. Proxy-acquired possible leaks (exception-path heuristic) ────
    // In JS/TS, any call can throw. If a proxy-acquired resource is fully
    // CLOSED at function exit (no OPEN paths), check whether there are
    // intervening calls between the proxy acquire and release nodes that
    // could throw and bypass the release. If so, emit a possible leak.
    //
    // **Language gate**: this heuristic is JS/TS-specific.  Other
    // languages (Go, Java, C, C++, Python, Rust, Ruby, PHP) use
    // explicit error returns / try-catch with deterministic control
    // flow, an intervening call does NOT silently bypass a release.
    // Firing this on Go gave the gin/context.go FP where any method
    // calling another method (`c.Set`, `c.Get`) was flagged as a
    // possible leak on the receiver.  Skip the section but continue
    // to section 3 (auth-required sinks) which is independent of the
    // resource state machine.
    if matches!(lang, Lang::JavaScript | Lang::TypeScript) {
        for (idx, info) in cfg.node_references() {
            if !is_terminal_function_exit(idx, info, cfg) {
                continue;
            }
            let Some(state) = result.states.get(&idx) else {
                continue;
            };
            for (&sym, &lifecycle) in &state.resource.vars {
                // Only for proxy-acquired resources that are fully CLOSED at exit
                if !state.proxy_acquire_spans.contains_key(&sym) {
                    continue;
                }
                if lifecycle.contains(ResourceLifecycle::OPEN) {
                    continue; // Already handled by the normal leak detection above
                }
                if !lifecycle.contains(ResourceLifecycle::CLOSED) {
                    continue;
                }
                // Check if there are intervening Call nodes between acquire and release
                // in the CFG (these could throw and bypass the release)
                let has_intervening_calls = cfg.node_references().any(|(_, ni)| {
                    ni.kind == StmtKind::Call
                        && ni.ast.enclosing_func == info.ast.enclosing_func
                        && ni.call.callee.is_some()
                        // Not the acquire or release proxy itself
                        && !state.proxy_acquire_spans.values().any(|s| *s == ni.ast.span)
                });
                if has_intervening_calls {
                    let var_name = interner.resolve(sym);
                    let acquire_span = state.proxy_acquire_spans.get(&sym).copied();
                    findings.push(StateFinding {
                        rule_id: "state-resource-leak-possible".into(),
                        severity: Severity::Low,
                        span: acquire_span.unwrap_or(info.ast.span),
                        message: format!("resource `{var_name}` may not be closed on all paths"),
                        machine: "resource",
                        subject: Some(var_name.to_string()),
                        from_state: "open",
                        to_state: "possibly_leaked",
                    });
                }
            }
        }
    }

    // ── 3. Auth-required sinks ───────────────────────────────────────────
    // Only run auth analysis when explicitly enabled (higher FP rate).
    // Check if any function is a web entrypoint
    let has_web_entrypoint = enable_auth
        && cfg.node_references().any(|(_, info)| {
            if let Some(ref func_name) = info.ast.enclosing_func {
                is_web_entrypoint_simple(func_name, lang, func_summaries, cfg)
            } else {
                false
            }
        });

    if has_web_entrypoint {
        for (idx, info) in cfg.node_references() {
            if !is_privileged_sink(info) {
                continue;
            }
            let Some(state) = result.states.get(&idx) else {
                continue;
            };
            if state.auth.auth_level == AuthLevel::Unauthed {
                // Suppress when the SSA taint engine has already proved
                // the tainted input flowing into this sink is path-safe
                // (PathFact `dotdot=No && absolute=No`).  A web handler
                // reading a sanitised user-controlled path is not the
                // same shape as a handler reading any user-controlled
                // path, the auth concern reduces once the data cannot
                // escape into a privileged location.  Note this is per
                // CFG-node span, so co-located unrelated sinks are
                // unaffected.
                if path_safe_suppressed_sink_spans.contains(&info.ast.span) {
                    continue;
                }
                let callee_desc =
                    sanitize_desc(info.call.callee.as_deref().unwrap_or("(sensitive op)"));
                findings.push(StateFinding {
                    rule_id: "state-unauthed-access".into(),
                    severity: Severity::High,
                    span: info.ast.span,
                    message: format!(
                        "sensitive operation `{callee_desc}` reached without authentication"
                    ),
                    machine: "auth",
                    subject: None,
                    from_state: "unauthed",
                    to_state: "access",
                });
            }
        }
    }

    // Dedup
    findings.sort_by(|a, b| a.span.cmp(&b.span).then_with(|| a.rule_id.cmp(&b.rule_id)));
    findings.dedup_by(|a, b| a.span == b.span && a.rule_id == b.rule_id);

    findings
}

/// Find the CFG node where a variable was acquired (defined via Call node).
fn find_acquire_node(
    cfg: &Cfg,
    sym: super::symbol::SymbolId,
    interner: &SymbolInterner,
    enclosing_func: Option<&str>,
) -> Option<petgraph::graph::NodeIndex> {
    let var_name = interner.resolve(sym);
    // Try function-scoped match first (correct for multi-function files
    // where the same variable name appears in multiple functions).
    if let Some(func) = enclosing_func {
        for (idx, info) in cfg.node_references() {
            if info.kind == StmtKind::Call
                && info.ast.enclosing_func.as_deref() == Some(func)
                && info.taint.defines.as_deref() == Some(var_name)
            {
                return Some(idx);
            }
        }
    }
    // Fallback: first global match (for file-level Exit or top-level code).
    for (idx, info) in cfg.node_references() {
        if info.kind == StmtKind::Call && info.taint.defines.as_deref() == Some(var_name) {
            return Some(idx);
        }
    }
    None
}

/// Check if a node is a privileged sink (shell execution or file I/O).
fn is_privileged_sink(info: &crate::cfg::NodeInfo) -> bool {
    info.taint.labels.iter().any(|l| {
        if let DataLabel::Sink(caps) = l {
            caps.intersects(Cap::SHELL_ESCAPE | Cap::FILE_IO)
        } else {
            false
        }
    })
}

/// Simplified web entrypoint check (avoids AnalysisContext dependency).
fn is_web_entrypoint_simple(
    func_name: &str,
    lang: Lang,
    func_summaries: &crate::cfg::FuncSummaries,
    _cfg: &Cfg,
) -> bool {
    let name_lower = func_name.to_ascii_lowercase();

    // Skip bare "main", it's typically a CLI entry
    if name_lower == "main" {
        return false;
    }

    let is_handler_name = name_lower.starts_with("handle_")
        || name_lower.starts_with("route_")
        || name_lower.starts_with("api_")
        || name_lower.starts_with("serve_")
        || name_lower.starts_with("process_")
        || name_lower == "handler";

    if !is_handler_name {
        return false;
    }

    // Check for web-like parameters
    let web_params: &[&str] = match lang {
        Lang::Rust => &["request", "req", "json", "query", "form", "payload", "body"],
        Lang::JavaScript | Lang::TypeScript => &["req", "request", "ctx", "res", "response"],
        Lang::Python => &["request", "req"],
        Lang::Go => &["w", "writer", "r", "req", "request"],
        Lang::Java => &["request", "req"],
        _ => &["request", "req"],
    };

    let has_web_params = func_summaries.values().any(|s| {
        s.param_names
            .iter()
            .any(|p| web_params.contains(&p.to_ascii_lowercase().as_str()))
    });

    // Only handle_* and route_* are strong enough to skip param confirmation.
    // api_*, serve_*, process_* require web parameter evidence.
    let strong_name = name_lower.starts_with("handle_") || name_lower.starts_with("route_");

    has_web_params || strong_name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{AstMeta, CallMeta, EdgeKind, NodeInfo, TaintMeta};
    use crate::cfg_analysis::rules;
    use crate::state::domain::ProductState;
    use crate::state::engine;
    use crate::state::symbol::SymbolInterner;
    use crate::state::transfer::DefaultTransfer;
    use petgraph::Graph;
    use std::collections::HashMap;

    fn make_node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    #[test]
    fn detects_resource_leak() {
        // Entry → fopen(f) → Exit (no close)
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (10, 20),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("f".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fopen".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = engine::run_forward(&cfg, entry, &transfer, ProductState::initial());
        let findings = extract_findings(
            &result,
            &cfg,
            &interner,
            Lang::C,
            &HashMap::new(),
            false,
            &std::collections::HashSet::new(),
            None,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "state-resource-leak");
        assert!(findings[0].message.contains("f"));
    }

    #[test]
    fn clean_open_close_no_findings() {
        // Entry → fopen(f) → fclose(f) → Exit
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_node(StmtKind::Entry));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                defines: Some("f".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fopen".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let close_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            taint: TaintMeta {
                uses: vec!["f".into()],
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fclose".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let exit = cfg.add_node(make_node(StmtKind::Exit));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, close_node, EdgeKind::Seq);
        cfg.add_edge(close_node, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = engine::run_forward(&cfg, entry, &transfer, ProductState::initial());
        let findings = extract_findings(
            &result,
            &cfg,
            &interner,
            Lang::C,
            &HashMap::new(),
            false,
            &std::collections::HashSet::new(),
            None,
        );

        assert!(findings.is_empty());
    }

    fn make_func_node(kind: StmtKind, func: &str) -> NodeInfo {
        NodeInfo {
            kind,
            ast: AstMeta {
                enclosing_func: Some(func.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn terminal_exit_is_topological() {
        // Per-body graph: Entry → Call → Return → Exit (all enclosing_func=Some)
        // Only Exit should be terminal (no successors in same scope).
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_func_node(StmtKind::Entry, "f"));
        let call = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some("fopen".into()),
                ..Default::default()
            },
            taint: TaintMeta {
                defines: Some("x".into()),
                ..Default::default()
            },
            ast: AstMeta {
                enclosing_func: Some("f".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let ret = cfg.add_node(NodeInfo {
            kind: StmtKind::Return,
            taint: TaintMeta {
                uses: vec!["x".into()],
                ..Default::default()
            },
            ast: AstMeta {
                enclosing_func: Some("f".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let exit = cfg.add_node(make_func_node(StmtKind::Exit, "f"));

        cfg.add_edge(entry, call, EdgeKind::Seq);
        cfg.add_edge(call, ret, EdgeKind::Seq);
        cfg.add_edge(ret, exit, EdgeKind::Seq);

        assert!(
            !is_terminal_function_exit(entry, &cfg[entry], &cfg),
            "Entry must not be terminal"
        );
        assert!(
            !is_terminal_function_exit(call, &cfg[call], &cfg),
            "Call must not be terminal"
        );
        assert!(
            !is_terminal_function_exit(ret, &cfg[ret], &cfg),
            "Return must not be terminal — it flows into Exit"
        );
        assert!(
            is_terminal_function_exit(exit, &cfg[exit], &cfg),
            "Exit must be terminal — no successors in same scope"
        );
    }

    #[test]
    fn per_body_factory_returned_resource_no_finding() {
        // Per-body graph: Entry → fopen(f) → return f → Exit
        // All nodes have enclosing_func=Some("factory").
        // The resource is returned, no leak finding expected.
        let func = "factory";
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_func_node(StmtKind::Entry, func));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (10, 20),
                enclosing_func: Some(func.into()),
            },
            taint: TaintMeta {
                defines: Some("f".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fopen".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let ret = cfg.add_node(NodeInfo {
            kind: StmtKind::Return,
            taint: TaintMeta {
                uses: vec!["f".into()],
                ..Default::default()
            },
            ast: AstMeta {
                enclosing_func: Some(func.into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let exit = cfg.add_node(make_func_node(StmtKind::Exit, func));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, ret, EdgeKind::Seq);
        cfg.add_edge(ret, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg_scoped(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = engine::run_forward(&cfg, entry, &transfer, ProductState::initial());
        let findings = extract_findings(
            &result,
            &cfg,
            &interner,
            Lang::C,
            &HashMap::new(),
            false,
            &std::collections::HashSet::new(),
            None,
        );

        assert!(
            findings.is_empty(),
            "Resource returned from factory must not produce leak finding.\n  Got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn per_body_non_returned_resource_leaks() {
        // Per-body graph: Entry → fopen(f) → return (no uses) → Exit
        // All nodes have enclosing_func=Some("leaker").
        // Resource is NOT returned, exactly one state-resource-leak expected.
        let func = "leaker";
        let mut cfg: Cfg = Graph::new();
        let entry = cfg.add_node(make_func_node(StmtKind::Entry, func));
        let open_node = cfg.add_node(NodeInfo {
            kind: StmtKind::Call,
            ast: AstMeta {
                span: (10, 20),
                enclosing_func: Some(func.into()),
            },
            taint: TaintMeta {
                defines: Some("f".into()),
                ..Default::default()
            },
            call: CallMeta {
                callee: Some("fopen".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let ret = cfg.add_node(NodeInfo {
            kind: StmtKind::Return,
            ast: AstMeta {
                enclosing_func: Some(func.into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let exit = cfg.add_node(make_func_node(StmtKind::Exit, func));

        cfg.add_edge(entry, open_node, EdgeKind::Seq);
        cfg.add_edge(open_node, ret, EdgeKind::Seq);
        cfg.add_edge(ret, exit, EdgeKind::Seq);

        let interner = SymbolInterner::from_cfg_scoped(&cfg);
        let transfer = DefaultTransfer {
            lang: Lang::C,
            resource_pairs: rules::resource_pairs(Lang::C),
            interner: &interner,
            resource_method_summaries: &[],
            ptr_proxy_hints: None,
        };

        let result = engine::run_forward(&cfg, entry, &transfer, ProductState::initial());
        let findings = extract_findings(
            &result,
            &cfg,
            &interner,
            Lang::C,
            &HashMap::new(),
            false,
            &std::collections::HashSet::new(),
            None,
        );

        assert_eq!(
            findings.len(),
            1,
            "Non-returned resource must produce exactly one finding.\n  Got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
        assert_eq!(findings[0].rule_id, "state-resource-leak");
    }
}
