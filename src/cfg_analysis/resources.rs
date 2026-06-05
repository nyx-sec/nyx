use super::dominators;
use super::rules;
use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence};
use crate::cfg::{EdgeKind, StmtKind};
use crate::patterns::Severity;
use crate::symbol::Lang;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::HashSet;

pub struct ResourceMisuse;

/// Distinguishes `obj.connect("event-name", handler)` event-handler
/// registrations from real database-connection acquires.
///
/// Recognises the canonical handler shape: a string-literal first arg
/// that does not look like a URL (`scheme://`), plus a second positional
/// argument that resolves to a single identifier (the callable being
/// registered).  SQLAlchemy `engine.connect()` and `sqlite3.connect(
/// "path.db")` either pass zero args or a single string, so they fall
/// through and the leak check still fires.
///
/// Kept out of the static `exclude_acquire` list because that list is
/// callee-substring-only; this check needs to read argument shape from
/// the call node.
fn is_event_handler_register_shape(info: &crate::cfg::NodeInfo) -> bool {
    let Some(first_literal) = info
        .call
        .arg_string_literals
        .first()
        .and_then(|x| x.as_ref())
    else {
        return false;
    };
    if first_literal.contains("://") {
        return false;
    }
    let Some(second_uses) = info.call.arg_uses.get(1) else {
        return false;
    };
    // A bare identifier (`callback`) lands as `["callback"]`; a
    // member-access ref (`self._on_status`) lands as `["self",
    // "_on_status"]`.  Both are valid handler shapes.  Real DB connects
    // either have no second positional or pass a non-ident value
    // (string literal for `connect("user", "pass", ...)`), which lands
    // as an empty `arg_uses[1]`.
    !second_uses.is_empty()
}

/// Find nodes matching acquire patterns for a given resource pair,
/// excluding any that match `exclude_patterns`.
fn find_acquire_nodes(
    ctx: &AnalysisContext,
    acquire_patterns: &[&str],
    exclude_patterns: &[&str],
) -> Vec<NodeIndex> {
    ctx.cfg
        .node_indices()
        .filter(|&idx| {
            let info = &ctx.cfg[idx];
            if info.kind != StmtKind::Call {
                return false;
            }
            if let Some(callee) = &info.call.callee {
                let callee_lower = callee.to_ascii_lowercase();
                // Check exclusions first, if the callee matches an exclude
                // pattern, it is NOT an acquire even if it also matches an
                // acquire pattern (e.g. `freopen` ends with `fopen`).
                let excluded = exclude_patterns.iter().any(|p| {
                    let pl = p.to_ascii_lowercase();
                    callee_lower.ends_with(&pl) || callee_lower == pl
                });
                if excluded {
                    return false;
                }
                acquire_patterns.iter().any(|p| {
                    let pl = p.to_ascii_lowercase();
                    callee_lower.ends_with(&pl) || callee_lower == pl
                })
            } else {
                false
            }
        })
        .collect()
}

/// Find nodes matching release patterns for a given resource pair.
///
/// Includes both direct release calls (`info.call.callee`) and inner-arg
/// release calls (`info.arg_callees`), so wrapper shapes like Go testify
/// `require.NoError(t, f.Close())` and `errs = append(errs, f.Close())`
/// register the close site even though the outer callee is the wrapper.
fn find_release_nodes(ctx: &AnalysisContext, release_patterns: &[&str]) -> Vec<NodeIndex> {
    let matches_release = |callee: &str| -> bool {
        let callee_lower = callee.to_ascii_lowercase();
        release_patterns.iter().any(|p| {
            let pl = p.to_ascii_lowercase();
            callee_lower.ends_with(&pl) || callee_lower == pl
        })
    };
    ctx.cfg
        .node_indices()
        .filter(|&idx| {
            let info = &ctx.cfg[idx];
            if let Some(callee) = &info.call.callee
                && info.kind == StmtKind::Call
                && matches_release(callee)
            {
                return true;
            }
            // Inner-call-release-in-arg: any kind, the close lives in an
            // argument to the outer wrapper.
            info.arg_callees
                .iter()
                .filter_map(|c| c.as_deref())
                .any(matches_release)
        })
        .collect()
}

/// Check if a release node is on all paths from acquire to every exit.
///
/// Treats null-guard-false edges as not-applicable: when control reaches an
/// `if (acquire_var)` (or `if (!acquire_var)`) and the edge represents
/// "acquire_var is null", the resource was never actually produced on that
/// path, so a release is unnecessary.  This closes the canonical
/// `FILE *f = fopen(...); if (f) fclose(f);` idiom, without this rule the
/// false edge of the null check provides a path acquire→exit that misses
/// the release, producing a may-leak FP.
fn release_on_all_exit_paths(
    ctx: &AnalysisContext,
    acquire: NodeIndex,
    release_nodes: &[NodeIndex],
    exit: NodeIndex,
) -> bool {
    // Use post-dominators as optimization: if any release post-dominates acquire, it's fine
    if let Some(post_doms) = dominators::compute_post_dominators(ctx.cfg) {
        for &release in release_nodes {
            if dominators::dominates(&post_doms, release, acquire) {
                return true;
            }
        }
    }

    // Fall back to path enumeration with null-guard pruning.
    let acquire_var = ctx.cfg[acquire].taint.defines.as_deref();
    let extra_defines = &ctx.cfg[acquire].taint.extra_defines;
    let release_set: HashSet<_> = release_nodes.iter().copied().collect();
    all_paths_pass_through(ctx, acquire, exit, &release_set, acquire_var, extra_defines)
}

/// Identify whether a CFG edge is the "null-guard false edge" for the named
/// acquired variable.  Returns `true` for the edge that, if traversed, means
/// the resource handle is null/falsy and therefore not actually acquired.
///
/// Recognises:
///   * `if (var)`, false edge means `var` is null
///   * `if (!var)`, true edge means `var` is null
///
/// Rejects comparisons (`if (var != NULL)`), method calls
/// (`if (var.is_valid())`), and composite conditions (`if (var && cond)`).
fn is_null_guard_false_edge(
    ctx: &AnalysisContext,
    src: NodeIndex,
    edge_kind: EdgeKind,
    acquire_var: &str,
) -> bool {
    let info = &ctx.cfg[src];
    if info.kind != StmtKind::If {
        return false;
    }
    if info.condition_vars.len() != 1 || info.condition_vars[0] != acquire_var {
        return false;
    }
    let Some(text) = info.condition_text.as_deref() else {
        return false;
    };
    let stripped = text
        .trim()
        .trim_start_matches('!')
        .trim()
        .trim_matches(|c: char| c == '(' || c == ')')
        .trim();
    if stripped != acquire_var {
        return false;
    }
    // Choose the null edge: false for plain truth check, true for negated.
    let null_edge = if info.condition_negated {
        EdgeKind::True
    } else {
        EdgeKind::False
    };
    edge_kind == null_edge
}

/// Recognise Go's err-companion guard: `if err != nil { return err }` where
/// `err` is a companion define of the acquire (`f, err := os.Open(...)`).
/// On the err-true edge the resource was never actually acquired (acquire
/// returned the zero value), so the path is not a real leak path.
///
/// Returns `true` for the edge that takes the err-non-nil branch.  Match is
/// strict: condition must reference exactly one var that lives in the
/// acquire's `extra_defines`, condition_text must compare against `nil`, and
/// the chosen edge must match the err-non-nil polarity.
fn is_err_companion_guard_edge(
    ctx: &AnalysisContext,
    src: NodeIndex,
    edge_kind: EdgeKind,
    extra_defines: &[String],
) -> bool {
    if extra_defines.is_empty() {
        return false;
    }
    let info = &ctx.cfg[src];
    if info.kind != StmtKind::If {
        return false;
    }
    if info.condition_vars.len() != 1 {
        return false;
    }
    let cond_var = &info.condition_vars[0];
    if !extra_defines.iter().any(|e| e == cond_var) {
        return false;
    }
    let Some(text) = info.condition_text.as_deref() else {
        return false;
    };
    // Normalise: drop spaces so `err!=nil` and `err != nil` both match.
    let collapsed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let var_eq_nil = format!("{cond_var}==nil");
    let var_neq_nil = format!("{cond_var}!=nil");
    // Polarity: `err != nil` → err-non-nil branch is the True edge;
    //           `err == nil` → err-non-nil branch is the False edge.
    let err_branch = if collapsed.contains(&var_neq_nil) {
        if info.condition_negated {
            EdgeKind::False
        } else {
            EdgeKind::True
        }
    } else if collapsed.contains(&var_eq_nil) {
        if info.condition_negated {
            EdgeKind::True
        } else {
            EdgeKind::False
        }
    } else {
        return false;
    };
    edge_kind == err_branch
}

/// Check if all paths from `from` to `to` pass through at least one node in `through`,
/// pruning null-guard-false edges for the acquired variable so the canonical
/// `if (var) release(var);` idiom is recognised as a complete release.
fn all_paths_pass_through(
    ctx: &AnalysisContext,
    from: NodeIndex,
    to: NodeIndex,
    through: &HashSet<NodeIndex>,
    acquire_var: Option<&str>,
    extra_defines: &[String],
) -> bool {
    use std::collections::VecDeque;

    if through.contains(&from) {
        return true;
    }

    // BFS, tracking whether we've passed through a required node
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((from, false));
    visited.insert((from, false));

    while let Some((node, passed)) = queue.pop_front() {
        if node == to {
            if !passed {
                return false; // Found a path to exit without passing through release
            }
            continue;
        }

        // Treat a Return-of-err-companion as a passing exit: in Go's
        // `f, err := os.Open(...); if err != nil { return err }` shape the
        // err-return path does not actually own a resource (acquire returned
        // the zero value), so reaching such a Return is not a leak.
        let info = &ctx.cfg[node];
        if info.kind == StmtKind::Return
            && !extra_defines.is_empty()
            && !info.taint.uses.is_empty()
            && info
                .taint
                .uses
                .iter()
                .all(|u| extra_defines.iter().any(|e| e == u))
        {
            continue;
        }

        for edge in ctx.cfg.edges(node) {
            // Prune null-guard-false edges: those represent "var is null",
            // a path on which the resource was never actually acquired.
            if let Some(var) = acquire_var
                && is_null_guard_false_edge(ctx, node, *edge.weight(), var)
            {
                continue;
            }
            // Prune Go err-companion guard edges: `if err != nil { return err }`
            // after `f, err := os.Open(...)` takes the err branch on which the
            // resource handle is the zero value and was never acquired.
            if is_err_companion_guard_edge(ctx, node, *edge.weight(), extra_defines) {
                continue;
            }
            let succ = edge.target();
            let new_passed = passed || through.contains(&succ);
            let state = (succ, new_passed);
            if visited.insert(state) {
                queue.push_back(state);
            }
        }
    }

    true
}

/// Check whether the acquired variable is stored into a struct field (ownership
/// transfer) downstream of the acquire node.  Patterns recognised:
///   - `ptr->field = var`   (C arrow operator)
///   - `obj.field = var`    (C dot / generic field store)
///   - `list->next = ...`   (linked-list insertion)
///
/// If the variable is transferred, there is no leak, the receiving struct is
/// responsible for the lifetime.
fn is_ownership_transferred(ctx: &AnalysisContext, acquire: NodeIndex) -> bool {
    let acquired_var = match &ctx.cfg[acquire].taint.defines {
        Some(v) => v.clone(),
        None => return false,
    };

    // BFS through CFG successors looking for a node whose span text
    // mentions the acquired variable in a struct-field store context.
    use std::collections::VecDeque;
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for succ in ctx.cfg.neighbors(acquire) {
        if visited.insert(succ) {
            queue.push_back(succ);
        }
    }

    while let Some(node) = queue.pop_front() {
        let info = &ctx.cfg[node];
        let (start, end) = info.ast.span;

        // Check the source text at this node's span for the acquired variable
        // appearing in a struct-field store context.
        let references_var = info.taint.uses.iter().any(|u| u == &acquired_var)
            || info
                .taint
                .defines
                .as_ref()
                .is_some_and(|d| d == &acquired_var);

        if references_var && start < end && end <= ctx.source_bytes.len() {
            let span_text = &ctx.source_bytes[start..end];
            // `->` anywhere in span means pointer-to-member store
            if span_text.windows(2).any(|w| w == b"->") {
                return true;
            }
            // `.field = var` pattern (but not `==`)
            if has_dot_field_assignment(span_text) {
                return true;
            }
        }

        // If the variable is truly redefined (not a field write), stop
        // following this path. A true redefinition is when `defines` matches
        // but the span doesn't contain `->` or `.field =` patterns.
        if info
            .taint
            .defines
            .as_ref()
            .is_some_and(|d| d == &acquired_var)
        {
            let is_field_write = if start < end && end <= ctx.source_bytes.len() {
                let span_text = &ctx.source_bytes[start..end];
                span_text.windows(2).any(|w| w == b"->") || has_dot_field_assignment(span_text)
            } else {
                false
            };
            if !is_field_write {
                continue; // genuine redefinition, stop this path
            }
        }

        for succ in ctx.cfg.neighbors(node) {
            if visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    false
}

/// Check if `span_text` contains a dot-field assignment pattern like
/// `obj.field = var` (but not `obj.method(...)` or `a == b`).
fn has_dot_field_assignment(span_text: &[u8]) -> bool {
    // Look for `.` followed (possibly with ident chars) by `=` but not `==`
    let mut i = 0;
    while i < span_text.len() {
        if span_text[i] == b'.' {
            // Scan forward past identifier chars to find `=`
            let mut j = i + 1;
            while j < span_text.len()
                && (span_text[j].is_ascii_alphanumeric() || span_text[j] == b'_')
            {
                j += 1;
            }
            // Skip whitespace
            while j < span_text.len() && span_text[j].is_ascii_whitespace() {
                j += 1;
            }
            // Check for `=` but not `==`
            if j < span_text.len()
                && span_text[j] == b'='
                && (j + 1 >= span_text.len() || span_text[j + 1] != b'=')
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Check whether the acquired variable is consumed by an ownership-taking
/// function (e.g. `FileResponse(f)`, `send_file(f)`) downstream of the
/// acquire node.  These functions take ownership of the file handle so there
/// is no leak.
fn is_consumed_by_owner(ctx: &AnalysisContext, acquire: NodeIndex) -> bool {
    static CONSUMING_SINKS: &[&str] = &[
        "fileresponse",
        "streaminghttpresponse",
        "send_file",
        "make_response",
    ];

    let acquired_var = match &ctx.cfg[acquire].taint.defines {
        Some(v) => v.clone(),
        None => return false,
    };

    use std::collections::VecDeque;
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for succ in ctx.cfg.neighbors(acquire) {
        if visited.insert(succ) {
            queue.push_back(succ);
        }
    }

    while let Some(node) = queue.pop_front() {
        let info = &ctx.cfg[node];

        // Check Call nodes with callee that matches a consuming sink
        if info.kind == StmtKind::Call
            && let Some(callee) = &info.call.callee
        {
            let callee_lower = callee.to_ascii_lowercase();
            let is_consuming = CONSUMING_SINKS.iter().any(|s| callee_lower.ends_with(s));
            if is_consuming && info.taint.uses.iter().any(|u| u == &acquired_var) {
                return true;
            }
        }

        // Also check the span text for consuming calls, handles cases where
        // the call is embedded in a return statement (e.g. `return FileResponse(f)`)
        if info.taint.uses.iter().any(|u| u == &acquired_var) {
            let (start, end) = info.ast.span;
            if start < end && end <= ctx.source_bytes.len() {
                let span_lower: Vec<u8> = ctx.source_bytes[start..end]
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect();
                if CONSUMING_SINKS
                    .iter()
                    .any(|s| span_lower.windows(s.len()).any(|w| w == s.as_bytes()))
                {
                    return true;
                }
            }
        }

        for succ in ctx.cfg.neighbors(node) {
            if visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    false
}

/// For mutex pairs, check that an explicit `.acquire()` or `.lock()` call
/// exists on the acquired variable in the CFG.  If only the constructor
/// (e.g. `threading.Lock()`) is observed without acquire, skip the finding.
fn has_explicit_lock_acquire(ctx: &AnalysisContext, acquire: NodeIndex) -> bool {
    let acquired_var = match &ctx.cfg[acquire].taint.defines {
        Some(v) => v.clone(),
        None => return false,
    };

    for idx in ctx.cfg.node_indices() {
        let info = &ctx.cfg[idx];
        if info.kind != StmtKind::Call {
            continue;
        }
        if let Some(callee) = &info.call.callee {
            let callee_lower = callee.to_ascii_lowercase();
            let is_lock_call = callee_lower.ends_with(".acquire")
                || callee_lower.ends_with(".lock")
                || callee_lower == "pthread_mutex_lock";
            if is_lock_call && info.taint.uses.iter().any(|u| u == &acquired_var) {
                return true;
            }
        }
    }

    false
}

impl CfgAnalysis for ResourceMisuse {
    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let pairs = rules::resource_pairs(ctx.lang);
        let exit = match dominators::find_exit_node(ctx.cfg) {
            Some(e) => e,
            None => return Vec::new(),
        };

        let mut findings = Vec::new();

        for pair in pairs {
            let acquire_nodes = find_acquire_nodes(ctx, pair.acquire, pair.exclude_acquire);
            let release_nodes = find_release_nodes(ctx, pair.release);

            for &acquire in &acquire_nodes {
                // Suppress resources inside managed cleanup scopes
                // (Python `with`, Java try-with-resources).
                if ctx.cfg[acquire].managed_resource {
                    continue;
                }
                // Suppress `obj.connect("event-name", callback)` event-
                // handler registrations that share the `connect` /
                // `cursor` callee suffix with real DB acquires.  Sphinx
                // app.connect("config-inited", on_init), Flask blueprint
                // handlers, and MQTT client.connect("topic", on_msg) all
                // pass a string literal event name plus a callable
                // identifier; SQLAlchemy `engine.connect()` and
                // `sqlite3.connect("path.db")` either have no args or a
                // single string arg.  Gated on the `db connection`
                // resource name so file/socket/mutex pairs are untouched.
                if pair.resource_name == "db connection"
                    && is_event_handler_register_shape(&ctx.cfg[acquire])
                {
                    continue;
                }
                // SAFE-FOR-FIELD-LHS (Go only): skip member-expression
                // LHS acquires.  `b.cpuprof = os.Create(...)` transfers
                // ownership to the containing struct; closure
                // responsibility belongs to a paired Stop()/Release()
                // method on the struct's lifecycle.  Mirrors the gate
                // in src/state/transfer.rs::apply_call.  Production
                // trigger: prometheus
                // cmd/promtool/tsdb.go::startProfiling cluster.
                // Restricted to Go because TS/JS class-field acquires
                // (`this.fd = fs.openSync(...)`) are still expected to
                // be tracked — the leak fixtures rely on it.
                if ctx.lang == Lang::Go
                    && let Some(acquired_var) = ctx.cfg[acquire].taint.defines.as_deref()
                    && acquired_var.contains('.')
                {
                    continue;
                }
                // Suppress resources with a deferred release (Go `defer f.Close()`).
                // Defer guarantees cleanup on all exit paths including early returns.
                if let Some(acquired_var) = ctx.cfg[acquire].taint.defines.as_deref() {
                    let has_deferred_release = release_nodes.iter().any(|&r| {
                        ctx.cfg[r].in_defer
                            && ctx.cfg[r].taint.uses.iter().any(|u| u == acquired_var)
                    });
                    if has_deferred_release {
                        continue;
                    }
                }
                if !release_on_all_exit_paths(ctx, acquire, &release_nodes, exit)
                    && !is_ownership_transferred(ctx, acquire)
                    && !is_consumed_by_owner(ctx, acquire)
                {
                    // For mutex pairs, require an explicit .acquire()/.lock() call
                    if pair.resource_name == "mutex" && !has_explicit_lock_acquire(ctx, acquire) {
                        continue;
                    }
                    // Suppress when a sibling closure / event handler in
                    // this file releases the same variable.  Common JS/TS
                    // shape: `const ws = new WebSocket(url);
                    // socket.on("close", () => ws.close())`.  The release
                    // node lives in a nested body the per-body CFG can't
                    // see, so the structural "no release on this exit
                    // path" check fires erroneously.  Match by acquired
                    // variable name; closure captures share the binding
                    // name with the outer handle.
                    if let Some(acq_var) = ctx.cfg[acquire].taint.defines.as_deref()
                        && ctx
                            .closure_released_var_names
                            .map(|s| s.contains(acq_var))
                            .unwrap_or(false)
                    {
                        continue;
                    }
                    let info = &ctx.cfg[acquire];
                    let callee_desc = info.call.callee.as_deref().unwrap_or("(acquire)");

                    findings.push(CfgFinding {
                        rule_id: if pair.resource_name == "mutex" {
                            "cfg-lock-not-released".to_string()
                        } else {
                            "cfg-resource-leak".to_string()
                        },
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        span: info.ast.span,
                        message: format!(
                            "`{callee_desc}` acquires {} but not all exit paths \
                             release it",
                            pair.resource_name
                        ),
                        evidence: vec![acquire],
                        score: None,
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{CallMeta, NodeInfo, StmtKind};

    fn call_node(arg_string_literals: Vec<Option<String>>, arg_uses: Vec<Vec<String>>) -> NodeInfo {
        NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some("obj.connect".into()),
                arg_string_literals,
                arg_uses,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn event_handler_shape_recognises_sphinx_connect() {
        // app.connect("config-inited", _on_init)
        let info = call_node(
            vec![Some("config-inited".into()), None],
            vec![vec![], vec!["_on_init".into()]],
        );
        assert!(is_event_handler_register_shape(&info));
    }

    #[test]
    fn event_handler_shape_recognises_self_method_callback() {
        // client.connect("device/+", self._on_status)
        let info = call_node(
            vec![Some("device/+".into()), None],
            vec![vec![], vec!["self".into(), "_on_status".into()]],
        );
        assert!(is_event_handler_register_shape(&info));
    }

    #[test]
    fn event_handler_shape_rejects_url_first_arg() {
        // engine.connect("postgres://localhost/mydb")
        let info = call_node(vec![Some("postgres://localhost/mydb".into())], vec![vec![]]);
        assert!(!is_event_handler_register_shape(&info));
    }

    #[test]
    fn event_handler_shape_rejects_oracle_string_args() {
        // cx_Oracle.connect("user", "pass", "dsn") -- arg1 is a literal,
        // no identifier in `arg_uses[1]`.
        let info = call_node(
            vec![Some("user".into()), Some("pass".into()), Some("dsn".into())],
            vec![vec![], vec![], vec![]],
        );
        assert!(!is_event_handler_register_shape(&info));
    }

    #[test]
    fn event_handler_shape_rejects_no_args() {
        // engine.connect()
        let info = call_node(vec![], vec![]);
        assert!(!is_event_handler_register_shape(&info));
    }

    #[test]
    fn event_handler_shape_rejects_single_string_arg() {
        // sqlite3.connect("path.db")
        let info = call_node(vec![Some("path.db".into())], vec![vec![]]);
        assert!(!is_event_handler_register_shape(&info));
    }

    #[test]
    fn event_handler_shape_rejects_ident_first_arg() {
        // signal.connect(receiver_func, sender=...) -- handled by the
        // static exclude list `signal.connect`, but the shape check
        // should also gate it out: first arg is not a string literal.
        let info = call_node(vec![None], vec![vec!["receiver_func".into()]]);
        assert!(!is_event_handler_register_shape(&info));
    }
}
