use super::dominators;
use super::rules;
use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence};
use crate::cfg::{CalleeNesting, EdgeKind, StmtKind};
use crate::patterns::Severity;
use crate::symbol::Lang;
use petgraph::algo::dominators::Dominators;
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

/// Recognises Django / blinker / PyDispatcher signal registration —
/// `post_save.connect(receiver, sender=Model, dispatch_uid="...")` — which
/// shares the `connect` callee leaf with real DB acquires but registers an
/// observer (the call returns `None` and holds no resource).  Complements
/// [`is_event_handler_register_shape`] (the Qt / Sphinx / MQTT
/// `obj.connect("event-name", handler)` string-event-name form) with the
/// signal-object form whose first argument is the receiver *callable*, not a
/// string event name.
///
/// The static `exclude_acquire` list (`signal.connect`, `event.connect`) can
/// only match those two literal receiver names; real Django signals are
/// dispatched off `post_save`, `pre_save`, `post_delete`, `m2m_changed`,
/// `setting_changed`, and arbitrary user `Signal()` instances, so a shape
/// recogniser is the only sound way to cover the family.
///
/// Two structural signals, either sufficient (both leaf-gated to `connect` so
/// a `connection.cursor()` acquire in the same pair is never suppressed):
///  1. a signal-API keyword argument (`sender`, `dispatch_uid`, `weak`,
///     `receiver`) is present — no DB driver's `connect()` accepts any of
///     these, so their presence is decisive; OR
///  2. the first positional argument is a callable reference (a passed
///     handler: bare identifier or attribute access, never a string DSN) AND
///     the call's return value is discarded (not bound to a variable).  A real
///     DB connect binds its handle (`conn = engine.connect(cfg)`), so the
///     discarded-return form is never a leak candidate to begin with.
fn is_signal_registration_shape(info: &crate::cfg::NodeInfo) -> bool {
    let is_connect_leaf = info.call.callee.as_deref().is_some_and(|callee| {
        callee
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(callee)
            .eq_ignore_ascii_case("connect")
    });
    if !is_connect_leaf {
        return false;
    }
    // (1) signal-API keyword argument present.
    const SIGNAL_KWARGS: &[&str] = &["sender", "dispatch_uid", "weak", "receiver"];
    if info
        .call
        .kwargs
        .iter()
        .any(|(k, _)| SIGNAL_KWARGS.iter().any(|s| k.eq_ignore_ascii_case(s)))
    {
        return true;
    }
    // (2) first positional is a callable reference AND the return is discarded.
    let first_is_callable_ref = info.call.arg_uses.first().is_some_and(|u| !u.is_empty())
        && info
            .call
            .arg_string_literals
            .first()
            .map(|s| s.is_none())
            .unwrap_or(true);
    first_is_callable_ref && info.taint.defines.is_none()
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
            // A member read hoisted out of a callback argument is no call of
            // this node, and a value stored into an aggregate handed to
            // another call is owned by that aggregate (same rule as the
            // container and field stores).  A call directly in another call's
            // arguments stays an acquire: `json.load(open(p))` leaks it.
            if matches!(
                info.call.callee_nesting,
                CalleeNesting::Hoisted | CalleeNesting::InAggregateArg
            ) {
                return false;
            }
            if let Some(callee) = &info.call.callee {
                let callee_lower = callee.to_ascii_lowercase();
                // Check exclusions first, if the callee matches an exclude
                // pattern, it is NOT an acquire even if it also matches an
                // acquire pattern (e.g. `freopen` ends with `fopen`).
                let excluded = exclude_patterns.iter().any(|p| {
                    rules::callee_matches_at_boundary(&callee_lower, &p.to_ascii_lowercase())
                });
                if excluded {
                    return false;
                }
                acquire_patterns.iter().any(|p| {
                    rules::callee_matches_at_boundary(&callee_lower, &p.to_ascii_lowercase())
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
        release_patterns
            .iter()
            .any(|p| rules::callee_matches_at_boundary(&callee_lower, &p.to_ascii_lowercase()))
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
            // A release that is the condition of an `if` (`if (fclose(f))`)
            // runs before either branch.
            if info
                .cond_call
                .as_deref()
                .is_some_and(|c| matches_release(&c.callee))
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
    post_doms: Option<&Dominators<NodeIndex>>,
) -> bool {
    // Use post-dominators as optimization: if any release post-dominates acquire, it's fine.
    // The post-dominator tree is computed once per CFG by the caller (the CFG is
    // immutable across acquire sites), so it is threaded in rather than recomputed here.
    if let Some(post_doms) = post_doms {
        for &release in release_nodes {
            if dominators::dominates(post_doms, release, acquire) {
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

/// Identify whether a CFG edge is the null edge of a null / failure test on
/// the acquired variable (`if (f)`, `if (!f)`, `f == NULL`, `fd < 0`, ...).
/// On that edge the resource handle was never produced, so the path owes no
/// release.  Reads the structured [`crate::cfg::NullCheck`] the CFG builder
/// attaches to the `If` node.
fn is_null_guard_false_edge(
    ctx: &AnalysisContext,
    src: NodeIndex,
    edge_kind: EdgeKind,
    acquire_var: &str,
) -> bool {
    let info = &ctx.cfg[src];
    info.kind == StmtKind::If
        && info
            .null_check
            .as_ref()
            .is_some_and(|nc| nc.var == acquire_var && nc.null_edge() == edge_kind)
}

/// Recognise Go's err-companion guard: `if err != nil { return err }` where
/// `err` is a companion define of the acquire (`f, err := os.Open(...)`).
/// On the err-non-nil edge the resource was never actually acquired (the
/// acquire returned the zero value), so the path is not a real leak path.
///
/// Returns `true` for the edge that takes the err-non-nil branch.  The
/// caller only asks while `err` still holds the acquire's error (see the
/// redefinition tracking in [`all_paths_pass_through`]).
fn is_err_companion_guard_edge(
    ctx: &AnalysisContext,
    src: NodeIndex,
    edge_kind: EdgeKind,
    extra_defines: &[String],
) -> bool {
    if extra_defines.is_empty() || ctx.lang != Lang::Go {
        return false;
    }
    let info = &ctx.cfg[src];
    info.kind == StmtKind::If
        && info
            .null_check
            .as_ref()
            .is_some_and(|nc| extra_defines.contains(&nc.var) && nc.non_null_edge() == edge_kind)
}

/// True when `node` (other than the acquire itself) reassigns one of the
/// acquire's error companions, after which an `err != nil` test no longer
/// describes the acquire.
fn redefines_err_companion(info: &crate::cfg::NodeInfo, extra_defines: &[String]) -> bool {
    !extra_defines.is_empty()
        && info
            .taint
            .defines
            .iter()
            .chain(info.taint.extra_defines.iter())
            .any(|d| extra_defines.iter().any(|e| e == d))
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

    // BFS over (node, passed a release, err companion reassigned).  The
    // third component keeps `_, err = f.Write(b); if err != nil { return err }`
    // from being mistaken for the acquire's own failure branch.
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((from, false, false));
    visited.insert((from, false, false));

    while let Some((node, passed, err_redefined)) = queue.pop_front() {
        if node == to {
            if !passed {
                return false; // Found a path to exit without passing through release
            }
            continue;
        }

        let info = &ctx.cfg[node];
        let err_redefined =
            err_redefined || (node != from && redefines_err_companion(info, extra_defines));

        // Treat a Return-of-err-companion as a passing exit: in Go's
        // `f, err := os.Open(...); if err != nil { return err }` shape the
        // err-return path does not actually own a resource (acquire returned
        // the zero value), so reaching such a Return is not a leak.
        if !err_redefined
            && ctx.lang == Lang::Go
            && info.kind == StmtKind::Return
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

        // Returning the handle (`return f`, `return f, nil`,
        // `return &W{f: f}`) hands ownership to the caller, so this path owes
        // no release.  Only escape positions count: `return f.read()` keeps
        // `f` here and still needs a release.  The state engine's
        // `returns_var` also counts any mention for C / C++ (see
        // `state::transfer::return_hands_off`); this pass keeps to escape
        // positions in every language, so C `return fgetc(f)` stays
        // reported here as it was before returns were modelled.
        if (info.kind == StmtKind::Return || info.implicit_return)
            && acquire_var.is_some_and(|v| info.returned_idents.iter().any(|r| r == v))
        {
            continue;
        }

        for edge in ctx.cfg.edges(node) {
            // The builder can emit a plain Seq edge alongside the True /
            // False edge into the same branch target (`if (!f) return -1;`).
            // It carries no branch meaning, so skip it the way the state
            // engine does; otherwise it would re-open the branch pruned below.
            if *edge.weight() == EdgeKind::Seq
                && ctx.cfg.edges(node).any(|e| {
                    e.target() == edge.target()
                        && matches!(e.weight(), EdgeKind::True | EdgeKind::False)
                })
            {
                continue;
            }
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
            if !err_redefined
                && is_err_companion_guard_edge(ctx, node, *edge.weight(), extra_defines)
            {
                continue;
            }
            let succ = edge.target();
            let new_passed = passed || through.contains(&succ);
            let state = (succ, new_passed, err_redefined);
            if visited.insert(state) {
                queue.push_back(state);
            }
        }
    }

    true
}

/// True when the acquire is the value of a `return` statement
/// (`return os.Open(p)`, `return new Foo()`, `return open(p)`): the handle is
/// never bound locally and goes straight to the caller.  The CFG builder
/// lowers such a return as a Call node followed by a Return node over the
/// same statement span; the Return records which calls it returns directly.
fn acquire_is_returned_value(ctx: &AnalysisContext, acquire: NodeIndex) -> bool {
    let info = &ctx.cfg[acquire];
    if info.taint.defines.is_some() {
        return false;
    }
    let Some(callee) = info.call.callee.as_deref() else {
        return false;
    };
    // Ruby `def open_log(p) File.open(p) end`: the acquire is itself the
    // method's implicit return value.
    if info.implicit_return && info.returned_call_callees.iter().any(|c| c == callee) {
        return true;
    }
    ctx.cfg.neighbors(acquire).any(|succ| {
        let ret = &ctx.cfg[succ];
        ret.kind == StmtKind::Return
            && ret.ast.span == info.ast.span
            && ret.returned_call_callees.iter().any(|c| c == callee)
    })
}

/// Check whether the acquired variable is stored into a struct field (ownership
/// transfer) downstream of the acquire node.  Patterns recognised:
///   - `ptr->field = var`   (C arrow operator)
///   - `obj.field = var`    (C dot / generic field store)
///   - `list->next = ...`   (linked-list insertion)
///
/// If the variable is transferred, there is no leak, the receiving struct is
/// responsible for the lifetime.
fn is_ownership_transferred(
    ctx: &AnalysisContext,
    acquire: NodeIndex,
    closeable_wrappers: &crate::state::transfer::CloseableWrappers,
) -> bool {
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

        // `*out = var`, `g_cache = var`, `slots[i] = var`: the handle now
        // lives in storage this function does not own.
        if info.escaping_store && info.taint.uses.iter().any(|u| u == &acquired_var) {
            return true;
        }
        // Handed to a collection (`list.add(s)`, `v.push_back(f)`), to a
        // C++ smart pointer (`std::unique_ptr<T> p(raw)`, `p.reset(raw)`),
        // or to a Java wrapper whose own lifetime is accounted for
        // (`new BufferedInputStream(in)` later closed / returned / managed).
        // Twin of the state-engine handoffs in `DefaultTransfer`.
        if crate::state::transfer::container_insert_arg_positions(ctx.lang, info)
            .iter()
            .any(|&i| info.call.arg_uses[i][0] == acquired_var)
        {
            return true;
        }
        if info.call.ctor_owned_args.contains(&acquired_var) {
            match ctx.lang {
                Lang::Cpp => return true,
                Lang::Java
                    if info
                        .taint
                        .defines
                        .as_deref()
                        .is_some_and(|w| closeable_wrappers.names.contains(w)) =>
                {
                    return true;
                }
                _ => {}
            }
        }

        if references_var && start < end && end <= ctx.source_bytes.len() {
            let span_text = &ctx.source_bytes[start..end];
            // `ptr->field = var` pointer-to-member store.  A bare `->`
            // anywhere in the span is NOT enough: a member READ on or near
            // the handle (`fread(buf->data, 1, n, fp)`, PHP
            // `$conn->query(...)`) also contains `->` but transfers no
            // ownership, so requiring the `= ` (assignment, not `==`) keeps
            // the suppression to actual stores.
            if has_arrow_field_assignment(span_text) {
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
                has_arrow_field_assignment(span_text) || has_dot_field_assignment(span_text)
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

/// Check if `span_text` contains a pointer-to-member assignment pattern like
/// `ptr->field = var` (but not a member READ such as `fread(buf->data, ...)`,
/// PHP `$conn->query(...)`, or a comparison `a->b == c`).
///
/// A bare `->` anywhere in the span is insufficient — only an arrow access
/// that is the LHS of an assignment indicates an ownership-transfer store.
/// We require, after one or more `->ident` (or `.ident`) member-access
/// segments, a single `=` that is not part of `==` / `!=` / `<=` / `>=`.
fn has_arrow_field_assignment(span_text: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < span_text.len() {
        if span_text[i] == b'-' && span_text[i + 1] == b'>' {
            // Walk past chained member-access segments: `->ident`,
            // `.ident`, further `->ident`, and any whitespace, looking for
            // the assignment `=`.
            let mut j = i + 2;
            loop {
                // identifier chars
                while j < span_text.len()
                    && (span_text[j].is_ascii_alphanumeric() || span_text[j] == b'_')
                {
                    j += 1;
                }
                // chained `->` / `.` member access keeps the LHS going
                if j + 1 < span_text.len() && span_text[j] == b'-' && span_text[j + 1] == b'>' {
                    j += 2;
                    continue;
                }
                if j < span_text.len() && span_text[j] == b'.' {
                    j += 1;
                    continue;
                }
                break;
            }
            // Skip whitespace before the operator
            while j < span_text.len() && span_text[j].is_ascii_whitespace() {
                j += 1;
            }
            // Reject `==`, `!=`, `<=`, `>=` — only a bare `=` is a store.
            if j < span_text.len()
                && span_text[j] == b'='
                && (j + 1 >= span_text.len() || span_text[j + 1] != b'=')
                && (j == 0 || !matches!(span_text[j - 1], b'!' | b'<' | b'>' | b'='))
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

        // The CFG is immutable for the duration of this pass, so the
        // post-dominator tree only needs to be computed once.  Previously
        // `release_on_all_exit_paths` recomputed it for every acquire site,
        // turning the body's post-dominator analysis into an O(A) hot spot.
        let post_doms = dominators::compute_post_dominators(ctx.cfg);

        let mut findings = Vec::new();

        // Java: variable names bound to a locally-acquired JDBC `Connection`
        // (`con = X.getConnection()`).  A `Statement` opened on one of these
        // receivers (`con.prepareStatement(...)`) is transitively closed /
        // covered by the connection's own lifecycle, so its standalone leak
        // is never a unique true positive — see
        // `rules::jdbc_statement_owning_connection`.  Computed once (structural
        // CFG property).  Python DB-API connections play the same role for
        // the cursors opened on them; empty for every other language.
        let local_connection_vars: HashSet<&str> = ctx
            .cfg
            .node_weights()
            .filter(|n| {
                n.kind == StmtKind::Call
                    && rules::is_owning_connection_acquire(ctx.lang, n.call.callee.as_deref())
            })
            .filter_map(|n| n.taint.defines.as_deref())
            .collect();

        // C/C++: struct-value container base names whose field-acquire
        // (`c.buf = malloc()`) provably does NOT transfer ownership — the
        // container is a locally-declared value struct that never escapes
        // the function, so the acquire genuinely leaks and the field-LHS
        // ownership-transfer suppression below must be LIFTED for it.
        // Twin of the `state-resource-leak` lift in
        // `src/state/transfer.rs::nonescaping_local_field_containers`.
        // Empty (no-op) for non-C/C++.
        let nonescaping_field_containers =
            crate::state::transfer::nonescaping_local_field_containers(ctx.cfg, ctx.lang);
        // Java wrappers whose lifetime this body accounts for (see
        // `state::transfer::closeable_wrapper_names`).
        let closeable_wrappers = crate::state::transfer::closeable_wrapper_names(ctx.cfg, ctx.lang);

        for pair in pairs {
            let acquire_nodes = find_acquire_nodes(ctx, pair.acquire, pair.exclude_acquire);
            let release_nodes = find_release_nodes(ctx, pair.release);

            for &acquire in &acquire_nodes {
                // Suppress resources inside managed cleanup scopes
                // (Python `with`, Java try-with-resources).
                if ctx.cfg[acquire].managed_resource {
                    continue;
                }
                // Suppress a JDBC `ResultSet` leak: the result set is owned by
                // the `Statement` that produced it (`stmt.executeQuery()`).
                // Closing the statement (via try-with-resources / explicit
                // close) transitively closes the result set, and if the
                // statement itself leaks that leak already covers the result
                // set — so a standalone `ResultSet` leak is never a unique
                // true positive.  Twin of the `state-resource-leak`
                // suppression in
                // `src/state/facts.rs::is_jdbc_resultset_acquire`.  The
                // `result set` pair is Java-only; gate on the language too so
                // a future same-named pair in another language is unaffected.
                if ctx.lang == Lang::Java && pair.resource_name == "result set" {
                    continue;
                }
                // Suppress a JDBC `Connection` BORROWED from a managed
                // session / DB abstraction — the owner (Liquibase `Database`,
                // Hibernate `Session`, MyBatis `SqlSession`, JPA
                // `EntityManager`) closes it, not the borrower.  `DataSource`
                // / static `DriverManager` connections are OWNED and still
                // fire.  Flag set at CFG build via receiver-type
                // discrimination (`cfg::java_getconnection_receiver_is_borrowed`).
                // Twin of the `state-resource-leak` suppression in
                // `src/state/facts.rs`.
                if ctx.lang == Lang::Java && ctx.cfg[acquire].borrowed_resource {
                    continue;
                }
                // Suppress a JDBC `Statement` (`prepareStatement`) leak whose
                // owning `Connection` is a resource acquired locally in this
                // body — closing the connection closes its statements, so a
                // statement derived from a locally-tracked connection (closed,
                // borrowed/managed, or itself leaking) is never a unique true
                // positive.  A statement on a field / parameter / pooled
                // connection this body does not track is KEPT.  Twin of the
                // `state-resource-leak` suppression in `src/state/facts.rs`;
                // interior-node sibling of the `result set` leaf gate above.
                if let Some(owner) =
                    rules::derived_resource_owner(ctx.lang, ctx.cfg[acquire].call.callee.as_deref())
                    && local_connection_vars.contains(owner)
                {
                    continue;
                }
                // Suppress `obj.connect("event-name", callback)` event-
                // handler registrations AND Django/blinker signal
                // registrations (`post_save.connect(receiver, sender=Model)`)
                // that share the `connect` / `cursor` callee suffix with real
                // DB acquires.  Sphinx app.connect("config-inited", on_init),
                // Flask blueprint handlers, and MQTT client.connect("topic",
                // on_msg) pass a string literal event name plus a callable
                // (`is_event_handler_register_shape`); Django signals pass the
                // receiver callable plus signal-API kwargs
                // (`is_signal_registration_shape`).  SQLAlchemy
                // `engine.connect()` and `sqlite3.connect("path.db")` either
                // have no args or a single string arg and bind their handle,
                // so they fall through and the leak check still fires.  Gated
                // on the `db connection` resource name so file/socket/mutex
                // pairs are untouched.
                if pair.resource_name == "db connection"
                    && (is_event_handler_register_shape(&ctx.cfg[acquire])
                        || is_signal_registration_shape(&ctx.cfg[acquire]))
                {
                    continue;
                }
                // SAFE-FOR-FIELD-LHS: skip member-expression LHS acquires.
                // `b.cpuprof = os.Create(...)` (Go) / `c->connect_timeout =
                // hi_malloc(...)` (C) transfers ownership to the containing
                // struct; release belongs to a paired Stop()/Release()/
                // free_*() method, or to the caller when the struct is a
                // parameter.  Same-node twin of the acquire-time gate in
                // src/state/transfer.rs::apply_call — without this, clearing
                // the state-resource-leak on such an acquire unmasks the
                // cfg-resource-leak here (the two passes dedup per line).
                // `is_ownership_transferred` below only catches the
                // *downstream* store shape (`ptr=malloc(); mem->buf=ptr;`), not
                // the same-node `x->field = malloc(...)` acquire.  Production
                // triggers: prometheus tsdb.go::startProfiling; redis/hiredis
                // net.c (c->connect_timeout), lua strbuf.c (s->buf).  Excludes
                // JS/TS (see `acquire_into_field_transfers_ownership`) — the
                // class-field acquire `this.fd = fs.openSync(...)` IS the
                // expected leak pattern the TS leak fixtures rely on.
                if let Some(acquired_var) = ctx.cfg[acquire].taint.defines.as_deref()
                    && crate::state::transfer::acquire_into_field_transfers_ownership(
                        ctx.lang,
                        acquired_var,
                    )
                    && !crate::state::transfer::field_container_is_nonescaping(
                        &nonescaping_field_containers,
                        acquired_var,
                    )
                {
                    continue;
                }
                // Acquire stored straight into a global, unqualified field,
                // pointer target or container element (`g_buf = malloc(n)`,
                // `*out = calloc(..)`).  Twin of the state-engine gate.
                if ctx.cfg[acquire].escaping_store {
                    continue;
                }
                // A factory that returns the acquire's result directly
                // (`return os.Open(p)`) hands the handle to its caller.
                if acquire_is_returned_value(ctx, acquire) {
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
                if !release_on_all_exit_paths(
                    ctx,
                    acquire,
                    &release_nodes,
                    exit,
                    post_doms.as_ref(),
                ) && !is_ownership_transferred(ctx, acquire, &closeable_wrappers)
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

    fn connect_node(
        callee: &str,
        arg_string_literals: Vec<Option<String>>,
        arg_uses: Vec<Vec<String>>,
        kwargs: Vec<(String, Vec<String>)>,
        defines: Option<String>,
    ) -> NodeInfo {
        let mut info = NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some(callee.into()),
                arg_string_literals,
                arg_uses,
                kwargs,
                ..Default::default()
            },
            ..Default::default()
        };
        info.taint.defines = defines;
        info
    }

    #[test]
    fn callee_boundary_rejects_disconnect_as_connect_acquire() {
        // `post_delete.disconnect(...)` shares the `connect` suffix but is a
        // teardown verb — must NOT match the `connect` acquire pattern.
        assert!(!rules::callee_matches_at_boundary(
            "post_delete.disconnect",
            "connect"
        ));
        assert!(!rules::callee_matches_at_boundary(
            "client.reconnect",
            "connect"
        ));
        // Real Django signal / DB connects still match at the `.` boundary.
        assert!(rules::callee_matches_at_boundary(
            "post_save.connect",
            "connect"
        ));
        assert!(rules::callee_matches_at_boundary(
            "engine.connect",
            "connect"
        ));
        assert!(rules::callee_matches_at_boundary("connect", "connect"));
    }

    #[test]
    fn callee_boundary_rejects_within_identifier_open_and_alloc() {
        // PIL `Image.register_open` and paperless `_ensure_open` end with
        // `open` but are single identifiers, not the `open` builtin.
        assert!(!rules::callee_matches_at_boundary(
            "image.register_open",
            "open"
        ));
        assert!(!rules::callee_matches_at_boundary(
            "obj._ensure_open",
            "open"
        ));
        // Rust release `dealloc` must not match acquire `alloc`.
        assert!(!rules::callee_matches_at_boundary("dealloc", "alloc"));
        // Genuine `.open` acquires still match.
        assert!(rules::callee_matches_at_boundary("codecs.open", "open"));
        assert!(rules::callee_matches_at_boundary("open", "open"));
        // Separator-led patterns keep matching by plain suffix.
        assert!(rules::callee_matches_at_boundary("f.close", ".close"));
        assert!(rules::callee_matches_at_boundary("os.open", "os.open"));
    }

    #[test]
    fn signal_shape_recognises_django_sender_kwarg() {
        // pre_save.connect(remove_files_on_change, sender=model)
        let info = connect_node(
            "pre_save.connect",
            vec![None],
            vec![vec!["remove_files_on_change".into()]],
            vec![("sender".into(), vec!["model".into()])],
            None,
        );
        assert!(is_signal_registration_shape(&info));
    }

    #[test]
    fn signal_shape_recognises_django_dispatch_uid_kwarg() {
        // signals.post_save.connect(handlers.on_save_any_model,
        //                           dispatch_uid="events_change")
        let info = connect_node(
            "signals.post_save.connect",
            vec![None],
            vec![vec!["handlers".into(), "on_save_any_model".into()]],
            vec![("dispatch_uid".into(), vec![])],
            None,
        );
        assert!(is_signal_registration_shape(&info));
    }

    #[test]
    fn signal_shape_recognises_bare_receiver_no_kwargs() {
        // setting_changed.connect(reload_api_settings) -- callable arg, no
        // kwargs, return discarded.
        let info = connect_node(
            "setting_changed.connect",
            vec![None],
            vec![vec!["reload_api_settings".into()]],
            vec![],
            None,
        );
        assert!(is_signal_registration_shape(&info));
    }

    #[test]
    fn signal_shape_rejects_real_db_connect_bound_handle() {
        // conn = engine.connect(cfg) -- callable-looking ident arg BUT the
        // handle is bound, so it is a real acquire that must still leak-check.
        let info = connect_node(
            "engine.connect",
            vec![None],
            vec![vec!["cfg".into()]],
            vec![],
            Some("conn".into()),
        );
        assert!(!is_signal_registration_shape(&info));
    }

    #[test]
    fn signal_shape_rejects_sqlite_string_arg_and_cursor_leaf() {
        // sqlite3.connect("path.db") -- string DSN, no callable receiver.
        let info = connect_node(
            "sqlite3.connect",
            vec![Some("path.db".into())],
            vec![vec![]],
            vec![],
            None,
        );
        assert!(!is_signal_registration_shape(&info));
        // connection.cursor() shares the pair but is not a `connect` leaf.
        let cur = connect_node("connection.cursor", vec![], vec![], vec![], None);
        assert!(!is_signal_registration_shape(&cur));
    }

    #[test]
    fn arrow_field_assignment_matches_real_stores() {
        // Genuine ownership-transfer stores: `ptr->field = var`.
        assert!(has_arrow_field_assignment(b"ctx->fp = fp"));
        assert!(has_arrow_field_assignment(b"p->next = cfg->variables"));
        // Chained member access on the LHS.
        assert!(has_arrow_field_assignment(b"a->b->c = handle"));
        // Whitespace variations.
        assert!(has_arrow_field_assignment(b"obj->handle=res"));
    }

    #[test]
    fn arrow_field_assignment_rejects_member_reads() {
        // Member READ on / near the handle: contains `->` but no store.
        // This is the false-negative the fix targets — must NOT be treated
        // as ownership transfer.
        assert!(!has_arrow_field_assignment(b"fread(buf->data, 1, n, fp)"));
        assert!(!has_arrow_field_assignment(b"$result = $conn->query(sql)"));
        assert!(!has_arrow_field_assignment(b"if (node->len > 0)"));
        // Comparisons through arrow access are not stores.
        assert!(!has_arrow_field_assignment(b"if (obj->state == READY)"));
        assert!(!has_arrow_field_assignment(b"x->y != z"));
        // No arrow at all.
        assert!(!has_arrow_field_assignment(b"fclose(fp)"));
    }
}
