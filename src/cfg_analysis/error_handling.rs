use super::{AnalysisContext, CfgAnalysis, CfgFinding, Confidence, is_sink};
use crate::cfg::{EdgeKind, StmtKind};
use crate::patterns::Severity;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

/// Strict err-identifier match for cfg-error-fallthrough.
///
/// The previous heuristic `lower.contains("err")` over-matched method
/// names like Java `logger.isErrorEnabled()` (the camelCase identifier
/// `isErrorEnabled` matched because it contains `err`).  The rule's
/// real target is a variable / field that holds an error value.
///
/// Returns true if the identifier is exactly `err` / `error` or a
/// snake-case error name (`err_x`, `error_x`, `x_err`, `x_error`).
/// CamelCase names (`isErrorEnabled`, `getError`, `errorMsg`) are
/// rejected, the cost is occasional FNs on Java-style error fields,
/// which is acceptable for a precision fix.
fn is_error_var_ident(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == "err" || lower == "error" {
        return true;
    }
    if lower.starts_with("err_") || lower.starts_with("error_") {
        return true;
    }
    if lower.ends_with("_err") || lower.ends_with("_error") {
        return true;
    }
    false
}

/// Does the condition text contain a unary `!` (logical-not, NOT `!=`)
/// applied to an identifier or member chain whose name contains "err"?
///
/// Used by the error-fallthrough rule to skip happy-path checks
/// like `if (!data.error && Array.isArray(results))` whose TRUE branch
/// is the success path and is not expected to return.  The original
/// rule fires on `if (err) { warn(); } sink_after()`, a positive
/// error check whose body forgets to early-return.
fn contains_negated_err_identifier(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'!' {
            i += 1;
            continue;
        }
        // Skip the `!=` / `!==` operators, those are comparisons, not
        // logical-not.  Only treat a `!` followed by whitespace or an
        // identifier-leading char as logical negation.
        if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        // Allow a leading `(` for `!(expr)` shapes, peek past one open
        // paren and continue capturing the identifier chain.
        if j < bytes.len() && bytes[j] == b'(' {
            j += 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
        }
        let start = j;
        while j < bytes.len() {
            let b = bytes[j];
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'$' {
                j += 1;
            } else {
                break;
            }
        }
        if j > start {
            // Lowercase compare without allocating a full lowercase
            // copy: walk byte-by-byte.
            let mut k = start;
            while k + 2 < j {
                if (bytes[k] | 0x20) == b'e'
                    && (bytes[k + 1] | 0x20) == b'r'
                    && (bytes[k + 2] | 0x20) == b'r'
                {
                    return true;
                }
                k += 1;
            }
        }
        i = if j > i { j } else { i + 1 };
    }
    false
}

pub struct IncompleteErrorHandling;

/// Check if the true branch of an If node terminates (has Return/Break/Continue).
fn branch_terminates(cfg: &crate::cfg::Cfg, if_node: NodeIndex) -> bool {
    // Follow the True edge from the If node
    let true_successors: Vec<NodeIndex> = cfg
        .edges(if_node)
        .filter(|e| matches!(e.weight(), EdgeKind::True))
        .map(|e| e.target())
        .collect();

    if true_successors.is_empty() {
        return false;
    }

    // The join point of the if statement is its immediate post-dominator:
    // the first node every branch reconverges on.  The true-branch walk
    // must stop there — reaching the join means the body fell through
    // *past* the if without terminating, so any `return` in the function
    // tail past the join must NOT count as the error branch terminating.
    // Without this bound, a trailing `return nil` (present in essentially
    // every Go `func(...) error`) makes the walk report "all paths
    // terminate" and silently suppresses the rule.
    let join = super::dominators::compute_post_dominators(cfg)
        .and_then(|pd| pd.immediate_dominator(if_node));

    // Check if any path through the true branch terminates before the join.
    for &start in &true_successors {
        if terminates_on_all_paths(cfg, start, join) {
            return true;
        }
    }

    false
}

/// Recognise calls that never return on the success path.
///
/// `cfg-error-fallthrough` looks for `if err != nil { … }` whose body
/// fails to terminate.  A `return`/`break`/`continue`/`throw` is the
/// canonical terminator and already produces a `StmtKind::Return` /
/// `Throw` / `Break` / `Continue` node.  But a large class of real
/// terminators arrives as a *call* whose callee is documented to abort
/// the goroutine, process, or test:
///
/// * Go testing, `t.Fatal`, `t.Fatalf`, `t.Fatalln`, `b.Fatal*`,
///   `*Helper()` chains ending in `Fatal*`, also third-party
///   `require.NoError(t, …)` (asserts and aborts on err) which the
///   common `c.Fatalf("...")` pattern in minio's table tests reduces
///   to.  All `Fatal*` methods on a `testing.T`/`B`/`F` call
///   `runtime.Goexit()` which is documented as never returning to the
///   caller.
/// * Go std-library, `os.Exit`, `syscall.Exit`, `runtime.Goexit`,
///   `log.Fatal`, `log.Fatalf`, `log.Fatalln`, `log.Panic*`.
/// * Go builtin, bare `panic(…)`.
/// * Rust, `panic!`, `unreachable!`, `unimplemented!`, `todo!`,
///   `process::exit`, `std::process::exit`, `process::abort`,
///   `std::process::abort` (the macros currently lower to
///   `StmtKind::Throw` via tree-sitter's macro arm; the function
///   forms need explicit recognition).
/// * Python, `sys.exit`, `os._exit`, `os.abort`.
///
/// The recogniser looks at the bare method name (last segment after
/// `.` or `::`) and, where the receiver is a closed token, the
/// receiver's first segment.  Bare `panic` / `exit` callees are
/// recognised only when the namespace context matches (callee equals
/// the literal string, no other receiver).  This keeps the recogniser
/// from claiming arbitrary user-defined `Exit(...)` / `Panic(...)` as
/// terminators.
///
/// Closes the minio test-file cluster (49 in `xl-storage_test.go`
/// alone, 176 across the repo) where every `if err != nil { c.Fatalf(...) }`
/// fired `cfg-error-fallthrough`: the `Fatalf` aborts the goroutine
/// and the post-if code never executes, but the rule classified it as
/// fall-through.  Conservative: only adds new terminators; never
/// removes the existing `Return`/`Throw`/`Break`/`Continue` recognition.
fn call_never_returns(info: &crate::cfg::NodeInfo) -> bool {
    if info.kind != StmtKind::Call {
        return false;
    }
    let Some(callee) = info.call.callee.as_deref() else {
        return false;
    };
    let last = callee.rsplit(['.', ':']).next().unwrap_or(callee);

    // Method names that always terminate when called on any receiver
    // that's a testing handle (`*testing.T`, `*testing.B`, `*testing.F`)
    // or a logger.  Receiver type is unknown to this rule; the names
    // are sufficiently distinctive that arbitrary user-defined methods
    // sharing the name are vanishingly rare.
    if matches!(
        last,
        // Go testing
        "Fatal" | "Fatalf" | "Fatalln" | "FailNow" |
        // Go log/slog terminating handlers
        "Panic" | "Panicf" | "Panicln" |
        // Rust process / never-return std fns
        "abort" | "unreachable_unchecked"
    ) {
        return true;
    }

    // Bare callees (no receiver) that are language builtins or
    // unambiguous std-library terminators.
    match callee {
        // Go builtin
        "panic" => return true,
        // Go std
        "os.Exit" | "syscall.Exit" | "runtime.Goexit" | "log.Fatal" | "log.Fatalf"
        | "log.Fatalln" | "log.Panic" | "log.Panicf" | "log.Panicln" | "slog.Fatal"
        | "klog.Fatal" | "klog.Fatalf" | "klog.Exit" | "klog.Exitf" => return true,
        // Rust std
        "process::exit" | "process::abort" | "std::process::exit" | "std::process::abort" => {
            return true;
        }
        // Python std
        "sys.exit" | "os._exit" | "os.abort" => return true,
        _ => {}
    }

    false
}

/// Check if all paths from `node` reach a Return/Break/Continue (or a
/// known never-returning call) before reaching the if's join point.
///
/// `join` is the if statement's immediate post-dominator (`None` if it
/// could not be computed — e.g. no Exit node).  The walk stops at the
/// join: reaching it means the true branch fell through past the if
/// without terminating, so that path does NOT terminate and the rule
/// should fire.  This prevents a `return` in the function tail (after the
/// join) from being mis-attributed to the error branch.
fn terminates_on_all_paths(
    cfg: &crate::cfg::Cfg,
    node: NodeIndex,
    join: Option<NodeIndex>,
) -> bool {
    use std::collections::HashSet;

    let mut visited = HashSet::new();
    let mut stack = vec![node];

    while let Some(current) = stack.pop() {
        if !visited.insert(current) {
            continue;
        }

        // Reaching the if's join point means this path fell through past
        // the if without terminating inside the branch.
        if join == Some(current) {
            return false;
        }

        let info = &cfg[current];
        match info.kind {
            StmtKind::Return | StmtKind::Throw | StmtKind::Break | StmtKind::Continue => {
                // This path terminates
                continue;
            }
            _ => {}
        }
        if call_never_returns(info) {
            // Documented never-returning call (`t.Fatalf`, `os.Exit`,
            // `panic`, `runtime.Goexit`, …), this path terminates.
            continue;
        }

        let successors: Vec<_> = cfg.neighbors(current).collect();
        if successors.is_empty() {
            // Reached a dead end without terminating, path does not terminate
            return false;
        }

        for succ in successors {
            // Don't follow back edges (loops)
            let is_back_edge = cfg
                .edges(current)
                .any(|e| e.target() == succ && matches!(e.weight(), EdgeKind::Back));
            if !is_back_edge {
                stack.push(succ);
            }
        }
    }

    true
}

/// Find successor nodes after an If node merges.
///
/// Walks **only** the False edge of the if (and Seq edges from there),
/// so that sinks inside the True body are NOT counted as "post-if"
/// fallthrough sinks.  The False edge represents the no-error branch,
/// which is the path the rule wants to scan for "did execution fall
/// through past an unhandled error?".
///
/// For `if err != nil { warn(); }` with no statement after the if,
/// the False edge leads to the function exit and no sinks are found.
/// For `if err != nil { warn(); } sink(x)`, the False edge leads to
/// `sink(x)` and the rule fires correctly.
fn find_post_if_sinks(cfg: &crate::cfg::Cfg, if_node: NodeIndex) -> Vec<NodeIndex> {
    let mut sinks_after = Vec::new();
    let mut visited = std::collections::HashSet::new();

    // Seed from the False edge only.  If the if has no explicit False
    // edge (some CFG shapes omit it for one-branch ifs), fall back to
    // Seq edges from the if node, but never follow True edges, which
    // lead into the body.
    let mut stack: Vec<NodeIndex> = cfg
        .edges(if_node)
        .filter(|e| matches!(e.weight(), EdgeKind::False | EdgeKind::Seq))
        .map(|e| e.target())
        .collect();

    while let Some(current) = stack.pop() {
        if !visited.insert(current) {
            continue;
        }

        let info = &cfg[current];
        if is_sink(info) || (info.kind == StmtKind::Call && info.call.callee.is_some()) {
            sinks_after.push(current);
        }

        for edge in cfg.edges(current) {
            let succ = edge.target();
            // Don't follow back edges (loops) or exception edges.
            if matches!(edge.weight(), EdgeKind::Back | EdgeKind::Exception) {
                continue;
            }
            stack.push(succ);
        }
    }

    sinks_after
}

impl CfgAnalysis for IncompleteErrorHandling {
    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let mut findings = Vec::new();

        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];

            // Look for If nodes whose CONDITION involves "err" or "error".
            // `info.taint.uses` for an If node contains identifiers from the
            // whole if statement (condition + body), see
            // `cfg::literals::extract_defs_uses_extra_defs` Kind::If branch
            //, so checking it would misfire on `if (!res.ok) { ... const
            // err = await … ; return … }` shapes whose body happens to
            // mention `err` even though the condition doesn't.  Use
            // `info.condition_vars`, which is populated strictly from the
            // condition subtree (`extract_condition_raw`).
            if info.kind != StmtKind::If {
                continue;
            }

            let mentions_err = info.condition_vars.iter().any(|u| is_error_var_ident(u));

            if !mentions_err {
                continue;
            }

            // Polarity gate: only fire when the condition POSITIVELY
            // checks for an error.  `if (!data.error && other)` is a
            // happy-path check, the TRUE branch is the success branch
            // and is not expected to terminate.  Detect by scanning the
            // condition text for any `!` (logical-not, distinct from
            // `!=`) preceding an identifier whose name contains "err".
            //
            // This is the polarity-aware complement to
            // `condition_negated` (which only catches the top-level
            // unary `!`); compound conditions with embedded
            // `!response.error` legitimately fall outside the rule's
            // intended target shape (Go `if err != nil { non-return }`
            // / JS `if (err) { warn(); }`).
            if let Some(text) = info.condition_text.as_deref()
                && contains_negated_err_identifier(text)
            {
                continue;
            }
            if info.condition_negated {
                continue;
            }

            // Check: does the true branch terminate?
            if branch_terminates(ctx.cfg, idx) {
                continue;
            }

            // Check: are there dangerous calls/sinks after this error check?
            let post_sinks = find_post_if_sinks(ctx.cfg, idx);
            let has_dangerous_successor = post_sinks.iter().any(|&s| is_sink(&ctx.cfg[s]));

            if has_dangerous_successor {
                findings.push(CfgFinding {
                    rule_id: "cfg-error-fallthrough".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    span: info.ast.span,
                    message: "Error check does not terminate on error; \
                              execution falls through to dangerous operations"
                        .to_string(),
                    evidence: vec![idx],
                    score: None,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod negation_tests {
    use super::contains_negated_err_identifier;

    #[test]
    fn detects_simple_negated_err() {
        assert!(contains_negated_err_identifier("!err"));
        assert!(contains_negated_err_identifier("!error"));
        assert!(contains_negated_err_identifier("! err"));
    }

    #[test]
    fn detects_negated_member_err() {
        assert!(contains_negated_err_identifier("!data.error"));
        assert!(contains_negated_err_identifier(
            "data && !data.error && Array.isArray(results)"
        ));
        assert!(contains_negated_err_identifier(
            "!response.errorMsg && response.ok"
        ));
    }

    #[test]
    fn does_not_match_inequality() {
        assert!(!contains_negated_err_identifier("err != nil"));
        assert!(!contains_negated_err_identifier("error !== null"));
    }

    #[test]
    fn does_not_match_positive_err_checks() {
        assert!(!contains_negated_err_identifier("err"));
        assert!(!contains_negated_err_identifier("err != null"));
        assert!(!contains_negated_err_identifier("response.error"));
        assert!(!contains_negated_err_identifier("hasError(x)"));
    }
}

#[cfg(test)]
mod err_ident_tests {
    use super::is_error_var_ident;

    #[test]
    fn matches_canonical_error_vars() {
        assert!(is_error_var_ident("err"));
        assert!(is_error_var_ident("error"));
        assert!(is_error_var_ident("ERR"));
        assert!(is_error_var_ident("Error"));
    }

    #[test]
    fn matches_snake_case_error_vars() {
        assert!(is_error_var_ident("err_resp"));
        assert!(is_error_var_ident("error_msg"));
        assert!(is_error_var_ident("response_err"));
        assert!(is_error_var_ident("parse_error"));
    }

    #[test]
    fn rejects_camelcase_method_names() {
        // Spring `logger.isErrorEnabled()` lifts `isErrorEnabled` into
        // `condition_vars`; under the old `lower.contains("err")` check
        // this fired the rule.  The new strict check rejects it, the
        // condition is asking "is logging enabled", not "is there an
        // error".
        assert!(!is_error_var_ident("isErrorEnabled"));
        assert!(!is_error_var_ident("getError"));
        assert!(!is_error_var_ident("hasError"));
        assert!(!is_error_var_ident("errorMsg"));
        assert!(!is_error_var_ident("errCode"));
    }

    #[test]
    fn rejects_unrelated_idents() {
        assert!(!is_error_var_ident("user"));
        assert!(!is_error_var_ident("merry"));
        assert!(!is_error_var_ident("perform"));
    }
}

#[cfg(test)]
mod join_boundary_tests {
    use super::branch_terminates;
    use crate::cfg::{CallMeta, Cfg, EdgeKind, NodeInfo, StmtKind};
    use petgraph::graph::NodeIndex;

    fn node(kind: StmtKind) -> NodeInfo {
        NodeInfo {
            kind,
            ..Default::default()
        }
    }

    fn call_node(callee: &str) -> NodeInfo {
        NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some(callee.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Build the canonical `if err != nil { <body> } <tail>; return`
    /// shape and return (cfg, if_node).  `body_terminates` selects whether
    /// the true branch body itself returns (terminates) or falls through
    /// to the join.
    fn build_if_cfg(body_terminates: bool) -> (Cfg, NodeIndex) {
        let mut cfg = Cfg::new();
        let entry = cfg.add_node(node(StmtKind::Entry));
        let if_n = cfg.add_node(node(StmtKind::If));
        // true-branch body
        let body = if body_terminates {
            cfg.add_node(node(StmtKind::Return))
        } else {
            cfg.add_node(call_node("log"))
        };
        // join point where both branches reconverge: a downstream use
        let join = cfg.add_node(call_node("use"));
        // function tail: an explicit `return nil` (present in every Go
        // value-returning function) followed by exit.
        let ret = cfg.add_node(node(StmtKind::Return));
        let exit = cfg.add_node(node(StmtKind::Exit));

        cfg.add_edge(entry, if_n, EdgeKind::Seq);
        cfg.add_edge(if_n, body, EdgeKind::True);
        cfg.add_edge(if_n, join, EdgeKind::False);
        if !body_terminates {
            cfg.add_edge(body, join, EdgeKind::Seq);
        } else {
            cfg.add_edge(body, exit, EdgeKind::Seq);
        }
        cfg.add_edge(join, ret, EdgeKind::Seq);
        cfg.add_edge(ret, exit, EdgeKind::Seq);

        (cfg, if_n)
    }

    #[test]
    fn fallthrough_body_does_not_terminate_despite_trailing_return() {
        // True branch falls through to the join; the function tail has a
        // `return nil`.  Before the join-boundary fix the walk reached
        // that trailing return and reported "terminates", suppressing the
        // rule.  The fix bounds the walk at the join, so this is correctly
        // reported as NOT terminating.
        let (cfg, if_n) = build_if_cfg(false);
        assert!(
            !branch_terminates(&cfg, if_n),
            "fall-through error branch must not count as terminating"
        );
    }

    #[test]
    fn returning_body_terminates() {
        // True branch returns directly: the error is handled, so the rule
        // must stay suppressed.
        let (cfg, if_n) = build_if_cfg(true);
        assert!(
            branch_terminates(&cfg, if_n),
            "error branch with an explicit return must count as terminating"
        );
    }
}

#[cfg(test)]
mod terminator_call_tests {
    use super::call_never_returns;
    use crate::cfg::{CallMeta, NodeInfo, StmtKind};

    fn call_node(callee: &str) -> NodeInfo {
        NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: Some(callee.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn recognises_go_testing_fatal_methods() {
        // Bare method name on any receiver, the canonical minio test
        // shape `c.Fatalf("bucket creat error: %v", err)`.
        assert!(call_never_returns(&call_node("c.Fatalf")));
        assert!(call_never_returns(&call_node("t.Fatal")));
        assert!(call_never_returns(&call_node("t.Fatalf")));
        assert!(call_never_returns(&call_node("t.Fatalln")));
        assert!(call_never_returns(&call_node("b.Fatal")));
        assert!(call_never_returns(&call_node("t.FailNow")));
        // Logger panics (handler-style fatal).
        assert!(call_never_returns(&call_node("logger.Panic")));
        assert!(call_never_returns(&call_node("logger.Panicf")));
    }

    #[test]
    fn recognises_go_std_terminators() {
        assert!(call_never_returns(&call_node("os.Exit")));
        assert!(call_never_returns(&call_node("syscall.Exit")));
        assert!(call_never_returns(&call_node("runtime.Goexit")));
        assert!(call_never_returns(&call_node("log.Fatal")));
        assert!(call_never_returns(&call_node("log.Fatalf")));
        assert!(call_never_returns(&call_node("log.Fatalln")));
        assert!(call_never_returns(&call_node("log.Panic")));
        assert!(call_never_returns(&call_node("klog.Exit")));
        // Bare builtin
        assert!(call_never_returns(&call_node("panic")));
    }

    #[test]
    fn recognises_rust_and_python_std_terminators() {
        assert!(call_never_returns(&call_node("std::process::exit")));
        assert!(call_never_returns(&call_node("std::process::abort")));
        assert!(call_never_returns(&call_node("process::exit")));
        assert!(call_never_returns(&call_node("sys.exit")));
        assert!(call_never_returns(&call_node("os._exit")));
    }

    #[test]
    fn does_not_claim_user_defined_lookalikes() {
        // Bare `Exit` on a custom receiver is a normal method, not the
        // process-level terminator.  The bare callee path only matches
        // exact std-library forms.
        assert!(!call_never_returns(&call_node("server.Exit")));
        assert!(!call_never_returns(&call_node("Exit")));
        assert!(!call_never_returns(&call_node("session.exit")));
        // Bare `panic` is a Go builtin; method `panic` is not.
        // The recogniser keys off the full callee path so
        // `widget.panic` does not match.
        assert!(!call_never_returns(&call_node("widget.panic")));
        // Common helpers that *don't* terminate.
        assert!(!call_never_returns(&call_node("log.Print")));
        assert!(!call_never_returns(&call_node("log.Println")));
        assert!(!call_never_returns(&call_node("t.Errorf")));
        assert!(!call_never_returns(&call_node("t.Logf")));
        assert!(!call_never_returns(&call_node("c.Skip")));
    }

    #[test]
    fn requires_call_kind() {
        // Only StmtKind::Call nodes are inspected; an If or Seq node
        // carrying the same callee text wouldn't ever come through
        // this path.  Defensive: confirm the kind gate.
        let mut node = call_node("t.Fatal");
        node.kind = StmtKind::Seq;
        assert!(!call_never_returns(&node));
        node.kind = StmtKind::If;
        assert!(!call_never_returns(&node));
    }

    #[test]
    fn missing_callee_does_not_panic() {
        let node = NodeInfo {
            kind: StmtKind::Call,
            call: CallMeta {
                callee: None,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!call_never_returns(&node));
    }
}
