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

/// Does the condition text compare an error identifier for equality with
/// nil (`err == nil`, `nil == err`, `err === null`, `error is None`)?  That
/// is a success check: its TRUE branch is the happy path and the error path
/// is the FALSE edge.
///
/// Returns false when the same condition also checks an error positively
/// (`err == nil || close_err != nil`), so mixed shapes keep the TRUE-branch
/// reading.
fn contains_err_nil_equality(text: &str) -> bool {
    let mut success = false;
    for cmp in nil_comparisons(text) {
        let err_operand = [cmp.left, cmp.right]
            .into_iter()
            .any(|operand| is_error_var_ident(operand.rsplit('.').next().unwrap_or(operand)));
        if !err_operand {
            continue;
        }
        if cmp.equal {
            success = true;
        } else {
            return false;
        }
    }
    success
}

/// One `<a> ==|!=|===|!==|is|is not <b>` comparison in a condition text
/// where at least one side is a nil literal.  `equal` is true for the
/// equality forms.
struct NilComparison<'a> {
    left: &'a str,
    right: &'a str,
    equal: bool,
}

fn is_nil_literal(token: &str) -> bool {
    matches!(token, "nil" | "null" | "undefined" | "None" | "NULL")
}

/// Scan a condition text for comparisons against a nil literal.  The
/// operands are the identifier / member chains directly left and right of
/// the operator; a single `(` or `)` next to an operand is skipped.
fn nil_comparisons(text: &str) -> Vec<NilComparison<'_>> {
    fn is_operand_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'$'
    }
    fn operand_before(text: &str, end: usize) -> &str {
        let bytes = text.as_bytes();
        let mut j = end;
        while j > 0 && bytes[j - 1].is_ascii_whitespace() {
            j -= 1;
        }
        if j > 0 && bytes[j - 1] == b')' {
            j -= 1;
        }
        let stop = j;
        while j > 0 && is_operand_byte(bytes[j - 1]) {
            j -= 1;
        }
        &text[j..stop]
    }
    fn operand_after(text: &str, start: usize) -> &str {
        let bytes = text.as_bytes();
        let mut j = start;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'(' {
            j += 1;
        }
        let begin = j;
        while j < bytes.len() && is_operand_byte(bytes[j]) {
            j += 1;
        }
        &text[begin..j]
    }

    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // `==` / `===` / `!=` / `!==`.  A lone `=` (assignment, `<=`, `>=`)
        // is not an equality operator.
        let equality = match (bytes[i], bytes.get(i + 1)) {
            (b'!', Some(b'=')) => Some(false),
            (b'=', Some(b'=')) => Some(true),
            _ => None,
        };
        let op = if let Some(equal) = equality {
            let mut op_end = i + 2;
            if bytes.get(op_end) == Some(&b'=') {
                op_end += 1;
            }
            Some((i, op_end, equal))
        } else if bytes[i..].starts_with(b" is ") {
            // Python `x is None` / `x is not None`.
            if bytes[i + 4..].starts_with(b"not ") {
                Some((i, i + 8, false))
            } else {
                Some((i, i + 4, true))
            }
        } else {
            None
        };
        let Some((op_start, op_end, equal)) = op else {
            i += 1;
            continue;
        };
        let left = operand_before(text, op_start);
        let right = operand_after(text, op_end);
        if is_nil_literal(left) || is_nil_literal(right) {
            out.push(NilComparison { left, right, equal });
        }
        i = op_end;
    }
    out
}

pub struct IncompleteErrorHandling;

/// Check if the true branch of an If node terminates (has Return/Break/Continue).
#[cfg(test)]
fn branch_terminates(cfg: &crate::cfg::Cfg, if_node: NodeIndex) -> bool {
    let join = super::dominators::compute_post_dominators(cfg)
        .and_then(|pd| pd.immediate_dominator(if_node));
    error_branch_terminates(cfg, if_node, EdgeKind::True, join)
}

/// Check if the branch an If node takes on `error_edge` terminates (has
/// Return/Break/Continue or a never-returning call) before `join`.
///
/// `join` is the if statement's immediate post-dominator: the first node
/// every branch reconverges on.  The branch walk must stop there: reaching
/// the join means the body fell through *past* the if without terminating,
/// so any `return` in the function tail past the join must NOT count as the
/// error branch terminating.  Without this bound, a trailing `return nil`
/// (present in essentially every Go `func(...) error`) makes the walk report
/// "all paths terminate" and silently suppresses the rule.
fn error_branch_terminates(
    cfg: &crate::cfg::Cfg,
    if_node: NodeIndex,
    error_edge: EdgeKind,
    join: Option<NodeIndex>,
) -> bool {
    cfg.edges(if_node)
        .filter(|e| *e.weight() == error_edge)
        .any(|e| terminates_on_all_paths(cfg, e.target(), join))
}

/// The synthetic pass-through node the CFG builder places on the FALSE edge
/// of an `if` without an `else` (zero-width span, no call, no labels).
fn is_no_else_pass_through(info: &crate::cfg::NodeInfo) -> bool {
    info.kind == StmtKind::Seq
        && info.ast.span.0 == info.ast.span.1
        && info.call.callee.is_none()
        && info.taint.labels.is_empty()
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
    // Seed from the False edge only.  If the if has no explicit False
    // edge (some CFG shapes omit it for one-branch ifs), fall back to
    // Seq edges from the if node, but never follow True edges, which
    // lead into the body.
    let seeds: Vec<NodeIndex> = cfg
        .edges(if_node)
        .filter(|e| matches!(e.weight(), EdgeKind::False | EdgeKind::Seq))
        .map(|e| e.target())
        .collect();
    collect_calls_from(cfg, seeds)
}

/// Sink and call nodes reachable from `seeds`, not following loop back
/// edges or exception edges.
fn collect_calls_from(cfg: &crate::cfg::Cfg, seeds: Vec<NodeIndex>) -> Vec<NodeIndex> {
    let mut sinks_after = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut stack = seeds;

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

/// Collect the variable names DEFINED (assigned / re-bound) anywhere in
/// the if's error branch (the TRUE branch of `if err != nil`, the `else` of
/// `if err == nil`), bounded at the if's post-dominator `join`.
///
/// This recognises the **default-on-error recovery idiom** — the single
/// most common `cfg-error-fallthrough` false positive on real Go code
/// (minio `interval, err := time.ParseDuration(...); if err != nil ||
/// interval < time.Second { interval = defaultMetricsInterval }`,
/// portainer `cmd, err := lookup(r); if err != nil { cmd = "all" }`):
///
/// ```go
/// name, err := lookup(r)
/// if err != nil {
///     name = "default"   // recovery: re-bind the failed value
/// }
/// os.Open(name)          // consumes the recovered default, not the failure
/// ```
///
/// The rule's premise is "an error occurred → the values produced by the
/// failing call are invalid → a downstream dangerous op consuming them is
/// risky".  When the error branch re-assigns the very value the sink
/// consumes, that premise no longer holds — on the error path the sink
/// sees the recovered default, not the failed result.  The caller
/// suppresses the finding only when EVERY dangerous post-if sink consumes
/// a recovered variable (a sink reading a non-recovered failed value still
/// fires — see the `handleUnrelated` / `vuln_error_log_then_sink` shapes).
///
/// The walk is bounded at the if's join (post-dominator) so assignments in
/// the function tail past the if are not attributed to the error branch.
fn collect_error_branch_defines(
    cfg: &crate::cfg::Cfg,
    if_node: NodeIndex,
    error_edge: EdgeKind,
    join: Option<NodeIndex>,
) -> std::collections::HashSet<String> {
    use std::collections::HashSet;

    let mut defs: HashSet<String> = HashSet::new();
    let mut visited: HashSet<NodeIndex> = HashSet::new();
    let mut stack: Vec<NodeIndex> = cfg
        .edges(if_node)
        .filter(|e| *e.weight() == error_edge)
        .map(|e| e.target())
        .collect();

    while let Some(current) = stack.pop() {
        // Reaching the join means we walked past the if body; stop.
        if join == Some(current) {
            continue;
        }
        if !visited.insert(current) {
            continue;
        }

        let info = &cfg[current];
        if let Some(d) = info.taint.defines.as_deref() {
            defs.insert(d.to_string());
        }
        for d in &info.taint.extra_defines {
            defs.insert(d.clone());
        }

        for edge in cfg.edges(current) {
            if matches!(edge.weight(), EdgeKind::Back | EdgeKind::Exception) {
                continue;
            }
            stack.push(edge.target());
        }
    }

    defs
}

/// A post-if sink whose injection payload is a constant cannot consume the
/// value the failed call left behind (nor any other data), so it is not a
/// dangerous operation for this rule: `if err != nil { log(err) };
/// exec.Command("sync").Run()`.  Same constant-payload checks as
/// `cfg-unguarded-sink`; a sink the taint engine confirms always counts.
fn sink_payload_provably_constant(ctx: &AnalysisContext, sink: NodeIndex) -> bool {
    if super::guards::taint_confirms_sink(ctx, sink) {
        return false;
    }
    super::guards::sink_payload_args_syntactic_const(ctx, sink)
        || super::guards::is_all_args_constant(ctx, sink)
}

impl CfgAnalysis for IncompleteErrorHandling {
    fn run(&self, ctx: &AnalysisContext) -> Vec<CfgFinding> {
        let mut findings = Vec::new();

        // Post-dominators bound both the error-branch termination walk and
        // the recovery-idiom walk; compute once per CFG rather than once per
        // error check.
        let post_doms = super::dominators::compute_post_dominators(ctx.cfg);

        for idx in ctx.cfg.node_indices() {
            let info = &ctx.cfg[idx];

            // Look for If nodes whose CONDITION involves "err" or "error".
            // Use `info.condition_vars` (bare identifiers of the condition,
            // from `extract_condition_raw`) rather than `info.taint.uses`,
            // which also carries dotted paths and, on a switch dispatch
            // header, the identifiers of the whole case.
            // A conditional expression (`msg = error > 0 ? ko : ok`) picks a
            // value on both arms; there is no branch that should have
            // returned.
            if info.kind != StmtKind::If || info.is_ternary_condition {
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

            let join = post_doms
                .as_ref()
                .and_then(|pd| pd.immediate_dominator(idx));

            // Success check (`if err == nil { use(v) }`, `if (err ===
            // null)`): the TRUE branch is the happy path and the error path
            // is the FALSE edge.  With no `else` there is no error handler
            // to judge; this is the best-effort idiom whose results are
            // scoped to the if body, so the rule does not apply.  With an
            // `else`, that branch is the error handler and is held to the
            // same standard as the body of `if err != nil`.
            let success_check = info
                .condition_text
                .as_deref()
                .is_some_and(contains_err_nil_equality);
            let error_edge = if success_check {
                let mut else_succs = ctx
                    .cfg
                    .edges(idx)
                    .filter(|e| *e.weight() == EdgeKind::False)
                    .map(|e| e.target())
                    .peekable();
                if else_succs.peek().is_none()
                    || else_succs.all(|n| is_no_else_pass_through(&ctx.cfg[n]))
                {
                    continue;
                }
                EdgeKind::False
            } else {
                EdgeKind::True
            };

            // Check: does the error branch terminate?
            if error_branch_terminates(ctx.cfg, idx, error_edge, join) {
                continue;
            }

            // Check: are there dangerous calls/sinks after this error check?
            // For a success check the FALSE edge runs through the error
            // handler itself, so start from the join instead.
            let post_sinks = if success_check {
                match join {
                    Some(j) => collect_calls_from(ctx.cfg, vec![j]),
                    None => continue,
                }
            } else {
                find_post_if_sinks(ctx.cfg, idx)
            };
            let dangerous: Vec<NodeIndex> = post_sinks
                .iter()
                .copied()
                .filter(|&s| is_sink(&ctx.cfg[s]))
                .filter(|&s| !sink_payload_provably_constant(ctx, s))
                .collect();

            if dangerous.is_empty() {
                continue;
            }

            // Default-on-error recovery idiom: the error branch re-binds
            // the value(s) the post-if sink consumes
            // (`if err != nil { name = "default" }; os.Open(name)`), so on
            // the error path the sink sees the recovered value, not the
            // failed result.  Suppress only when EVERY dangerous sink
            // consumes a recovered variable — a sink reading a
            // non-recovered failed value (`if err != nil { log(err) };
            // sink(failed)`) still fires.
            let recovered = collect_error_branch_defines(ctx.cfg, idx, error_edge, join);
            if !recovered.is_empty()
                && dangerous
                    .iter()
                    .all(|&s| ctx.cfg[s].taint.uses.iter().any(|u| recovered.contains(u)))
            {
                continue;
            }

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

        findings
    }
}

#[cfg(test)]
mod err_nil_equality_tests {
    use super::contains_err_nil_equality;

    #[test]
    fn detects_success_checks() {
        for text in [
            "err == nil",
            "nil == err",
            "err === null",
            "err == null",
            "error === undefined",
            "error is None",
            "resp.err == nil",
            "(err == nil)",
            "err == nil && n > 0",
        ] {
            assert!(contains_err_nil_equality(text), "{text}");
        }
    }

    #[test]
    fn rejects_error_checks_and_unrelated_comparisons() {
        for text in [
            "err != nil",
            "err !== null",
            "error is not None",
            "result == nil",
            "errCount == 0",
            "err == nil || close_err != nil",
            "x <= nil",
            "err",
        ] {
            assert!(!contains_err_nil_equality(text), "{text}");
        }
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
    use crate::cfg::{CallMeta, Cfg, EdgeKind, NodeInfo, StmtKind};
    use petgraph::graph::NodeIndex;

    /// Run `super::branch_terminates`, which bounds the walk by the If node's
    /// immediate post-dominator the same way `run` does.
    fn branch_terminates(cfg: &Cfg, if_n: NodeIndex) -> bool {
        super::branch_terminates(cfg, if_n)
    }

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
