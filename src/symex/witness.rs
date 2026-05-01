//! Witness generation for confirmed symbolic findings.
//!
//! When the multi-path explorer confirms a finding as feasible, this module
//! generates a concrete proof witness, an actual input value that would
//! trigger the vulnerability. Witnesses are best-effort: if the expression
//! is not string-renderable or constraints are too complex, a generic
//! description is produced instead.
#![allow(clippy::needless_borrow)]

use std::collections::HashSet;

use crate::cfg::Cfg;
use crate::labels::{Cap, DataLabel};
use crate::ssa::ir::{SsaBody, SsaValue};
use crate::taint::Finding;

use super::state::SymbolicState;
use super::value::SymbolicValue;

// ─────────────────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Extract a human-readable witness string for a confirmed finding.
///
/// Returns `None` if:
/// - The sink's symbolic expression is `Unknown`
/// - The sink node is not mapped in the SSA
///
/// The witness is **sink-shape-aware**: specialized exploit payloads are only
/// substituted when the sink expression is string-renderable. For non-string
/// expressions, a generic description is produced instead.
pub fn extract_witness(
    state: &SymbolicState,
    finding: &Finding,
    ssa: &SsaBody,
    cfg: &Cfg,
) -> Option<String> {
    // 1. Get sink's symbolic expression
    let ssa_val = ssa.cfg_node_map.get(&finding.sink)?;
    let sym = state.get(*ssa_val);
    if matches!(sym, SymbolicValue::Unknown) {
        return None;
    }

    // 1b. When the sink is a Call node, the return value is typically opaque.
    // Look for the best tainted argument instead, that's where injected
    // data actually flows into the sink.
    let sym = unwrap_sink_call_arg(&sym, state);

    // 2. Derive sink cap from CFG labels
    let cap = sink_cap(finding, cfg);

    // 3. Extract source variable name
    let source_var = finding
        .flow_steps
        .iter()
        .find(|s| matches!(s.op_kind, crate::evidence::FlowStepKind::Source))
        .and_then(|s| s.var_name.as_deref())
        .unwrap_or("input");

    // 4. Extract sink callee name
    let sink_callee = if finding.sink.index() < cfg.node_count() {
        cfg[finding.sink].call.callee.as_deref().unwrap_or("sink")
    } else {
        "sink"
    };

    // 5. Find tainted symbols in expression tree
    let tainted = collect_tainted_symbols(&sym, state);

    // 5b. Collect field paths from heap access trace.
    let field_paths: Vec<String> = state
        .heap()
        .field_accesses()
        .iter()
        .filter(|a| tainted.contains(&a.ssa_value))
        .map(|a| format!("{}.{}", a.object_name, a.field_name))
        .collect();
    let field_suffix = if field_paths.is_empty() {
        String::new()
    } else {
        format!(" via {}", field_paths.join(", "))
    };

    // 6. Branch on string-renderability
    if tainted.is_empty() {
        // No tainted symbols, expression is fully concrete or opaque
        let concrete = evaluate_concrete(&sym);
        Some(format!(
            "input '{}' flows to {}(\"{}\")",
            source_var, sink_callee, concrete
        ))
    } else if is_string_renderable(&sym) {
        // String-renderable: substitute tainted symbols with exploit payload
        let payload = witness_payload(cap);
        let substituted = substitute_tainted(&sym, &tainted, payload);
        let concrete = evaluate_concrete(&substituted);
        // Heuristic mismatch note when a protective transform doesn't match
        // the sink's vulnerability class.
        let mismatch_suffix = detect_transform_mismatch(&sym, cap)
            .map(|note| format!(" {}", note))
            .unwrap_or_default();
        Some(format!(
            "input '{}' = \"{}\" flows to {}(\"{}\"){}{}",
            source_var, payload, sink_callee, concrete, field_suffix, mismatch_suffix
        ))
    } else {
        // Not string-renderable: generic witness.
        // Still check for transform mismatch in the expression tree.
        let mismatch_suffix = detect_transform_mismatch(&sym, cap)
            .map(|note| format!(" {}", note))
            .unwrap_or_default();
        Some(format!(
            "tainted input '{}' reaches {}() unsanitized{}{}",
            source_var, sink_callee, field_suffix, mismatch_suffix
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// When the sink expression is a `Call`, find the most informative tainted
/// argument to use for witness generation instead of the opaque return value.
///
/// Scores each tainted arg by structural richness, args containing protective
/// transforms (`Encode`/`Decode`), string composition (`Concat`/`BinOp(Add)`),
/// or string methods (`Replace`/`Substr`/etc.) outrank bare `Call(...)`
/// wrappers (which typically come from prepended receivers or opaque property
/// access). This preserves transform-mismatch witnesses when a receiver is
/// present among the sink's args.
///
/// Returns the original expression unchanged if it's not a `Call` or no
/// tainted argument is found.
fn unwrap_sink_call_arg<'a>(expr: &'a SymbolicValue, state: &SymbolicState) -> &'a SymbolicValue {
    if let SymbolicValue::Call(_, args) = expr {
        let best = args
            .iter()
            .filter(|a| !collect_tainted_symbols(a, state).is_empty())
            .max_by_key(|a| arg_richness(a));

        if let Some(arg) = best {
            return arg;
        }
    }
    expr
}

/// Score a symbolic expression by how informative it is as a witness target.
///
/// Higher = more informative. Protective transforms and string composition
/// rank highest because they carry the semantic structure users care about
/// (sanitization class, injection shape). Opaque `Call(...)` wrappers rank
/// lowest because they are typically receivers or property-access proxies
/// that merely thread a tainted symbol through a wrapper.
fn arg_richness(expr: &SymbolicValue) -> u32 {
    match expr {
        SymbolicValue::Encode(_, _) | SymbolicValue::Decode(_, _) => 100,
        SymbolicValue::Concat(_, _) => 90,
        SymbolicValue::BinOp(super::value::Op::Add, l, r)
            if is_string_renderable(l) || is_string_renderable(r) =>
        {
            85
        }
        SymbolicValue::Replace(_, _, _)
        | SymbolicValue::Substr(_, _, _)
        | SymbolicValue::Trim(_)
        | SymbolicValue::ToLower(_)
        | SymbolicValue::ToUpper(_) => 80,
        SymbolicValue::Symbol(_) => 50,
        SymbolicValue::ConcreteStr(_) => 40,
        SymbolicValue::Call(_, inner) => {
            // Pass-through single-arg Calls (property access) inherit their
            // inner richness minus a small penalty so a true composite is
            // still preferred over a wrapped symbol.
            if inner.len() == 1 {
                arg_richness(&inner[0]).saturating_sub(5)
            } else {
                20
            }
        }
        SymbolicValue::Phi(_) => 15,
        SymbolicValue::BinOp(_, _, _) => 10,
        SymbolicValue::StrLen(_) | SymbolicValue::Concrete(_) | SymbolicValue::Unknown => 0,
    }
}

/// Derive the sink's capability bits from CFG node labels.
fn sink_cap(finding: &Finding, cfg: &Cfg) -> Cap {
    if finding.sink.index() >= cfg.node_count() {
        return Cap::empty();
    }
    let info = &cfg[finding.sink];
    let mut caps = Cap::empty();
    for lbl in &info.taint.labels {
        if let DataLabel::Sink(bits) = *lbl {
            caps |= bits;
        }
    }
    caps
}

/// Select a witness payload string based on the vulnerability class.
fn witness_payload(cap: Cap) -> &'static str {
    // Check bits in priority order (most specific first).
    //
    // `DATA_EXFIL` is checked before the action-class caps (CODE_EXEC, SQL,
    // etc.) because a data-exfil sink reflects what the *attacker reads*,
    // not what they *do*: the witness needs to look like a leaked secret
    // ("<SESSION_TOKEN>") rather than an injected payload ("' OR 1=1 --").
    if cap.intersects(Cap::DATA_EXFIL) {
        "<SESSION_TOKEN>"
    } else if cap.intersects(Cap::CODE_EXEC) {
        "require('child_process').execSync('id')"
    } else if cap.intersects(Cap::HTML_ESCAPE) {
        "<script>alert('xss')</script>"
    } else if cap.intersects(Cap::SQL_QUERY) {
        "' OR 1=1 --"
    } else if cap.intersects(Cap::SHELL_ESCAPE) {
        "$(id)"
    } else if cap.intersects(Cap::FILE_IO) {
        "../../etc/passwd"
    } else if cap.intersects(Cap::SSRF) {
        "http://169.254.169.254/metadata"
    } else if cap.intersects(Cap::DESERIALIZE) {
        "malicious_serialized_object"
    } else {
        "TAINTED"
    }
}

/// Check if a symbolic expression is string-renderable.
///
/// String-renderable expressions produce meaningful witness strings when
/// tainted symbols are substituted with exploit payloads. Non-string
/// expressions (arithmetic, opaque calls) would produce misleading output.
fn is_string_renderable(expr: &SymbolicValue) -> bool {
    match expr {
        SymbolicValue::ConcreteStr(_) => true,
        SymbolicValue::Symbol(_) => true,
        SymbolicValue::Concat(l, r) => is_string_renderable(l) && is_string_renderable(r),
        // String ops on string-renderable operands are renderable
        SymbolicValue::Trim(s)
        | SymbolicValue::ToLower(s)
        | SymbolicValue::ToUpper(s)
        | SymbolicValue::Replace(s, _, _) => is_string_renderable(s),
        SymbolicValue::Substr(s, _, _) => is_string_renderable(s),
        // Encoding/decoding transforms produce strings
        SymbolicValue::Encode(_, s) | SymbolicValue::Decode(_, s) => is_string_renderable(s),
        // StrLen returns integer, not string-renderable
        SymbolicValue::StrLen(_) => false,
        // BinOp(Add) on string-renderable operands is string concatenation
        // in languages where + is overloaded (JS, Python, etc.)
        SymbolicValue::BinOp(super::value::Op::Add, l, r) => {
            is_string_renderable(l) && is_string_renderable(r)
        }
        // Call nodes with a single string-renderable argument are treated as
        // pass-through for witness purposes (covers property access, simple
        // wrappers). Multi-arg calls or calls with non-renderable args are opaque.
        SymbolicValue::Call(_, args) if args.len() == 1 => is_string_renderable(&args[0]),
        // Other arithmetic, opaque calls, phis, integers, unknown, not string-renderable
        SymbolicValue::Concrete(_)
        | SymbolicValue::BinOp(_, _, _)
        | SymbolicValue::Call(_, _)
        | SymbolicValue::Phi(_)
        | SymbolicValue::Unknown => false,
    }
}

/// Collect all tainted SSA symbols from an expression tree.
fn collect_tainted_symbols(expr: &SymbolicValue, state: &SymbolicState) -> HashSet<SsaValue> {
    let mut tainted = HashSet::new();
    collect_tainted_inner(expr, state, &mut tainted);
    tainted
}

fn collect_tainted_inner(expr: &SymbolicValue, state: &SymbolicState, out: &mut HashSet<SsaValue>) {
    match expr {
        SymbolicValue::Symbol(v) => {
            if state.is_tainted(*v) {
                out.insert(*v);
            }
        }
        SymbolicValue::BinOp(_, l, r) | SymbolicValue::Concat(l, r) => {
            collect_tainted_inner(l, state, out);
            collect_tainted_inner(r, state, out);
        }
        SymbolicValue::Call(_, args) => {
            for arg in args {
                collect_tainted_inner(arg, state, out);
            }
        }
        SymbolicValue::Phi(ops) => {
            for (_, v) in ops {
                collect_tainted_inner(v, state, out);
            }
        }
        // String operations, recurse into operands
        SymbolicValue::ToLower(s)
        | SymbolicValue::ToUpper(s)
        | SymbolicValue::Trim(s)
        | SymbolicValue::StrLen(s)
        | SymbolicValue::Replace(s, _, _)
        // Encoding/decoding transforms
        | SymbolicValue::Encode(_, s)
        | SymbolicValue::Decode(_, s) => {
            collect_tainted_inner(s, state, out);
        }
        SymbolicValue::Substr(s, start, end) => {
            collect_tainted_inner(s, state, out);
            collect_tainted_inner(start, state, out);
            if let Some(e) = end {
                collect_tainted_inner(e, state, out);
            }
        }
        SymbolicValue::Concrete(_) | SymbolicValue::ConcreteStr(_) | SymbolicValue::Unknown => {}
    }
}

/// Substitute tainted symbols with a concrete payload string.
fn substitute_tainted(
    expr: &SymbolicValue,
    tainted: &HashSet<SsaValue>,
    payload: &str,
) -> SymbolicValue {
    match expr {
        SymbolicValue::Symbol(v) if tainted.contains(v) => {
            SymbolicValue::ConcreteStr(payload.to_owned())
        }
        SymbolicValue::Concat(l, r) => {
            let new_l = substitute_tainted(l, tainted, payload);
            let new_r = substitute_tainted(r, tainted, payload);
            // Try to fold if both sides are concrete strings
            if let (SymbolicValue::ConcreteStr(a), SymbolicValue::ConcreteStr(b)) = (&new_l, &new_r)
            {
                SymbolicValue::ConcreteStr(format!("{}{}", a, b))
            } else {
                SymbolicValue::Concat(Box::new(new_l), Box::new(new_r))
            }
        }
        SymbolicValue::BinOp(op, l, r) => {
            let new_l = substitute_tainted(l, tainted, payload);
            let new_r = substitute_tainted(r, tainted, payload);
            SymbolicValue::BinOp(*op, Box::new(new_l), Box::new(new_r))
        }
        SymbolicValue::Call(name, args) => {
            let new_args: Vec<_> = args
                .iter()
                .map(|a| substitute_tainted(a, tainted, payload))
                .collect();
            SymbolicValue::Call(name.clone(), new_args)
        }
        SymbolicValue::Phi(ops) => {
            let new_ops: Vec<_> = ops
                .iter()
                .map(|(bid, v)| (*bid, substitute_tainted(v, tainted, payload)))
                .collect();
            SymbolicValue::Phi(new_ops)
        }
        // String operations, recurse into operands
        SymbolicValue::Trim(s) => {
            SymbolicValue::Trim(Box::new(substitute_tainted(s, tainted, payload)))
        }
        SymbolicValue::ToLower(s) => {
            SymbolicValue::ToLower(Box::new(substitute_tainted(s, tainted, payload)))
        }
        SymbolicValue::ToUpper(s) => {
            SymbolicValue::ToUpper(Box::new(substitute_tainted(s, tainted, payload)))
        }
        SymbolicValue::StrLen(s) => {
            SymbolicValue::StrLen(Box::new(substitute_tainted(s, tainted, payload)))
        }
        SymbolicValue::Replace(s, pat, rep) => SymbolicValue::Replace(
            Box::new(substitute_tainted(s, tainted, payload)),
            pat.clone(),
            rep.clone(),
        ),
        SymbolicValue::Substr(s, start, end) => SymbolicValue::Substr(
            Box::new(substitute_tainted(s, tainted, payload)),
            Box::new(substitute_tainted(start, tainted, payload)),
            end.as_ref()
                .map(|e| Box::new(substitute_tainted(e, tainted, payload))),
        ),
        // Encoding/decoding transforms, preserve structure
        SymbolicValue::Encode(kind, s) => {
            SymbolicValue::Encode(*kind, Box::new(substitute_tainted(s, tainted, payload)))
        }
        SymbolicValue::Decode(kind, s) => {
            SymbolicValue::Decode(*kind, Box::new(substitute_tainted(s, tainted, payload)))
        }
        // Leaf nodes that are not tainted symbols, return unchanged
        other => other.clone(),
    }
}

/// Attempt to fold a symbolic expression to a concrete string.
///
/// For fully concrete expressions, returns the string value. For mixed
/// expressions, falls back to the Display representation.
fn evaluate_concrete(expr: &SymbolicValue) -> String {
    match expr {
        SymbolicValue::ConcreteStr(s) => s.clone(),
        SymbolicValue::Concrete(n) => n.to_string(),
        SymbolicValue::Concat(l, r) => {
            let left = evaluate_concrete(l);
            let right = evaluate_concrete(r);
            format!("{}{}", left, right)
        }
        // BinOp(Add) on concrete strings acts as concatenation
        SymbolicValue::BinOp(super::value::Op::Add, l, r) if is_string_renderable(expr) => {
            let left = evaluate_concrete(l);
            let right = evaluate_concrete(r);
            format!("{}{}", left, right)
        }
        // String operations, apply to recursively evaluated inner
        SymbolicValue::Trim(s) => evaluate_concrete(s).trim().to_owned(),
        SymbolicValue::ToLower(s) => evaluate_concrete(s).to_lowercase(),
        SymbolicValue::ToUpper(s) => evaluate_concrete(s).to_uppercase(),
        SymbolicValue::Replace(s, pat, rep) => {
            evaluate_concrete(s).replace(pat.as_str(), rep.as_str())
        }
        SymbolicValue::Substr(s, start, end) => {
            let inner = evaluate_concrete(s);
            match (
                start.as_concrete_int(),
                end.as_ref().and_then(|e| e.as_concrete_int()),
            ) {
                (Some(i), Some(j)) => {
                    let i = i.max(0) as usize;
                    let j = j.max(0) as usize;
                    inner.get(i..j.min(inner.len())).unwrap_or("").to_owned()
                }
                (Some(i), None) if end.is_none() => {
                    let i = i.max(0) as usize;
                    inner.get(i..).unwrap_or("").to_owned()
                }
                _ => format!("{}", expr),
            }
        }
        SymbolicValue::StrLen(s) => {
            if let SymbolicValue::ConcreteStr(cs) = s.as_ref() {
                cs.len().to_string()
            } else {
                format!("{}", expr)
            }
        }
        // Encoding/decoding, apply transform to recursively evaluated inner
        SymbolicValue::Encode(kind, s) => {
            let inner = evaluate_concrete(s);
            super::strings::encode_concrete_for_witness(*kind, &inner)
                .unwrap_or_else(|| format!("{}", expr))
        }
        SymbolicValue::Decode(kind, s) => {
            let inner = evaluate_concrete(s);
            super::strings::decode_concrete_for_witness(*kind, &inner)
                .unwrap_or_else(|| format!("{}", expr))
        }
        // Single-arg Call: pass-through for witness rendering (property access)
        SymbolicValue::Call(_, args) if args.len() == 1 => evaluate_concrete(&args[0]),
        // For non-foldable expressions, use Display
        other => format!("{}", other),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Transform–sink mismatch detection
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristic check: does a protective transform in the expression match
/// the sink's vulnerability class?
///
/// Returns a human-readable note if a transform's `verified_cap()` is
/// non-empty AND does NOT intersect the sink's cap, indicating the
/// transform does not match the sink's neutralization class.
///
/// This is a **heuristic witness annotation**, not a proof. Representation
/// transforms (base64, URL decode) and unverified transforms (SqlEscape)
/// never trigger mismatch notes.
fn detect_transform_mismatch(expr: &SymbolicValue, sink_cap: Cap) -> Option<String> {
    if sink_cap.is_empty() {
        return None;
    }
    match expr {
        SymbolicValue::Encode(kind, inner) => {
            let neutralizes = kind.verified_cap();
            if !neutralizes.is_empty() && !sink_cap.intersects(neutralizes) {
                Some(format!(
                    "[transform note: {} does not match sink neutralization class ({})]",
                    kind.display_name(),
                    cap_description(sink_cap),
                ))
            } else {
                // Correct transform or non-protective, recurse
                detect_transform_mismatch(inner, sink_cap)
            }
        }
        SymbolicValue::Concat(l, r) => detect_transform_mismatch(l, sink_cap)
            .or_else(|| detect_transform_mismatch(r, sink_cap)),
        SymbolicValue::Trim(s)
        | SymbolicValue::ToLower(s)
        | SymbolicValue::ToUpper(s)
        | SymbolicValue::Replace(s, _, _)
        | SymbolicValue::Decode(_, s) => detect_transform_mismatch(s, sink_cap),
        SymbolicValue::Substr(s, _, _) => detect_transform_mismatch(s, sink_cap),
        _ => None,
    }
}

/// Human-readable description of the primary cap in a sink's cap set.
fn cap_description(cap: Cap) -> &'static str {
    if cap.intersects(Cap::SQL_QUERY) {
        "sql_escape"
    } else if cap.intersects(Cap::HTML_ESCAPE) {
        "html_escape"
    } else if cap.intersects(Cap::SHELL_ESCAPE) {
        "shell_escape"
    } else if cap.intersects(Cap::URL_ENCODE) {
        "url_encode"
    } else if cap.intersects(Cap::FILE_IO) {
        "path_sanitization"
    } else if cap.intersects(Cap::SSRF) {
        "url_validation"
    } else if cap.intersects(Cap::CODE_EXEC) {
        "code_execution_sanitization"
    } else {
        "appropriate sanitization"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::StmtKind;
    use crate::ssa::ir::{BlockId, SsaValue};
    use petgraph::graph::NodeIndex;
    use smallvec::smallvec;

    /// Construct a minimal NodeInfo with the given labels and optional callee.
    fn make_node_info(
        labels: smallvec::SmallVec<[DataLabel; 2]>,
        callee: Option<String>,
    ) -> crate::cfg::NodeInfo {
        crate::cfg::NodeInfo {
            kind: StmtKind::Seq,
            call: crate::cfg::CallMeta {
                callee,
                ..Default::default()
            },
            taint: crate::cfg::TaintMeta {
                labels,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_sink_cap_extraction() {
        let mut cfg = Cfg::new();
        let n = cfg.add_node(make_node_info(
            smallvec![DataLabel::Sink(Cap::SQL_QUERY)],
            None,
        ));
        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: n,
            source: NodeIndex::new(0),
            path: vec![],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 0,
            uses_summary: false,
            flow_steps: vec![],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };
        assert_eq!(sink_cap(&finding, &cfg), Cap::SQL_QUERY);
    }

    #[test]
    fn test_sink_cap_multiple_labels() {
        let mut cfg = Cfg::new();
        let n = cfg.add_node(make_node_info(
            smallvec![
                DataLabel::Sink(Cap::SQL_QUERY),
                DataLabel::Source(Cap::ENV_VAR),
                DataLabel::Sink(Cap::FILE_IO),
            ],
            None,
        ));
        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: n,
            source: NodeIndex::new(0),
            path: vec![],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 0,
            uses_summary: false,
            flow_steps: vec![],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };
        let cap = sink_cap(&finding, &cfg);
        assert!(cap.contains(Cap::SQL_QUERY));
        assert!(cap.contains(Cap::FILE_IO));
        assert!(!cap.contains(Cap::ENV_VAR)); // Source, not Sink
    }

    #[test]
    fn test_witness_payload_per_cap() {
        assert_eq!(
            witness_payload(Cap::CODE_EXEC),
            "require('child_process').execSync('id')"
        );
        assert_eq!(witness_payload(Cap::SQL_QUERY), "' OR 1=1 --");
        assert_eq!(witness_payload(Cap::SHELL_ESCAPE), "$(id)");
        assert_eq!(witness_payload(Cap::FILE_IO), "../../etc/passwd");
        assert_eq!(
            witness_payload(Cap::SSRF),
            "http://169.254.169.254/metadata"
        );
        assert_eq!(
            witness_payload(Cap::DESERIALIZE),
            "malicious_serialized_object"
        );
        assert_eq!(witness_payload(Cap::DATA_EXFIL), "<SESSION_TOKEN>");
        assert_eq!(witness_payload(Cap::CRYPTO), "TAINTED"); // fallback
    }

    #[test]
    fn test_witness_payload_data_exfil_wins_over_action_caps() {
        // A `fetch` call's body slot can carry both DATA_EXFIL (the leak
        // class) and the underlying action cap (e.g. SSRF) when the same
        // sink is multi-gated.  The witness should reflect the *leaked*
        // value (a session token) rather than an injection payload, the
        // attacker is reading data, not writing it.
        let combined = Cap::DATA_EXFIL | Cap::SSRF;
        assert_eq!(witness_payload(combined), "<SESSION_TOKEN>");
    }

    #[test]
    fn test_witness_payload_code_exec_separate_from_xss() {
        // CODE_EXEC must return a code-execution payload, not an XSS one.
        let code_exec = witness_payload(Cap::CODE_EXEC);
        assert!(
            code_exec.contains("child_process"),
            "CODE_EXEC payload should be code-execution, got: {code_exec}"
        );
        assert!(
            !code_exec.contains("script"),
            "CODE_EXEC payload must not be an XSS payload"
        );

        // HTML_ESCAPE still gets the XSS payload.
        let xss = witness_payload(Cap::HTML_ESCAPE);
        assert!(
            xss.contains("script"),
            "HTML_ESCAPE payload should be XSS, got: {xss}"
        );
    }

    #[test]
    fn test_witness_payload_combined_caps_prefers_code_exec() {
        // When both CODE_EXEC and HTML_ESCAPE are present, CODE_EXEC wins.
        let combined = Cap::CODE_EXEC | Cap::HTML_ESCAPE;
        let payload = witness_payload(combined);
        assert_eq!(
            payload, "require('child_process').execSync('id')",
            "CODE_EXEC should take priority over HTML_ESCAPE"
        );
    }

    #[test]
    fn test_witness_payload_unrelated_caps_unchanged() {
        // Verify that unrelated caps are not affected by the CODE_EXEC split.
        assert_eq!(witness_payload(Cap::SQL_QUERY), "' OR 1=1 --");
        assert_eq!(witness_payload(Cap::SHELL_ESCAPE), "$(id)");
        assert_eq!(witness_payload(Cap::FILE_IO), "../../etc/passwd");
        assert_eq!(
            witness_payload(Cap::SSRF),
            "http://169.254.169.254/metadata"
        );
        assert_eq!(
            witness_payload(Cap::DESERIALIZE),
            "malicious_serialized_object"
        );

        // Combined caps that don't include CODE_EXEC or HTML_ESCAPE
        let sql_file = Cap::SQL_QUERY | Cap::FILE_IO;
        assert_eq!(
            witness_payload(sql_file),
            "' OR 1=1 --",
            "SQL_QUERY should take priority over FILE_IO"
        );
    }

    #[test]
    fn test_is_string_renderable() {
        assert!(is_string_renderable(&SymbolicValue::ConcreteStr(
            "hello".into()
        )));
        assert!(is_string_renderable(&SymbolicValue::Symbol(SsaValue(0))));
        assert!(is_string_renderable(&SymbolicValue::Concat(
            Box::new(SymbolicValue::ConcreteStr("a".into())),
            Box::new(SymbolicValue::Symbol(SsaValue(1))),
        )));
        // Not string-renderable
        assert!(!is_string_renderable(&SymbolicValue::Concrete(42)));
        assert!(!is_string_renderable(&SymbolicValue::BinOp(
            super::super::value::Op::Add,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
            Box::new(SymbolicValue::Concrete(5)),
        )));
        assert!(!is_string_renderable(&SymbolicValue::Call(
            "foo".into(),
            vec![],
        )));
        assert!(!is_string_renderable(&SymbolicValue::Unknown));
    }

    #[test]
    fn test_substitute_tainted_concat() {
        let expr = SymbolicValue::Concat(
            Box::new(SymbolicValue::ConcreteStr(
                "SELECT * FROM t WHERE id = ".into(),
            )),
            Box::new(SymbolicValue::Symbol(SsaValue(5))),
        );
        let mut tainted = HashSet::new();
        tainted.insert(SsaValue(5));

        let result = substitute_tainted(&expr, &tainted, "' OR 1=1 --");
        assert_eq!(
            evaluate_concrete(&result),
            "SELECT * FROM t WHERE id = ' OR 1=1 --"
        );
    }

    #[test]
    fn test_extract_witness_sqli() {
        use crate::taint::FlowStepRaw;

        let mut state = SymbolicState::new();
        let sink_val = SsaValue(10);
        let tainted_val = SsaValue(5);

        // Set up: "SELECT ... " ++ tainted_val
        state.set(
            sink_val,
            SymbolicValue::Concat(
                Box::new(SymbolicValue::ConcreteStr(
                    "SELECT * FROM t WHERE id = ".into(),
                )),
                Box::new(SymbolicValue::Symbol(tainted_val)),
            ),
        );
        state.mark_tainted(tainted_val);

        // Build a CFG with a Sink(SQL_QUERY) label
        let mut cfg = Cfg::new();
        let sink_node = cfg.add_node(make_node_info(
            smallvec![DataLabel::Sink(Cap::SQL_QUERY)],
            Some("query".into()),
        ));
        let source_node = cfg.add_node(make_node_info(smallvec![], None));

        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: [(sink_node, sink_val)].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: sink_node,
            source: source_node,
            path: vec![source_node, sink_node],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 1,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![
                FlowStepRaw {
                    cfg_node: source_node,
                    var_name: Some("userInput".into()),
                    op_kind: crate::evidence::FlowStepKind::Source,
                },
                FlowStepRaw {
                    cfg_node: sink_node,
                    var_name: Some("userInput".into()),
                    op_kind: crate::evidence::FlowStepKind::Sink,
                },
            ],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };

        let witness = extract_witness(&state, &finding, &ssa, &cfg);
        assert!(witness.is_some());
        let w = witness.unwrap();
        assert!(w.contains("' OR 1=1 --"), "witness: {}", w);
        assert!(w.contains("flows to"), "witness: {}", w);
        assert!(w.contains("query"), "witness: {}", w);
    }

    #[test]
    fn test_extract_witness_unknown_returns_none() {
        let state = SymbolicState::new();
        let sink_node = NodeIndex::new(10);
        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: [(sink_node, SsaValue(5))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };
        let cfg = Cfg::new();
        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: sink_node,
            source: NodeIndex::new(0),
            path: vec![],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 0,
            cap_specificity: 0,
            uses_summary: false,
            flow_steps: vec![],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };

        assert!(extract_witness(&state, &finding, &ssa, &cfg).is_none());
    }

    #[test]
    fn test_non_string_renderable_generic_witness() {
        use crate::taint::FlowStepRaw;

        let mut state = SymbolicState::new();
        let sink_val = SsaValue(10);
        let tainted_val = SsaValue(5);

        // BinOp(Add, tainted, 5), not string-renderable
        state.set(
            sink_val,
            SymbolicValue::BinOp(
                super::super::value::Op::Add,
                Box::new(SymbolicValue::Symbol(tainted_val)),
                Box::new(SymbolicValue::Concrete(5)),
            ),
        );
        state.mark_tainted(tainted_val);

        let mut cfg = Cfg::new();
        let sink_node = cfg.add_node(make_node_info(
            smallvec![DataLabel::Sink(Cap::SQL_QUERY)],
            Some("execute".into()),
        ));
        let source_node = cfg.add_node(make_node_info(smallvec![], None));

        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: [(sink_node, sink_val)].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: sink_node,
            source: source_node,
            path: vec![source_node, sink_node],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 1,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![FlowStepRaw {
                cfg_node: source_node,
                var_name: Some("count".into()),
                op_kind: crate::evidence::FlowStepKind::Source,
            }],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };

        let witness = extract_witness(&state, &finding, &ssa, &cfg);
        assert!(witness.is_some());
        let w = witness.unwrap();
        assert!(w.contains("reaches"), "witness: {}", w);
        assert!(w.contains("unsanitized"), "witness: {}", w);
        assert!(w.contains("execute"), "witness: {}", w);
        // Should NOT contain exploit payload for non-string expression
        assert!(!w.contains("' OR 1=1"), "witness: {}", w);
    }

    #[test]
    fn test_no_tainted_symbols() {
        use crate::taint::FlowStepRaw;

        let mut state = SymbolicState::new();
        let sink_val = SsaValue(10);
        // Fully concrete, no taint
        state.set(sink_val, SymbolicValue::ConcreteStr("SELECT 1".into()));

        let mut cfg = Cfg::new();
        let sink_node = cfg.add_node(make_node_info(
            smallvec![DataLabel::Sink(Cap::SQL_QUERY)],
            Some("query".into()),
        ));
        let source_node = cfg.add_node(make_node_info(smallvec![], None));

        let ssa = SsaBody {
            blocks: vec![],
            entry: BlockId(0),
            value_defs: vec![],
            cfg_node_map: [(sink_node, sink_val)].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let finding = Finding {
            body_id: crate::cfg::BodyId(0),
            sink: sink_node,
            source: source_node,
            path: vec![source_node, sink_node],
            source_kind: crate::labels::SourceKind::UserInput,
            path_validated: false,
            guard_kind: None,
            hop_count: 1,
            cap_specificity: 1,
            uses_summary: false,
            flow_steps: vec![FlowStepRaw {
                cfg_node: source_node,
                var_name: Some("x".into()),
                op_kind: crate::evidence::FlowStepKind::Source,
            }],
            symbolic: None,
            source_span: None,
            primary_location: None,
            engine_notes: smallvec::SmallVec::new(),
            path_hash: 0,
            finding_id: String::new(),
            alternative_finding_ids: smallvec::SmallVec::new(),
            effective_sink_caps: crate::labels::Cap::empty(),
        };

        let witness = extract_witness(&state, &finding, &ssa, &cfg);
        assert!(witness.is_some());
        let w = witness.unwrap();
        assert!(w.contains("flows to"), "witness: {}", w);
        assert!(w.contains("SELECT 1"), "witness: {}", w);
    }

    // ── String operation witness tests ──────────────────────

    #[test]
    fn test_string_ops_are_string_renderable() {
        // Trim, ToLower, ToUpper, Replace on string-renderable inner → renderable
        assert!(is_string_renderable(&SymbolicValue::Trim(Box::new(
            SymbolicValue::Symbol(SsaValue(0))
        ))));
        assert!(is_string_renderable(&SymbolicValue::ToLower(Box::new(
            SymbolicValue::Symbol(SsaValue(0))
        ))));
        assert!(is_string_renderable(&SymbolicValue::ToUpper(Box::new(
            SymbolicValue::Symbol(SsaValue(0))
        ))));
        assert!(is_string_renderable(&SymbolicValue::Replace(
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
            "<".into(),
            "&lt;".into(),
        )));
        assert!(is_string_renderable(&SymbolicValue::Substr(
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
            Box::new(SymbolicValue::Concrete(0)),
            Some(Box::new(SymbolicValue::Concrete(5))),
        )));
        // StrLen returns int, NOT string-renderable
        assert!(!is_string_renderable(&SymbolicValue::StrLen(Box::new(
            SymbolicValue::Symbol(SsaValue(0))
        ))));
    }

    #[test]
    fn test_evaluate_concrete_string_ops() {
        // Trim
        let v = SymbolicValue::Trim(Box::new(SymbolicValue::ConcreteStr("  hi  ".into())));
        assert_eq!(evaluate_concrete(&v), "hi");

        // ToLower
        let v = SymbolicValue::ToLower(Box::new(SymbolicValue::ConcreteStr("ABC".into())));
        assert_eq!(evaluate_concrete(&v), "abc");

        // Replace
        let v = SymbolicValue::Replace(
            Box::new(SymbolicValue::ConcreteStr("a<b".into())),
            "<".into(),
            "&lt;".into(),
        );
        assert_eq!(evaluate_concrete(&v), "a&lt;b");
    }

    #[test]
    fn test_substitute_tainted_through_string_ops() {
        let tainted_val = SsaValue(5);
        let mut tainted = HashSet::new();
        tainted.insert(tainted_val);

        // Concat("prefix", Trim(Symbol(5)))
        let expr = SymbolicValue::Concat(
            Box::new(SymbolicValue::ConcreteStr("prefix".into())),
            Box::new(SymbolicValue::Trim(Box::new(SymbolicValue::Symbol(
                tainted_val,
            )))),
        );

        let result = substitute_tainted(&expr, &tainted, "PAYLOAD");
        // After substitution: Concat("prefix", Trim(ConcreteStr("PAYLOAD")))
        // evaluate_concrete should fold: "prefix" + "PAYLOAD".trim() = "prefixPAYLOAD"
        assert_eq!(evaluate_concrete(&result), "prefixPAYLOAD");
    }

    #[test]
    fn test_collect_tainted_through_string_ops() {
        let tainted_val = SsaValue(5);
        let mut state = SymbolicState::new();
        state.mark_tainted(tainted_val);

        let expr = SymbolicValue::ToLower(Box::new(SymbolicValue::Symbol(tainted_val)));
        let tainted = collect_tainted_symbols(&expr, &state);
        assert!(tainted.contains(&tainted_val));
    }

    // ── Encoding/decoding witness tests ────────────────────────

    #[test]
    fn test_encoding_is_string_renderable() {
        use super::super::strings::TransformKind;
        let v = SymbolicValue::Encode(
            TransformKind::HtmlEscape,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
        );
        assert!(is_string_renderable(&v));

        let v = SymbolicValue::Decode(
            TransformKind::UrlDecode,
            Box::new(SymbolicValue::Symbol(SsaValue(1))),
        );
        assert!(is_string_renderable(&v));
    }

    #[test]
    fn test_substitute_tainted_through_encode() {
        use super::super::strings::TransformKind;
        let tainted_val = SsaValue(10);
        let mut tainted = HashSet::new();
        tainted.insert(tainted_val);

        let expr = SymbolicValue::Encode(
            TransformKind::HtmlEscape,
            Box::new(SymbolicValue::Symbol(tainted_val)),
        );
        let result = substitute_tainted(&expr, &tainted, "<script>");
        // Should preserve Encode structure wrapping the substituted payload
        match &result {
            SymbolicValue::Encode(kind, inner) => {
                assert_eq!(*kind, TransformKind::HtmlEscape);
                assert_eq!(**inner, SymbolicValue::ConcreteStr("<script>".into()));
            }
            other => panic!("expected Encode, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_concrete_encode() {
        use super::super::strings::TransformKind;
        let v = SymbolicValue::Encode(
            TransformKind::HtmlEscape,
            Box::new(SymbolicValue::ConcreteStr("<b>hi</b>".into())),
        );
        assert_eq!(evaluate_concrete(&v), "&lt;b&gt;hi&lt;/b&gt;");
    }

    #[test]
    fn test_evaluate_concrete_decode() {
        use super::super::strings::TransformKind;
        let v = SymbolicValue::Decode(
            TransformKind::UrlDecode,
            Box::new(SymbolicValue::ConcreteStr("hello%20world".into())),
        );
        assert_eq!(evaluate_concrete(&v), "hello world");
    }

    #[test]
    fn test_collect_tainted_through_encode() {
        use super::super::strings::TransformKind;
        let tainted_val = SsaValue(20);
        let mut state = SymbolicState::new();
        state.mark_tainted(tainted_val);

        let expr = SymbolicValue::Encode(
            TransformKind::UrlEncode,
            Box::new(SymbolicValue::Symbol(tainted_val)),
        );
        let tainted = collect_tainted_symbols(&expr, &state);
        assert!(tainted.contains(&tainted_val));
    }

    #[test]
    fn test_detect_mismatch_url_at_sql_sink() {
        use super::super::strings::TransformKind;
        let expr = SymbolicValue::Encode(
            TransformKind::UrlEncode,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
        );
        let result = detect_transform_mismatch(&expr, Cap::SQL_QUERY);
        assert!(result.is_some());
        let note = result.unwrap();
        assert!(note.contains("urlEncode"));
        assert!(note.contains("does not match sink neutralization class"));
        assert!(note.contains("sql_escape"));
    }

    #[test]
    fn test_no_mismatch_when_encoding_matches_sink() {
        use super::super::strings::TransformKind;
        let expr = SymbolicValue::Encode(
            TransformKind::HtmlEscape,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
        );
        // HTML escape at HTML_ESCAPE sink, correct match
        assert!(detect_transform_mismatch(&expr, Cap::HTML_ESCAPE).is_none());
    }

    #[test]
    fn test_no_mismatch_for_representation_transform() {
        use super::super::strings::TransformKind;
        let expr = SymbolicValue::Encode(
            TransformKind::Base64Encode,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
        );
        // Base64 is a representation transform with empty verified_cap
        // → never triggers mismatch, regardless of sink cap
        assert!(detect_transform_mismatch(&expr, Cap::SQL_QUERY).is_none());
    }

    #[test]
    fn test_no_mismatch_for_sql_escape() {
        use super::super::strings::TransformKind;
        let expr = SymbolicValue::Encode(
            TransformKind::SqlEscape,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
        );
        // SqlEscape has empty verified_cap → no mismatch reasoning
        assert!(detect_transform_mismatch(&expr, Cap::SQL_QUERY).is_none());
    }

    #[test]
    fn test_mismatch_through_concat() {
        use super::super::strings::TransformKind;
        let encoded = SymbolicValue::Encode(
            TransformKind::ShellEscape,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
        );
        let expr = SymbolicValue::Concat(
            Box::new(SymbolicValue::ConcreteStr("prefix".into())),
            Box::new(encoded),
        );
        // ShellEscape at SQL sink, mismatch
        let result = detect_transform_mismatch(&expr, Cap::SQL_QUERY);
        assert!(result.is_some());
        assert!(result.unwrap().contains("shellEscape"));
    }

    #[test]
    fn test_no_mismatch_empty_sink_cap() {
        use super::super::strings::TransformKind;
        let expr = SymbolicValue::Encode(
            TransformKind::UrlEncode,
            Box::new(SymbolicValue::Symbol(SsaValue(0))),
        );
        // Empty sink cap → no mismatch possible
        assert!(detect_transform_mismatch(&expr, Cap::empty()).is_none());
    }
}
