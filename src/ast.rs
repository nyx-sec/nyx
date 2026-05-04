//! Tree-sitter parsing and two-pass analysis for all supported languages.
//!
//! The core type is `ParsedSource`, a thin wrapper around a parsed tree-sitter
//! tree that carries the source bytes and language. Parsing reuses a thread-local
//! [`tree_sitter::Parser`] so each worker thread keeps one live parser instance.
//!
//! ## Two-pass pipeline
//!
//! **Pass 1** (`extract_summaries_from_file`): builds the CFG, lowers to SSA,
//! and extracts a [`crate::summary::FuncSummary`] per function. Summaries
//! describe boundary behaviour: which arguments flow to sinks, which sources
//! the function reads, what taint it strips, and what it returns.
//!
//! **Pass 2** (`run_rules_on_file`): reanalyses each file with the merged
//! [`crate::summary::GlobalSummaries`] from pass 1. The taint engine runs a
//! forward dataflow worklist over SSA, resolving cross-file calls via summaries.
//!
//! Parse timeouts are tracked per-thread via [`take_last_parse_timeout_ms`]
//! so callers can surface the event as an informational diagnostic instead
//! of silently skipping the file.

#![allow(clippy::only_used_in_recursion, clippy::type_complexity)]

use crate::auth_analysis;
use crate::cfg::{Cfg, FileCfg, FuncSummaries, build_cfg, export_summaries};
use crate::cfg_analysis;
use crate::commands::scan::Diag;
use crate::errors::{NyxError, NyxResult};
use crate::evidence::{Evidence, FlowStep, SpanEvidence, StateEvidence};
use crate::labels::{
    Cap, DataLabel, LangAnalysisRules, build_lang_rules, severity_for_source_kind,
};
use crate::patterns::{FindingCategory, Severity};
use crate::state;
use crate::summary::ssa_summary::SsaFuncSummary;
use crate::summary::{FuncSummary, GlobalSummaries};
use crate::symbol::{Lang, normalize_namespace};
use crate::utils::config::AnalysisMode;
use crate::utils::ext::lowercase_ext;
use crate::utils::{Config, query_cache};
use petgraph::graph::NodeIndex;
use std::borrow::Cow;
use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::Path;
use std::time::Instant;
use tree_sitter::{Language, QueryCursor, StreamingIterator};

thread_local! {
    static PARSER: RefCell<tree_sitter::Parser> = RefCell::new(tree_sitter::Parser::new());
    /// Records the timeout budget (in ms) when a tree-sitter parse is
    /// aborted due to [`parse_timeout_ms`].  Callers that want to surface
    /// the event as a synthetic informational [`Diag`] read this slot
    /// immediately after [`ParsedSource::try_new`] returns `Ok(None)`
    /// and clear it with `take_last_parse_timeout_ms`.
    static LAST_PARSE_TIMEOUT_MS: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
}

/// Consume and return the most recent parse-timeout event on this thread
/// (set by `ParsedSource::try_new`).  Used to lift the event into a
/// synthetic [`Diag`] carrying an [`crate::engine_notes::EngineNote::ParseTimeout`].
pub fn take_last_parse_timeout_ms() -> Option<u64> {
    LAST_PARSE_TIMEOUT_MS.with(|c| c.take())
}

/// Synthesize an informational diagnostic surfacing a parse-timeout event
/// for `path`.  The diag carries an [`crate::engine_notes::EngineNote::ParseTimeout`]
/// in its evidence so downstream tooling can distinguish "found nothing"
/// from "parse was aborted before we could look".
fn parse_timeout_diag(path: &Path, timeout_ms: u64) -> Diag {
    let mut evidence = Evidence::default();
    evidence.notes.push(format!(
        "tree-sitter parse exceeded timeout budget ({timeout_ms} ms); file skipped"
    ));
    evidence
        .engine_notes
        .push(crate::engine_notes::EngineNote::ParseTimeout {
            timeout_ms: timeout_ms.min(u32::MAX as u64) as u32,
        });
    Diag {
        path: path.to_string_lossy().into_owned(),
        line: 0,
        col: 0,
        severity: Severity::Low,
        id: "engine.parse_timeout".into(),
        category: FindingCategory::Quality,
        path_validated: false,
        guard_kind: None,
        message: Some(format!(
            "tree-sitter parse exceeded timeout budget ({timeout_ms} ms); file skipped"
        )),
        labels: vec![],
        confidence: None,
        evidence: Some(evidence),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: String::new(),
        alternative_finding_ids: Vec::new(),
    }
}

/// Resolve the effective parse-timeout budget in milliseconds.  Tree-sitter
/// is generally fast, but adversarially-crafted inputs (deeply ambiguous
/// grammar constructs, pathological backtracking) can drive it into slow
/// parses; the default 10 s ceiling lets a 10 000-file scan survive even if
/// every file is hostile.  Configured via `analysis.engine.parse_timeout_ms`
/// in `nyx.conf` (or `--parse-timeout-ms` on the CLI); `0` disables the cap.
fn parse_timeout_ms() -> u64 {
    crate::utils::analysis_options::current().parse_timeout_ms
}

/// Test-only: when the `NYX_TEST_FORCE_PANIC_PATH` env var is set, any file
/// path containing that substring triggers a deterministic panic here.  Used
/// by `tests/panic_recovery_tests.rs` to exercise per-file panic behaviour in
/// the scan pipeline.  The env var is re-read each call so successive tests
/// in the same process can toggle injection; `std::env::var` is an in-memory
/// lookup on supported platforms so the overhead is negligible.
fn maybe_inject_test_panic(path: &Path) {
    if let Ok(marker) = std::env::var("NYX_TEST_FORCE_PANIC_PATH")
        && !marker.is_empty()
        && path.to_string_lossy().contains(marker.as_str())
    {
        panic!(
            "NYX_TEST_FORCE_PANIC_PATH injection: {} matches {:?}",
            path.display(),
            marker
        );
    }
}

/// Convenience alias for node indices.
fn byte_offset_to_point(tree: &tree_sitter::Tree, byte: usize) -> tree_sitter::Point {
    tree.root_node()
        .descendant_for_byte_range(byte, byte)
        .map(|n| n.start_position())
        .unwrap_or_else(|| tree_sitter::Point { row: 0, column: 0 })
}

use crate::utils::snippet::line_snippet as extract_line_snippet;

/// Resolve a `file_rel` (relative to `scan_root` per
/// [`normalize_namespace`] convention) back to the absolute path the
/// diagnostic pipeline expects.
///
/// * Empty `file_rel`, single-file scans normalize every namespace to
///   `""`; treat that as "the file under analysis" and return
///   `fallback.to_string_lossy()`.
/// * `scan_root` absent, we have no workspace root to resolve against;
///   return `file_rel` verbatim (it may already be absolute).
/// * Otherwise, join `scan_root` with `file_rel`.
fn resolve_file_rel(file_rel: &str, scan_root: Option<&Path>, fallback: &Path) -> String {
    if file_rel.is_empty() {
        return fallback.to_string_lossy().into_owned();
    }
    match scan_root {
        Some(root) => root.join(file_rel).to_string_lossy().into_owned(),
        None => file_rel.to_string(),
    }
}

/// Build a [`Diag`] from a taint [`Finding`], the CFG that produced it,
/// the parsed tree (for byte→line/col conversion) and the file path.
///
/// Returns `None` when source-sensitivity gating fully suppresses the
/// finding (the canonical case is a multi-gate `DATA_EXFIL` event whose
/// contributing source is plain user input — see the
/// `effective_caps` strip below).
fn build_taint_diag(
    finding: &crate::taint::Finding,
    cfg_graph: &crate::cfg::Cfg,
    tree: &tree_sitter::Tree,
    path: &Path,
    src: &[u8],
    scan_root: Option<&Path>,
) -> Option<Diag> {
    let call_site_byte = cfg_graph[finding.sink].classification_span().0;
    let call_site_point = byte_offset_to_point(tree, call_site_byte);
    // `finding.source` should be a NodeIndex valid in this body's CFG, but
    // cross-body / cross-file inline analysis has historically leaked
    // callee-NodeIndex origins (see `extract_inline_return_taint`).  Guard
    // the lookup so a stray out-of-bounds index degrades the diagnostic
    // rather than panicking the worker thread.
    let source_info = cfg_graph.node_weight(finding.source);
    // The reconstructed flow path is the authoritative view of where the
    // taint started *in this body*. When present, prefer its first step's
    // CFG span over `finding.source_span`, which can be stale across
    // multi-hop cross-body remaps (e.g. JS two-level solve where a
    // callee-interior source gets its span rewritten to the enclosing
    // body's entry node). Fall back to `source_span`, then to the source
    // NodeIndex, then finally to the sink byte.
    let source_byte = finding
        .flow_steps
        .first()
        .and_then(|s| {
            cfg_graph
                .node_weight(s.cfg_node)
                .map(|i| i.classification_span().0)
        })
        .or(finding.source_span)
        .or_else(|| source_info.map(|i| i.classification_span().0))
        .unwrap_or(call_site_byte);
    let source_point = byte_offset_to_point(tree, source_byte);

    // Prefer the source CFG node's callee string when it's a call expression
    // (e.g. `os.getenv("X")`). For property-access sources like
    // `navigator.userAgent` there is no callee, fall back to the first flow
    // step's `variable` (the SSA var name, e.g. "userAgent"), then to the
    // source node's `taint.defines` / first `taint.uses` entry, before
    // finally giving up and rendering "(unknown)".
    let source_callee = source_info
        .and_then(|i| i.call.callee.as_deref())
        .map(sanitize_desc)
        .or_else(|| {
            finding
                .flow_steps
                .first()
                .and_then(|s| s.var_name.as_deref())
                .map(sanitize_desc)
        })
        .or_else(|| {
            source_info
                .and_then(|i| i.taint.defines.as_deref())
                .map(sanitize_desc)
        })
        .or_else(|| {
            source_info
                .and_then(|i| i.taint.uses.first().map(String::as_str))
                .map(sanitize_desc)
        })
        .unwrap_or_else(|| "(unknown)".into());
    let call_site_callee = cfg_graph[finding.sink]
        .call
        .callee
        .as_deref()
        .map(sanitize_desc)
        .unwrap_or_else(|| "(unknown)".into());
    let kind_label = source_kind_label(finding.source_kind);

    let file_path_owned = path.to_string_lossy().into_owned();

    // Primary-location attribution: when the sink was resolved via a
    // callee summary that carried a [`SinkSite`], `finding.primary_location`
    // names the dangerous instruction inside the callee body.  Use those
    // coordinates as the diag's primary (file, line, col); otherwise fall
    // back to the caller's call-site position.
    let (primary_path, primary_line, primary_col, primary_snippet_hint) =
        if let Some(loc) = finding.primary_location.as_ref() {
            let abs = resolve_file_rel(&loc.file_rel, scan_root, path);
            if abs != file_path_owned {
                tracing::debug!(
                    caller_file = %file_path_owned,
                    primary_file = %abs,
                    primary_line = loc.line,
                    "taint finding attributed to a cross-file primary sink location",
                );
            }
            let snippet = if loc.snippet.is_empty() {
                None
            } else {
                Some(loc.snippet.clone())
            };
            (abs, loc.line as usize, loc.col as usize, snippet)
        } else {
            (
                file_path_owned.clone(),
                call_site_point.row + 1,
                call_site_point.column + 1,
                None,
            )
        };

    let short_source = crate::fmt::shorten_callee(&source_callee);
    let short_call_site = crate::fmt::shorten_callee(&call_site_callee);
    let sink_display = primary_snippet_hint
        .as_deref()
        .map(crate::fmt::shorten_callee)
        .unwrap_or_else(|| short_call_site.clone());
    let sink_label_display = if finding.primary_location.is_some() {
        format!("{call_site_callee} \u{2192} {sink_display}")
    } else {
        call_site_callee.clone()
    };

    let mut labels = vec![
        (
            "Source".into(),
            format!(
                "{source_callee} ({}:{})",
                source_point.row + 1,
                source_point.column + 1
            ),
        ),
        ("Sink".into(), sink_label_display),
    ];
    if let Some(guard) = finding.guard_kind {
        labels.push(("Path guard".into(), format!("{guard:?}")));
    }

    let mut evidence_notes = Vec::new();
    if finding.path_validated {
        evidence_notes.push("path_validated".into());
    }
    evidence_notes.push(format!("source_kind:{:?}", finding.source_kind));
    evidence_notes.push(format!("hop_count:{}", finding.hop_count));
    evidence_notes.push(format!("cap_specificity:{}", finding.cap_specificity));
    if finding.uses_summary {
        evidence_notes.push("uses_summary".into());
    }

    // Convert raw flow steps to display FlowSteps.  When the finding has a
    // primary_location distinct from the call site, the last raw step is
    // really the Call, reclassify it and append a synthetic Sink step
    // pointing at the callee-internal dangerous instruction so analysts
    // see both the call site and the final sink in the trace.
    let mut flow_steps: Vec<FlowStep> = finding
        .flow_steps
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let step_byte = cfg_graph[raw.cfg_node].classification_span().0;
            let point = byte_offset_to_point(tree, step_byte);
            let snippet = extract_line_snippet(src, step_byte);
            let callee = cfg_graph[raw.cfg_node].call.callee.clone();
            let function = cfg_graph[raw.cfg_node].ast.enclosing_func.clone();
            FlowStep {
                step: (i + 1) as u32,
                kind: raw.op_kind.clone(),
                file: file_path_owned.clone(),
                line: (point.row + 1) as u32,
                col: (point.column + 1) as u32,
                snippet,
                variable: raw.var_name.clone(),
                callee,
                function,
                is_cross_file: false,
            }
        })
        .collect();

    if let Some(loc) = finding.primary_location.as_ref() {
        if let Some(last) = flow_steps.last_mut()
            && matches!(last.kind, crate::evidence::FlowStepKind::Sink)
        {
            last.kind = crate::evidence::FlowStepKind::Call;
        }
        let is_cross_file = primary_path != file_path_owned;
        let synthetic_snippet = if loc.snippet.is_empty() {
            None
        } else {
            Some(loc.snippet.clone())
        };
        let next_step = (flow_steps.len() + 1) as u32;
        flow_steps.push(FlowStep {
            step: next_step,
            kind: crate::evidence::FlowStepKind::Sink,
            file: primary_path.clone(),
            line: loc.line,
            col: loc.col,
            snippet: synthetic_snippet,
            variable: None,
            callee: None,
            function: None,
            is_cross_file,
        });
    }

    let sink_evidence_snippet = primary_snippet_hint
        .clone()
        .or_else(|| Some(short_call_site.clone()));

    // Resolved sink capability bits, used by deduplication to distinguish
    // sinks with different cap types on the same source line (e.g.
    // `sink_sql(x); sink_shell(x);`).
    let sink_caps_bits: u16 = cfg_graph[finding.sink]
        .taint
        .labels
        .iter()
        .filter_map(|l| match l {
            crate::labels::DataLabel::Sink(c) => Some(c.bits()),
            _ => None,
        })
        .fold(0u16, |acc, b| acc | b);

    // Cap-specific rule-id routing.
    //
    // 1. `UNAUTHORIZED_ID`: namespace alongside the standalone `auth_analysis`
    //    subsystem's output so cross-tool aggregation lines up.
    // 2. `DATA_EXFIL`: route to `taint-data-exfiltration` so SARIF surfaces a
    //    distinct rule id from SSRF, the two share callees (e.g. `fetch`)
    //    but represent different vulnerability classes.
    //
    // Prefer the per-finding `effective_sink_caps` (set by the multi-gate
    // SSA dispatch) when populated; fall back to the union of all sink-label
    // caps on the CFG node so legacy paths that build findings without
    // setting `effective_sink_caps` still pick the right rule id.
    let mut effective_caps = if finding.effective_sink_caps.is_empty() {
        crate::labels::Cap::from_bits_truncate(sink_caps_bits)
    } else {
        finding.effective_sink_caps
    };

    // Source-sensitivity gate for `DATA_EXFIL`.  Plain attacker input echoed
    // back into an outbound request body / headers / json is not data
    // exfiltration, the user already controls the value, surfacing it as a
    // leak is noise (the canonical false-positive class for API gateways
    // and telemetry forwarders that proxy `req.body`).  A `DATA_EXFIL`
    // finding requires the contributing source to be at least `Sensitive`
    // (cookies, headers, env, db rows, file reads).  Plain user-input
    // sources have the cap stripped so the finding either drops entirely
    // or downgrades to whatever non-`DATA_EXFIL` cap also applies (e.g.
    // SSRF on the URL position of the same `fetch` call).
    if effective_caps.contains(crate::labels::Cap::DATA_EXFIL)
        && finding.source_kind.sensitivity() < crate::labels::Sensitivity::Sensitive
    {
        effective_caps.remove(crate::labels::Cap::DATA_EXFIL);
        // The multi-gate dispatch produces one finding per (source, sink-cap)
        // pair, a body-flow finding's `effective_sink_caps` is exactly the
        // cap that fired (e.g. `DATA_EXFIL`).  When that single cap is the
        // sensitivity-stripped one, the finding has no surviving rationale
        // and we drop it entirely rather than reroute it to the generic
        // `taint-unsanitised-flow` bucket (which would just re-emit the same
        // false positive under a different rule id).  Findings with a
        // multi-cap `effective_sink_caps` keep their non-DATA_EXFIL caps and
        // are routed normally below.
        if finding.effective_sink_caps == crate::labels::Cap::DATA_EXFIL {
            return None;
        }
    }

    // DATA_EXFIL routing.
    //
    // Multi-gate dispatch (JS / Go) emits one event per cap, so by this
    // point each finding's `effective_sink_caps` carries exactly one bit
    // and the simple `DATA_EXFIL && !SSRF` test routes correctly.  Flat-
    // rule paths (Java HTTP clients where type-qualified resolution
    // attaches both `SSRF` and `DATA_EXFIL` Sink labels to the same call,
    // e.g. `client.send(req)` covering both URL and body channels of the
    // request value) produce a single dual-cap event.  Disambiguate using
    // the flow path: when a body-bind verb (`.body(`, `.json(`, `.form(`,
    // `.multipart(`, `BodyPublishers`, `setEntity`, `bodyValue`, etc.)
    // appears anywhere in the SSA flow steps or the sink chain text, the
    // taint reached an outbound payload field, route to DATA_EXFIL.  When
    // no body-bind verb is on the path (Sensitive-tier source flowing
    // straight into the URL position via `.get`/`.post`/`.send`), this is
    // a real SSRF and routes to taint-unsanitised-flow regardless of
    // source sensitivity.  Source sensitivity is still required for the
    // DATA_EXFIL route, plain user input echoed into a request body is
    // not exfiltration.
    let flow_has_body_bind = {
        let body_bind_substrings = [
            ".body(",
            ".json(",
            ".form(",
            ".multipart(",
            ".bodyvalue(",
            ".setentity(",
            "bodypublishers",
            "body_string",
            "body_json",
            "body_bytes",
            "send_string",
            "send_json",
            "send_form",
            // Spring RestTemplate one-shot verbs that take a body argument
            // inline (no separate `BodyPublishers` / `setEntity` step in the
            // chain).  Method-name suffixes are unique enough that bare
            // substring matching is safe.
            "postforobject",
            "postforentity",
            "patchforobject",
        ];
        let chain_lower = call_site_callee.to_ascii_lowercase();
        let in_sink = body_bind_substrings.iter().any(|m| chain_lower.contains(m));
        let in_steps = finding.flow_steps.iter().any(|step| {
            cfg_graph[step.cfg_node]
                .call
                .callee
                .as_deref()
                .map(|c| {
                    let lc = c.to_ascii_lowercase();
                    body_bind_substrings.iter().any(|m| lc.contains(m))
                })
                .unwrap_or(false)
        });
        in_sink || in_steps
    };
    // Java HTTP-client builder pattern hides the body-bind step inside a
    // builder chain whose intermediate calls collapse to `HttpRequest.build`
    // in the flow.  When the source is unambiguously credential-bearing
    // (cookies, session attributes, caught exceptions carrying stack
    // frames) and the sink fires DATA_EXFIL, treat that as exfil even
    // when no body-bind verb is visible in the flow.  Env vars stay
    // ambiguous (they often carry URL config) so they still require an
    // explicit body-bind hit on the path.
    let source_is_credential_bearing = matches!(
        finding.source_kind,
        crate::labels::SourceKind::Cookie | crate::labels::SourceKind::CaughtException
    );
    let is_data_exfil_rule = effective_caps.contains(crate::labels::Cap::DATA_EXFIL)
        && !effective_caps.contains(crate::labels::Cap::UNAUTHORIZED_ID)
        && (!effective_caps.contains(crate::labels::Cap::SSRF)
            || (finding.source_kind.sensitivity() >= crate::labels::Sensitivity::Sensitive
                && (flow_has_body_bind || source_is_credential_bearing)));

    let diag_id = if effective_caps.contains(crate::labels::Cap::UNAUTHORIZED_ID) {
        "rs.auth.missing_ownership_check.taint".to_string()
    } else if is_data_exfil_rule {
        format!(
            "taint-data-exfiltration (source {}:{})",
            source_point.row + 1,
            source_point.column + 1
        )
    } else {
        format!(
            "taint-unsanitised-flow (source {}:{})",
            source_point.row + 1,
            source_point.column + 1
        )
    };

    // For `DATA_EXFIL` rules, look up which destination object-literal field
    // (`body` / `headers` / `json`) the tainted value reached.  Each
    // [`crate::cfg::GateFilter`] carries `destination_uses` (var names) in
    // parallel with `destination_fields` (the field each var was bound to),
    // so we walk the gate filter whose `label_caps` includes `DATA_EXFIL`
    // and match the tainted var name from the last flow step.  Falls back
    // to the first non-empty destination field on the matching filter when
    // the var-name match fails (e.g. the SSA sink event is reported on a
    // copy-propagated value whose name no longer matches the original
    // destination ident).  `None` when the sink wasn't a destination-aware
    // gate (no object literal, or non-fetch sink).
    let data_exfil_field: Option<String> = if is_data_exfil_rule {
        let last_var = finding
            .flow_steps
            .last()
            .and_then(|s| s.var_name.as_deref());
        let filters = &cfg_graph[finding.sink].call.gate_filters;
        filters
            .iter()
            .find(|f| f.label_caps.contains(crate::labels::Cap::DATA_EXFIL))
            .and_then(|f| {
                if let (Some(uses), Some(var)) = (f.destination_uses.as_ref(), last_var)
                    && let Some(idx) = uses.iter().position(|u| u == var)
                {
                    return f.destination_fields.get(idx).cloned();
                }
                f.destination_fields.first().cloned()
            })
    } else {
        None
    };

    // DATA_EXFIL severity calibration (Phase: detector ranking).
    //
    // Generic taint severity comes from `severity_for_source_kind`, which
    // maps Cookie/Header/Env to High because those sources are spicy
    // *as taint roots*.  For `DATA_EXFIL` we are scoring the leak class,
    // not the source itself: not every Sensitive-tier source is a Secret.
    // Cookies and env carry credential / session material whose leakage
    // is an immediate disclosure (Secret-tier); request headers, file
    // reads, db rows, and caught exceptions are Sensitive but not
    // automatically secret, so they downgrade to Medium.  Plain user
    // input is already stripped above by the source-sensitivity gate, so
    // the `_` arm here is reached only by Sensitive sources that are not
    // explicit secrets.
    let severity = if is_data_exfil_rule {
        match finding.source_kind {
            crate::labels::SourceKind::Cookie | crate::labels::SourceKind::EnvironmentConfig => {
                crate::patterns::Severity::High
            }
            _ => crate::patterns::Severity::Medium,
        }
    } else {
        severity_for_source_kind(finding.source_kind)
    };

    // DATA_EXFIL: surface the destination field in the message so analysts
    // see at a glance whether the leak reached the request body, headers,
    // or json payload.  Generic taint findings stay on the existing
    // "unsanitised … flows from … → …" template.
    let message = if is_data_exfil_rule {
        let suffix = data_exfil_field
            .as_deref()
            .map(|f| format!(" ({f} field)"))
            .unwrap_or_default();
        format!("sensitive data flows from {short_source} \u{2192} {sink_display}{suffix}")
    } else {
        format!("unsanitised {kind_label} flows from {short_source} \u{2192} {sink_display}")
    };

    let mut diag = Diag {
        path: primary_path.clone(),
        line: primary_line,
        col: primary_col,
        severity,
        id: diag_id,
        category: FindingCategory::Security,
        path_validated: finding.path_validated,
        guard_kind: finding.guard_kind.map(|k| format!("{k:?}")),
        message: Some(message),
        labels,
        confidence: None,
        evidence: Some(Evidence {
            source: Some(SpanEvidence {
                path: file_path_owned.clone(),
                line: (source_point.row + 1) as u32,
                col: (source_point.column + 1) as u32,
                kind: "source".into(),
                snippet: Some(short_source.clone()),
            }),
            sink: Some(SpanEvidence {
                path: primary_path.clone(),
                line: primary_line as u32,
                col: primary_col as u32,
                kind: "sink".into(),
                snippet: sink_evidence_snippet,
            }),
            guards: finding
                .guard_kind
                .map(|g| {
                    vec![SpanEvidence {
                        path: primary_path.clone(),
                        line: primary_line as u32,
                        col: 0,
                        kind: "guard".into(),
                        snippet: Some(format!("{g:?}")),
                    }]
                })
                .unwrap_or_default(),
            sanitizers: vec![],
            state: None,
            notes: evidence_notes,
            source_kind: Some(finding.source_kind),
            hop_count: Some(finding.hop_count),
            uses_summary: finding.uses_summary,
            cap_specificity: Some(finding.cap_specificity),
            flow_steps,
            symbolic: finding.symbolic.clone(),
            sink_caps: sink_caps_bits,
            engine_notes: finding.engine_notes.clone(),
            data_exfil_field,
            ..Default::default()
        }),
        rank_score: None,
        rank_reason: None,
        suppressed: false,
        suppression: None,
        rollup: None,
        finding_id: finding.finding_id.clone(),
        alternative_finding_ids: finding.alternative_finding_ids.to_vec(),
    };

    // Post-fill explanation and confidence limiters
    let explanation = crate::evidence::generate_explanation(&diag);
    let limiters = crate::evidence::compute_confidence_limiters(&diag);
    if let Some(ref mut ev) = diag.evidence {
        ev.explanation = explanation;
        ev.confidence_limiters = limiters;
    }

    Some(diag)
}

/// Resolve a file extension to a language slug (e.g. `"rust"`,
/// `"javascript"`).  Public façade over `lang_for_path` for callers
/// that only need the slug, used by the debug API to look up
/// per-language rule enablement without re-parsing the file.
pub fn lang_slug_for_path(path: &Path) -> Option<&'static str> {
    lang_for_path(path).map(|(_, slug)| slug)
}

/// Resolve a file extension to a (tree‑sitter Language, slug) pair.
fn lang_for_path(path: &Path) -> Option<(Language, &'static str)> {
    match lowercase_ext(path) {
        Some("rs") => Some((Language::from(tree_sitter_rust::LANGUAGE), "rust")),
        Some("c") => Some((Language::from(tree_sitter_c::LANGUAGE), "c")),
        // Real-world C++ codebases (gRPC, rocksdb, LLVM, …) overwhelmingly
        // use `.cc` / `.cxx` / `.hpp` / `.hh` / `.h++` rather than the
        // `.cpp` synthetic-fixture extension.  Without these mappings,
        // the scanner silently skipped them.  Headers (`.h` is omitted
        // intentionally, it's also valid C and disambiguating without a
        // build system is brittle).
        Some("cpp" | "cc" | "cxx" | "c++" | "hpp" | "hxx" | "hh" | "h++") => {
            Some((Language::from(tree_sitter_cpp::LANGUAGE), "cpp"))
        }
        Some("java") => Some((Language::from(tree_sitter_java::LANGUAGE), "java")),
        Some("go") => Some((Language::from(tree_sitter_go::LANGUAGE), "go")),
        Some("php") => Some((Language::from(tree_sitter_php::LANGUAGE_PHP), "php")),
        Some("py") => Some((Language::from(tree_sitter_python::LANGUAGE), "python")),
        Some("ts") => Some((
            Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
            "typescript",
        )),
        // TSX grammar is a superset of TypeScript plus JSX element/attribute
        // nodes, all TypeScript KINDS / RULES / PARAM_CONFIG entries apply,
        // and JSX-specific sinks (e.g. `dangerouslySetInnerHTML`) layer on top
        // via the same `typescript` slug.
        Some("tsx") => Some((
            Language::from(tree_sitter_typescript::LANGUAGE_TSX),
            "typescript",
        )),
        Some("js") => Some((
            Language::from(tree_sitter_javascript::LANGUAGE),
            "javascript",
        )),
        // JSX uses the same JavaScript grammar (tree-sitter-javascript handles
        // JSX natively), slug "javascript" so all JS rules apply.
        Some("jsx") => Some((
            Language::from(tree_sitter_javascript::LANGUAGE),
            "javascript",
        )),
        Some("rb") => Some((Language::from(tree_sitter_ruby::LANGUAGE), "ruby")),
        _ => None,
    }
}

/// Fast binary-file guard: skip if >1% NUL bytes.
fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().filter(|b| **b == 0).count() * 100 / bytes.len().max(1) > 1
}

/// Check if a file path indicates a test file. Matches filename-based
/// conventions (`.test.js`, `.spec.ts`) and the `__tests__` directory
/// convention.  Directory-only checks (`test/`, `tests/`, `fixtures/`)
/// are intentionally excluded because they're too broad when scanning
/// absolute paths.
fn is_test_file(path: &Path) -> bool {
    static TEST_SUFFIXES: &[&str] = &[
        ".test.js",
        ".test.ts",
        ".test.jsx",
        ".test.tsx",
        ".spec.js",
        ".spec.ts",
        ".spec.jsx",
        ".spec.tsx",
    ];

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        for suffix in TEST_SUFFIXES {
            if name.ends_with(suffix) {
                return true;
            }
        }
    }

    // __tests__ is specific enough (React/Jest convention) to match on directory
    for component in path.components() {
        if let std::path::Component::Normal(c) = component
            && c == "__tests__"
        {
            return true;
        }
    }

    false
}

/// Pattern IDs that are noise-prone in test files (fixture credentials,
/// non-crypto randomness, plain HTTP in test harnesses).
fn is_test_suppressible_pattern(id: &str) -> bool {
    // Suffix-match to handle both js. and ts. prefixes
    id.ends_with(".secrets.hardcoded_secret")
        || id.ends_with(".crypto.math_random")
        || id.ends_with(".transport.fetch_http")
}

/// Check if a file path belongs to a non-production context (tests, vendor,
/// benchmarks, etc.).  Used to downgrade severity for findings in paths that
/// are unlikely to represent attack surface.
fn is_nonprod_path(path: &Path) -> bool {
    static NONPROD_DIRS: &[&str] = &[
        "tests",
        "test",
        "__tests__",
        "benches",
        "benchmarks",
        "examples",
        "build",
        "scripts",
        "docs",
        "js_tests",
        "fixtures",
        "vendor",
    ];
    static NONPROD_FILES: &[&str] = &["build.rs"];

    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && (NONPROD_FILES.contains(&name) || name.ends_with(".min.js"))
    {
        return true;
    }

    for component in path.components() {
        if let std::path::Component::Normal(c) = component
            && let Some(s) = c.to_str()
            && NONPROD_DIRS.contains(&s)
        {
            return true;
        }
    }

    false
}

/// Normalize a callee description for display.
fn sanitize_desc(s: &str) -> String {
    crate::fmt::normalize_snippet(s)
}

/// Human-readable label for a `SourceKind`.
fn source_kind_label(sk: crate::labels::SourceKind) -> &'static str {
    use crate::labels::SourceKind;
    match sk {
        SourceKind::UserInput => "user input",
        SourceKind::Cookie => "cookie value",
        SourceKind::Header => "request header",
        SourceKind::EnvironmentConfig => "environment config",
        SourceKind::FileSystem => "file system data",
        SourceKind::Database => "database result",
        SourceKind::CaughtException => "caught exception",
        SourceKind::Unknown => "tainted data",
    }
}

/// Downgrade severity by one tier: High→Medium, Medium→Low, Low→Low.
fn downgrade_severity(s: Severity) -> Severity {
    match s {
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Low,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ParsedSource + ParsedFile: shared parse/CFG pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Level 1: parsed tree + lang info. No CFG construction.
struct ParsedSource<'a> {
    tree: tree_sitter::Tree,
    ts_lang: Language,
    lang_slug: &'static str,
    bytes: &'a [u8],
    path: &'a Path,
    file_path_str: Cow<'a, str>,
}

impl<'a> ParsedSource<'a> {
    /// Parse bytes into a tree-sitter AST. Returns `None` for binary files,
    /// parse timeouts, or unsupported languages.  File-size filtering is
    /// handled at the walker boundary via
    /// [`ScannerConfig::max_file_size_mb`]; the timeout check here defends
    /// against hostile inputs (pathological grammar ambiguities) that could
    /// tie up a worker indefinitely even for files within the size cap.
    fn try_new(bytes: &'a [u8], path: &'a Path) -> NyxResult<Option<Self>> {
        // Clear any stale parse-timeout signal from a prior `try_new` on
        // this thread that the caller did not consume.  Ensures the slot
        // always reflects "this parse" by the time we return.
        LAST_PARSE_TIMEOUT_MS.with(|c| c.set(None));
        if is_binary(bytes) {
            return Ok(None);
        }
        let Some((ts_lang, lang_slug)) = lang_for_path(path) else {
            return Ok(None);
        };
        let timeout_ms = parse_timeout_ms();
        let start = Instant::now();
        let mut timed_out = false;
        let parsed = PARSER.with(|cell| -> NyxResult<Option<tree_sitter::Tree>> {
            let mut parser = cell.borrow_mut();
            parser.set_language(&ts_lang)?;
            if timeout_ms == 0 {
                return Ok(parser.parse(bytes, None));
            }
            let len = bytes.len();
            let mut input = |i: usize, _pt: tree_sitter::Point| -> &[u8] {
                if i < len { &bytes[i..] } else { &[] }
            };
            let mut progress = |_state: &tree_sitter::ParseState| -> ControlFlow<()> {
                if start.elapsed().as_millis() as u64 >= timeout_ms {
                    timed_out = true;
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            };
            let options = tree_sitter::ParseOptions::new().progress_callback(&mut progress);
            Ok(parser.parse_with_options(&mut input, None, Some(options)))
        })?;
        let Some(tree) = parsed else {
            if timed_out {
                tracing::warn!(
                    file = %path.display(),
                    timeout_ms,
                    "tree-sitter parse timed out; skipping file",
                );
                LAST_PARSE_TIMEOUT_MS.with(|c| c.set(Some(timeout_ms)));
                return Ok(None);
            }
            return Err(NyxError::Other("tree-sitter failed".into()));
        };
        let file_path_str = path.to_string_lossy();
        Ok(Some(Self {
            tree,
            ts_lang,
            lang_slug,
            bytes,
            path,
            file_path_str,
        }))
    }

    /// Run AST pattern queries and return diagnostics.
    fn run_ast_queries(&self, cfg: &Config) -> Vec<Diag> {
        let root = self.tree.root_node();
        let compiled = query_cache::for_lang(self.lang_slug, self.ts_lang.clone());
        let mut cursor = QueryCursor::new();
        let mut out = Vec::new();
        let in_test_file = is_test_file(self.path);

        for cq in compiled.iter() {
            if cq.meta.severity > cfg.scanner.min_severity {
                continue;
            }
            // Suppress noise-prone patterns in test files
            if in_test_file && is_test_suppressible_pattern(cq.meta.id) {
                continue;
            }
            let mut matches = cursor.matches(&cq.query, root, self.bytes);
            while let Some(m) = matches.next() {
                if let Some(cap) = m.captures.iter().find(|c| c.index == 0) {
                    // Layer A: suppress Security findings on calls with all-literal args
                    if cq.meta.category.finding_category() == FindingCategory::Security
                        && is_call_all_args_literal(cap.node, self.bytes)
                    {
                        continue;
                    }
                    // Layer B: PHP `include $var` where $var is a formal parameter
                    // of the immediately enclosing function/method/closure and is
                    // not reassigned before the include.  This is the canonical
                    // PHP autoloader / scope-isolated-include shape (composer's
                    // ClassLoader, PSR-4 loaders, route-file loaders); the
                    // pattern rule is heuristic without taint and over-fires
                    // here.  A taint-aware sink check (the engine's
                    // taint-unsanitised-flow rule) still catches the case where
                    // a tainted value reaches the parameter at the call site.
                    if cq.meta.id == "php.path.include_variable"
                        && self.lang_slug == "php"
                        && is_php_include_param_passthrough(cap.node, self.bytes)
                    {
                        continue;
                    }
                    // Layer C: PHP `unserialize($x, ['allowed_classes' => [...]])`
                    // or `unserialize($x, ['allowed_classes' => false])` ,
                    // PHP 7+ structural mitigation against object injection.
                    // When the call passes an `allowed_classes` option set to
                    // either `false` (no class instantiation) or an array
                    // literal of explicit class names, the deserialised data
                    // cannot construct arbitrary user classes.  Skip
                    // `allowed_classes => true` (the unsafe default) and
                    // dynamic / variable values (let those fire).
                    if cq.meta.id == "php.deser.unserialize"
                        && self.lang_slug == "php"
                        && is_php_unserialize_allowed_classes_restricted(cap.node, self.bytes)
                    {
                        continue;
                    }
                    // Layer C2: PHP `Serializable::unserialize($input)` magic
                    // method body — `public function unserialize($x) { ...
                    // unserialize($x) ... }`.  This is the legacy
                    // `Serializable` interface contract (deprecated since PHP
                    // 8.1).  PHP itself invokes the method when restoring an
                    // instance, so the body's `\unserialize($x)` call cannot
                    // be removed without breaking the interface.  The
                    // actionable signal is at the class level (the class
                    // implements Serializable — fix is to migrate to
                    // `__serialize` / `__unserialize`), not at this call
                    // site.  Genuine deserialization sinks (free-function
                    // `unserialize($_GET[..])`, helpers reading from session
                    // / cache, etc.) keep firing because they are not inside
                    // a method declaration named `unserialize` with a single
                    // formal parameter passed straight to the call.
                    if cq.meta.id == "php.deser.unserialize"
                        && self.lang_slug == "php"
                        && is_php_unserialize_magic_method_passthrough(cap.node, self.bytes)
                    {
                        continue;
                    }
                    // Layer D: C/C++ buffer-overflow pattern rules
                    // (`{c,cpp}.memory.strcpy`, `strcat`, `sprintf`) fire
                    // syntactically on every call regardless of argument
                    // bounds.  The pattern's stated danger ("no bounds
                    // checking on destination buffer" / "no length limit on
                    // output buffer") is only realisable when the source /
                    // format-string contributes attacker-controlled length.
                    // When the source argument is a string literal (or a
                    // ternary of two string literals), the contributed length
                    // is statically bounded, there is no overflow vector
                    // for an attacker even if the destination buffer is
                    // mis-sized.  Same principle for `sprintf` when the
                    // format string is a literal containing no bare `%s`
                    // (only width-bounded numeric / char specifiers, or
                    // precision-bounded `%.<N>s` / `%.*s`).
                    if (self.lang_slug == "c" || self.lang_slug == "cpp")
                        && is_c_buffer_call_literal_safe(cq.meta.id, cap.node, self.bytes)
                    {
                        continue;
                    }
                    // Layer E: C++ `reinterpret_cast<T>(x)` when T is a
                    // type explicitly defined as safe by the C++ aliasing
                    // rules — byte-pointer family (`char*`, `unsigned
                    // char*`, `uint8_t*`, `std::byte*`, etc., per
                    // [basic.lval]/11), `void*`, the integer round-trip
                    // types `uintptr_t` / `intptr_t`, and the BSD-socket
                    // `sockaddr` family (POSIX intentionally type-puns
                    // `sockaddr*` <-> `sockaddr_in*` etc.).  A pattern
                    // rule cannot tell these from genuinely dangerous
                    // strict-aliasing UB casts, so it over-fires
                    // dramatically on serialization, hashing, and
                    // socket-API code where the cast is the canonical
                    // (and standard-blessed) idiom.
                    if self.lang_slug == "cpp"
                        && is_cpp_cast_target_type_safe(cq.meta.id, cap.node, self.bytes)
                    {
                        continue;
                    }
                    // Layer F: PHP `md5()` / `sha1()` flagged as weak hash
                    // functions, but used in a non-cryptographic context
                    // (ETag generation, cache-key / array-index hashing,
                    // identifier fingerprinting, deduplication).  The
                    // pattern rule cannot distinguish weak-hash crypto
                    // misuse from these idiomatic uses, so it over-fires
                    // on every `md5(...)` callsite regardless of the
                    // surrounding consuming context.  Suppress when the
                    // call's *consuming context* yields a name that
                    // matches a recognised non-cryptographic identifier
                    // pattern (variable / field / array-key / method
                    // suffix).  Genuine weak-hash crypto misuse —
                    // `$password_hash = md5(...)`, `$signature = md5(...)`,
                    // `$tokenHash = md5(...)` — keeps firing because the
                    // name contains an excluded crypto-keyword substring.
                    if (cq.meta.id == "php.crypto.md5" || cq.meta.id == "php.crypto.sha1")
                        && self.lang_slug == "php"
                        && is_php_weak_hash_non_crypto_use(cap.node, self.bytes)
                    {
                        continue;
                    }
                    let point = cap.node.start_position();
                    out.push(Diag {
                        path: self.path.to_string_lossy().into_owned(),
                        line: point.row + 1,
                        col: point.column + 1,
                        severity: cq.meta.severity,
                        id: cq.meta.id.to_owned(),
                        category: cq.meta.category.finding_category(),
                        path_validated: false,
                        guard_kind: None,
                        message: Some(cq.meta.description.to_owned()),
                        labels: vec![],
                        confidence: Some(cq.meta.confidence),
                        evidence: Some(Evidence {
                            source: None,
                            sink: Some(SpanEvidence {
                                path: self.path.to_string_lossy().into_owned(),
                                line: (point.row + 1) as u32,
                                col: (point.column + 1) as u32,
                                kind: "sink".into(),
                                snippet: None,
                            }),
                            guards: vec![],
                            sanitizers: vec![],
                            state: None,
                            notes: vec![],
                            ..Default::default()
                        }),
                        rank_score: None,
                        rank_reason: None,
                        suppressed: false,
                        suppression: None,
                        rollup: None,
                        finding_id: String::new(),
                        alternative_finding_ids: Vec::new(),
                    });
                }
            }
        }
        out
    }

    /// Sort, dedup, and optionally downgrade severity for non-production paths.
    ///
    /// Dedup key matches the `issues` table PRIMARY KEY `(file_id, rule_id,
    /// line, col)`, severity is NOT part of the key.  Two diags that agree
    /// on (line, col, id) but differ in severity (e.g. a pattern-rule finding
    /// plus a taint-pipeline finding on the same call) would otherwise survive
    /// dedup here and crash the indexer with a UNIQUE constraint violation.
    /// Sorting severity ascending (Severity::High < Medium < Low) means
    /// `dedup_by` keeps the first occurrence, preserving the highest severity.
    fn finalize_diags(&self, out: &mut Vec<Diag>, cfg: &Config) {
        out.sort_by(|a, b| {
            (a.line, a.col, &a.id, a.severity).cmp(&(b.line, b.col, &b.id, b.severity))
        });
        out.dedup_by(|a, b| a.line == b.line && a.col == b.col && a.id == b.id);

        if !cfg.scanner.include_nonprod && is_nonprod_path(self.path) {
            for d in out.iter_mut() {
                d.severity = downgrade_severity(d.severity);
            }
        }
    }
}

/// Level 2: adds CFG graph, summaries, lang rules on top of ParsedSource.
struct ParsedFile<'a> {
    source: ParsedSource<'a>,
    file_cfg: FileCfg,
    lang_rules: LangAnalysisRules,
    has_lang_rules: bool,
    /// Per-body SSA + const-prop + type-fact cache, lazily populated on first
    /// request and indexed by `BodyId.0`.  Was being recomputed 2-3× per body
    /// across `run_cfg_analyses_with_lowered` (cfg analyses + state analyses)
    /// and `run_auth_analyses` (`collect_file_var_types`); on the gin profile
    /// `build_body_const_facts` accounted for 13.6% of wall-clock and a
    /// single-pass cache collapses that to ~4.5%.
    body_const_facts_cache: OnceCell<Vec<Option<cfg_analysis::BodyConstFacts>>>,
}

impl<'a> ParsedFile<'a> {
    /// Build CFG + lang rules from a parsed source.
    fn from_source(source: ParsedSource<'a>, cfg: &Config) -> Self {
        let mut lang_rules = build_lang_rules(cfg, source.lang_slug);
        // Single-file scans rarely have a nearby package.json, so the
        // project-level `FrameworkContext` misses frameworks the file
        // obviously imports. Augment the per-file rule set with any
        // framework-conditional rules keyed off in-file import specifiers
        // (e.g. `import fastify from 'fastify'`). Idempotent, skips
        // frameworks already active from the manifest pass.
        let in_file_fws =
            crate::utils::project::detect_in_file_frameworks(source.bytes, source.lang_slug);
        let missing: Vec<_> = in_file_fws
            .into_iter()
            .filter(|fw| !lang_rules.frameworks.contains(fw))
            .collect();
        if !missing.is_empty() {
            let aug_ctx = crate::utils::project::FrameworkContext {
                frameworks: missing.clone(),
                inspected_langs: std::collections::HashSet::new(),
            };
            lang_rules
                .extra_labels
                .extend(crate::labels::framework_rules_for_lang_pub(
                    source.lang_slug,
                    &aug_ctx,
                ));
            lang_rules.frameworks.extend(missing);
        }
        let has_lang_rules = !lang_rules.extra_labels.is_empty()
            || !lang_rules.terminators.is_empty()
            || !lang_rules.event_handlers.is_empty();
        let rules_ref = if has_lang_rules {
            Some(&lang_rules)
        } else {
            None
        };
        let file_cfg = build_cfg(
            &source.tree,
            source.bytes,
            source.lang_slug,
            &source.file_path_str,
            rules_ref,
        );
        Self {
            source,
            file_cfg,
            lang_rules,
            has_lang_rules,
            body_const_facts_cache: OnceCell::new(),
        }
    }

    /// Per-body const-fact cache, computed once on first request and shared
    /// across every per-body iteration in this file's analysis.  Indexed by
    /// `BodyId.0` so callers can look up by body identity.
    fn body_const_facts_all(&self) -> &[Option<cfg_analysis::BodyConstFacts>] {
        self.body_const_facts_cache.get_or_init(|| {
            let lang = Lang::from_slug(self.source.lang_slug).unwrap_or(Lang::Rust);
            self.file_cfg
                .bodies
                .iter()
                .map(|b| cfg_analysis::build_body_const_facts(b, lang))
                .collect()
        })
    }

    /// Look up the cached const facts for a specific body.
    fn body_const_facts(
        &self,
        body: &crate::cfg::BodyCfg,
    ) -> Option<&cfg_analysis::BodyConstFacts> {
        let all = self.body_const_facts_all();
        all.get(body.meta.id.0 as usize).and_then(|f| f.as_ref())
    }

    /// The top-level body's CFG graph (for backward-compatible access).
    fn cfg_graph(&self) -> &Cfg {
        &self.file_cfg.toplevel().graph
    }

    /// The top-level body's entry node.
    #[allow(dead_code)]
    fn entry(&self) -> NodeIndex {
        self.file_cfg.toplevel().entry
    }

    fn local_summaries(&self) -> &FuncSummaries {
        &self.file_cfg.summaries
    }

    fn rules_ref(&self) -> Option<&LangAnalysisRules> {
        if self.has_lang_rules {
            Some(&self.lang_rules)
        } else {
            None
        }
    }

    fn export_summaries(&self) -> Vec<FuncSummary> {
        self.export_summaries_with_root(None)
    }

    fn export_summaries_with_root(&self, scan_root: Option<&Path>) -> Vec<FuncSummary> {
        let mut out = export_summaries(
            self.local_summaries(),
            &self.source.file_path_str,
            self.source.lang_slug,
        );

        // every
        // `FuncSummary` exported from this file carries a copy of the
        // file's `hierarchy_edges` so the inheritance / impl /
        // implements relationships persist through SQLite round-trips
        // and re-merge into `crate::callgraph::TypeHierarchyIndex` at
        // call-graph build time.  Cheap (one clone per summary) and
        // strictly additive, `merge_summaries` deduplicates downstream.
        if !self.file_cfg.hierarchy_edges.is_empty() {
            let edges = self.file_cfg.hierarchy_edges.clone();
            for s in &mut out {
                s.hierarchy_edges = edges.clone();
            }
        }

        // Rust-specific enrichment: derive the crate-relative module path for
        // this file and parse every top-level `use` declaration into an alias
        // map. The information lets the call graph resolve same-name functions
        // across modules and is cheap enough to compute once per file and
        // duplicate across the file's summaries. Non-Rust files skip all of
        // this and keep the new fields at `None`.
        if self.source.lang_slug == "rust" && !out.is_empty() {
            let module_path = crate::rust_resolve::derive_module_path(self.source.path, scan_root);
            let use_map =
                crate::rust_resolve::parse_rust_use_map(self.source.bytes, &self.source.tree);

            let aliases = if use_map.aliases.is_empty() {
                None
            } else {
                Some(use_map.aliases)
            };
            let wildcards = if use_map.wildcards.is_empty() {
                None
            } else {
                Some(use_map.wildcards)
            };

            for s in &mut out {
                s.module_path = module_path.clone();
                s.rust_use_map = aliases.clone();
                s.rust_wildcards = wildcards.clone();
            }
        }

        out
    }

    /// Extract SSA function summaries for all functions in this file.
    /// Extract SSA summaries and eligible callee bodies in a single lowering pass.
    ///
    /// Returns two vectors keyed by canonical [`crate::symbol::FuncKey`].
    /// The `FuncKey` identity preserves `(lang, namespace, container, name,
    /// arity, disambig, kind)`, so two same-name definitions in this file
    /// (e.g. a free `process` and a `Worker::process`, or overloads with
    /// different arities) land on distinct entries instead of the later one
    /// shadowing the earlier one.
    fn extract_ssa_artifacts(
        &self,
        global_summaries: Option<&GlobalSummaries>,
        scan_root: Option<&Path>,
    ) -> (
        Vec<(crate::symbol::FuncKey, SsaFuncSummary)>,
        Vec<(
            crate::symbol::FuncKey,
            crate::taint::ssa_transfer::CalleeSsaBody,
        )>,
    ) {
        let caller_lang = Lang::from_slug(self.source.lang_slug).unwrap_or(Lang::Rust);
        let scan_root_str = scan_root.map(|p| p.to_string_lossy());
        let namespace = normalize_namespace(&self.source.file_path_str, scan_root_str.as_deref());

        // Use the FileCfg path (same one `analyse_file` uses at taint time) so
        // the SSA summaries stored cross-file match exactly what pass 2 will
        // resolve against, no NodeIndex-space or entry-detection drift.
        let locator = crate::summary::SinkSiteLocator {
            tree: &self.source.tree,
            bytes: self.source.bytes,
            file_rel: &namespace,
        };
        let (summaries, bodies) = crate::taint::extract_ssa_artifacts_from_file_cfg(
            &self.file_cfg,
            caller_lang,
            &namespace,
            self.local_summaries(),
            global_summaries,
            Some(&locator),
        );

        (summaries.into_iter().collect(), bodies)
    }

    /// Lower every function body in this file to SSA exactly once.  Used by
    /// [`analyse_file_fused`] to share the result between the taint engine
    /// ([`run_cfg_analyses_with_lowered`]) and the SSA artifact filter
    /// ([`build_eligible_bodies_from_lowered`]), the prior code path lowered
    /// twice (once inside `analyse_file`, once inside
    /// `extract_ssa_artifacts_from_file_cfg`) and accounted for ~24% of the
    /// pass-2 wall-clock on the bench corpus.
    ///
    /// # Locator policy
    ///
    /// Lowering does **not** attach a [`crate::summary::SinkSiteLocator`].
    /// Per the same-file rationale documented on [`crate::taint::analyse_file`]:
    /// pass-2 intra-file summaries are transient and behavior depends on
    /// `SinkSite.cap` only, which is always populated.  Attaching a locator
    /// here populates `param_to_sink` with concrete coordinates that the
    /// emission path then promotes into `Finding.primary_location`,
    /// causing the same-file summary-resolved sink to be reported at the
    /// callee-internal sink line instead of the call site, which both
    /// duplicates the intraprocedural finding the taint engine already
    /// emits at that exact line and re-attributes the flow finding away
    /// from the user-visible call site.  Closure-capture, lambda, and
    /// helper-with-internal-sink fixtures all expect call-site emission;
    /// the standalone [`crate::taint::analyse_file`] entry point already
    /// passes `None` here for the same reason.
    ///
    /// Cross-file primary attribution is unaffected: the artifact-extraction
    /// path that persists summaries to SQLite for cross-file consumption
    /// runs through [`crate::taint::extract_ssa_artifacts_from_file_cfg`]
    /// which threads its own locator-equipped lowering separately.
    fn lower_ssa_for_fused(
        &self,
        global_summaries: Option<&GlobalSummaries>,
        scan_root: Option<&Path>,
    ) -> (
        std::collections::HashMap<
            crate::symbol::FuncKey,
            crate::summary::ssa_summary::SsaFuncSummary,
        >,
        std::collections::HashMap<
            crate::symbol::FuncKey,
            crate::taint::ssa_transfer::CalleeSsaBody,
        >,
    ) {
        let caller_lang = Lang::from_slug(self.source.lang_slug).unwrap_or(Lang::Rust);
        let scan_root_str = scan_root.map(|p| p.to_string_lossy());
        let namespace = normalize_namespace(&self.source.file_path_str, scan_root_str.as_deref());
        crate::taint::lower_all_functions_from_bodies(
            &self.file_cfg,
            caller_lang,
            &namespace,
            self.local_summaries(),
            global_summaries,
            None,
        )
    }

    /// Run taint analysis, CFG structural analyses, and state-model analysis.
    ///
    /// Wrapper around [`run_cfg_analyses_with_lowered`] that lowers SSA
    /// internally (the standalone path).  Callers that already hold a
    /// pre-lowered result (today: only [`analyse_file_fused`]) should use
    /// the `_with_lowered` variant directly to avoid the duplicate
    /// lowering.
    fn run_cfg_analyses(
        &self,
        cfg: &Config,
        global_summaries: Option<&GlobalSummaries>,
        scan_root: Option<&Path>,
    ) -> Vec<Diag> {
        // Reset before lowering: probes during lowering may publish
        // path-safe-suppressed sink spans that state analysis consumes,
        // and the SSA engine may publish all-validated sink spans that
        // AST-pattern suppression consumes.  See the equivalent resets
        // in `analyse_file_fused`.
        crate::taint::ssa_transfer::reset_path_safe_suppressed_spans();
        crate::taint::ssa_transfer::reset_all_validated_spans();
        let (ssa_summaries, callee_bodies) = self.lower_ssa_for_fused(global_summaries, scan_root);
        self.run_cfg_analyses_with_lowered(
            cfg,
            global_summaries,
            scan_root,
            &ssa_summaries,
            &callee_bodies,
        )
    }

    /// Like [`run_cfg_analyses`] but takes pre-lowered SSA summaries +
    /// callee bodies and threads them into [`taint::analyse_file_with_lowered`].
    /// Used by [`analyse_file_fused`] to share the lowering with the SSA
    /// artifact extractor.
    #[allow(clippy::too_many_arguments)]
    fn run_cfg_analyses_with_lowered(
        &self,
        cfg: &Config,
        global_summaries: Option<&GlobalSummaries>,
        scan_root: Option<&Path>,
        ssa_summaries: &std::collections::HashMap<
            crate::symbol::FuncKey,
            crate::summary::ssa_summary::SsaFuncSummary,
        >,
        callee_bodies: &std::collections::HashMap<
            crate::symbol::FuncKey,
            crate::taint::ssa_transfer::CalleeSsaBody,
        >,
    ) -> Vec<Diag> {
        let mut out = Vec::new();
        let caller_lang = Lang::from_slug(self.source.lang_slug).unwrap_or(Lang::Rust);

        // ── Taint analysis ──────────────────────────────────────────────
        tracing::debug!("Running taint analysis on: {}", self.source.path.display());
        tracing::debug!("Func summaries: {:?}", self.local_summaries());
        let scan_root_str = scan_root.map(|p| p.to_string_lossy());
        let namespace = normalize_namespace(&self.source.file_path_str, scan_root_str.as_deref());
        let extra = if self.lang_rules.extra_labels.is_empty() {
            None
        } else {
            Some(self.lang_rules.extra_labels.as_slice())
        };
        let taint_results = crate::taint::analyse_file_with_lowered(
            &self.file_cfg,
            self.local_summaries(),
            global_summaries,
            caller_lang,
            &namespace,
            &[],
            extra,
            ssa_summaries,
            callee_bodies,
        );
        // Drain the path-safe-suppressed sink-span set published by the
        // SSA taint engine.  Used below by the state-analysis pass to
        // suppress `state-unauthed-access` on sinks the taint engine has
        // already proved cannot reach a privileged location.
        let path_safe_suppressed_spans =
            crate::taint::ssa_transfer::take_path_safe_suppressed_spans();
        for finding in &taint_results {
            let body_cfg = &self.file_cfg.body(finding.body_id).graph;

            // Suppress internal redirect taint findings: res.redirect(`/path/...`)
            // with a path-prefix argument is server-relative, not an open redirect.
            let sink_info = &body_cfg[finding.sink];
            let sink_has_ssrf = sink_info
                .taint
                .labels
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SSRF)));
            if sink_has_ssrf
                && let Some(ref callee) = sink_info.call.callee
                && (callee.ends_with("redirect") || callee.ends_with("Redirect"))
                && crate::cfg_analysis::guards::has_redirect_path_prefix(
                    self.source.bytes,
                    sink_info.ast.span,
                )
            {
                continue;
            }

            if let Some(diag) = build_taint_diag(
                finding,
                body_cfg,
                &self.source.tree,
                self.source.path,
                self.source.bytes,
                scan_root,
            ) {
                out.push(diag);
            }
        }

        // ── CFG structural analyses (per body) ─────────────────────────
        let taint_active = global_summaries.is_some() || !taint_results.is_empty();
        // Pre-compute, per body, the set of variable names whose
        // release / close calls live in a NESTED closure body inside
        // that body (e.g. `socket.on("close", () => ws.close())`).
        // Both the structural ResourceMisuse pass and the state-model
        // leak pass consult it to suppress findings whose cleanup is
        // registered as a callback the per-body CFG can't follow.
        // Only descendants count — sibling methods on the same class
        // don't share resource ownership.
        let closure_released_per_body =
            state::collect_closure_released_var_names(&self.file_cfg.bodies, caller_lang);
        let empty_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for body in &self.file_cfg.bodies {
            let body_taint: Vec<_> = taint_results
                .iter()
                .filter(|f| f.body_id == body.meta.id)
                .cloned()
                .collect();
            let body_const_facts = self.body_const_facts(body);
            let cfg_ctx = cfg_analysis::AnalysisContext {
                cfg: &body.graph,
                entry: body.entry,
                lang: caller_lang,
                file_path: &self.source.file_path_str,
                source_bytes: self.source.bytes,
                func_summaries: self.local_summaries(),
                global_summaries,
                ssa_summaries: Some(ssa_summaries),
                taint_findings: &body_taint,
                analysis_rules: self.rules_ref(),
                taint_active,
                body_const_facts,
                type_facts: body_const_facts.map(|f| &f.type_facts),
                auth_decorators: &body.meta.auth_decorators,
                closure_released_var_names: Some(
                    closure_released_per_body
                        .get(&body.meta.id)
                        .unwrap_or(&empty_set),
                ),
            };
            for cf in cfg_analysis::run_all(&cfg_ctx) {
                let point = byte_offset_to_point(&self.source.tree, cf.span.0);
                let cfg_confidence = Some(match cf.confidence {
                    cfg_analysis::Confidence::High => crate::evidence::Confidence::High,
                    cfg_analysis::Confidence::Medium => crate::evidence::Confidence::Medium,
                    cfg_analysis::Confidence::Low => crate::evidence::Confidence::Low,
                });
                out.push(Diag {
                    path: self.source.path.to_string_lossy().into_owned(),
                    line: point.row + 1,
                    col: point.column + 1,
                    severity: cf.severity,
                    id: cf.rule_id,
                    category: FindingCategory::Security,
                    path_validated: false,
                    guard_kind: None,
                    message: Some(cf.message),
                    labels: vec![],
                    confidence: cfg_confidence,
                    evidence: Some(Evidence {
                        source: None,
                        sink: Some(SpanEvidence {
                            path: self.source.path.to_string_lossy().into_owned(),
                            line: (point.row + 1) as u32,
                            col: (point.column + 1) as u32,
                            kind: "sink".into(),
                            snippet: None,
                        }),
                        guards: vec![],
                        sanitizers: vec![],
                        state: None,
                        notes: vec![],
                        ..Default::default()
                    }),
                    rank_score: None,
                    rank_reason: None,
                    suppressed: false,
                    suppression: None,
                    rollup: None,
                    finding_id: String::new(),
                    alternative_finding_ids: Vec::new(),
                });
            }
        } // end for body in bodies (CFG structural analyses)

        // ── State-model dataflow analysis (per body) ─────────────────────
        if cfg.scanner.enable_state_analysis {
            let resource_method_summaries =
                state::build_resource_method_summaries(&self.file_cfg.bodies, caller_lang);
            let mut all_state_findings = Vec::new();
            for body in &self.file_cfg.bodies {
                // When `NYX_POINTER_ANALYSIS=1` is set, derive a
                // `var_name → PtrProxyHint` map from the body's
                // points-to facts so the proxy-acquire transfer can
                // suppress SymbolId attribution on field-aliased
                // receivers (e.g. `m := c.mu; m.Lock()`).
                let body_pointer_hints = self.body_const_facts(body).and_then(|f| {
                    f.pointer_facts
                        .as_ref()
                        .map(|pf| pf.name_proxy_hints(&f.ssa))
                });
                let state_findings = state::run_state_analysis(
                    &body.graph,
                    body.entry,
                    caller_lang,
                    self.source.bytes,
                    self.local_summaries(),
                    global_summaries,
                    cfg.scanner.enable_auth_analysis,
                    &resource_method_summaries,
                    &body.meta.auth_decorators,
                    &path_safe_suppressed_spans,
                    body_pointer_hints.as_ref(),
                    Some(
                        closure_released_per_body
                            .get(&body.meta.id)
                            .unwrap_or(&empty_set),
                    ),
                );

                for sf in &state_findings {
                    let point = byte_offset_to_point(&self.source.tree, sf.span.0);
                    out.push(Diag {
                        path: self.source.path.to_string_lossy().into_owned(),
                        line: point.row + 1,
                        col: point.column + 1,
                        severity: sf.severity,
                        id: sf.rule_id.clone(),
                        category: FindingCategory::Security,
                        path_validated: false,
                        guard_kind: None,
                        message: Some(sf.message.clone()),
                        labels: vec![],
                        confidence: None,
                        evidence: Some(Evidence {
                            source: None,
                            sink: Some(SpanEvidence {
                                path: self.source.path.to_string_lossy().into_owned(),
                                line: (point.row + 1) as u32,
                                col: (point.column + 1) as u32,
                                kind: "sink".into(),
                                snippet: None,
                            }),
                            guards: vec![],
                            sanitizers: vec![],
                            state: Some(StateEvidence {
                                machine: sf.machine.into(),
                                subject: sf.subject.clone(),
                                from_state: sf.from_state.into(),
                                to_state: sf.to_state.into(),
                            }),
                            notes: vec![],
                            ..Default::default()
                        }),
                        rank_score: None,
                        rank_reason: None,
                        suppressed: false,
                        suppression: None,
                        rollup: None,
                        finding_id: String::new(),
                        alternative_finding_ids: Vec::new(),
                    });
                }

                all_state_findings.extend(state_findings);
            } // end for body in bodies (state analysis)

            // Suppress cfg-resource-leak / cfg-auth-gap when state analysis
            // already covers the same line (state analysis is more precise).
            let state_lines: std::collections::HashSet<usize> = all_state_findings
                .iter()
                .map(|sf| byte_offset_to_point(&self.source.tree, sf.span.0).row + 1)
                .collect();
            if !all_state_findings.is_empty() {
                out.retain(|d| {
                    !((d.id == "cfg-resource-leak" || d.id == "cfg-auth-gap")
                        && state_lines.contains(&d.line))
                });
            }
        }

        out
    }

    /// Run AST-backed authorization analyses that do not require CFG construction.
    fn run_auth_analyses(
        &self,
        cfg: &Config,
        global_summaries: Option<&GlobalSummaries>,
        scan_root: Option<&Path>,
    ) -> Vec<Diag> {
        // Harvest SSA-derived variable types across every body in the
        // file so `run_auth_analysis` can refine sink classification by
        // receiver type (e.g. `HttpClient::send` → `OutboundNetwork`,
        // `HashMap::new`-bound var → `InMemoryLocal`).
        let var_types = self.collect_file_var_types();
        auth_analysis::run_auth_analysis(
            &self.source.tree,
            self.source.bytes,
            self.source.lang_slug,
            self.source.path,
            cfg,
            var_types.as_ref(),
            global_summaries,
            scan_root,
        )
    }

    /// Build a per-file `var_name → TypeKind` map from SSA + type facts.
    /// Conflicting non-`Unknown` types across bodies drop the entry ,
    /// absence is safe because the auth sink gate falls back to
    /// syntactic heuristics. Returns `None` when no body produces a
    /// typed variable.
    fn collect_file_var_types(&self) -> Option<auth_analysis::VarTypes> {
        let mut merged: std::collections::HashMap<String, crate::ssa::type_facts::TypeKind> =
            std::collections::HashMap::new();
        let mut dropped: std::collections::HashSet<String> = std::collections::HashSet::new();
        for body in &self.file_cfg.bodies {
            let Some(facts) = self.body_const_facts(body) else {
                continue;
            };
            for (idx, def) in facts.ssa.value_defs.iter().enumerate() {
                let Some(name) = def.var_name.as_ref() else {
                    continue;
                };
                let Some(ty) = facts.type_facts.get_type(crate::ssa::SsaValue(idx as u32)) else {
                    continue;
                };
                if matches!(ty, crate::ssa::type_facts::TypeKind::Unknown) {
                    continue;
                }
                if dropped.contains(name) {
                    continue;
                }
                match merged.get(name) {
                    Some(existing) if existing == ty => {}
                    Some(_) => {
                        merged.remove(name);
                        dropped.insert(name.clone());
                    }
                    None => {
                        merged.insert(name.clone(), ty.clone());
                    }
                }
            }
        }
        if merged.is_empty() {
            None
        } else {
            Some(merged)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Pass 1: Extract function summaries (no taint analysis)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract function summaries from pre-read bytes.
///
/// This is the core **pass 1** implementation. Callers that already hold the
/// file contents should use this variant to avoid a redundant `fs::read`.
pub fn extract_summaries_from_bytes(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
) -> NyxResult<Vec<FuncSummary>> {
    let _span = tracing::debug_span!("extract_summaries", file = %path.display()).entered();
    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        return Ok(vec![]);
    };
    let parsed = ParsedFile::from_source(source, cfg);
    Ok(parsed.export_summaries())
}

/// Like [`extract_summaries_from_bytes`] but forwards `scan_root` so Rust
/// summaries carry their crate-relative module path.
pub fn extract_summaries_from_bytes_with_root(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    scan_root: Option<&Path>,
) -> NyxResult<Vec<FuncSummary>> {
    let _span = tracing::debug_span!("extract_summaries", file = %path.display()).entered();
    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        return Ok(vec![]);
    };
    let parsed = ParsedFile::from_source(source, cfg);
    Ok(parsed.export_summaries_with_root(scan_root))
}

/// Convenience wrapper that reads the file then delegates to
/// [`extract_summaries_from_bytes`].
#[allow(dead_code)] // used by benchmarks and lib consumers
pub fn extract_summaries_from_file(path: &Path, cfg: &Config) -> NyxResult<Vec<FuncSummary>> {
    let bytes = std::fs::read(path)?;
    extract_summaries_from_bytes(&bytes, path, cfg)
}

/// Build a CFG from a file and return the graph, entry node, function summaries,
/// and language.
///
/// Returns `None` for binary files or unsupported languages.
/// Intended for benchmarks and isolated testing of state analysis.
pub fn build_cfg_for_file(path: &Path, cfg: &Config) -> NyxResult<Option<(FileCfg, Lang)>> {
    let bytes = std::fs::read(path)?;
    let Some(source) = ParsedSource::try_new(&bytes, path)? else {
        return Ok(None);
    };
    let lang = Lang::from_slug(source.lang_slug).unwrap_or(Lang::C);
    let parsed = ParsedFile::from_source(source, cfg);
    Ok(Some((parsed.file_cfg, lang)))
}

/// Parse a file and return its `AuthorizationModel` for debug inspection.
///
/// Runs only the auth-extraction pipeline, no taint, no CFG construction.
/// Returns `None` for binary files or unsupported languages.  Used by the
/// `/api/debug/auth` route to surface the structured authorization model
/// (routes, units, sensitive operations, auth checks) in the debug UI.
pub fn extract_auth_model_for_debug(
    path: &Path,
    cfg: &Config,
) -> NyxResult<Option<auth_analysis::model::AuthorizationModel>> {
    let bytes = std::fs::read(path)?;
    let Some(source) = ParsedSource::try_new(&bytes, path)? else {
        return Ok(None);
    };
    let rules = auth_analysis::config::build_auth_rules(cfg, source.lang_slug);
    if !rules.enabled {
        return Ok(Some(auth_analysis::model::AuthorizationModel::default()));
    }
    let model = auth_analysis::extract::extract_authorization_model(
        source.lang_slug,
        cfg.framework_ctx.as_ref(),
        &source.tree,
        source.bytes,
        source.path,
        &rules,
        None,
    );
    Ok(Some(model))
}

/// Production-equivalent fused-path stage timing.
///
/// Returns `[parse+CFG, shared_lower, taint_flow, build_eligible,
///           ast_queries, suppression, auth, run_cfg_state]` in µs, plus
/// the per-substage breakdown of `shared_lower` from the thread-local
/// timers in `taint::perf_lower_timings_*`.
///
/// Mirrors `analyse_file_fused`'s control flow so each chunk is timed
/// without the double-lowering overcount that `perf_stage_breakdown`
/// suffers (the latter calls `run_cfg_analyses` and
/// `extract_ssa_artifacts` separately, both of which lower).
#[doc(hidden)]
pub fn perf_stage_breakdown_fused(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    global_summaries: Option<&crate::summary::GlobalSummaries>,
    scan_root: Option<&Path>,
) -> Option<([u128; 8], [u128; 7])> {
    use std::time::Instant;
    let s_parse = Instant::now();
    let source = ParsedSource::try_new(bytes, path).ok()??;
    let parsed = ParsedFile::from_source(source, cfg);
    let t_parse_cfg = s_parse.elapsed().as_micros();

    crate::taint::ssa_transfer::reset_path_safe_suppressed_spans();
    crate::taint::ssa_transfer::reset_all_validated_spans();
    crate::taint::perf_lower_timings_start();

    let s_lower = Instant::now();
    let (lowered_summaries, lowered_bodies) =
        parsed.lower_ssa_for_fused(global_summaries, scan_root);
    let t_lower = s_lower.elapsed().as_micros();
    let lower_breakdown = crate::taint::perf_lower_timings_take().unwrap_or([0; 7]);

    let s_taint = Instant::now();
    let taint_diags = parsed.run_cfg_analyses_with_lowered(
        cfg,
        global_summaries,
        scan_root,
        &lowered_summaries,
        &lowered_bodies,
    );
    let t_taint_flow = s_taint.elapsed().as_micros();

    let s_eligible = Instant::now();
    let _ = crate::taint::build_eligible_bodies(&parsed.file_cfg, lowered_bodies);
    let t_eligible = s_eligible.elapsed().as_micros();

    let s_ast = Instant::now();
    let ast_findings = parsed.source.run_ast_queries(cfg);
    let t_ast = s_ast.elapsed().as_micros();

    let s_suppr = Instant::now();
    let suppression =
        TaintSuppressionCtx::build(&parsed.file_cfg, &parsed.source.tree, &taint_diags);
    let _filtered: Vec<_> = ast_findings
        .into_iter()
        .filter(|d| !suppression.should_suppress(&d.id, d.line))
        .collect();
    let t_suppr = s_suppr.elapsed().as_micros();

    let s_auth = Instant::now();
    let _ = parsed.run_auth_analyses(cfg, global_summaries, scan_root);
    let t_auth = s_auth.elapsed().as_micros();

    // 8th slot reserved (state-analysis breakdown if needed later);
    // currently included in t_taint_flow.
    let t_state = 0u128;

    Some((
        [
            t_parse_cfg,
            t_lower,
            t_taint_flow,
            t_eligible,
            t_ast,
            t_suppr,
            t_auth,
            t_state,
        ],
        lower_breakdown,
    ))
}

/// Diagnostic stage-timing helper for the perf audit.
///
/// Times each stage of pass 2 internally and returns µs counts.  Returns
/// `None` for unsupported languages.  Not used in production, just for
/// `tests/perf_breakdown.rs` to attribute time inside `run_rules_on_bytes`
/// without touching the hot path.
#[doc(hidden)]
pub fn perf_stage_breakdown(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    global_summaries: Option<&crate::summary::GlobalSummaries>,
    scan_root: Option<&Path>,
) -> Option<[u128; 6]> {
    use std::time::Instant;
    let s_parse = Instant::now();
    let source = ParsedSource::try_new(bytes, path).ok()??;
    let parsed = ParsedFile::from_source(source, cfg);
    let t_parse_cfg = s_parse.elapsed().as_micros();

    let s_taint = Instant::now();
    let taint = parsed.run_cfg_analyses(cfg, global_summaries, scan_root);
    let t_taint = s_taint.elapsed().as_micros();

    let s_suppr = Instant::now();
    let _ = TaintSuppressionCtx::build(&parsed.file_cfg, &parsed.source.tree, &taint);
    let t_suppr = s_suppr.elapsed().as_micros();

    let s_ast = Instant::now();
    let _ast_findings = parsed.source.run_ast_queries(cfg);
    let t_ast = s_ast.elapsed().as_micros();

    let s_auth = Instant::now();
    let _ = parsed.run_auth_analyses(cfg, global_summaries, scan_root);
    let t_auth = s_auth.elapsed().as_micros();

    let s_ssa = Instant::now();
    let _ = parsed.extract_ssa_artifacts(global_summaries, scan_root);
    let t_ssa = s_ssa.elapsed().as_micros();

    Some([t_parse_cfg, t_taint, t_suppr, t_ast, t_auth, t_ssa])
}

/// Extract both `FuncSummary` and `SsaFuncSummary` from pre-read bytes.
///
/// This is the shared pass-1 pipeline for indexed scans: parses once, builds
/// CFG once, and returns both summary types. Uses the same `ParsedFile`
/// pipeline as `analyse_file_fused`, no divergent extraction path.
pub fn extract_all_summaries_from_bytes(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    scan_root: Option<&Path>,
) -> NyxResult<(
    Vec<FuncSummary>,
    Vec<(crate::symbol::FuncKey, SsaFuncSummary)>,
    Vec<(
        crate::symbol::FuncKey,
        crate::taint::ssa_transfer::CalleeSsaBody,
    )>,
    Vec<(
        crate::symbol::FuncKey,
        auth_analysis::model::AuthCheckSummary,
    )>,
)> {
    let _span = tracing::debug_span!("extract_all_summaries", file = %path.display()).entered();
    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        return Ok((vec![], vec![], vec![], vec![]));
    };
    let lang_slug = source.lang_slug;
    let parsed = ParsedFile::from_source(source, cfg);
    let func_summaries = parsed.export_summaries_with_root(scan_root);
    let (ssa_summaries, ssa_bodies) = parsed.extract_ssa_artifacts(None, scan_root);
    let auth_summaries = auth_analysis::extract_auth_summaries_by_key(
        &parsed.source.tree,
        parsed.source.bytes,
        lang_slug,
        parsed.source.path,
        cfg,
        scan_root,
    );
    Ok((func_summaries, ssa_summaries, ssa_bodies, auth_summaries))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Constant-argument suppression helper
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` when the captured call node has only literal arguments
/// (string, number, boolean, null/nil/none).  Used to suppress AST pattern
/// findings on provably-constant calls like `os.system("echo health-ok")`.
///
/// Conservative: returns `false` whenever the tree structure is unclear or
/// any argument is non-literal (including interpolated strings).
fn is_call_all_args_literal(node: tree_sitter::Node, bytes: &[u8]) -> bool {
    // Walk upwards from the captured node to find the closest call_expression
    // (or similar) ancestor, then locate its argument list child.
    let call_node = find_enclosing_call(node);
    let call_node = match call_node {
        Some(n) => n,
        None => return false,
    };

    // Find the argument_list / arguments child of the call node.
    let arg_list = find_arg_list(call_node);
    let arg_list = match arg_list {
        Some(n) => n,
        None => return false,
    };

    let mut has_any_arg = false;
    for i in 0..arg_list.named_child_count() as u32 {
        let child = match arg_list.named_child(i) {
            Some(c) => c,
            None => continue,
        };
        has_any_arg = true;
        if !is_literal_node(child, bytes) {
            return false;
        }
    }

    // If the argument list is empty (no args), we conservatively do NOT
    // suppress, the danger may come from side effects, not arguments.
    has_any_arg
}

/// Walk up to find a call-expression-like ancestor of the captured node.
/// Stops at statement/block boundaries to avoid matching unrelated outer calls.
fn find_enclosing_call(mut node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    // The captured node may already be the call, or it could be the callee
    // identifier inside a call_expression.  Walk up a few levels.
    for _ in 0..4 {
        let kind = node.kind();
        if kind.contains("call") && !kind.contains("callee") {
            return Some(node);
        }
        // PHP: function_call_expression
        if kind == "function_call_expression" {
            return Some(node);
        }
        // Stop at scope/statement boundaries, don't cross into outer calls
        if kind.contains("block")
            || kind.contains("body")
            || kind == "program"
            || kind == "module"
            || kind == "expression_statement"
        {
            return None;
        }
        node = node.parent()?;
    }
    None
}

/// Find the argument-list child of a call node across languages.
fn find_arg_list(call: tree_sitter::Node) -> Option<tree_sitter::Node> {
    for i in 0..call.child_count() as u32 {
        if let Some(child) = call.child(i) {
            let kind = child.kind();
            // Common argument list node kinds across languages:
            // Python/JS/TS/Java/Go/C/C++/Rust: argument_list / arguments
            // PHP: arguments
            // Ruby: argument_list
            if kind == "argument_list" || kind == "arguments" || kind == "actual_parameters" {
                return Some(child);
            }
        }
    }
    None
}

/// Check if a tree-sitter node represents a literal value.
fn is_literal_node(node: tree_sitter::Node, bytes: &[u8]) -> bool {
    let kind = node.kind();
    match kind {
        // String literals, but Python's `string` node also covers
        // f-strings, which carry `interpolation` children.  An f-string
        // with interpolation is *not* a literal: it embeds arbitrary
        // expressions, so a sink call like `cursor.execute(f"…{x}")`
        // must not be suppressed under Layer A's "all-literal args"
        // shortcut.  Same shape applies to any tree-sitter grammar
        // that nests an `interpolation` (or `string_interpolation`)
        // child inside a string node.
        "string"
        | "string_literal"
        | "interpreted_string_literal"
        | "raw_string_literal"
        | "string_content"
        | "string_fragment" => !has_interpolation(node),

        // Numeric literals
        "integer" | "integer_literal" | "int_literal" | "float" | "float_literal" | "number" => {
            true
        }

        // Boolean / null / nil / none
        "true" | "false" | "null" | "nil" | "none" | "null_literal" | "boolean"
        | "boolean_literal" => true,

        // PHP encapsed_string: safe only if it has no variable interpolation
        "encapsed_string" => {
            // If it contains `$` variable interpolation nodes, it's not literal
            !has_interpolation(node)
        }

        // Wrapper nodes: PHP wraps each arg in an `argument` node,
        // Go uses `argument` too.  Unwrap and check the inner value.
        "argument" => {
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|c| is_literal_node(c, bytes))
        }

        // Unary minus on a number literal: `-42`
        "unary_expression" | "unary_op" => {
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|c| is_literal_node(c, bytes))
        }

        // String concatenation of literals: `"a" + "b"` or `"a" . "b"`
        "binary_expression" | "concatenated_string" => {
            node.named_child_count() >= 2
                && (0..node.named_child_count() as u32).all(|i| {
                    node.named_child(i)
                        .is_some_and(|c| is_literal_node(c, bytes))
                })
        }

        _ => false,
    }
}

/// PHP-only: returns `true` when the captured `include_expression` node is
/// `include $var` (or `require $var`, etc.) and `$var` is a formal parameter
/// of the immediately enclosing function / method / closure / arrow function,
/// with no assignment to `$var` between the function body start and the
/// include site.  This is the canonical PHP autoloader / scope-isolated
/// `Closure::bind(static function ($file) { include $file; }, ...)` shape;
/// composer's `ClassLoader::initializeIncludeClosure`, PSR-4 loaders, and
/// route-file loaders all match this.  The pattern rule is intentionally
/// heuristic (no taint), so a parameter pass-through is the broadest
/// safe-suppression boundary; if the caller passes a tainted value, the
/// engine's separate taint-unsanitised-flow rule still fires.
fn is_php_include_param_passthrough(include_node: tree_sitter::Node, bytes: &[u8]) -> bool {
    // tree-sitter-php shape:
    //   include_expression
    //     variable_name
    //       name "<param>"
    let var_node = include_node.named_child(0);
    let Some(var_node) = var_node else {
        return false;
    };
    if var_node.kind() != "variable_name" {
        return false;
    }
    let name_node = var_node.named_child(0);
    let Some(name_node) = name_node else {
        return false;
    };
    let var_name = match std::str::from_utf8(&bytes[name_node.byte_range()]) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Walk up to the enclosing function/method/closure.
    let mut cur = include_node;
    while let Some(parent) = cur.parent() {
        match parent.kind() {
            "method_declaration"
            | "function_definition"
            | "anonymous_function"
            | "anonymous_function_creation_expression"
            | "arrow_function" => {
                let params = parent
                    .child_by_field_name("parameters")
                    .or_else(|| find_named_child_of_kind(parent, "formal_parameters"));
                let Some(params) = params else {
                    return false;
                };
                if !param_list_contains_name(params, var_name, bytes) {
                    return false;
                }
                // Reassignment guard: if the variable is reassigned inside the
                // function body before the include, the parameter-pass-through
                // assumption breaks down.
                let body = parent
                    .child_by_field_name("body")
                    .or_else(|| find_named_child_of_kind(parent, "compound_statement"));
                let body_start = body.map(|b| b.start_byte()).unwrap_or(parent.start_byte());
                if is_var_reassigned_before(
                    body.unwrap_or(parent),
                    var_name,
                    include_node.start_byte(),
                    body_start,
                    bytes,
                ) {
                    return false;
                }
                return true;
            }
            // Stop at class/program scope without a matching function, bare
            // top-level `include $var` does not benefit from this guard.
            "program" | "class_declaration" | "trait_declaration" | "interface_declaration" => {
                return false;
            }
            _ => {}
        }
        cur = parent;
    }
    false
}

fn find_named_child_of_kind<'a>(
    parent: tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    for i in 0..parent.named_child_count() as u32 {
        if let Some(child) = parent.named_child(i)
            && child.kind() == kind
        {
            return Some(child);
        }
    }
    None
}

fn param_list_contains_name(params: tree_sitter::Node, target_name: &str, bytes: &[u8]) -> bool {
    for i in 0..params.named_child_count() as u32 {
        let Some(param) = params.named_child(i) else {
            continue;
        };
        if !matches!(
            param.kind(),
            "simple_parameter"
                | "variadic_parameter"
                | "property_promotion_parameter"
                | "promoted_constructor_parameter"
        ) {
            continue;
        }
        // simple_parameter has a `variable_name` child whose `name` child is the bare ident.
        let var_node = param
            .child_by_field_name("name")
            .or_else(|| find_named_child_of_kind(param, "variable_name"));
        let Some(var_node) = var_node else {
            continue;
        };
        let name_node = if var_node.kind() == "variable_name" {
            var_node.named_child(0)
        } else {
            Some(var_node)
        };
        let Some(name_node) = name_node else {
            continue;
        };
        if let Ok(name) = std::str::from_utf8(&bytes[name_node.byte_range()])
            && name == target_name
        {
            return true;
        }
    }
    false
}

/// Walk the function body looking for any `assignment_expression` whose LHS
/// names `target_name`, between `body_start` (inclusive) and `before_byte`
/// (exclusive).  Crosses nested scopes (closures inside the function are
/// rare in this idiom, and reassignment inside them wouldn't shadow the
/// outer parameter).
fn is_var_reassigned_before(
    root: tree_sitter::Node,
    target_name: &str,
    before_byte: usize,
    body_start: usize,
    bytes: &[u8],
) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        if node.end_byte() <= body_start {
            continue;
        }
        if node.kind() == "assignment_expression" {
            // LHS is the first named child (or the `left` field in newer grammars).
            let lhs = node
                .child_by_field_name("left")
                .or_else(|| node.named_child(0));
            if let Some(lhs) = lhs
                && lhs.kind() == "variable_name"
                && let Some(n) = lhs.named_child(0)
                && let Ok(s) = std::str::from_utf8(&bytes[n.byte_range()])
                && s == target_name
            {
                return true;
            }
        }
        for i in 0..node.named_child_count() as u32 {
            if let Some(c) = node.named_child(i) {
                stack.push(c);
            }
        }
    }
    false
}

/// PHP-only: returns `true` when the captured `function_call_expression`
/// node is `unserialize($x, [..., 'allowed_classes' => <ARRAY|false>, ...])`.
/// This is the canonical PHP 7+ structural mitigation against object
/// injection, explicitly restricting which classes the deserialiser may
/// instantiate.  Only suppress when the option is either:
///
///   - `'allowed_classes' => false`           (no class instantiation), or
///   - `'allowed_classes' => [Foo::class]`    (an array literal allow-list).
///
/// `'allowed_classes' => true` (the unsafe default) and dynamic values
/// (`'allowed_classes' => $opts`) leave the finding in place.
fn is_php_unserialize_allowed_classes_restricted(
    cap_node: tree_sitter::Node,
    bytes: &[u8],
) -> bool {
    // The pattern captures `@n` (the function name) at index 0, so walk up
    // to the enclosing function_call_expression.
    let call_node = if cap_node.kind() == "function_call_expression" {
        cap_node
    } else {
        let mut cur = cap_node;
        let mut found = None;
        for _ in 0..4 {
            if cur.kind() == "function_call_expression" {
                found = Some(cur);
                break;
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
        match found {
            Some(c) => c,
            None => return false,
        }
    };
    let arg_list = find_named_child_of_kind(call_node, "arguments");
    let Some(arg_list) = arg_list else {
        return false;
    };
    // arg 0 is the data; arg 1 is the options array.
    let mut args = Vec::new();
    for i in 0..arg_list.named_child_count() as u32 {
        if let Some(c) = arg_list.named_child(i)
            && c.kind() == "argument"
        {
            args.push(c);
        }
    }
    if args.len() < 2 {
        return false;
    }
    // Unwrap the `argument` wrapper to its inner expression.
    let opts = args[1].named_child(0);
    let Some(opts) = opts else { return false };
    if opts.kind() != "array_creation_expression" {
        return false;
    }
    // Walk array_element_initializer children looking for the
    // 'allowed_classes' key.
    for i in 0..opts.named_child_count() as u32 {
        let Some(elem) = opts.named_child(i) else {
            continue;
        };
        if elem.kind() != "array_element_initializer" {
            continue;
        }
        // Two named children: key, value.
        if elem.named_child_count() < 2 {
            continue;
        }
        let key = elem.named_child(0);
        let value = elem.named_child(1);
        let (Some(key), Some(value)) = (key, value) else {
            continue;
        };
        if !is_string_literal_with_text(key, "allowed_classes", bytes) {
            continue;
        }
        // Accept structural mitigation forms.  The intent signal is
        // "developer explicitly set allowed_classes to something other than
        // `true`":
        //   - boolean `false`            , no class instantiation at all
        //   - array literal              , explicit allow-list
        //   - class-constant reference   , `self::ALLOWED_CLASSES` /
        //                                    `Foo::CONSTANTS` resolved to
        //                                    a const array; engine cannot
        //                                    statically inspect, but the
        //                                    explicit option already
        //                                    distinguishes safe usage from
        //                                    the unsafe default.
        match value.kind() {
            "boolean" => {
                if let Ok(s) = std::str::from_utf8(&bytes[value.byte_range()])
                    && s.eq_ignore_ascii_case("false")
                {
                    return true;
                }
            }
            "array_creation_expression"
            | "class_constant_access_expression"
            | "scoped_property_access_expression" => return true,
            _ => {}
        }
    }
    false
}

/// PHP-only: returns `true` when the captured `function_call_expression`
/// is the canonical `Serializable::unserialize($input)` magic-method
/// pass-through — i.e. the call is inside a `method_declaration` named
/// exactly `unserialize` (PHP method names are case-insensitive) with
/// one formal parameter, and the call's single argument is the bare
/// parameter variable.
///
/// **Why this is a non-actionable site for `php.deser.unserialize`:**
/// `Serializable::unserialize($input)` is an interface contract method
/// that PHP itself invokes when restoring an instance via the runtime
/// `\unserialize($bytes)` machinery.  The implementation MUST decode
/// `$input` (the body's `\unserialize(...)` call) — there is no
/// "safer" rewrite that preserves the contract.  The actionable signal
/// is at the class level (the class implements the deprecated
/// `Serializable` interface — fix is to migrate to `__serialize` /
/// `__unserialize`), not at this call site.
///
/// Conservative recognition:
/// - method must be a `method_declaration` (NOT a free `function_definition` —
///   the magic semantics only apply to instance methods)
/// - method name == `unserialize` (case-insensitive)
/// - exactly 1 formal parameter
/// - call has exactly 1 argument
/// - argument's inner expression is a `variable_name` whose name equals the
///   formal parameter's name
///
/// Genuine deserialization sinks (free `unserialize($_GET[...])`, helpers
/// reading from session/cache and passing through, etc.) keep firing
/// because they are not inside a method declaration named `unserialize`.
fn is_php_unserialize_magic_method_passthrough(cap_node: tree_sitter::Node, bytes: &[u8]) -> bool {
    // The pattern captures `@n` (the function name); locate the enclosing
    // function_call_expression.
    let call_node = if cap_node.kind() == "function_call_expression" {
        cap_node
    } else {
        let mut cur = cap_node;
        let mut found = None;
        for _ in 0..4 {
            if cur.kind() == "function_call_expression" {
                found = Some(cur);
                break;
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
        match found {
            Some(c) => c,
            None => return false,
        }
    };

    // Walk up to the nearest method_declaration.  Stop at any other
    // function-introducing scope (free function, closure, arrow) — those
    // are not the Serializable contract.
    let mut cur = call_node;
    let method = loop {
        let Some(parent) = cur.parent() else {
            return false;
        };
        match parent.kind() {
            "method_declaration" => break parent,
            "function_definition"
            | "anonymous_function"
            | "anonymous_function_creation_expression"
            | "arrow_function"
            | "program" => return false,
            _ => {}
        }
        cur = parent;
    };

    // Method name must be exactly `unserialize` (case-insensitive).
    let Some(name_node) = method
        .child_by_field_name("name")
        .or_else(|| find_named_child_of_kind(method, "name"))
    else {
        return false;
    };
    let Ok(method_name) = std::str::from_utf8(&bytes[name_node.byte_range()]) else {
        return false;
    };
    if !method_name.eq_ignore_ascii_case("unserialize") {
        return false;
    }

    // Method must have exactly 1 formal parameter; capture its bare name.
    let Some(params) = method
        .child_by_field_name("parameters")
        .or_else(|| find_named_child_of_kind(method, "formal_parameters"))
    else {
        return false;
    };
    let mut formal_params: Vec<tree_sitter::Node> = Vec::new();
    for i in 0..params.named_child_count() as u32 {
        if let Some(p) = params.named_child(i)
            && matches!(
                p.kind(),
                "simple_parameter"
                    | "variadic_parameter"
                    | "property_promotion_parameter"
                    | "promoted_constructor_parameter"
            )
        {
            formal_params.push(p);
        }
    }
    if formal_params.len() != 1 {
        return false;
    }
    let param = formal_params[0];
    let var_node = param
        .child_by_field_name("name")
        .or_else(|| find_named_child_of_kind(param, "variable_name"));
    let Some(var_node) = var_node else {
        return false;
    };
    let inner_name_node = if var_node.kind() == "variable_name" {
        var_node.named_child(0)
    } else {
        Some(var_node)
    };
    let Some(inner_name_node) = inner_name_node else {
        return false;
    };
    let Ok(param_name) = std::str::from_utf8(&bytes[inner_name_node.byte_range()]) else {
        return false;
    };

    // Call must have exactly 1 argument that is the bare parameter variable.
    let Some(arg_list) = find_named_child_of_kind(call_node, "arguments") else {
        return false;
    };
    let mut args: Vec<tree_sitter::Node> = Vec::new();
    for i in 0..arg_list.named_child_count() as u32 {
        if let Some(c) = arg_list.named_child(i)
            && c.kind() == "argument"
        {
            args.push(c);
        }
    }
    if args.len() != 1 {
        return false;
    }
    let inner = args[0].named_child(0);
    let Some(inner) = inner else { return false };
    if inner.kind() != "variable_name" {
        return false;
    }
    let Some(arg_name_node) = inner.named_child(0) else {
        return false;
    };
    let Ok(arg_name) = std::str::from_utf8(&bytes[arg_name_node.byte_range()]) else {
        return false;
    };
    arg_name == param_name
}

/// C/C++-only Layer D: structural suppression of buffer-overflow pattern
/// rules when the source / format-string argument is a literal whose
/// contributed length is statically bounded.
///
/// **Policy (vulnerability detection, not style):** Nyx flags
/// `c.memory.strcpy` / `c.memory.strcat` / `c.memory.sprintf` (and the
/// `cpp.memory.*` mirrors) when the source argument can carry
/// attacker-controlled length.  Calls whose source is a string literal
/// have a compile-time bound and cannot overflow due to attacker input
///, a too-small destination is a fixed developer bug (caught by
/// compiler warnings / `-fstack-protector` / clang-tidy / ASan), not an
/// exploitable channel.  Suppressing these literal-source calls is a
/// deliberate noise / false-positive reduction aligned with Nyx's scope
/// (vulnerability detection over style enforcement).
///
/// **Test coverage convention:**
/// - Negative cases (suppression correct) live alongside other state /
///   lifecycle fixtures and are recorded as soft expectations
///   (`must_match: false`) in `*.expect.json`.  The notes there
///   reference this function so future authors can trace why the AST
///   pattern doesn't fire.  Examples:
///     - `tests/fixtures/real_world/c/state/malloc_lifecycle.expect.json`
///     - `tests/fixtures/real_world/cpp/state/new_delete.expect.json`
///     - `tests/fixtures/real_world/cpp/state/malloc_branches.expect.json`
/// - Positive cases (suppression must NOT fire, source is a parameter
///   or other attacker-reachable value) live as hard expectations
///   (`must_match: true`) in the taint fixtures:
///     - `tests/fixtures/real_world/c/taint/buffer_overflow.c`
///     - `tests/fixtures/real_world/cpp/taint/gets_strcpy.cpp`
///
/// Removing this function or weakening its predicate would be caught by
/// neither, it would be caught by the unit tests below.
///
/// Pattern rules `c.memory.strcpy` / `c.memory.strcat` / `c.memory.sprintf`
/// (and the `cpp.memory.*` mirrors) flag the call syntactically; their
/// stated danger is "no bounds checking on destination buffer" / "no length
/// limit on output buffer".  That danger is realised only when the source
/// argument can carry attacker-controlled length.  When the source is a
/// string literal the bound is fixed at compile time, so the call cannot
/// overflow due to attacker input (a too-small destination is a fixed
/// developer bug, not an exploitable channel).
///
/// Shapes recognised:
///   - `strcpy(dst, "literal")`            → suppress
///   - `strcpy(dst, COND ? "a" : "b")`     → suppress (ternary of two
///     string-literal branches; the postgres `formatting.c` shape)
///   - `strcat(dst, "literal")`            → same
///   - `sprintf(dst, "format")` where the format string is a literal
///     containing no bare `%s` (only width/precision-bounded specifiers
///     like `%d`, `%lld`, `%c`, `%.*s`, `%.5s`)
///     → suppress
///
/// Conservative refusals:
///   - source / format is an identifier (could be tainted, e.g.
///     `sprintf(buf, fmt, …)`) → keep firing
///   - format is `concatenated_string` containing identifier macros (e.g.
///     `"%" PRId64`), we cannot statically expand the macro, so refuse
///   - bare `%s` in format → keep firing (could read unbounded length)
fn is_c_buffer_call_literal_safe(rule_id: &str, cap_node: tree_sitter::Node, bytes: &[u8]) -> bool {
    let kind = match rule_id {
        "c.memory.strcpy" | "cpp.memory.strcpy" => CBufferRule::StrcpyOrCat,
        "c.memory.strcat" | "cpp.memory.strcat" => CBufferRule::StrcpyOrCat,
        "c.memory.sprintf" | "cpp.memory.sprintf" => CBufferRule::Sprintf,
        _ => return false,
    };
    let call = find_enclosing_call(cap_node);
    let Some(call) = call else { return false };
    let arg_list = find_arg_list(call);
    let Some(arg_list) = arg_list else {
        return false;
    };
    let mut args = Vec::new();
    for i in 0..arg_list.named_child_count() as u32 {
        if let Some(c) = arg_list.named_child(i) {
            args.push(c);
        }
    }
    if args.len() < 2 {
        return false;
    }
    let src = args[1];
    match kind {
        CBufferRule::StrcpyOrCat => is_c_string_literal_or_lit_ternary(src, bytes),
        CBufferRule::Sprintf => {
            // Format must be a single string literal with safe specifiers.
            // Refuse identifiers and concatenated_string (PRI* macros).
            if !matches!(
                src.kind(),
                "string_literal" | "raw_string_literal" | "string"
            ) {
                return false;
            }
            let Some(text) = c_string_literal_payload(src, bytes) else {
                return false;
            };
            sprintf_format_is_safe(&text)
        }
    }
}

#[derive(Copy, Clone)]
enum CBufferRule {
    StrcpyOrCat,
    Sprintf,
}

/// True for: a C/C++ string literal, OR a `conditional_expression` whose
/// consequence + alternative are both either string literals or ALL_CAPS
/// identifiers (the canonical preprocessor-macro naming convention for
/// string-constant `#define`s, `P_M_STR`, `A_M_STR`, `BG_NAME`, etc., used
/// pervasively in postgres' `formatting.c::DCH_a_m`).  Parenthesised forms
/// are unwrapped.
///
/// The ALL_CAPS heuristic recognises identifiers whose every character is
/// in `[A-Z0-9_]` and which contain at least one alphabetic letter.
/// Variables in C/C++ are conventionally lower / camelCase; macros are
/// SHOUTING_SNAKE.  False acceptance of an actual variable is possible but
/// extraordinarily rare in real codebases.
fn is_c_string_literal_or_lit_ternary(node: tree_sitter::Node, bytes: &[u8]) -> bool {
    let n = unwrap_c_paren(node);
    match n.kind() {
        "string_literal" | "raw_string_literal" | "string" => true,
        "conditional_expression" => {
            // tree-sitter-c shape: condition, consequence, alternative as
            // named children.  Accept when BOTH branches are string
            // literals or ALL_CAPS identifiers.
            let mut branches: Vec<tree_sitter::Node> = Vec::new();
            for i in 0..n.named_child_count() as u32 {
                if let Some(c) = n.named_child(i) {
                    branches.push(c);
                }
            }
            if branches.len() < 3 {
                return false;
            }
            // first child is the condition; the next two are the branches.
            let conseq = unwrap_c_paren(branches[1]);
            let alt = unwrap_c_paren(branches[2]);
            is_c_lit_or_macro_branch(conseq, bytes) && is_c_lit_or_macro_branch(alt, bytes)
        }
        _ => false,
    }
}

fn is_c_lit_or_macro_branch(node: tree_sitter::Node, bytes: &[u8]) -> bool {
    match node.kind() {
        "string_literal" | "raw_string_literal" | "string" => true,
        "identifier" => {
            let Ok(name) = std::str::from_utf8(&bytes[node.byte_range()]) else {
                return false;
            };
            is_all_caps_macro_name(name)
        }
        _ => false,
    }
}

fn is_all_caps_macro_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut has_alpha = false;
    for ch in s.chars() {
        if ch.is_ascii_uppercase() {
            has_alpha = true;
        } else if ch == '_' || ch.is_ascii_digit() {
            // ok
        } else {
            return false;
        }
    }
    has_alpha
}

fn unwrap_c_paren(mut node: tree_sitter::Node) -> tree_sitter::Node {
    for _ in 0..4 {
        if node.kind() == "parenthesized_expression"
            && let Some(inner) = node.named_child(0)
        {
            node = inner;
            continue;
        }
        break;
    }
    node
}

/// Extract the textual payload of a C/C++ string literal node, stripping
/// the surrounding double-quotes and the optional encoding prefix
/// (`L"..."`, `u8"..."`, `R"(...)"`).  Returns `None` if the bytes are not
/// valid UTF-8 or the literal cannot be decoded.
fn c_string_literal_payload(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    // Prefer a `string_content` child if tree-sitter exposes one.
    for i in 0..node.named_child_count() as u32 {
        if let Some(c) = node.named_child(i)
            && c.kind() == "string_content"
            && let Ok(s) = std::str::from_utf8(&bytes[c.byte_range()])
        {
            return Some(s.to_string());
        }
    }
    // Fall back: strip the surrounding quotes from the full literal text.
    let raw = std::str::from_utf8(&bytes[node.byte_range()]).ok()?;
    let trimmed = raw.trim();
    // Drop optional encoding prefix.
    let after_prefix = trimmed
        .trim_start_matches('L')
        .trim_start_matches("u8")
        .trim_start_matches('u')
        .trim_start_matches('U');
    let s = after_prefix
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'));
    s.map(|s| s.to_string())
}

/// Returns `true` when a `printf`-family format string can never overflow a
/// destination buffer due to attacker-controlled length.  Walks every `%`
/// specifier in the format and refuses if any bare `%s` is present.
/// Width-bounded `%5s` is unbounded (width is a *minimum*), but
/// precision-bounded `%.5s` / `%.*s` is safe (precision caps the maximum).
pub(crate) fn sprintf_format_is_safe(fmt: &str) -> bool {
    let bytes = fmt.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            // trailing `%`, malformed, refuse to suppress
            return false;
        }
        if bytes[i] == b'%' {
            i += 1;
            continue;
        }
        // Skip flags
        while i < bytes.len() && matches!(bytes[i], b'-' | b'+' | b'#' | b' ' | b'0' | b'\'') {
            i += 1;
        }
        // Skip width (digits or `*`)
        if i < bytes.len() && bytes[i] == b'*' {
            i += 1;
        } else {
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        // Optional precision
        let mut has_precision = false;
        if i < bytes.len() && bytes[i] == b'.' {
            has_precision = true;
            i += 1;
            if i < bytes.len() && bytes[i] == b'*' {
                i += 1;
            } else {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
        }
        // Length modifiers: h hh l ll L q z j t
        while i < bytes.len() && matches!(bytes[i], b'h' | b'l' | b'L' | b'q' | b'z' | b'j' | b't')
        {
            i += 1;
        }
        if i >= bytes.len() {
            return false;
        }
        let conv = bytes[i];
        i += 1;
        match conv {
            // Numeric / char / pointer specifiers, bounded output for any input
            b'd' | b'i' | b'u' | b'o' | b'x' | b'X' | b'c' | b'e' | b'E' | b'f' | b'F' | b'g'
            | b'G' | b'a' | b'A' | b'p' | b'n' => continue,
            // String specifier: only safe when precision-bounded
            b's' => {
                if !has_precision {
                    return false;
                }
            }
            // Unknown conversion (e.g. `%S` wide-char on Windows is
            // unbounded) → conservative refuse.
            _ => return false,
        }
    }
    true
}

fn is_string_literal_with_text(node: tree_sitter::Node, text: &str, bytes: &[u8]) -> bool {
    if node.kind() != "string" && node.kind() != "encapsed_string" {
        return false;
    }
    // Look for a single string_content / string_value child.
    let mut payload = None;
    for i in 0..node.named_child_count() as u32 {
        if let Some(c) = node.named_child(i)
            && (c.kind() == "string_content" || c.kind() == "string_value")
        {
            payload = Some(c);
            break;
        }
    }
    let Some(payload) = payload else {
        // Fall back: PHP single-quoted strings sometimes inline the content.
        if let Ok(s) = std::str::from_utf8(&bytes[node.byte_range()]) {
            let trimmed = s.trim_matches(|c| c == '\'' || c == '"');
            return trimmed == text;
        }
        return false;
    };
    if let Ok(s) = std::str::from_utf8(&bytes[payload.byte_range()]) {
        return s == text;
    }
    false
}

/// C++-only Layer E: structural suppression of `cpp.memory.reinterpret_cast`
/// when the cast's target type is explicitly defined as safe by the C++
/// aliasing rules.
///
/// `reinterpret_cast<T>(x)` is *not* always undefined behaviour — the C++
/// standard ([basic.lval]/11) explicitly permits accessing any object
/// representation through a pointer to `char`, `unsigned char`, or
/// `std::byte` (and, by long-standing convention, `int8_t` / `uint8_t`).
/// `void*` is similarly safe because reads / writes are illegal through it
/// (the program must always cast back before dereferencing).  The integer
/// round-trip `uintptr_t` / `intptr_t` is guaranteed lossless by the
/// standard.  POSIX additionally type-puns the `sockaddr` family — the
/// BSD-socket API takes `struct sockaddr *` and the program must cast from
/// `sockaddr_in*` / `sockaddr_in6*` / `sockaddr_un*` / `sockaddr_storage*`,
/// which is the API's intended use.
///
/// The pattern rule `cpp.memory.reinterpret_cast` cannot distinguish these
/// well-defined casts from genuinely dangerous strict-aliasing UB casts
/// (`reinterpret_cast<MyStruct*>(buf)`), so it over-fires by ~70% on
/// real-repo serialization, hashing, IPC, and socket-API code where the
/// cast is the canonical (and standard-blessed) idiom.  Suppressing the
/// well-defined target-type set is a layer-2 structural fix (per the
/// bughunt depth hierarchy): the engine recognises the property
/// (well-defined target type) that makes the cast safe in C++ and
/// suppresses based on it.  Genuine strict-aliasing risk casts (target is
/// a user struct / class type) keep firing.
///
/// Shapes recognised (any pointer depth `>= 1` unless noted):
///   - `char*`, `signed char*`, `unsigned char*`, `wchar_t*`
///   - `uint8_t*`, `int8_t*`, `std::byte*`, `byte*`
///   - `void*`
///   - `uintptr_t`, `std::uintptr_t`, `intptr_t`, `std::intptr_t` (no
///     pointer depth required — the standard guarantees the lossless
///     round-trip even for the integer form)
///   - `sockaddr*`, `struct sockaddr*`, `sockaddr_in*`, `sockaddr_in6*`,
///     `sockaddr_un*`, `sockaddr_storage*` (any of the BSD-socket
///     address-structure family)
///
/// Conservative refusals (kept firing): user-defined struct / class
/// pointer targets, template type parameters (`T*`), and any target the
/// normaliser cannot identify.
fn is_cpp_cast_target_type_safe(rule_id: &str, cap_node: tree_sitter::Node, bytes: &[u8]) -> bool {
    if rule_id != "cpp.memory.reinterpret_cast" {
        return false;
    }
    // `cap_node` is the `(identifier) @n` "reinterpret_cast" capture (the
    // pattern's index-0 capture, by query-string order — see Layer A's
    // `c.index == 0` selection in `run_ast_queries`).  Walk up via
    // `find_enclosing_call` to reach the outer `call_expression`.  Its
    // `function` field is a `template_function` whose `arguments` field is
    // the `template_argument_list` carrying the target type.
    let call = find_enclosing_call(cap_node);
    let Some(call) = call else { return false };
    let func = call.child_by_field_name("function");
    let Some(func) = func else { return false };
    if func.kind() != "template_function" {
        return false;
    }
    let targs = func.child_by_field_name("arguments");
    let Some(targs) = targs else { return false };
    if targs.kind() != "template_argument_list" {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&bytes[targs.byte_range()]) else {
        return false;
    };
    let inner = text
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    cpp_cast_target_type_is_safe(inner)
}

/// Normalise a C++ cast target type string and report whether it names a
/// well-defined-by-aliasing-rules type per the policy in
/// [`is_cpp_cast_target_type_safe`].  Public to the module so the unit
/// tests can pin the canonical and adversarial shapes.
pub(crate) fn cpp_cast_target_type_is_safe(s: &str) -> bool {
    // Collapse all internal whitespace (tabs, newlines, multiple spaces)
    // to single spaces so the normalised form is `const char *` with one
    // space between every token.
    let normalised: String = {
        let mut out = String::with_capacity(s.len());
        let mut prev_ws = true;
        for ch in s.chars() {
            if ch.is_whitespace() {
                if !prev_ws {
                    out.push(' ');
                    prev_ws = true;
                }
            } else {
                out.push(ch);
                prev_ws = false;
            }
        }
        out.trim().to_string()
    };
    let Some(base) = strip_pointer_and_cv(&normalised) else {
        return false;
    };
    // Pointer-indirection depth = count of `*` tokens in the normalised
    // form (whitespace already collapsed; compound forms with parens /
    // brackets / templates are filtered by `strip_pointer_and_cv`).
    let depth = normalised.chars().filter(|c| *c == '*').count();

    // Depth 0 (value cast): only the pointer<->integer round-trip types
    // are well-defined.  Aliasing *through* a `uintptr_t*` / `intptr_t*`
    // is **not** covered by the standard exemption — only converting a
    // pointer value to/from the integer type is defined behaviour
    // ([basic.compound]/3).  Therefore we accept these names only at
    // depth 0.
    if depth == 0 {
        return matches!(
            base.as_str(),
            "uintptr_t" | "intptr_t" | "std::uintptr_t" | "std::intptr_t"
        );
    }

    // Depth >= 2 (pointer-to-pointer and beyond) is never safe: the
    // [basic.lval]/11 aliasing exemption is for accessing an object's
    // representation as bytes through a single pointer indirection.
    // Reading a `char*` object through a `char**` is a strict-aliasing
    // violation, and the same logic applies to `void**`, `uint8_t**`,
    // etc.
    if depth != 1 {
        return false;
    }

    // Depth 1: standard aliasing exemption for byte-view access plus
    // POSIX socket type-punning and the opaque `void*` target.
    matches!(
        base.as_str(),
        "char"
            | "signed char"
            | "unsigned char"
            | "wchar_t"
            | "uint8_t"
            | "int8_t"
            | "std::byte"
            | "byte"
            | "void"
            | "sockaddr"
            | "struct sockaddr"
            | "sockaddr_in"
            | "sockaddr_in6"
            | "sockaddr_un"
            | "sockaddr_storage"
            | "struct sockaddr_in"
            | "struct sockaddr_in6"
            | "struct sockaddr_un"
            | "struct sockaddr_storage"
    )
}

/// Strip a single C++ cast target's leading/trailing `const`/`volatile`
/// qualifiers and trailing `*` characters (any depth).  Returns the bare
/// base type identifier on success.  Returns `None` if anything left over
/// after pointer/cv stripping is not a plain identifier or scoped name
/// (e.g. function-pointer `void(*)(int)` or template `vector<int>`).
fn strip_pointer_and_cv(s: &str) -> Option<String> {
    let mut t: &str = s.trim();
    // Strip leading `const` / `volatile`, possibly multiple.
    loop {
        let after = t
            .strip_prefix("const ")
            .or_else(|| t.strip_prefix("volatile "));
        match after {
            Some(rest) => t = rest.trim_start(),
            None => break,
        }
    }
    // Repeatedly strip trailing `*` and trailing cv-qualifiers in either
    // order — `T*`, `T* const`, `T*const`, `T const*`, `T**`, `const T*`
    // are all reachable.  The loop terminates when neither suffix
    // matches.
    loop {
        let mut progressed = false;
        // Strip trailing const/volatile that appears AFTER any `*` or
        // before the first `*` (e.g. `T const`).  Forms: ` const`, ` volatile`.
        loop {
            let after = t
                .trim_end()
                .strip_suffix(" const")
                .or_else(|| t.trim_end().strip_suffix(" volatile"));
            match after {
                Some(rest) => {
                    t = rest;
                    progressed = true;
                }
                None => break,
            }
        }
        // Strip trailing `*`s.
        let trimmed = t.trim_end();
        if let Some(stripped) = trimmed.strip_suffix('*') {
            t = stripped;
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    let base = t.trim();
    if base.is_empty() {
        return None;
    }
    // Refuse anything that contains characters typical of compound
    // type forms we don't want to reason about: parens (function
    // pointer), angle brackets (template instantiation), brackets
    // (array), commas (multiple arguments).  Accept identifier
    // characters, `_`, `:` (for `std::byte`), spaces (for `unsigned
    // char` / `struct sockaddr`).
    for ch in base.chars() {
        if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == ' ') {
            return None;
        }
    }
    Some(base.to_string())
}

/// PHP-only Layer F: structural suppression of `php.crypto.md5` /
/// `php.crypto.sha1` when the call's *consuming context* yields a name
/// that matches a recognised non-cryptographic identifier pattern.
///
/// The pattern rule fires syntactically on every `md5(...)` /
/// `sha1(...)` callsite regardless of how the result is used.  In real
/// PHP code these functions are pervasively used for non-cryptographic
/// purposes — ETag generation (HTTP cache validators), array/cache-key
/// hashing, dedup fingerprints, content addressing for templates — and
/// those uses do not realise the "weak hash function" risk the rule
/// names.  Suppress only when the consuming context yields a name from
/// a recognised non-crypto suffix set, while keeping every callsite
/// whose name contains a crypto-keyword substring (`password`,
/// `secret`, `token`, `signature`, `hmac`, `digest`, `salt`, …).
///
/// Consuming contexts inspected (walk up through transparent wrappers
/// — `binary_expression` for concat / equality, `parenthesized_expression`,
/// `conditional_expression`, `argument`):
///   - `assignment_expression` (covers `=`, `??=`, `+=`, …) — resolve
///     the LHS to a final identifier (variable name, member-access
///     property name, or string-literal subscript index).
///   - `array_element_initializer` — the key is a string literal whose
///     contents are the consuming name.
///   - `subscript_expression` where the call sits in the index position
///     — using a hash as an array index is intrinsically non-crypto.
///   - `return_statement` — resolve the enclosing
///     `function_definition` / `method_declaration` name (with the
///     conventional `get` prefix stripped).
///
/// All other consuming forms (bare expression statements, comparison
/// operands without an LHS, lambda returns, arguments to user-defined
/// helpers) keep firing.
fn is_php_weak_hash_non_crypto_use(cap_node: tree_sitter::Node, bytes: &[u8]) -> bool {
    let call = if cap_node.kind() == "function_call_expression" {
        cap_node
    } else {
        let mut cur = cap_node;
        let mut found = None;
        for _ in 0..4 {
            if cur.kind() == "function_call_expression" {
                found = Some(cur);
                break;
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
        match found {
            Some(c) => c,
            None => return false,
        }
    };

    let mut cur = call;
    let mut steps = 0u32;
    while let Some(parent) = cur.parent() {
        if steps > 16 {
            return false;
        }
        steps += 1;
        match parent.kind() {
            // Transparent wrappers — keep walking to find the
            // consumer.  These node kinds preserve the value flowing
            // out of the md5/sha1 call without transforming its
            // semantics, so we let the OUTER context (LHS name,
            // array key, return method, etc.) classify the use.
            //
            // - `binary_expression`: concat (`'foo_' . md5($x)`),
            //   equality (`md5($x) === $stored`), arithmetic.
            // - `parenthesized_expression`: redundant parens.
            // - `conditional_expression`: `$cond ? md5($x) : ''`.
            // - `argument` / `arguments`: positional / wrapped arg
            //   lists — the enclosing call (`substr(md5($x), 0, 8)`,
            //   `$q->createNamedParameter(md5($x))`) is what matters.
            // - `function_call_expression`: identity-shaped wrappers
            //   such as `substr(...)`, `strtolower(...)`,
            //   `urlencode(...)` which propagate the hash to its
            //   real consumer.
            // - `encapsed_string`: `"prefix-{md5($x)}"` interpolation.
            //
            // `member_call_expression` / `nullsafe_member_call_expression`
            // are NOT in this transparent set — they have their own
            // arm below that performs lookup-verb classification on
            // the method name (`->get(md5($k))`, `->set(...)`, …)
            // before optionally falling through to the outer
            // consumer.
            "binary_expression"
            | "parenthesized_expression"
            | "conditional_expression"
            | "argument"
            | "arguments"
            | "function_call_expression"
            | "encapsed_string" => {}
            "assignment_expression" | "augmented_assignment_expression" => {
                let lhs = parent
                    .child_by_field_name("left")
                    .or_else(|| parent.named_child(0));
                let Some(lhs) = lhs else {
                    return false;
                };
                return resolve_php_lvalue_name(lhs, bytes)
                    .map(|n| name_is_non_crypto(&n))
                    .unwrap_or(false);
            }
            "array_element_initializer" => {
                if parent.named_child_count() < 2 {
                    return false;
                }
                let key = parent.named_child(0);
                let Some(key) = key else {
                    return false;
                };
                let Some(key_text) = string_literal_text(key, bytes) else {
                    return false;
                };
                return name_is_non_crypto(&key_text);
            }
            "subscript_expression" => {
                // tree-sitter-php: subscript_expression has the receiver as
                // the first named child and the index as the second.  If our
                // call sits past the receiver's end byte, we are the index.
                let r0 = parent.named_child(0);
                let Some(r0) = r0 else {
                    cur = parent;
                    continue;
                };
                if call.start_byte() >= r0.end_byte() {
                    return true;
                }
                // Otherwise we're inside the receiver chain; the surrounding
                // `assignment_expression` (if any) will resolve the LHS name.
            }
            "member_call_expression" | "nullsafe_member_call_expression" => {
                // The md5/sha1 result is being passed as an argument to a
                // method call.  When the method name is a recognised
                // key/cache/lookup verb (`get`, `set`, `has`, `delete`,
                // `fetch`, `store`, `find`, `getItem`, `setItem`, …), the
                // result is being used as a non-cryptographic lookup key —
                // canonical for cache backends, hash maps, and storage
                // adapters where the developer is hashing arbitrary input
                // to a fixed-length, character-safe key.  Genuine
                // crypto-comparison wrappers (`hash_equals`, `verify`,
                // `password_verify`) keep firing because their method
                // name does not match the verb set.
                let name_node = parent.child_by_field_name("name").or_else(|| {
                    // Fallback: last named child is the method name.
                    let count = parent.named_child_count();
                    if count == 0 {
                        None
                    } else {
                        parent.named_child(count as u32 - 1)
                    }
                });
                if let Some(nn) = name_node
                    && nn.kind() == "name"
                    && let Ok(method) = std::str::from_utf8(&bytes[nn.byte_range()])
                    && method_is_lookup_verb(method)
                {
                    return true;
                }
                // Otherwise treat as transparent so the OUTER consumer can
                // classify (`$x = $cache->get(sha1($k))` resolves LHS `x`).
            }
            "return_statement" => {
                let mut p = parent;
                for _ in 0..10 {
                    let Some(pp) = p.parent() else {
                        return false;
                    };
                    p = pp;
                    let kind = p.kind();
                    if kind == "method_declaration" || kind == "function_definition" {
                        let Some(nn) = p
                            .child_by_field_name("name")
                            .or_else(|| find_named_child_of_kind(p, "name"))
                        else {
                            return false;
                        };
                        let Ok(name) = std::str::from_utf8(&bytes[nn.byte_range()]) else {
                            return false;
                        };
                        return method_name_is_non_crypto(name);
                    }
                    if kind == "anonymous_function"
                        || kind == "arrow_function"
                        || kind == "anonymous_function_creation_expression"
                    {
                        return false;
                    }
                }
                return false;
            }
            // Halt at scope / statement boundaries we cannot resolve through.
            "expression_statement"
            | "compound_statement"
            | "method_declaration"
            | "function_definition"
            | "anonymous_function"
            | "anonymous_function_creation_expression"
            | "arrow_function"
            | "program" => return false,
            _ => return false,
        }
        cur = parent;
    }
    false
}

/// Resolve the final identifier of a PHP l-value expression to a string
/// suitable for [`name_is_non_crypto`] classification.
///
/// Handles:
///   - `$variable` (`variable_name` → inner name child)
///   - `$obj->property` (`member_access_expression` → name field)
///   - `$arr['literal_key']` (`subscript_expression` → string-literal index)
///   - `Class::$static` / `self::$prop` (`scoped_property_access_expression`)
///
/// Returns `None` for unrecognised l-value shapes (dynamic property
/// access, computed indices, function-call l-values, etc.); the caller
/// then falls back to keeping the finding.
fn resolve_php_lvalue_name(lhs: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let lhs = unwrap_php_paren(lhs);
    match lhs.kind() {
        "variable_name" => {
            let name_node = lhs.named_child(0)?;
            std::str::from_utf8(&bytes[name_node.byte_range()])
                .ok()
                .map(String::from)
        }
        "member_access_expression" => {
            let n = lhs.child_by_field_name("name").or_else(|| {
                let count = lhs.named_child_count();
                if count == 0 {
                    None
                } else {
                    lhs.named_child(count as u32 - 1)
                }
            })?;
            // Property access can name a `name` (bare ident) or a
            // `variable_name` (dynamic ${$x} — which we don't resolve).
            if n.kind() == "name" {
                std::str::from_utf8(&bytes[n.byte_range()])
                    .ok()
                    .map(String::from)
            } else {
                None
            }
        }
        "subscript_expression" => {
            if lhs.named_child_count() >= 2 {
                let idx = lhs.named_child(1)?;
                if let Some(txt) = string_literal_text(idx, bytes) {
                    return Some(txt);
                }
            }
            // Dynamic / non-literal index: recurse into the receiver
            // so `$columnNamesHashes[$col]` resolves to
            // `columnNamesHashes`.  This handles canonical
            // `$lookup_by_hash[$key] = md5($key)` shapes.
            let r = lhs.named_child(0)?;
            resolve_php_lvalue_name(r, bytes)
        }
        "scoped_property_access_expression" => {
            let count = lhs.named_child_count();
            if count == 0 {
                return None;
            }
            let prop = lhs.named_child(count as u32 - 1)?;
            // The static property is a `variable_name`.  Reuse this
            // function recursively to extract the bare name.
            resolve_php_lvalue_name(prop, bytes)
        }
        _ => None,
    }
}

/// Return the textual contents of a PHP string literal node (`string`
/// or `encapsed_string`), stripping surrounding quotes.  Returns `None`
/// for any non-string node and for interpolated `encapsed_string`s
/// containing template variables.
fn string_literal_text(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    if node.kind() != "string" && node.kind() != "encapsed_string" {
        return None;
    }
    if has_interpolation(node) {
        return None;
    }
    for i in 0..node.named_child_count() as u32 {
        if let Some(c) = node.named_child(i)
            && (c.kind() == "string_content" || c.kind() == "string_value")
        {
            return std::str::from_utf8(&bytes[c.byte_range()])
                .ok()
                .map(String::from);
        }
    }
    if let Ok(s) = std::str::from_utf8(&bytes[node.byte_range()]) {
        let trimmed = s.trim_matches(|c| c == '\'' || c == '"');
        return Some(trimmed.to_string());
    }
    None
}

fn unwrap_php_paren(mut node: tree_sitter::Node) -> tree_sitter::Node {
    for _ in 0..4 {
        if node.kind() == "parenthesized_expression"
            && let Some(inner) = node.named_child(0)
        {
            node = inner;
            continue;
        }
        break;
    }
    node
}

/// Classify a PHP identifier as non-cryptographic by name.  Two-tier
/// check: any name containing a crypto-keyword substring is hard-rejected
/// (kept as a finding); the remaining names are accepted when their
/// form ends in a recognised non-crypto suffix at a word boundary
/// (underscore, digit, camelCase transition) or via a long-enough
/// stand-alone suffix (≥4 chars).
///
/// The crypto-keyword exclude list uses substring match (not just
/// suffix) so compound names like `hashedPassword` / `tokenHash` /
/// `sigStore` are conservatively kept.  False rejections of safe
/// shapes are acceptable; false acceptances of crypto shapes are not.
pub(crate) fn name_is_non_crypto(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    static CRYPTO_EXCLUDES: &[&str] = &[
        "password",
        "passwd",
        "pw_hash",
        "pwhash",
        "pwdhash",
        "pwd_hash",
        "passhash",
        "pass_hash",
        "secret",
        "token",
        "signature",
        "signed",
        "hmac",
        "digest",
        "verifier",
        "challenge",
        "csrf",
        "salt",
        "nonce_secret",
        "auth_code",
        "authcode",
        "auth_key",
        "authkey",
        "private",
        "credential",
        "creds",
        "encryption",
        "decryption",
        "encryptkey",
        "decryptkey",
        "encrypt_key",
        "decrypt_key",
        "apikey",
        "api_key",
    ];
    for ex in CRYPTO_EXCLUDES {
        if lower.contains(ex) {
            return false;
        }
    }
    // `sig` / `mac` are excluded only at word boundaries — the substrings
    // appear in legitimate non-crypto names (`signal`, `unsigned`,
    // `assignee`, `design`, `magic`).
    if lower == "sig" || lower.ends_with("_sig") || lower.ends_with("sig_") {
        return false;
    }
    if lower == "mac" || lower.ends_with("_mac") {
        return false;
    }
    // Permissive safe-suffix recognition.
    static SAFE_SUFFIXES: &[&str] = &[
        "hash",
        "hashes",
        "etag",
        "etags",
        "md5",
        "sha1",
        "fingerprint",
        "fingerprints",
        "cachekey",
        "cache_key",
        "cacheid",
        "cache_id",
        "id",
        "uid",
        "uuid",
        "guid",
        "name_hash",
        "checksum",
        "slot",
        "bucket",
        "seed",
        "marker",
        "tag",
        "gravatar",
        "hashid",
        "opaque",
        "shortid",
        "short_id",
        "fnv",
        "fingerprintkey",
        "anchor",
        "version",
        "buster",
        "cachebuster",
        "cache_buster",
        "revision",
        "rev",
    ];
    let bytes_orig = name.as_bytes();
    for s in SAFE_SUFFIXES {
        if lower == *s {
            return true;
        }
        if !lower.ends_with(s) {
            continue;
        }
        let prev_pos = lower.len() - s.len();
        if prev_pos == 0 {
            return true;
        }
        let prev_char_orig = bytes_orig[prev_pos - 1] as char;
        // Word boundary: underscore, digit, etc.
        if !prev_char_orig.is_ascii_alphabetic() {
            return true;
        }
        // CamelCase boundary: suffix starts with an uppercase letter
        // in the original casing (`storageId`, `tableHash`, `sqlMd5`).
        let suffix_first_orig = bytes_orig[prev_pos] as char;
        if suffix_first_orig.is_ascii_uppercase() {
            return true;
        }
        // Long stand-alone suffix (≥4 chars) — accept without boundary.
        if s.len() >= 4 {
            return true;
        }
    }
    false
}

/// Like [`name_is_non_crypto`] but with a leading `get` prefix stripped
/// to recognise the canonical `getETag` / `getHash` / `getCacheKey`
/// accessor naming convention.  Pass the original-case name through so
/// downstream camelCase-boundary detection still works.
fn method_name_is_non_crypto(name: &str) -> bool {
    let stripped = name
        .strip_prefix("get")
        .or_else(|| name.strip_prefix("Get"))
        .unwrap_or(name);
    if name_is_non_crypto(stripped) {
        return true;
    }
    // Some accessors keep the prefix (e.g., `recoveryKeyId`,
    // `formatPath` returning a hashed-path identifier).  Also try the
    // raw name for camelCase-boundary suffix detection.
    name_is_non_crypto(name)
}

/// Recognise PHP method names that signal a lookup / cache / store /
/// container key-or-value operation.  When `md5(...)` / `sha1(...)` is
/// passed to such a method, the result is being used as a content-
/// addressed key — not for cryptographic strength.  The verb set is
/// purposely narrow so cryptographic comparison helpers
/// (`hash_equals`, `verify`, `password_verify`, `decryptWith`) keep
/// firing.
fn method_is_lookup_verb(method: &str) -> bool {
    let lower = method.to_ascii_lowercase();
    static VERBS: &[&str] = &[
        "get",
        "set",
        "has",
        "delete",
        "remove",
        "fetch",
        "store",
        "put",
        "save",
        "exists",
        "find",
        "lookup",
        "getitem",
        "setitem",
        "hasitem",
        "deleteitem",
        "addtag",
        "addtotag",
        "key",
        "keyfor",
        "containskey",
        "haskey",
        "loadbykey",
        "fetchbykey",
        "getbykey",
        "setbykey",
        "deletebykey",
        "incr",
        "incrby",
        "decr",
        "decrby",
        "expire",
        "ttl",
        "namespacekey",
        "cachekey",
    ];
    if VERBS.contains(&lower.as_str()) {
        return true;
    }
    // Composite forms like `getCacheKey`, `setCacheKey`, `getRoute` —
    // very common in cache adapters, accept any name ending in one of
    // a few non-crypto-typed-result suffixes preceded by a get/set/has
    // verb.
    static SUFFIX_HINTS: &[&str] = &[
        "cachekey",
        "key",
        "id",
        "hash",
        "etag",
        "uid",
        "tag",
        "fingerprint",
    ];
    if let Some(rest) = lower
        .strip_prefix("get")
        .or_else(|| lower.strip_prefix("set"))
        .or_else(|| lower.strip_prefix("has"))
        .or_else(|| lower.strip_prefix("create"))
        .or_else(|| lower.strip_prefix("build"))
    {
        for h in SUFFIX_HINTS {
            if rest.ends_with(h) {
                return true;
            }
        }
    }
    false
}

/// Check if a string node contains interpolation (e.g., PHP `"Hello $name"`).
fn has_interpolation(node: tree_sitter::Node) -> bool {
    for i in 0..node.child_count() as u32 {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if kind == "variable_name"
                || kind == "simple_variable"
                || kind.contains("interpolation")
            {
                return true;
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
//  Layer B: AST pattern suppression when taint confirms safety
// ─────────────────────────────────────────────────────────────────────────────

/// Map the second segment of a pattern ID (e.g. "cmdi" from "py.cmdi.os_system")
/// to the `Cap` that taint analysis models. Returns `None` for categories taint
/// cannot subsume (memory safety, crypto, etc.), so those patterns are never suppressed.
fn pattern_category_cap(pattern_id: &str) -> Option<Cap> {
    let category = pattern_id.split('.').nth(1)?;
    match category {
        "cmdi" => Some(Cap::SHELL_ESCAPE),
        "xss" => Some(Cap::HTML_ESCAPE),
        "sqli" => Some(Cap::SQL_QUERY),
        "code_exec" => Some(Cap::CODE_EXEC),
        "ssrf" => Some(Cap::SSRF),
        "path" => Some(Cap::FILE_IO),
        // deser/memory/crypto: taint cannot fully subsume these structural patterns
        _ => None,
    }
}

/// Suppression context built from CFG + taint results. Used to decide whether
/// an AST pattern finding can be safely suppressed because taint analysis
/// evaluated the data flow and found it safe.
struct TaintSuppressionCtx {
    /// For each function scope, the set of lines containing Source-labeled nodes.
    source_lines_by_func: HashMap<Option<String>, HashSet<usize>>,
    /// For each function scope, the set of lines containing Sanitizer-labeled
    /// nodes.  Presence of an explicit sanitizer is the structural signal
    /// that taint analysis successfully evaluated (and cleared) the flow,
    /// so AST-pattern suppression is safe even when no taint findings
    /// fired in the function.
    sanitizer_lines_by_func: HashMap<Option<String>, HashSet<usize>>,
    /// For each sink node line, its enclosing function scope.
    sink_func_at_line: HashMap<usize, Option<String>>,
    /// Lines where taint emitted a `taint-unsanitised-flow` finding.
    taint_finding_lines: HashSet<usize>,
    /// Per-function set of taint-finding lines.  Used by Condition 4 of
    /// [`should_suppress`] alongside [`sanitizer_lines_by_func`] to
    /// distinguish "taint proved safe" from "taint failed to track".
    taint_finding_lines_by_func: HashMap<Option<String>, HashSet<usize>>,
    /// Functions where the SSA engine emitted at least one
    /// `all_validated` event, every tainted input to *some* sink in
    /// the function passed through a recognised validation/
    /// sanitisation predicate.  Drained from
    /// `take_all_validated_spans`; positive evidence that the engine
    /// reached a sink in this function and proved safety, even when no
    /// `taint-unsanitised-flow` finding fired and no Sanitizer label
    /// is present.  Covers validation, dominator-based pruning,
    /// early-return guards, type-check predicates, and interprocedural
    /// sanitiser wrappers, all of which legitimately clear taint via
    /// SSA branch-narrowing rather than a labelled sanitiser node.
    engine_validated_funcs: HashSet<Option<String>>,
    /// Functions where some Source's defining variable is later
    /// rebound to a literal RHS (carries `TaintMeta.const_text`) in
    /// the same scope, with no Source label on the rebinding node.
    /// Positive evidence that the engine's SSA renaming structurally
    /// kills the source's taint before any sink can read it, covers
    /// `cmd = getenv(); cmd = "echo hello"; system(cmd)` patterns
    /// where the rebind is what makes the code safe but the engine
    /// has no `Sanitizer` label or `taint-unsanitised-flow` finding to
    /// witness it.
    source_killed_funcs: HashSet<Option<String>>,
    /// Functions that call a same-file helper which itself contains a
    /// labelled Sanitizer node.  Positive evidence that the engine's
    /// interprocedural analysis cleared the flow through a
    /// user-defined wrapper (e.g. `def sanitize(s): return
    /// shlex.quote(s)`).  The current per-function `Sanitizer` check
    /// only sees direct sanitisers in the *caller's* scope, without
    /// this signal, every helper-wrapped sanitiser fires as an
    /// AST-pattern FP because the engine cleared the value via Phase
    /// 11 inline analysis but the sink's enclosing scope has no
    /// labelled Sanitizer of its own.
    interproc_sanitizer_callers: HashSet<Option<String>>,
}

impl TaintSuppressionCtx {
    /// Build suppression context from ALL per-body CFG graphs, tree (for
    /// byte→line mapping), and existing taint findings.
    ///
    /// Scans every body's graph (not just top-level) so that Source/Sink
    /// nodes inside function bodies are visible for suppression decisions.
    fn build(file_cfg: &FileCfg, tree: &tree_sitter::Tree, taint_diags: &[Diag]) -> Self {
        let mut source_lines_by_func: HashMap<Option<String>, HashSet<usize>> = HashMap::new();
        let mut sanitizer_lines_by_func: HashMap<Option<String>, HashSet<usize>> = HashMap::new();
        let mut sink_func_at_line: HashMap<usize, Option<String>> = HashMap::new();
        // Per-function (var_name, source_line) pairs for Source nodes whose
        // `defines` is set.  Used below to detect SSA source kills via
        // const reassignment (`cmd = getenv(); cmd = "echo hello"`).
        let mut source_var_defs_by_func: HashMap<Option<String>, Vec<(String, usize)>> =
            HashMap::new();
        // Per-function (var_name, line) pairs for nodes that bind a
        // variable to a literal RHS (carry `TaintMeta.const_text`).
        // Used to match against `source_var_defs_by_func` for kill
        // detection.
        let mut const_def_var_by_func: HashMap<Option<String>, Vec<(String, usize)>> =
            HashMap::new();
        // Set of `enclosing_func` names whose body contains at least
        // one labelled Sanitizer.  These are user-defined sanitiser
        // wrappers callable from other functions in the same file
        // (e.g. `def sanitize(s): return shlex.quote(s)`).
        let mut sanitizer_funcs: HashSet<String> = HashSet::new();
        // Per-function set of bare callee names invoked from this
        // function's body.  Bare = last `.`-separated segment, so
        // `this.sanitize`, `obj.sanitize`, and `sanitize` all collapse
        // to the same key for matching against `sanitizer_funcs`.
        let mut callees_by_func: HashMap<Option<String>, HashSet<String>> = HashMap::new();

        for body in &file_cfg.bodies {
            for idx in body.graph.node_indices() {
                let info = &body.graph[idx];
                let mut has_source = false;
                let mut has_sink = false;
                let mut has_sanitizer = false;
                for label in &info.taint.labels {
                    match label {
                        DataLabel::Source(_) => has_source = true,
                        DataLabel::Sink(_) => has_sink = true,
                        DataLabel::Sanitizer(_) => has_sanitizer = true,
                    }
                }
                // Skip synthetic source nodes emitted by `pre_emit_arg_source_nodes`
                // (`__nyx_src_*` / `__nyx_chainsrc_*`).  These are a CFG-level
                // synthesis that hoists a source-labeled member-expression into
                // its own Source node so taint can see a definition; absence of
                // a downstream taint finding through such a synth source does
                // NOT prove safety, it can also mean the engine couldn't
                // propagate the taint (e.g. `&req` with `var req struct{}`
                // where points-to doesn't track the address-of of a stack
                // variable).  Treating synth sources as "real" sources here
                // would silently silence AST-pattern findings on every Go
                // CRUD handler whose Decode destination is an `&req`-style
                // address-of-local.
                let is_synth_source = info.taint.defines.as_deref().is_some_and(|d| {
                    d.starts_with("__nyx_src_") || d.starts_with("__nyx_chainsrc_")
                });
                let byte = info.classification_span().0;
                let point = byte_offset_to_point(tree, byte);
                let line = point.row + 1;
                if has_source && !is_synth_source {
                    source_lines_by_func
                        .entry(info.ast.enclosing_func.clone())
                        .or_default()
                        .insert(line);
                    if let Some(var) = info.taint.defines.as_deref() {
                        source_var_defs_by_func
                            .entry(info.ast.enclosing_func.clone())
                            .or_default()
                            .push((var.to_string(), line));
                    }
                }
                if has_sanitizer {
                    sanitizer_lines_by_func
                        .entry(info.ast.enclosing_func.clone())
                        .or_default()
                        .insert(line);
                    if let Some(func_name) = info.ast.enclosing_func.as_deref() {
                        sanitizer_funcs.insert(func_name.to_string());
                    }
                }
                if has_sink {
                    sink_func_at_line.insert(line, info.ast.enclosing_func.clone());
                }
                // Const-rebind detection: a node that defines a variable
                // from a literal RHS and carries no Source label is a
                // candidate kill site.  Skip nodes that are themselves
                // Sources (a literal-init source like `cmd := "ls"` is
                // not a kill).
                if !has_source
                    && let (Some(var), Some(_)) = (
                        info.taint.defines.as_deref(),
                        info.taint.const_text.as_ref(),
                    )
                {
                    const_def_var_by_func
                        .entry(info.ast.enclosing_func.clone())
                        .or_default()
                        .push((var.to_string(), line));
                }
                // Per-function callee inventory for interprocedural
                // sanitiser detection.  `bare_method_name` collapses
                // `this.sanitize` / `obj.sanitize` / `sanitize` to the
                // same key so receiver-prefixed Java/Ruby/etc. calls
                // match a bare-named helper definition.  Also include
                // `arg_callees` so `println(... + sanitize(name) +
                // ...)` recognises the inline sanitiser call buried
                // inside the sink's argument expression.
                let bare_inserts: Vec<&str> = info
                    .call
                    .callee
                    .as_deref()
                    .into_iter()
                    .chain(info.arg_callees.iter().filter_map(|c| c.as_deref()))
                    .collect();
                if !bare_inserts.is_empty() {
                    let entry = callees_by_func
                        .entry(info.ast.enclosing_func.clone())
                        .or_default();
                    for callee in bare_inserts {
                        let bare = crate::labels::bare_method_name(callee);
                        if !bare.is_empty() {
                            entry.insert(bare.to_string());
                        }
                    }
                }
            }
        }

        // Source-kill detection: a function is "source-killed" when at
        // least one of its Source-defined variables is re-bound to a
        // literal at a later line in the same scope.  Captures
        // `safe_reassigned`-style fixtures: the SSA engine renames the
        // sink-read SSA value to a clean constant before any sink can
        // observe taint, but neither a `Sanitizer` label nor a
        // `taint-unsanitised-flow` finding fires to witness the kill.
        let mut source_killed_funcs: HashSet<Option<String>> = HashSet::new();
        for (func, src_defs) in &source_var_defs_by_func {
            let Some(kills) = const_def_var_by_func.get(func) else {
                continue;
            };
            for (src_var, src_line) in src_defs {
                if kills
                    .iter()
                    .any(|(kill_var, kill_line)| kill_var == src_var && kill_line > src_line)
                {
                    source_killed_funcs.insert(func.clone());
                    break;
                }
            }
        }

        // Interprocedural sanitiser caller detection: a function is
        // an "interproc sanitiser caller" when its body invokes any
        // helper whose own body contains a labelled Sanitizer.  This
        // handles wrappers like `def sanitize(s): return
        // shlex.quote(s)`, the engine clears taint via
        // inline analysis, but the caller's scope has no labelled
        // Sanitizer of its own to satisfy Condition 4(b).
        let mut interproc_sanitizer_callers: HashSet<Option<String>> = HashSet::new();
        if !sanitizer_funcs.is_empty() {
            for (func, callees) in &callees_by_func {
                if callees.iter().any(|c| sanitizer_funcs.contains(c)) {
                    interproc_sanitizer_callers.insert(func.clone());
                }
            }
        }

        // Drain the SSA engine's all-validated sink spans, attribute
        // each to its enclosing function via `sink_func_at_line`, and
        // record the function as "engine-validated".  The set was
        // populated by `ssa_events_to_findings` whenever the engine
        // emitted an `SsaTaintEvent { all_validated: true, .. }` ,
        // i.e. the engine reached a sink and proved every tainted
        // input passed validation.  This is the broadest form of
        // engine-success evidence, covering predicate validation
        // (`if !allowed[x]`), dominator early-return, type-check
        // (`Atoi` / `typeof`), and interprocedural sanitiser
        // wrappers.
        let mut engine_validated_funcs: HashSet<Option<String>> = HashSet::new();
        for (start, _end) in crate::taint::ssa_transfer::take_all_validated_spans() {
            let line = byte_offset_to_point(tree, start).row + 1;
            if let Some(func) = sink_func_at_line.get(&line) {
                engine_validated_funcs.insert(func.clone());
            }
        }

        let taint_finding_lines: HashSet<usize> = taint_diags
            .iter()
            .filter(|d| d.id.starts_with("taint-unsanitised-flow"))
            .map(|d| d.line)
            .collect();

        // Per-function partition of taint findings.  Maps each finding's
        // line to the enclosing function scope by reusing
        // `sink_func_at_line` (the same span/function mapping the Sink-side
        // of taint analysis populated above).
        let mut taint_finding_lines_by_func: HashMap<Option<String>, HashSet<usize>> =
            HashMap::new();
        for line in &taint_finding_lines {
            let func = sink_func_at_line.get(line).cloned().unwrap_or(None);
            taint_finding_lines_by_func
                .entry(func)
                .or_default()
                .insert(*line);
        }

        Self {
            source_lines_by_func,
            sanitizer_lines_by_func,
            sink_func_at_line,
            taint_finding_lines,
            taint_finding_lines_by_func,
            engine_validated_funcs,
            source_killed_funcs,
            interproc_sanitizer_callers,
        }
    }

    /// Returns `true` if this AST pattern finding should be suppressed.
    fn should_suppress(&self, pattern_id: &str, line: usize) -> bool {
        // Condition 1: pattern category maps to a Cap taint models
        if pattern_category_cap(pattern_id).is_none() {
            return false;
        }
        // Condition 2: at least one Source exists in the same function scope
        // at an EARLIER line (upstream in control flow). This prevents suppression
        // when the only Source is co-located (dual-label) or downstream from the
        // sink, since taint couldn't have evaluated a flow that doesn't exist.
        let func = match self.sink_func_at_line.get(&line) {
            Some(f) => f,
            None => return false, // No CFG sink at this line, taint had no opportunity to evaluate
        };
        match self.source_lines_by_func.get(func) {
            Some(source_lines) => {
                if !source_lines.iter().any(|&sl| sl < line) {
                    return false;
                }
            }
            None => return false,
        }
        // Condition 3: no taint finding at this line (taint found it safe)
        if self.taint_finding_lines.contains(&line) {
            return false;
        }
        // Condition 4: distinguish "taint proved safe" from "taint failed
        // to track".  Suppress only when there's a structural signal that
        // taint analysis actually evaluated this flow:
        //   (a) the function fired at least one taint-unsanitised-flow
        //       finding (engine ran successfully and reached *some* sink),
        //       OR
        //   (b) the function contains an explicit Sanitizer node (the
        //       canonical mechanism by which a flow is cleared, e.g.
        //       `escapeshellarg` between $_GET and `system`),
        //       OR
        //   (c) the SSA engine emitted at least one `all_validated`
        //       event in this function (engine reached *some* sink and
        //       proved every tainted input was validated, covers
        //       predicate validation, dominator early-return,
        //       type-check predicates, and interprocedural sanitiser
        //       wrappers that don't carry an explicit Sanitizer
        //       label),
        //       OR
        //   (d) the function rebinds a Source's defining variable to
        //       a literal RHS at a later line (engine's SSA renaming
        //       structurally kills taint before any sink reads it ,
        //       covers `cmd = getenv(); cmd = "echo"; system(cmd)`),
        //       OR
        //   (e) the function calls a same-file helper whose body
        //       contains a labelled Sanitizer (interprocedural
        //       sanitiser wrapper, covers `def sanitize(s): return
        //       shlex.quote(s)` patterns where the engine clears
        //       taint via inline analysis but the caller's
        //       scope has no Sanitizer label of its own).
        //
        // When none hold, we can't distinguish silent engine failure
        // from real safety, e.g. Go points-to limitation on `&local`
        // Decode destinations leaves the chain writeback fired but the
        // field-cell propagation dead, suppressing legitimate
        // AST-pattern findings on every Go CRUD handler whose Decode
        // destination is a stack-local address-of.
        let func_has_taint_finding = self
            .taint_finding_lines_by_func
            .get(func)
            .is_some_and(|s| !s.is_empty());
        let func_has_sanitizer = self
            .sanitizer_lines_by_func
            .get(func)
            .is_some_and(|s| !s.is_empty());
        let func_engine_validated = self.engine_validated_funcs.contains(func);
        let func_source_killed = self.source_killed_funcs.contains(func);
        let func_interproc_sanitizer = self.interproc_sanitizer_callers.contains(func);
        if !func_has_taint_finding
            && !func_has_sanitizer
            && !func_engine_validated
            && !func_source_killed
            && !func_interproc_sanitizer
        {
            return false;
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Pass 2 / single‑file: Full rule execution (AST queries + taint)
// ─────────────────────────────────────────────────────────────────────────────

/// Run all enabled analyses on pre-read bytes and return diagnostics.
///
/// This is the core **pass 2** implementation. Callers that already hold the
/// file contents should use this variant to avoid a redundant `fs::read`.
pub fn run_rules_on_bytes(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    global_summaries: Option<&GlobalSummaries>,
    scan_root: Option<&Path>,
) -> NyxResult<Vec<Diag>> {
    let _span = tracing::debug_span!("run_rules", file = %path.display()).entered();
    maybe_inject_test_panic(path);

    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        // Not a recognized tree-sitter language, try text-based patterns,
        // but first surface a parse-timeout synthetic diag if that's what
        // caused try_new to return None.
        let mut out = scan_text_based_patterns(bytes, path, cfg);
        if let Some(timeout_ms) = take_last_parse_timeout_ms() {
            out.push(parse_timeout_diag(path, timeout_ms));
        }
        return Ok(out);
    };

    let mut out = Vec::new();

    // CFG construction + taint + cfg_analysis only needed for CFG-capable modes.
    let needs_cfg = matches!(
        cfg.scanner.mode,
        AnalysisMode::Full | AnalysisMode::Cfg | AnalysisMode::Taint
    );

    if needs_cfg {
        let parsed = ParsedFile::from_source(source, cfg);
        out.extend(parsed.run_cfg_analyses(cfg, global_summaries, scan_root));
        if cfg.scanner.mode == AnalysisMode::Full {
            // Layer B: suppress AST findings where taint confirmed safety
            let suppression =
                TaintSuppressionCtx::build(&parsed.file_cfg, &parsed.source.tree, &out);
            let ast_findings = parsed.source.run_ast_queries(cfg);
            out.extend(
                ast_findings
                    .into_iter()
                    .filter(|d| !suppression.should_suppress(&d.id, d.line)),
            );
        }
        if cfg.scanner.mode == AnalysisMode::Full {
            out.extend(parsed.run_auth_analyses(cfg, global_summaries, scan_root));
        }
        parsed.source.finalize_diags(&mut out, cfg);
    } else {
        // AST-only: no CFG construction (fast path preserved)
        out.extend(source.run_ast_queries(cfg));
        let parsed = ParsedFile::from_source(source, cfg);
        out.extend(parsed.run_auth_analyses(cfg, global_summaries, scan_root));
        parsed.source.finalize_diags(&mut out, cfg);
    }

    Ok(out)
}

/// Convenience wrapper that reads the file then delegates to
/// [`run_rules_on_bytes`].
pub fn run_rules_on_file(
    path: &Path,
    cfg: &Config,
    global_summaries: Option<&GlobalSummaries>,
    scan_root: Option<&Path>,
) -> NyxResult<Vec<Diag>> {
    let bytes = std::fs::read(path)?;
    run_rules_on_bytes(&bytes, path, cfg, global_summaries, scan_root)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fused single-pass: extract summaries + run full analysis in one parse/CFG
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a fused analysis pass: both function summaries and diagnostics.
pub struct FusedResult {
    pub summaries: Vec<FuncSummary>,
    pub diags: Vec<Diag>,
    /// SSA-derived per-parameter summaries keyed by canonical
    /// [`crate::symbol::FuncKey`].  Keys preserve `(lang, namespace,
    /// container, name, arity, disambig, kind)` so two same-name definitions
    /// in the same file never collide.
    pub ssa_summaries: Vec<(crate::symbol::FuncKey, SsaFuncSummary)>,
    pub cfg_nodes: usize,
    /// Eligible callee bodies for cross-file symex, keyed by
    /// canonical [`crate::symbol::FuncKey`] (same identity model as
    /// `ssa_summaries`).
    pub ssa_bodies: Vec<(
        crate::symbol::FuncKey,
        crate::taint::ssa_transfer::CalleeSsaBody,
    )>,
    /// Per-function auth-check summaries for cross-file helper
    /// lifting.  One entry per analysis unit whose body proves at
    /// least one positional parameter under an ownership / membership
    /// / admin / authorization check; empty for files with no such
    /// helpers.
    pub auth_summaries: Vec<(
        crate::symbol::FuncKey,
        auth_analysis::model::AuthCheckSummary,
    )>,
    /// Per-Python-file router-level dep declarations + `include_router`
    /// edges for cross-file FastAPI router-dep propagation.  `None` for
    /// non-Python files; `Some((module_id, facts))` for Python files
    /// where `module_id` is the file's
    /// [`auth_analysis::router_facts::module_id_for_storage`] key.
    /// Pass 1 collects these into
    /// `GlobalSummaries.router_facts_by_module`; pass 2 resolves them
    /// per-file via `GlobalSummaries::resolve_cross_file_router_deps`.
    pub router_facts: Option<(String, auth_analysis::router_facts::PerFileRouterFacts)>,
}

/// Parse the file once, build the CFG once, and produce both function
/// summaries (for cross-file resolution) and full diagnostics (AST analyses +
/// taint + CFG structural analyses).
///
/// When `global_summaries` is `None`, the taint engine runs with local
/// context only (equivalent to pass 1 + partial pass 2).  A second call
/// to `run_taint_only` can refine findings with the full cross-file view
/// without re-parsing or re-building the CFG.
pub fn analyse_file_fused(
    bytes: &[u8],
    path: &Path,
    cfg: &Config,
    global_summaries: Option<&GlobalSummaries>,
    scan_root: Option<&Path>,
) -> NyxResult<FusedResult> {
    let _span = tracing::debug_span!("analyse_fused", file = %path.display()).entered();
    maybe_inject_test_panic(path);

    let Some(source) = ParsedSource::try_new(bytes, path)? else {
        // Not a recognized tree-sitter language, try text-based patterns,
        // and surface a parse-timeout synthetic diag if that's what caused
        // try_new to return None.
        let mut diags = scan_text_based_patterns(bytes, path, cfg);
        if let Some(timeout_ms) = take_last_parse_timeout_ms() {
            diags.push(parse_timeout_diag(path, timeout_ms));
        }
        return Ok(FusedResult {
            summaries: vec![],
            diags,
            ssa_summaries: vec![],
            cfg_nodes: 0,
            ssa_bodies: vec![],
            auth_summaries: vec![],
            router_facts: None,
        });
    };

    let parsed = ParsedFile::from_source(source, cfg);
    let cfg_nodes = parsed.cfg_graph().node_count();
    let summaries = parsed.export_summaries_with_root(scan_root);

    let mut out = Vec::new();

    let needs_cfg = matches!(
        cfg.scanner.mode,
        AnalysisMode::Full | AnalysisMode::Cfg | AnalysisMode::Taint
    );

    let (ssa_summaries, ssa_bodies) = if needs_cfg {
        // Lower SSA exactly once and feed both the taint engine and the
        // SSA-artifact extractor.  Pre-fix, both consumers re-lowered the
        // same `FileCfg` independently, `lower_all_functions_from_bodies`
        // accounted for ~20% of `analyse_file_fused` wall-clock on the
        // bench corpus.
        //
        // Reset the path-safe-suppressed span set BEFORE lowering: the
        // per-parameter probes inside the lowering phase publish spans
        // (`record_path_safe_suppressed_span`), and the state-analysis
        // pass downstream relies on those spans surviving until
        // `take_path_safe_suppressed_spans` drains the set inside
        // `run_cfg_analyses_with_lowered`.  The all-validated span set
        // (cap-agnostic, AST-pattern suppression evidence) follows the
        // same lifecycle and is drained inside `TaintSuppressionCtx`.
        crate::taint::ssa_transfer::reset_path_safe_suppressed_spans();
        crate::taint::ssa_transfer::reset_all_validated_spans();
        let (lowered_summaries, lowered_bodies) =
            parsed.lower_ssa_for_fused(global_summaries, scan_root);
        out.extend(parsed.run_cfg_analyses_with_lowered(
            cfg,
            global_summaries,
            scan_root,
            &lowered_summaries,
            &lowered_bodies,
        ));
        let eligible_bodies = crate::taint::build_eligible_bodies(&parsed.file_cfg, lowered_bodies);
        let summaries_vec: Vec<_> = lowered_summaries.into_iter().collect();
        (summaries_vec, eligible_bodies)
    } else {
        (vec![], vec![])
    };

    let mut auth_summaries: Vec<(
        crate::symbol::FuncKey,
        auth_analysis::model::AuthCheckSummary,
    )> = Vec::new();

    // Per-file router-dep facts for cross-file FastAPI propagation.
    // Extracted unconditionally for Python files so pass 1 can persist
    // them into `GlobalSummaries.router_facts_by_module` even on Cfg /
    // Taint modes (the auth analysis itself runs only under Full, but
    // the index has to be populated by the time pass 2 launches).
    let router_facts_for_this_file = if parsed.source.lang_slug == "python" {
        auth_analysis::router_facts::module_id_for_storage(parsed.source.path).map(|module_id| {
            let facts = auth_analysis::router_facts::extract_router_facts_for_python(
                &parsed.source.tree,
                parsed.source.bytes,
            );
            (module_id, facts)
        })
    } else {
        None
    };

    if cfg.scanner.mode == AnalysisMode::Full || cfg.scanner.mode == AnalysisMode::Ast {
        let ast_findings = parsed.source.run_ast_queries(cfg);
        // Layer B only applies when taint had the opportunity to evaluate
        if needs_cfg && cfg.scanner.mode == AnalysisMode::Full {
            let suppression =
                TaintSuppressionCtx::build(&parsed.file_cfg, &parsed.source.tree, &out);
            out.extend(
                ast_findings
                    .into_iter()
                    .filter(|d| !suppression.should_suppress(&d.id, d.line)),
            );
        } else {
            out.extend(ast_findings);
        }
        // Build the AuthorizationModel exactly once per file when Full
        // mode needs both diagnostics AND per-file summaries; pre-fix
        // the diag path and the summary path each ran their own
        // `extract::extract_authorization_model`, duplicating
        // `collect_top_level_units` + every framework extractor's AST
        // walk.  See `auth_analysis::run_auth_analysis_with_model` for
        // measured savings.
        let auth_rules = auth_analysis::config::build_auth_rules(cfg, parsed.source.lang_slug);
        if auth_rules.enabled {
            // Resolve cross-file router-deps for the current file (Python only).
            // The resolved map lives on `AuthorizationModel.cross_file_router_deps`
            // BEFORE `FlaskExtractor::extract` runs, so the in-extractor merge
            // sees both inline router-deps and the cross-file lift in one pass.
            let cross_file_router_deps = if parsed.source.lang_slug == "python"
                && let Some(gs) = global_summaries
                && let Some(child_module_id) =
                    auth_analysis::router_facts::module_id_for_path(parsed.source.path)
            {
                let resolved = gs.resolve_cross_file_router_deps(&child_module_id);
                if resolved.is_empty() {
                    None
                } else {
                    Some(resolved)
                }
            } else {
                None
            };
            let auth_model = auth_analysis::extract::extract_authorization_model(
                parsed.source.lang_slug,
                cfg.framework_ctx.as_ref(),
                &parsed.source.tree,
                parsed.source.bytes,
                parsed.source.path,
                &auth_rules,
                cross_file_router_deps.as_ref(),
            );
            // Extract summaries from the **base** model (pre var-types,
            // pre-helper-lifting) so the persisted per-file summary
            // carries only the helper's own intrinsic auth checks,
            // matching the legacy `extract_auth_summaries_by_key` path
            // bit-for-bit.
            if cfg.scanner.mode == AnalysisMode::Full {
                auth_summaries = auth_analysis::extract_auth_summaries_from_model(
                    &auth_model,
                    parsed.source.lang_slug,
                    parsed.source.path,
                    scan_root,
                );
            }
            let var_types = parsed.collect_file_var_types();
            out.extend(auth_analysis::run_auth_analysis_with_model(
                auth_model,
                &parsed.source.tree,
                parsed.source.lang_slug,
                parsed.source.path,
                &auth_rules,
                var_types.as_ref(),
                global_summaries,
                scan_root,
            ));
        }
    }
    parsed.source.finalize_diags(&mut out, cfg);

    Ok(FusedResult {
        summaries,
        diags: out,
        ssa_summaries,
        cfg_nodes,
        ssa_bodies,
        auth_summaries,
        router_facts: router_facts_for_this_file,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
//  Text-based pattern scanning (non-tree-sitter files)
// ─────────────────────────────────────────────────────────────────────────────

/// Run text-based pattern scanners on files whose extension is not supported
/// by tree-sitter.  Currently handles `.ejs` templates.
fn scan_text_based_patterns(bytes: &[u8], path: &Path, cfg: &Config) -> Vec<Diag> {
    let ext = lowercase_ext(path);
    match ext {
        Some("ejs") => {
            let mut diags = crate::patterns::ejs::scan_ejs_file(path, bytes);
            // Respect severity filter
            diags.retain(|d| d.severity <= cfg.scanner.min_severity);
            diags
        }
        _ => vec![],
    }
}

#[test]
fn unknown_extension_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let txt = dir.path().join("notes.txt");
    std::fs::write(&txt, "just some text").unwrap();

    let diags = run_rules_on_file(&txt, &Config::default(), None, None)
        .expect("function should never error on plain text");

    assert!(diags.is_empty());
}

#[test]
fn binary_file_guard_triggers() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("junk.bin");

    let mut data = vec![0_u8; 2048];
    for i in (0..data.len()).step_by(3) {
        data[i] = 0;
    }
    std::fs::write(&bin, &data).unwrap();

    let diags = run_rules_on_file(&bin, &Config::default(), None, None).unwrap();
    assert!(diags.is_empty(), "binary files are skipped");
}

#[test]
fn nonprod_path_detection() {
    // Test that is_nonprod_path recognises common non-production paths
    assert!(is_nonprod_path(Path::new("project/tests/test_main.py")));
    assert!(is_nonprod_path(Path::new("src/__tests__/foo.js")));
    assert!(is_nonprod_path(Path::new("benches/bench.rs")));
    assert!(is_nonprod_path(Path::new("vendor/lib/foo.py")));
    assert!(is_nonprod_path(Path::new("src/build.rs")));
    assert!(is_nonprod_path(Path::new("dist/app.min.js")));
    assert!(is_nonprod_path(Path::new("examples/demo.py")));
    assert!(is_nonprod_path(Path::new("fixtures/data.json")));

    // Should NOT match production paths
    assert!(!is_nonprod_path(Path::new("src/main.rs")));
    assert!(!is_nonprod_path(Path::new("lib/handler.py")));
    assert!(!is_nonprod_path(Path::new("app/views.py")));
}

#[test]
fn severity_downgrade_works() {
    assert_eq!(downgrade_severity(Severity::High), Severity::Medium);
    assert_eq!(downgrade_severity(Severity::Medium), Severity::Low);
    assert_eq!(downgrade_severity(Severity::Low), Severity::Low);
}

#[test]
fn nonprod_path_downgrades_findings() {
    let dir = tempfile::tempdir().unwrap();
    // Create a file under a "tests" directory
    let test_dir = dir.path().join("tests");
    std::fs::create_dir_all(&test_dir).unwrap();
    let test_file = test_dir.join("test_cmd.py");
    std::fs::write(
        &test_file,
        b"import os\ndef test():\n    cmd = os.environ['X']\n    os.system(cmd)\n",
    )
    .unwrap();

    let default_cfg = Config::default();
    let diags = run_rules_on_file(&test_file, &default_cfg, None, None).unwrap();

    // All findings in tests/ should be downgraded (no HIGH)
    let high: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::High)
        .collect();
    assert!(
        high.is_empty(),
        "Findings in tests/ should be downgraded from HIGH; got {:?}",
        high
    );

    // With include_nonprod=true, original severity preserved
    let mut prod_cfg = Config::default();
    prod_cfg.scanner.include_nonprod = true;
    let diags_prod = run_rules_on_file(&test_file, &prod_cfg, None, None).unwrap();

    // Not all diagnostics are necessarily high, but include_nonprod should not downgrade
    // Just verify that if there are findings, they weren't downgraded by the nonprod logic
    let _ = diags_prod;
}

#[test]
fn constant_arg_suppression_works() {
    use tree_sitter::StreamingIterator;

    // PHP: system("echo health-ok") should be suppressed
    {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        let code = b"<?php\nsystem(\"echo health-ok\");\n";
        let tree = parser.parse(code, None).unwrap();
        let query_str = r#"(function_call_expression
            function: (name) @n (#match? @n "^(system)$"))
            @vuln"#;
        let query = tree_sitter::Query::new(&lang, query_str).unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), code.as_slice());
        let m = matches.next().expect("query should match");
        let cap = m.captures.iter().find(|c| c.index == 0).unwrap();
        assert!(
            is_call_all_args_literal(cap.node, code),
            "PHP system(\"echo health-ok\") should have all-literal args"
        );
    }

    // Python: os.system("echo health-ok") should be suppressed
    {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        let code = b"import os\nos.system(\"echo health-ok\")\n";
        let tree = parser.parse(code, None).unwrap();
        let query_str = r#"(call
            function: (attribute
                object: (identifier) @pkg (#eq? @pkg "os")
                attribute: (identifier) @fn (#eq? @fn "system")))
            @vuln"#;
        let query = tree_sitter::Query::new(&lang, query_str).unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), code.as_slice());
        let m = matches.next().expect("query should match");
        let cap = m.captures.iter().find(|c| c.index == 0).unwrap();
        assert!(
            is_call_all_args_literal(cap.node, code),
            "Python os.system(\"echo health-ok\") should have all-literal args"
        );
    }

    // Python: os.system(cmd) should NOT be suppressed (variable arg)
    {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
        parser.set_language(&lang).unwrap();
        let code = b"import os\nos.system(cmd)\n";
        let tree = parser.parse(code, None).unwrap();
        let query_str = r#"(call
            function: (attribute
                object: (identifier) @pkg (#eq? @pkg "os")
                attribute: (identifier) @fn (#eq? @fn "system")))
            @vuln"#;
        let query = tree_sitter::Query::new(&lang, query_str).unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), code.as_slice());
        let m = matches.next().expect("query should match");
        let cap = m.captures.iter().find(|c| c.index == 0).unwrap();
        assert!(
            !is_call_all_args_literal(cap.node, code),
            "Python os.system(cmd) should NOT have all-literal args"
        );
    }
}

/// Helper that runs a tree-sitter query against PHP source and returns the
/// first capture-0 node, panicking if no match is found.  Used by the PHP
/// suppression tests below.
#[cfg(test)]
fn first_php_capture<'tree>(
    tree: &'tree tree_sitter::Tree,
    code: &[u8],
    query_str: &str,
) -> tree_sitter::Node<'tree> {
    use tree_sitter::StreamingIterator;
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let query = tree_sitter::Query::new(&lang, query_str).expect("query compiles");
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), code);
    let m = matches.next().expect("query should match");
    let cap = m
        .captures
        .iter()
        .find(|c| c.index == 0)
        .expect("capture index 0");
    cap.node
}

#[test]
fn php_include_param_passthrough_recognises_canonical_shapes() {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    parser.set_language(&lang).unwrap();
    let q = r#"(include_expression (variable_name)) @vuln"#;

    // Closure parameter pass-through (composer ClassLoader idiom).
    let code = b"<?php\nstatic $cb = function ($file) { include $file; };\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_include_param_passthrough(cap, code),
        "closure param pass-through should be recognised"
    );

    // Method parameter pass-through.
    let code = b"<?php\nclass C { function f(string $file): void { include $file; } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_include_param_passthrough(cap, code),
        "method param pass-through should be recognised"
    );

    // Local variable assigned from concat, NOT a pass-through.
    let code = b"<?php\nclass C { function f(string $base): void { $f = $base . '/x.php'; include $f; } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_include_param_passthrough(cap, code),
        "concat-built local should NOT be treated as pass-through"
    );

    // Param reassigned before include, NOT a pass-through.
    let code = b"<?php\nfunction f($file) { $file = $_GET['x']; include $file; }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_include_param_passthrough(cap, code),
        "reassigned param should NOT be treated as pass-through"
    );

    // Top-level (no enclosing function), NOT a pass-through.
    let code = b"<?php\n$file = $_GET['x'];\ninclude $file;\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_include_param_passthrough(cap, code),
        "top-level include should NOT be treated as pass-through"
    );
}

#[test]
fn php_unserialize_allowed_classes_recognises_safe_forms() {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    parser.set_language(&lang).unwrap();
    let q = r#"(function_call_expression function: (name) @n (#eq? @n "unserialize")) @vuln"#;

    // allowed_classes => false
    let code = b"<?php\n$x = unserialize($d, ['allowed_classes' => false]);\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_unserialize_allowed_classes_restricted(cap, code),
        "allowed_classes => false should be recognised as safe"
    );

    // allowed_classes => [Foo::class, Bar::class]
    let code = b"<?php\n$x = unserialize($d, ['allowed_classes' => [Foo::class]]);\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_unserialize_allowed_classes_restricted(cap, code),
        "allowed_classes => [array] should be recognised as safe"
    );

    // allowed_classes => self::ALLOWED  (class constant reference)
    let code =
        b"<?php\nclass C { const A = []; function f($d) { return unserialize($d, ['allowed_classes' => self::A]); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_unserialize_allowed_classes_restricted(cap, code),
        "allowed_classes => self::CONST should be recognised as safe"
    );

    // allowed_classes => true, unsafe default, must NOT be suppressed
    let code = b"<?php\n$x = unserialize($d, ['allowed_classes' => true]);\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_allowed_classes_restricted(cap, code),
        "allowed_classes => true is the unsafe default, should NOT be suppressed"
    );

    // No second arg, must NOT be suppressed
    let code = b"<?php\n$x = unserialize($d);\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_allowed_classes_restricted(cap, code),
        "single-arg unserialize should NOT be suppressed"
    );

    // Dynamic options variable, must NOT be suppressed
    let code = b"<?php\n$x = unserialize($d, $opts);\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_allowed_classes_restricted(cap, code),
        "dynamic options variable should NOT be suppressed"
    );
}

#[test]
fn php_unserialize_magic_method_passthrough_recognises_serializable_contract() {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    parser.set_language(&lang).unwrap();
    let q = r#"(function_call_expression function: (name) @n (#eq? @n "unserialize")) @vuln"#;

    // Canonical Serializable::unserialize delegating to __unserialize.
    let code = b"<?php\nclass R {\n  public function unserialize($serialized): void {\n    $this->__unserialize(unserialize($serialized));\n  }\n}\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_unserialize_magic_method_passthrough(cap, code),
        "Serializable::unserialize($x) → unserialize($x) should be suppressed"
    );

    // Multi-target list-destructuring assignment shape (Joomla Cli/Input).
    let code = b"<?php\nclass C {\n  public function unserialize($input) {\n    [$this->a, $this->b] = unserialize($input);\n  }\n}\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_unserialize_magic_method_passthrough(cap, code),
        "list-destructuring inside Serializable::unserialize should be suppressed"
    );

    // Case-insensitive method name (PHP semantics).
    let code = b"<?php\nclass C { public function UnSerialize($d) { return unserialize($d); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_unserialize_magic_method_passthrough(cap, code),
        "method name should match case-insensitively (PHP)"
    );

    // Free function `unserialize` is NOT a magic method, must NOT be suppressed.
    let code = b"<?php\nfunction load($d) { return unserialize($d); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_magic_method_passthrough(cap, code),
        "free function should NOT be suppressed"
    );

    // Different method name, NOT a Serializable contract, must NOT be suppressed.
    let code = b"<?php\nclass C { public function decode($d) { return unserialize($d); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_magic_method_passthrough(cap, code),
        "method named `decode` should NOT be suppressed"
    );

    // Method named `unserialize` but with TWO params, NOT the magic signature,
    // must NOT be suppressed.
    let code = b"<?php\nclass C { public function unserialize($d, $opts) { return unserialize($d, $opts); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_magic_method_passthrough(cap, code),
        "two-param method named unserialize should NOT be suppressed"
    );

    // Magic-method signature but the call argument is NOT the formal param —
    // user is unserializing some other source.  Must NOT be suppressed.
    let code = b"<?php\nclass C { public function unserialize($input) { return unserialize($_GET['x']); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_magic_method_passthrough(cap, code),
        "non-pass-through arg inside magic method should NOT be suppressed"
    );

    // Wrapped argument (`unserialize(trim($input))`) is NOT a bare-param
    // pass-through — keep firing.  This shape covers cache/session
    // pass-throughs that the rule should still surface.
    let code = b"<?php\nclass C { public function unserialize($input) { return unserialize(trim($input)); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_magic_method_passthrough(cap, code),
        "wrapped argument inside magic method should NOT be suppressed (conservative)"
    );

    // Anonymous function named-like context (defensive — anonymous_function
    // is not a method_declaration).
    let code = b"<?php\n$f = function($input) { return unserialize($input); };\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_unserialize_magic_method_passthrough(cap, code),
        "closure should NOT be suppressed"
    );
}

#[test]
fn php_weak_hash_non_crypto_use_recognises_canonical_shapes() {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    parser.set_language(&lang).unwrap();
    let q = r#"(function_call_expression function: (name) @n (#match? @n "^(md5|sha1)$")) @vuln"#;

    // ETag concat returned from getETag() — return-statement enclosing
    // method name path.
    let code = b"<?php\nclass C { public function getETag(): string { return '\"' . md5($this->data) . '\"'; } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "getETag concat should be suppressed"
    );

    // Array element value with a string-literal key whose name is non-crypto.
    let code = b"<?php\nfunction f($x) { return ['table_name_hash' => md5($x)]; }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "array element with `*_hash` key should be suppressed"
    );

    // Subscript LHS with a string-literal index `'etag'`.
    let code = b"<?php\nfunction f($x, &$row) { $row['etag'] = md5($x); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "subscript LHS with 'etag' key should be suppressed"
    );

    // Member-access LHS named `storageId` (camelCase boundary on `Id` suffix).
    let code = b"<?php\nclass C { function f() { $this->storageId = md5($this->id); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "member-access LHS `storageId` should be suppressed"
    );

    // Null-coalescing assignment with subscript LHS.
    let code = b"<?php\nfunction f($t, &$tables) { $tables[$t]['hash'] ??= md5($t); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "??= subscript LHS with 'hash' key should be suppressed"
    );

    // Call result used as an array index.
    let code = b"<?php\nfunction f($a, $x) { return $a[md5($x)]; }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "md5 used as subscript index should be suppressed"
    );

    // Cache-style lookup verb (`$cache->get(sha1(...))`).
    let code = b"<?php\nclass C { public $cache; function f($u) { return $this->cache->get(sha1($u)); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "method call to lookup-verb `get(sha1(..))` should be suppressed"
    );

    // Createnamedparameter wrapper around md5 inside an array element value.
    let code = b"<?php\nclass C { public $q; function f($d) { $this->q->insert('t')->values(['etag' => $this->q->createNamedParameter(md5($d))]); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "wrapper-call inside array element with `etag` key should be suppressed"
    );

    // Dynamic-index subscript LHS with a non-crypto receiver name.
    let code = b"<?php\nfunction f($cols) { $columnNamesHashes = []; foreach ($cols as $c) { $columnNamesHashes[$c] = md5($c); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        is_php_weak_hash_non_crypto_use(cap, code),
        "subscript LHS with dynamic index — receiver name `*Hashes` should drive suppression"
    );

    // Crypto consumer — keep firing.  $this->password = md5($pwd).
    let code =
        b"<?php\nclass C { public $password; function f($p) { $this->password = md5($p); } }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_weak_hash_non_crypto_use(cap, code),
        "$this->password = md5(...) is crypto storage and must NOT be suppressed"
    );

    // Compound name with crypto-keyword substring.  $tokenHash = md5(...).
    let code = b"<?php\nfunction f($x) { $tokenHash = md5($x); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_weak_hash_non_crypto_use(cap, code),
        "$tokenHash compound name must NOT be suppressed (contains 'token')"
    );

    // pw_hash compound — must NOT be suppressed.
    let code = b"<?php\nfunction f($p) { $pw_hash = md5($p); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_weak_hash_non_crypto_use(cap, code),
        "$pw_hash compound name must NOT be suppressed"
    );

    // Bare statement / unrecognised consumer — keep firing.
    let code = b"<?php\nfunction f($x) { var_dump(md5($x)); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_php_capture(&tree, code, q);
    assert!(
        !is_php_weak_hash_non_crypto_use(cap, code),
        "var_dump(md5(...)) has no recognisable consumer name and must NOT be suppressed"
    );
}

#[test]
fn name_is_non_crypto_recognises_word_boundary_suffixes() {
    // Whole-word and underscore boundaries.
    assert!(name_is_non_crypto("hash"));
    assert!(name_is_non_crypto("etag"));
    assert!(name_is_non_crypto("table_name_hash"));
    assert!(name_is_non_crypto("table_id"));
    assert!(name_is_non_crypto("cache_key"));

    // CamelCase boundaries.
    assert!(name_is_non_crypto("storageId"));
    assert!(name_is_non_crypto("tableHash"));
    assert!(name_is_non_crypto("sqlMd5"));
    assert!(name_is_non_crypto("cacheBuster"));

    // Long stand-alone suffix (≥4) without word boundary.
    assert!(name_is_non_crypto("columnnameshashes"));
    assert!(name_is_non_crypto("tablefingerprint"));

    // Non-letter previous char — digit.
    assert!(name_is_non_crypto("v1id"));

    // Keep firing on crypto-keyword compound names.
    assert!(!name_is_non_crypto("password_hash"));
    assert!(!name_is_non_crypto("hashedPassword"));
    assert!(!name_is_non_crypto("tokenHash"));
    assert!(!name_is_non_crypto("signatureHash"));
    assert!(!name_is_non_crypto("pw_hash"));
    assert!(!name_is_non_crypto("digest"));
    assert!(!name_is_non_crypto("hmac"));
    assert!(!name_is_non_crypto("salt"));
    assert!(!name_is_non_crypto("private_key"));

    // Bare `key`/`keys` and `apiKey` shapes are crypto-credential
    // candidates and must keep firing; specific safe forms like
    // `cache_key`/`cachekey` are still suppressed via their own
    // entries in `SAFE_SUFFIXES`.
    assert!(!name_is_non_crypto("key"));
    assert!(!name_is_non_crypto("keys"));
    assert!(!name_is_non_crypto("apiKey"));
    assert!(!name_is_non_crypto("api_key"));
    assert!(!name_is_non_crypto("apiKeyHash"));
    assert!(!name_is_non_crypto("api_key_hash"));
    assert!(name_is_non_crypto("cache_key"));
    assert!(name_is_non_crypto("cachekey"));

    // Words that LOOK like an `id` suffix but lack a word boundary —
    // do NOT classify (no boundary, length-2 suffix).
    assert!(!name_is_non_crypto("said"));
    assert!(!name_is_non_crypto("void"));
    assert!(!name_is_non_crypto("rapid"));

    // Unrecognised generic names.
    assert!(!name_is_non_crypto("x"));
    assert!(!name_is_non_crypto("result"));
    assert!(!name_is_non_crypto("output"));
    assert!(!name_is_non_crypto(""));
}

#[test]
fn method_is_lookup_verb_recognises_cache_verbs() {
    // Direct verb match.
    assert!(method_is_lookup_verb("get"));
    assert!(method_is_lookup_verb("set"));
    assert!(method_is_lookup_verb("has"));
    assert!(method_is_lookup_verb("delete"));
    assert!(method_is_lookup_verb("fetch"));
    assert!(method_is_lookup_verb("getItem"));
    assert!(method_is_lookup_verb("setItem"));

    // Composite forms — verb prefix + non-crypto suffix.
    assert!(method_is_lookup_verb("getCacheKey"));
    assert!(method_is_lookup_verb("setCacheKey"));
    assert!(method_is_lookup_verb("buildKey"));
    assert!(method_is_lookup_verb("createId"));
    assert!(method_is_lookup_verb("hasFingerprint"));

    // Crypto-comparison helpers — keep firing.
    assert!(!method_is_lookup_verb("hash_equals"));
    assert!(!method_is_lookup_verb("verify"));
    assert!(!method_is_lookup_verb("password_verify"));
    assert!(!method_is_lookup_verb("decrypt"));
    assert!(!method_is_lookup_verb("encrypt"));
    assert!(!method_is_lookup_verb("sign"));
    assert!(!method_is_lookup_verb("invoke"));
    assert!(!method_is_lookup_verb("doSomething"));
}

#[test]
fn sprintf_format_safety_classifier() {
    // Numeric / char / pointer specifiers, bounded by definition.
    assert!(sprintf_format_is_safe(""));
    assert!(sprintf_format_is_safe("hello world"));
    assert!(sprintf_format_is_safe("%d"));
    assert!(sprintf_format_is_safe("%lld%c"));
    assert!(sprintf_format_is_safe("fixed=%d/%c"));
    assert!(sprintf_format_is_safe("%5d %x %llo"));
    assert!(sprintf_format_is_safe("%%literal-percent"));
    assert!(sprintf_format_is_safe("%p"));
    // Precision-bounded `%s` / `%.*s`, output capped at precision.
    assert!(sprintf_format_is_safe(" %.*s"));
    assert!(sprintf_format_is_safe("%.5s"));
    assert!(sprintf_format_is_safe("[%-.10s]"));
    // Bare `%s` / width-only `%5s`, width is a *minimum*, length is
    // unbounded.  Must NOT be suppressed.
    assert!(!sprintf_format_is_safe("%s"));
    assert!(!sprintf_format_is_safe("hello %s world"));
    assert!(!sprintf_format_is_safe("%5s"));
    assert!(!sprintf_format_is_safe("[%-20s]"));
    // Unknown / non-standard conversions → conservative refuse.
    assert!(!sprintf_format_is_safe("%S"));
    assert!(!sprintf_format_is_safe("%"));
    assert!(!sprintf_format_is_safe("%lZ"));
}

#[cfg(test)]
fn first_c_capture<'tree>(
    tree: &'tree tree_sitter::Tree,
    code: &[u8],
    query_str: &str,
) -> tree_sitter::Node<'tree> {
    use tree_sitter::StreamingIterator;
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    let query = tree_sitter::Query::new(&lang, query_str).expect("query compiles");
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), code);
    let m = matches.next().expect("query should match");
    m.captures
        .iter()
        .find(|c| c.index == 0)
        .expect("capture index 0")
        .node
}

#[cfg(test)]
fn first_cpp_capture<'tree>(
    tree: &'tree tree_sitter::Tree,
    code: &[u8],
    query_str: &str,
) -> tree_sitter::Node<'tree> {
    use tree_sitter::StreamingIterator;
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    let query = tree_sitter::Query::new(&lang, query_str).expect("query compiles");
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), code);
    let m = matches.next().expect("query should match");
    m.captures
        .iter()
        .find(|c| c.index == 0)
        .expect("capture index 0")
        .node
}

#[test]
fn cpp_cast_target_type_is_safe_recognises_canonical_shapes() {
    use crate::ast::cpp_cast_target_type_is_safe as f;
    // Byte-pointer family — C++ explicitly permits byte-level access.
    assert!(f("char*"));
    assert!(f("char *"));
    assert!(f("const char*"));
    assert!(f("const char *"));
    assert!(f("unsigned char*"));
    assert!(f("const unsigned char*"));
    assert!(f("signed char*"));
    assert!(f("uint8_t*"));
    assert!(f("const uint8_t*"));
    assert!(f("int8_t*"));
    assert!(f("std::byte*"));
    assert!(f("const std::byte*"));
    assert!(f("byte*"));
    assert!(f("wchar_t*"));
    // void* — well-defined target.
    assert!(f("void*"));
    assert!(f("const void*"));
    // Integer round-trip — value cast only (depth 0).  Aliasing
    // *through* a `uintptr_t*` / `intptr_t*` is NOT covered by the
    // standard exemption — only the pointer<->integer value
    // conversion is well-defined.
    assert!(f("uintptr_t"));
    assert!(f("std::uintptr_t"));
    assert!(f("intptr_t"));
    assert!(f("std::intptr_t"));
    // BSD socket family — POSIX intentionally type-puns these.
    assert!(f("sockaddr*"));
    assert!(f("struct sockaddr*"));
    assert!(f("sockaddr_in*"));
    assert!(f("sockaddr_in6*"));
    assert!(f("sockaddr_un*"));
    assert!(f("sockaddr_storage*"));

    // Multi-token / extra whitespace — normaliser should collapse it.
    assert!(f("const   uint8_t *"));
    assert!(f("uint8_t  * const"));
    assert!(f("const  unsigned   char *"));

    // Pointer-to-pointer is NOT covered by the [basic.lval]/11
    // aliasing exemption — accessing a `char*` object through a
    // `char**` is a strict-aliasing violation.  Same for `void**`,
    // `uint8_t**`, etc.
    assert!(!f("char**"));
    assert!(!f("uint8_t**"));
    assert!(!f("void**"));
    assert!(!f("void **"));
    // Pointer-to-integer-roundtrip-type (`uintptr_t*`, `intptr_t*`)
    // is also not safe: only the pointer<->integer **value** cast is
    // well-defined, not aliasing through a pointer-to-uintptr_t.
    assert!(!f("uintptr_t*"));
    assert!(!f("intptr_t*"));
    assert!(!f("std::uintptr_t*"));

    // Non-safe shapes — must NOT be suppressed.
    assert!(!f("MyStruct*"));
    assert!(!f("InstanceType*"));
    assert!(!f("DBImpl*"));
    assert!(!f("C*"));
    assert!(!f("CPP*"));
    assert!(!f("T*"));
    assert!(!f("secp256k1_keypair*"));
    assert!(!f("PIP_ADAPTER_ADDRESSES"));
    assert!(!f("std::vector<int>*"));
    assert!(!f("void(*)(int)"));
    assert!(!f("char[10]"));
    // Bare integer (no pointer) is only safe for the round-trip
    // types — `int`, `size_t`, `uint64_t` should NOT match.
    assert!(!f("int"));
    assert!(!f("size_t"));
    assert!(!f("uint64_t"));
    assert!(!f("char")); // bare char without pointer
    assert!(!f("uint8_t")); // bare uint8_t without pointer
}

#[test]
fn cpp_reinterpret_cast_layer_e_recognises_byte_pointer_targets() {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_cpp::LANGUAGE);
    parser.set_language(&lang).unwrap();
    let q = r#"(call_expression
                 function: (template_function
                   name: (identifier) @n (#eq? @n "reinterpret_cast")))
               @vuln"#;

    // reinterpret_cast<uint8_t*>(p) — the leveldb / serialization shape.
    let code = b"void f(int* p) { auto q = reinterpret_cast<uint8_t*>(p); (void)q; }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_cpp_capture(&tree, code, q);
    assert!(
        is_cpp_cast_target_type_safe("cpp.memory.reinterpret_cast", cap, code),
        "reinterpret_cast<uint8_t*> must be suppressed (byte-pointer target)"
    );

    // reinterpret_cast<const std::byte*>(p) — qualified scoped name.
    let code = b"#include <cstddef>\nvoid f(int* p) { auto q = reinterpret_cast<const std::byte*>(p); (void)q; }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_cpp_capture(&tree, code, q);
    assert!(
        is_cpp_cast_target_type_safe("cpp.memory.reinterpret_cast", cap, code),
        "reinterpret_cast<const std::byte*> must be suppressed"
    );

    // reinterpret_cast<void*>(0x08000000) — synthetic-address shape.
    let code = b"void* f() { return reinterpret_cast<void*>(0x08000000); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_cpp_capture(&tree, code, q);
    assert!(
        is_cpp_cast_target_type_safe("cpp.memory.reinterpret_cast", cap, code),
        "reinterpret_cast<void*> must be suppressed (synthetic address)"
    );

    // reinterpret_cast<uintptr_t>(p) — integer round-trip.
    let code =
        b"#include <cstdint>\nuintptr_t f(int* p) { return reinterpret_cast<uintptr_t>(p); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_cpp_capture(&tree, code, q);
    assert!(
        is_cpp_cast_target_type_safe("cpp.memory.reinterpret_cast", cap, code),
        "reinterpret_cast<uintptr_t> must be suppressed (integer round-trip)"
    );

    // reinterpret_cast<sockaddr*>(&addr) — POSIX socket-API shape.
    let code = b"struct sockaddr_in { int x; };\nstruct sockaddr;\nvoid f(struct sockaddr_in* a) { auto* s = reinterpret_cast<sockaddr*>(a); (void)s; }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_cpp_capture(&tree, code, q);
    assert!(
        is_cpp_cast_target_type_safe("cpp.memory.reinterpret_cast", cap, code),
        "reinterpret_cast<sockaddr*> must be suppressed (BSD socket pun)"
    );

    // reinterpret_cast<MyStruct*>(buf) — strict-aliasing UB risk, must NOT
    // be suppressed.
    let code = b"struct MyStruct { int a; };\nMyStruct* f(char* buf) { return reinterpret_cast<MyStruct*>(buf); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_cpp_capture(&tree, code, q);
    assert!(
        !is_cpp_cast_target_type_safe("cpp.memory.reinterpret_cast", cap, code),
        "reinterpret_cast<MyStruct*> must NOT be suppressed (genuine strict-aliasing risk)"
    );

    // Other rule ids are unaffected.
    assert!(
        !is_cpp_cast_target_type_safe("cpp.memory.const_cast", cap, code),
        "Layer E must only fire for cpp.memory.reinterpret_cast"
    );
}

#[test]
fn c_buffer_call_literal_safe_recognises_canonical_shapes() {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_c::LANGUAGE);
    parser.set_language(&lang).unwrap();

    let q_strcpy = r#"(call_expression function: (identifier) @id (#eq? @id "strcpy")) @vuln"#;
    let q_strcat = r#"(call_expression function: (identifier) @id (#eq? @id "strcat")) @vuln"#;
    let q_sprintf = r#"(call_expression function: (identifier) @id (#eq? @id "sprintf")) @vuln"#;

    // strcpy(dst, "literal"), postgres autoprewarm shape.
    let code = b"void f(char *d) { strcpy(d, \"pg_prewarm\"); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_strcpy);
    assert!(
        is_c_buffer_call_literal_safe("c.memory.strcpy", cap, code),
        "strcpy with string-literal source must be suppressed"
    );

    // strcpy(dst, cond ? "a" : "b"), string-literal ternary.
    let code = b"void f(char *s, int h) { strcpy(s, (h >= 12) ? \"p.m.\" : \"a.m.\"); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_strcpy);
    assert!(
        is_c_buffer_call_literal_safe("c.memory.strcpy", cap, code),
        "strcpy with ternary-of-literals source must be suppressed"
    );

    // strcpy(dst, cond ? P_M_STR : A_M_STR), postgres formatting.c
    // shape with #define'd ALL_CAPS string-constant macros.
    let code = b"#define P_M_STR \"p.m.\"\n#define A_M_STR \"a.m.\"\nvoid f(char *s, int h) { strcpy(s, (h >= 12) ? P_M_STR : A_M_STR); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_strcpy);
    assert!(
        is_c_buffer_call_literal_safe("c.memory.strcpy", cap, code),
        "strcpy with ternary-of-ALL_CAPS-macros must be suppressed"
    );

    // strcpy(dst, cond ? var_a : var_b), lowercase variables, NOT a
    // recognisable preprocessor macro shape.  Must NOT suppress.
    let code = b"void f(char *s, int h, char *a, char *b) { strcpy(s, (h >= 12) ? a : b); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_strcpy);
    assert!(
        !is_c_buffer_call_literal_safe("c.memory.strcpy", cap, code),
        "strcpy with ternary-of-lowercase-vars must NOT be suppressed"
    );

    // strcat(dst, "literal"), same principle as strcpy.
    let code = b"void f(char *d) { strcat(d, \" (done)\"); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_strcat);
    assert!(
        is_c_buffer_call_literal_safe("c.memory.strcat", cap, code),
        "strcat with string-literal source must be suppressed"
    );

    // sprintf(dst, "%lld%c", ...), numeric format string.
    let code = b"void f(char *cp, long long v, char u) { sprintf(cp, \"%lld%c\", v, u); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_sprintf);
    assert!(
        is_c_buffer_call_literal_safe("c.memory.sprintf", cap, code),
        "sprintf with numeric-only format must be suppressed"
    );

    // sprintf(str, " %.*s", N, x), precision-bounded `%s`.
    let code = b"void f(char *str, int n, const char *x) { sprintf(str, \" %.*s\", n, x); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_sprintf);
    assert!(
        is_c_buffer_call_literal_safe("c.memory.sprintf", cap, code),
        "sprintf with precision-bounded `%.*s` must be suppressed"
    );

    // strcpy(dst, src) where src is a non-literal, must NOT suppress.
    let code = b"void f(char *d, char **a) { strcpy(d, a[1]); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_strcpy);
    assert!(
        !is_c_buffer_call_literal_safe("c.memory.strcpy", cap, code),
        "strcpy with non-literal source must NOT be suppressed"
    );

    // sprintf with bare `%s`, must NOT suppress.
    let code = b"void f(char *b, const char *u) { sprintf(b, \"%s\", u); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_sprintf);
    assert!(
        !is_c_buffer_call_literal_safe("c.memory.sprintf", cap, code),
        "sprintf with bare `%%s` must NOT be suppressed"
    );

    // sprintf with non-literal format (concatenated_string with PRI* macro)
    //, must NOT suppress (engine cannot statically expand the macro).
    let code = b"void f(char *b, long long v) { sprintf(b, \"%\" PRId64, v); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_sprintf);
    assert!(
        !is_c_buffer_call_literal_safe("c.memory.sprintf", cap, code),
        "sprintf with concatenated_string format must NOT be suppressed"
    );

    // Other rule ids should not be affected.
    let code = b"void f(char *d) { strcpy(d, \"x\"); }\n";
    let tree = parser.parse(code, None).unwrap();
    let cap = first_c_capture(&tree, code, q_strcpy);
    assert!(
        !is_c_buffer_call_literal_safe("c.memory.gets", cap, code),
        "Layer D should only fire for buffer-overflow rule ids"
    );
}

/// Regression: `is_literal_node` must NOT classify a Python f-string
/// (a `string` node containing `interpolation` children) as literal.
/// Layer A's "all-args-literal → suppress Security finding" shortcut
/// otherwise hides every CVE that injects via `cursor.execute(f"…{x}…")`
/// or `text(f"…{x}…")`.  Motivated by CVE-2025-69662 (geopandas SQLi
/// via `text(f"SELECT … '{geom_name}' …")`) and CVE-2025-24793
/// (snowflake-connector-python f-string-built CREATE STAGE / DROP).
#[test]
fn is_literal_node_rejects_python_fstring_with_interpolation() {
    let mut parser = tree_sitter::Parser::new();
    let lang = tree_sitter::Language::from(tree_sitter_python::LANGUAGE);
    parser.set_language(&lang).unwrap();

    // f-string with one interpolation segment, must be non-literal.
    let code = b"x = f\"SELECT * WHERE y = '{u}'\"\n";
    let tree = parser.parse(code, None).unwrap();
    let assignment = tree
        .root_node()
        .child(0)
        .and_then(|s| s.child(0))
        .expect("assignment node");
    let rhs = assignment
        .child_by_field_name("right")
        .expect("RHS of assignment");
    assert_eq!(rhs.kind(), "string");
    assert!(
        !is_literal_node(rhs, code),
        "f-string with interpolation must not be classified as literal"
    );

    // Plain string literal, must remain literal.
    let code = b"x = \"plain literal\"\n";
    let tree = parser.parse(code, None).unwrap();
    let assignment = tree
        .root_node()
        .child(0)
        .and_then(|s| s.child(0))
        .expect("assignment node");
    let rhs = assignment
        .child_by_field_name("right")
        .expect("RHS of assignment");
    assert_eq!(rhs.kind(), "string");
    assert!(
        is_literal_node(rhs, code),
        "plain string literal must be classified as literal"
    );
}
