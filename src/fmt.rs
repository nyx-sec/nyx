//! Console output formatting for scan diagnostics.
//!
//! Produces professional, security-tool-grade aligned output with a clear
//! severity hierarchy, normalised taint flow rendering, and stable wrapping.
#![allow(clippy::collapsible_if)]

use crate::commands::scan::{Diag, SuppressionStats};
use crate::patterns::Severity;
use console::style;
use std::collections::BTreeMap;

/// Default maximum line width when terminal size is unknown.
const DEFAULT_WIDTH: usize = 100;

// ─────────────────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Render all diagnostics as grouped, formatted console output with a summary.
pub fn render_console(
    diags: &[Diag],
    project_name: &str,
    suppression_stats: Option<&SuppressionStats>,
) -> String {
    let width = terminal_width();
    let mut out = String::new();

    let mut grouped: BTreeMap<&str, Vec<&Diag>> = BTreeMap::new();
    for d in diags {
        grouped.entry(&d.path).or_default().push(d);
    }

    for (path, issues) in &grouped {
        // File path header, dim blue, never brighter than severity.
        out.push_str(&format!("{}\n", style(path).blue().dim().underlined()));
        for d in issues {
            out.push_str(&render_diag(d, width));
            out.push('\n'); // blank line between findings
        }
    }

    let suppressed_count = diags.iter().filter(|d| d.suppressed).count();
    let active_count = diags.len() - suppressed_count;

    if suppressed_count > 0 {
        out.push_str(&format!(
            "{} '{}' generated {} {} ({} suppressed).\n\n",
            style("warning").yellow().bold(),
            style(project_name).white().bold(),
            style(active_count).bold(),
            if active_count == 1 { "issue" } else { "issues" },
            suppressed_count,
        ));
    } else {
        out.push_str(&format!(
            "{} '{}' generated {} {}.\n\n",
            style("warning").yellow().bold(),
            style(project_name).white().bold(),
            style(diags.len()).bold(),
            if diags.len() == 1 { "issue" } else { "issues" },
        ));
    }

    // ── Suppression footer ─────────────────────────────────────────────
    if let Some(stats) = suppression_stats {
        let total = stats.total_suppressed();
        if total > 0 {
            out.push_str(&format!(
                "{}\n",
                style(format!("Suppressed {total} LOW/Quality findings.")).dim()
            ));
            out.push_str(&format!("{}\n", style("Active filters:").dim()));
            if !stats.include_quality {
                out.push_str(&format!(
                    "  {} {}\n",
                    style("include_quality =").dim(),
                    style("false").dim()
                ));
            }
            out.push_str(&format!(
                "  {} {}\n",
                style("max_low =").dim(),
                style(stats.max_low).dim()
            ));
            out.push_str(&format!(
                "  {} {}\n",
                style("max_low_per_file =").dim(),
                style(stats.max_low_per_file).dim()
            ));
            out.push_str(&format!(
                "  {} {}\n",
                style("max_low_per_rule =").dim(),
                style(stats.max_low_per_rule).dim()
            ));
            out.push_str(&format!(
                "\n{}\n",
                style("Use --include-quality, --max-low, or --all to adjust.").dim()
            ));
        }
    }

    out
}

/// Normalise a code snippet for display: collapse whitespace, join lines,
/// clean up method-chain spacing, trim, and truncate.
pub fn normalize_snippet(s: &str) -> String {
    // Strip newlines/carriage returns with no replacement, then collapse
    // runs of spaces into a single space.
    let no_newlines: String = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    let collapsed: String = no_newlines.split_whitespace().collect::<Vec<_>>().join(" ");
    // Clean up `) .foo(` → `).foo(` and similar spacing around dots in chains.
    let cleaned = collapse_chain_spacing(&collapsed);
    let trimmed = cleaned.trim();
    if trimmed.len() > 120 {
        let trunc = match trimmed.char_indices().nth(120) {
            Some((i, _)) => &trimmed[..i],
            None => trimmed,
        };
        format!("{trunc}…")
    } else {
        trimmed.to_string()
    }
}

/// Truncate method chains: keep constructor + first balanced `(...)`, then `…`.
///
/// E.g. `Command::new("sh").arg("-c").arg(&cmd)` → `Command::new("sh")…`
#[allow(dead_code)] // public API, used by consumers
pub fn shorten_callee(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }

    let Some(open) = s.find('(') else {
        return s.to_string();
    };

    let mut depth = 0u32;
    let mut close = None;
    for (i, ch) in s[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }

    let Some(close_idx) = close else {
        return s.to_string();
    };

    let end = close_idx + 1;
    if end < s.len() {
        format!("{}…", &s[..end])
    } else {
        s.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Welcome screen
// ─────────────────────────────────────────────────────────────────────────────

/// Render the branded welcome screen shown when `nyx` is invoked with no arguments.
pub fn render_welcome() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let mut out = String::new();

    out.push('\n');

    for line in LOGO {
        out.push_str(&format!(
            "  {}\n",
            style(line).true_color(114, 243, 215).bold()
        ));
    }

    out.push_str(&format!(
        "\n{}  {}\n",
        style(format!("v{version}")).dim(),
        style("static analysis engine").dim(),
    ));
    out.push_str(&format!(
        "{}\n",
        style("────────────────────────────────────────").dim()
    ));
    out.push('\n');

    out.push_str(&format!("{}\n\n", style("Getting started").bold()));
    for &(cmd, desc) in &[
        ("nyx scan", "Scan the current directory"),
        ("nyx serve", "Start the web dashboard"),
        ("nyx config show", "Show current configuration"),
    ] {
        out.push_str(&format!(
            "  {}  {}\n",
            style(format!("{cmd:<18}")).green(),
            style(desc).dim(),
        ));
    }
    out.push('\n');

    out.push_str(&format!("{}\n\n", style("More help").bold()));
    for &(cmd, desc) in &[
        ("nyx --help", "All commands"),
        ("nyx <command> --help", "Help for a specific command"),
    ] {
        out.push_str(&format!(
            "  {}  {}\n",
            style(format!("{cmd:<22}")).white(),
            style(desc).dim(),
        ));
    }
    out.push('\n');

    out
}

const LOGO: &[&str] = &[
    r"███╗   ██╗██╗   ██╗██╗  ██╗",
    r"████╗  ██║╚██╗ ██╔╝╚██╗██╔╝",
    r"██╔██╗ ██║ ╚████╔╝  ╚███╔╝",
    r"██║╚██╗██║  ╚██╔╝   ██╔██╗",
    r"██║ ╚████║   ██║   ██╔╝ ██╗",
    r"╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝",
];

// ─────────────────────────────────────────────────────────────────────────────
//  Internal rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Indentation for body/evidence lines (spaces).
const BODY_INDENT: usize = 6;

/// Render a single diagnostic block.
fn render_diag(d: &Diag, width: usize) -> String {
    let mut out = String::new();

    // ── Header line ──────────────────────────────────────────────────────
    // Format: `  98:5  ⚠ [MEDIUM] taint-unsanitised-flow  (Score: 87, Confidence: Medium)`
    let loc = format!("{}:{}", d.line, d.col);
    let sev = if d.suppressed {
        format!("{} {}", style("○").dim(), style("[SUPPRESSED]").dim(),)
    } else {
        severity_tag(d.severity)
    };
    let meta_suffix = match (d.rank_score, d.confidence) {
        (Some(s), Some(c)) => format!(
            "  {}",
            style(format!("(Score: {}, Confidence: {c})", s as u32)).dim()
        ),
        (Some(s), None) => format!("  {}", style(format!("(Score: {})", s as u32)).dim()),
        (None, Some(c)) => format!("  {}", style(format!("(Confidence: {c})")).dim()),
        (None, None) => String::new(),
    };
    // Engine provenance notes: show count + worst direction so a user
    // scanning the console can see "this finding is from capped analysis"
    // at a glance.  Direction tags ("under-report", "over-report", "bail")
    // are stable strings from `LossDirection::tag()`, kept in sync with
    // the SARIF `result.properties.engine_notes[].kind` serialization so
    // downstream tooling can cross-reference console and SARIF output.
    // Informational-only notes (e.g. InlineCacheReused) are not surfaced
    // here because they carry no credibility signal.
    let engine_notes_suffix = d
        .evidence
        .as_ref()
        .filter(|e| !e.engine_notes.is_empty())
        .and_then(|e| {
            let direction = crate::engine_notes::worst_direction(&e.engine_notes)?;
            let count = e.engine_notes.len();
            Some(format!(
                "  {}",
                style(format!(
                    "[capped: {count} note{}, {}]",
                    if count == 1 { "" } else { "s" },
                    direction.tag(),
                ))
                .yellow()
            ))
        })
        .unwrap_or_default();
    // Alternative-path annotation.  When dedup preserves sibling
    // findings for the same `(body, sink, source)` that differ on
    // validation status or traversed variables, mark the primary
    // finding with a suffix naming the sibling count.
    let alt_count = d.alternative_finding_ids.len();
    let alt_suffix = if alt_count > 0 {
        format!(
            "  {}",
            style(format!(
                "(+{alt_count} alternative path{})",
                if alt_count == 1 { "" } else { "s" }
            ))
            .yellow()
        )
    } else {
        String::new()
    };
    out.push_str(&format!(
        "  {}  {} {}{}{}{}\n",
        style(&loc).dim(),
        sev,
        style(&d.id).dim(),
        meta_suffix,
        engine_notes_suffix,
        alt_suffix,
    ));

    // ── Rollup body ─────────────────────────────────────────────────────
    let indent_str = " ".repeat(BODY_INDENT);
    if let Some(ref rollup) = d.rollup {
        out.push_str(&format!(
            "{indent_str}{} ({} occurrences)\n",
            style(&d.id).dim(),
            rollup.count
        ));
        if !rollup.occurrences.is_empty() {
            let examples: Vec<String> = rollup
                .occurrences
                .iter()
                .map(|loc| format!("{}:{}", loc.line, loc.col))
                .collect();
            out.push_str(&format!(
                "{indent_str}{} {}\n",
                style("Examples:").dim(),
                style(examples.join(", ")).dim()
            ));
        }
        out.push_str(&format!(
            "{indent_str}{}\n",
            style(format!("Run: nyx scan --show-instances {}", d.id)).dim()
        ));
        return out;
    }

    // ── Message body ─────────────────────────────────────────────────────
    if let Some(msg) = &d.message {
        let capitalized = capitalize_first(msg);
        let wrapped = wrap_text(&capitalized, width, BODY_INDENT);
        out.push_str(&format!("{indent_str}{wrapped}\n"));
    }

    // ── Evidence labels (Source, Sink, Path guard) ───────────────────────
    if !d.labels.is_empty() {
        out.push('\n');
        let max_label = d.labels.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        let key_width = max_label + 1; // +1 for ':'
        for (label, value) in &d.labels {
            let key_str = format!("{label}:");
            let value_indent = BODY_INDENT + key_width + 1; // key + space
            let wrapped_val = wrap_text(value, width, value_indent);
            if label == "Path guard" {
                out.push_str(&format!(
                    "{indent_str}{:<kw$} {}\n",
                    style(&key_str).dim(),
                    style(&wrapped_val).cyan(),
                    kw = key_width,
                ));
            } else {
                out.push_str(&format!(
                    "{indent_str}{:<kw$} {}\n",
                    style(&key_str).dim(),
                    wrapped_val,
                    kw = key_width,
                ));
            }
        }
    } else if let Some(guard) = &d.guard_kind {
        out.push_str(&format!(
            "{indent_str}{}  {}\n",
            style("Path guard:").dim(),
            style(guard).cyan(),
        ));
    }

    // ── State evidence (resource lifecycle / auth) ────────────────────
    if let Some(ev) = d.evidence.as_ref().and_then(|e| e.state.as_ref()) {
        if d.labels.is_empty() && d.guard_kind.is_none() {
            out.push('\n');
        }
        let arrow = format!("[{} \u{2192} {}]", ev.from_state, ev.to_state);
        let subject_part = ev
            .subject
            .as_ref()
            .map(|s| format!("  subject: {s}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "{indent_str}{} {} {}{}\n",
            style("State:").dim(),
            style(&ev.machine).dim(),
            style(&arrow).cyan(),
            style(&subject_part).dim(),
        ));

        // For leak rules, show acquisition location from evidence.sink
        if d.id == "state-resource-leak" || d.id == "state-resource-leak-possible" {
            if let Some(sink) = d.evidence.as_ref().and_then(|e| e.sink.as_ref()) {
                out.push_str(&format!(
                    "{indent_str}{} {}:{}:{}\n",
                    style("Acquired:").dim(),
                    style(&sink.path).dim(),
                    style(sink.line).dim(),
                    style(sink.col).dim(),
                ));
            }
        }
    }

    // ── Remediation hint (state rules only) ─────────────────────────
    if let Some(hint) = state_remediation_hint(&d.id) {
        let wrapped = wrap_text(hint, width, BODY_INDENT + 6);
        out.push_str(&format!(
            "{indent_str}{} {}\n",
            style("Hint:").dim(),
            style(&wrapped).dim(),
        ));
    }

    // ── Dynamic verification annotation ──────────────────────────────
    if let Some(ev) = d.evidence.as_ref() {
        if let Some(ref dv) = ev.dynamic_verdict {
            let annotation = format_dynamic_verdict_annotation(dv);
            out.push_str(&format!("{indent_str}{}\n", style(&annotation).dim()));
        }
    }

    out
}

/// Return a remediation hint for state analysis rule IDs.
fn state_remediation_hint(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "state-use-after-close" => Some(
            "Ensure the resource is not accessed after calling close/free. \
             Consider restructuring to use the resource before releasing it.",
        ),
        "state-double-close" => {
            Some("Remove the duplicate close call, or guard with a null/closed check.")
        }
        "state-resource-leak" => Some(
            "Add a close/free call before the function exits, or use a \
             language-specific cleanup pattern (defer, with, try-with-resources, RAII).",
        ),
        "state-resource-leak-possible" => Some(
            "Ensure the resource is closed on all code paths, including \
             error/early-return paths.",
        ),
        "state-unauthed-access" => Some(
            "Add an authentication check before this operation, or move it \
             behind an auth middleware/guard.",
        ),
        _ => None,
    }
}

/// Format a dynamic verification annotation line.
///
/// Spec §5.4: `[DYN: confirmed via {payload}]` / `[DYN: not confirmed]` /
/// `[DYN: unsupported ({reason})]` / `[DYN: inconclusive ({reason})]`
fn format_dynamic_verdict_annotation(dv: &crate::evidence::VerifyResult) -> String {
    use crate::evidence::VerifyStatus;
    match dv.status {
        VerifyStatus::Confirmed => {
            let pid = dv.triggered_payload.as_deref().unwrap_or("unknown");
            format!("[DYN: confirmed via {pid}]")
        }
        VerifyStatus::NotConfirmed => "[DYN: not confirmed]".to_string(),
        VerifyStatus::Unsupported => {
            let reason = dv
                .reason
                .as_ref()
                .map(format_unsupported_reason)
                .unwrap_or_else(|| "unknown".to_string());
            format!("[DYN: unsupported ({reason})]")
        }
        VerifyStatus::Inconclusive => {
            let reason = dv
                .inconclusive_reason
                .map(format_inconclusive_reason)
                .unwrap_or_else(|| {
                    dv.detail
                        .as_deref()
                        .map(|d| d.chars().take(40).collect())
                        .unwrap_or_else(|| "unknown".to_string())
                });
            format!("[DYN: inconclusive ({reason})]")
        }
    }
}

fn format_unsupported_reason(r: &crate::evidence::UnsupportedReason) -> String {
    use crate::evidence::UnsupportedReason;
    match r {
        UnsupportedReason::BackendUnavailable => "backend unavailable".to_string(),
        UnsupportedReason::EntryKindUnsupported => "entry kind not supported".to_string(),
        UnsupportedReason::ConfidenceTooLow => "confidence too low".to_string(),
        UnsupportedReason::NoFlowSteps => "no flow steps".to_string(),
        UnsupportedReason::NoPayloadsForCap => "no payloads for cap".to_string(),
        UnsupportedReason::SpecDerivationFailed => "spec derivation failed".to_string(),
        UnsupportedReason::RequiredFileRedactedForSecrets(_) => {
            "file redacted for secrets".to_string()
        }
        UnsupportedReason::LangUnsupported => "language not supported".to_string(),
    }
}

fn format_inconclusive_reason(r: crate::evidence::InconclusiveReason) -> String {
    use crate::evidence::InconclusiveReason;
    match r {
        InconclusiveReason::OracleCollisionSuspected => "oracle collision".to_string(),
        InconclusiveReason::NonReproducible => "non-reproducible".to_string(),
        InconclusiveReason::BuildFailed => "build failed".to_string(),
        InconclusiveReason::SandboxError => "sandbox error".to_string(),
    }
}

/// Colored severity tag with icon. The tag is the visual anchor of each finding.
///
/// - HIGH:   bold red
/// - MEDIUM: bold 208 (orange), distinct from yellow
/// - LOW:    dim 67 (muted blue-gray)
fn severity_tag(sev: Severity) -> String {
    match sev {
        Severity::High => format!(
            "{} [{}]",
            style("✖").red().bold(),
            style("HIGH").red().bold(),
        ),
        Severity::Medium => format!(
            "{} [{}]",
            style("⚠").color256(208).bold(),
            style("MEDIUM").color256(208).bold(),
        ),
        Severity::Low => format!(
            "{} [{}]",
            style("●").color256(67),
            style("LOW").color256(67),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Text utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Collapse spacing artefacts in method chains.
///
/// - `") .foo("` → `").foo("` (space between `)` and `.`)
/// - Multiple spaces → single space
fn collapse_chain_spacing(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Pattern: `)` followed by whitespace then `.`
        if chars[i] == ')' {
            out.push(')');
            i += 1;
            // Skip whitespace between `)` and `.`
            let ws_start = i;
            while i < len && chars[i] == ' ' {
                i += 1;
            }
            if i < len && chars[i] == '.' {
                // Collapse: emit `.` directly after `)`
                continue;
            } else {
                // Not a chain continuation, emit the whitespace we skipped
                for c in &chars[ws_start..i] {
                    out.push(*c);
                }
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Word-wrap text to fit within `max_width`, with continuation lines indented
/// to `indent` spaces. The first line is NOT indented (caller handles that).
fn wrap_text(text: &str, max_width: usize, indent: usize) -> String {
    let available_first = max_width.saturating_sub(indent);
    let available_cont = max_width.saturating_sub(indent);
    if available_first == 0 || text.len() <= available_first {
        return text.to_string();
    }

    let indent_str = " ".repeat(indent);
    let mut result = String::new();
    let mut line_len = 0usize;
    let mut first_line = true;

    for word in text.split_whitespace() {
        let wlen = word.len();
        let avail = if first_line {
            available_first
        } else {
            available_cont
        };

        if line_len == 0 {
            result.push_str(word);
            line_len = wlen;
        } else if line_len + 1 + wlen > avail {
            result.push('\n');
            result.push_str(&indent_str);
            result.push_str(word);
            line_len = wlen;
            first_line = false;
        } else {
            result.push(' ');
            result.push_str(word);
            line_len += 1 + wlen;
        }
    }

    result
}

/// Get terminal width, falling back to DEFAULT_WIDTH.
fn terminal_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(DEFAULT_WIDTH)
}

/// Capitalise the first character of a string.
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => {
            let mut out = String::with_capacity(s.len());
            for upper in c.to_uppercase() {
                out.push(upper);
            }
            out.push_str(chars.as_str());
            out
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Strip ANSI escape codes for testing visible content.
    fn strip_ansi(s: &str) -> String {
        let mut result = String::new();
        let mut in_escape = false;
        for ch in s.chars() {
            if ch == '\x1b' {
                in_escape = true;
            } else if in_escape {
                if ch == 'm' {
                    in_escape = false;
                }
            } else {
                result.push(ch);
            }
        }
        result
    }

    // ── normalize_snippet ────────────────────────────────────────────────

    #[test]
    fn normalize_snippet_strips_newlines_no_space() {
        // Newlines are removed with no whitespace inserted in their place.
        assert_eq!(normalize_snippet("foo\nbar\rbaz"), "foobarbaz");
    }

    #[test]
    fn normalize_snippet_collapses_whitespace() {
        assert_eq!(
            normalize_snippet("Command::new(\"tar\")        .arg(\"-czf\")"),
            "Command::new(\"tar\").arg(\"-czf\")"
        );
    }

    #[test]
    fn normalize_snippet_trims() {
        assert_eq!(normalize_snippet("  hello  "), "hello");
    }

    #[test]
    fn normalize_snippet_truncates_at_120() {
        let long = "a".repeat(200);
        let result = normalize_snippet(&long);
        // 120 chars + '…' (3 bytes UTF-8)
        assert!(result.len() > 120);
        assert!(result.ends_with('…'));
    }

    #[test]
    fn normalize_snippet_short_unchanged() {
        assert_eq!(normalize_snippet("short"), "short");
    }

    // ── collapse_chain_spacing ───────────────────────────────────────────

    #[test]
    fn collapse_chain_removes_space_before_dot() {
        assert_eq!(
            collapse_chain_spacing("foo() .bar() .baz()"),
            "foo().bar().baz()"
        );
    }

    #[test]
    fn collapse_chain_preserves_non_chain_spacing() {
        assert_eq!(collapse_chain_spacing("foo() + bar()"), "foo() + bar()");
    }

    #[test]
    fn collapse_chain_multiple_spaces() {
        assert_eq!(
            collapse_chain_spacing("cmd()     .arg(\"-c\")"),
            "cmd().arg(\"-c\")"
        );
    }

    // ── shorten_callee ───────────────────────────────────────────────────

    #[test]
    fn shorten_callee_truncates_chain() {
        assert_eq!(
            shorten_callee("Command::new(\"sh\").arg(\"-c\").arg(&cmd)"),
            "Command::new(\"sh\")…"
        );
    }

    #[test]
    fn shorten_callee_no_chain_unchanged() {
        assert_eq!(shorten_callee("env::var(\"HOME\")"), "env::var(\"HOME\")");
    }

    #[test]
    fn shorten_callee_nested_parens() {
        assert_eq!(shorten_callee("foo(bar(1, 2)).baz()"), "foo(bar(1, 2))…");
    }

    #[test]
    fn shorten_callee_no_parens() {
        assert_eq!(shorten_callee("simple_name"), "simple_name");
    }

    #[test]
    fn shorten_callee_empty() {
        assert_eq!(shorten_callee(""), "");
    }

    // ── wrap_text ────────────────────────────────────────────────────────

    #[test]
    fn wrap_short_text_unchanged() {
        assert_eq!(wrap_text("short text", 80, 4), "short text");
    }

    #[test]
    fn wrap_breaks_at_boundary() {
        let text = "word1 word2 word3 word4 word5";
        let result = wrap_text(text, 20, 4);
        assert!(result.contains('\n'));
        for line in result.lines().skip(1) {
            assert!(line.starts_with("    "));
        }
    }

    // ── severity_tag ─────────────────────────────────────────────────────

    #[test]
    fn severity_tags_contain_level_name() {
        let h = strip_ansi(&severity_tag(Severity::High));
        let m = strip_ansi(&severity_tag(Severity::Medium));
        let l = strip_ansi(&severity_tag(Severity::Low));
        assert!(h.contains("HIGH"), "got: {h}");
        assert!(m.contains("MEDIUM"), "got: {m}");
        assert!(l.contains("LOW"), "got: {l}");
    }

    #[test]
    fn severity_tags_have_icons() {
        let h = strip_ansi(&severity_tag(Severity::High));
        let m = strip_ansi(&severity_tag(Severity::Medium));
        let l = strip_ansi(&severity_tag(Severity::Low));
        assert!(h.contains('✖'), "HIGH should have ✖");
        assert!(m.contains('⚠'), "MEDIUM should have ⚠");
        assert!(l.contains('●'), "LOW should have ●");
    }

    // ── render_console ───────────────────────────────────────────────────

    #[test]
    fn render_console_groups_by_file() {
        let diags = vec![
            Diag {
                path: "src/a.rs".into(),
                line: 10,
                col: 5,
                severity: Severity::High,
                id: "test-rule".into(),
                category: crate::patterns::FindingCategory::Security,
                path_validated: false,
                guard_kind: None,
                message: Some("test message".into()),
                labels: vec![],
                confidence: None,
                evidence: None,
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
                finding_id: String::new(),
                alternative_finding_ids: Vec::new(),
                stable_hash: 0,
            },
            Diag {
                path: "src/b.rs".into(),
                line: 20,
                col: 1,
                severity: Severity::Low,
                id: "another-rule".into(),
                category: crate::patterns::FindingCategory::Security,
                path_validated: false,
                guard_kind: None,
                message: None,
                labels: vec![],
                confidence: None,
                evidence: None,
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
                finding_id: String::new(),
                alternative_finding_ids: Vec::new(),
                stable_hash: 0,
            },
        ];
        let output = render_console(&diags, "test-project", None);
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("src/a.rs"));
        assert!(stripped.contains("src/b.rs"));
        assert!(stripped.contains("2 issues"));
        assert!(stripped.contains("test-project"));
    }

    #[test]
    fn render_console_evidence_displayed() {
        let diags = vec![Diag {
            path: "src/main.rs".into(),
            line: 42,
            col: 5,
            severity: Severity::High,
            id: "taint-unsanitised-flow (source 12:3)".into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: Some("unsanitised input".into()),
            labels: vec![
                ("Source".into(), "env::var(\"HOME\") at 12:3".into()),
                ("Sink".into(), "Command::new(\"sh\")".into()),
            ],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        }];
        let output = render_console(&diags, "proj", None);
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("Source:"), "should contain Source label");
        assert!(stripped.contains("Sink:"), "should contain Sink label");
        // No backticks in output
        assert!(
            !stripped.contains('`'),
            "should not contain backticks in evidence"
        );
    }

    #[test]
    fn render_console_blank_line_between_findings() {
        let diags = vec![
            Diag {
                path: "src/a.rs".into(),
                line: 1,
                col: 1,
                severity: Severity::High,
                id: "rule-a".into(),
                category: crate::patterns::FindingCategory::Security,
                path_validated: false,
                guard_kind: None,
                message: Some("first".into()),
                labels: vec![],
                confidence: None,
                evidence: None,
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
                finding_id: String::new(),
                alternative_finding_ids: Vec::new(),
                stable_hash: 0,
            },
            Diag {
                path: "src/a.rs".into(),
                line: 10,
                col: 1,
                severity: Severity::Medium,
                id: "rule-b".into(),
                category: crate::patterns::FindingCategory::Security,
                path_validated: false,
                guard_kind: None,
                message: Some("second".into()),
                labels: vec![],
                confidence: None,
                evidence: None,
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
                finding_id: String::new(),
                alternative_finding_ids: Vec::new(),
                stable_hash: 0,
            },
        ];
        let output = render_console(&diags, "proj", None);
        let stripped = strip_ansi(&output);
        // There should be a blank line between the two findings
        assert!(
            stripped.contains("First\n\n"),
            "blank line between findings: {stripped}"
        );
    }

    #[test]
    fn json_omits_empty_labels() {
        let d = Diag {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            severity: Severity::Low,
            id: "test".into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            !json.contains("labels"),
            "empty labels should be omitted from JSON"
        );
    }

    #[test]
    fn json_omits_rank_fields_when_none() {
        let d = Diag {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            severity: Severity::Low,
            id: "test".into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            !json.contains("rank_score"),
            "rank_score should be omitted when None"
        );
        assert!(
            !json.contains("rank_reason"),
            "rank_reason should be omitted when None"
        );
    }

    #[test]
    fn json_includes_rank_score_when_set() {
        let d = Diag {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            severity: Severity::High,
            id: "taint-unsanitised-flow".into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: Some(120.0),
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            json.contains("rank_score"),
            "rank_score should be present when set"
        );
        assert!(json.contains("120"), "rank_score value should appear");
    }

    // ── capitalize_first ─────────────────────────────────────────────────

    #[test]
    fn capitalize_first_works() {
        assert_eq!(capitalize_first("hello"), "Hello");
        assert_eq!(capitalize_first(""), "");
        assert_eq!(capitalize_first("A"), "A");
        assert_eq!(capitalize_first("unsanitised"), "Unsanitised");
    }

    // ── render_welcome ────────────────────────────────────────────────────

    #[test]
    fn welcome_screen_content() {
        let output = render_welcome();
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("nyx"), "should contain logo text");
        assert!(
            stripped.contains(env!("CARGO_PKG_VERSION")),
            "should contain version"
        );
        assert!(stripped.contains("nyx scan"), "should mention scan command");
        assert!(
            stripped.contains("nyx serve"),
            "should mention serve command"
        );
        assert!(stripped.contains("nyx --help"), "should mention help");
        let line_count = stripped.lines().count();
        assert!(
            line_count <= 25,
            "should be compact, got {line_count} lines"
        );
    }

    // ── taint flow rendering (integration-style) ─────────────────────────

    #[test]
    fn taint_flow_no_broken_backticks_or_weird_spacing() {
        let raw_sink = "Command::new(\"tar\")        .arg(\"-czf\")        .arg(\"/backups/nightly.tar.gz\")        .arg(\"/var/data\")        .output()";
        let normalised = normalize_snippet(raw_sink);
        // Chain spacing should be collapsed
        assert!(
            !normalised.contains(") ."),
            "chain spacing should be collapsed: {normalised}"
        );
        assert!(!normalised.contains("  "), "no double-spaces: {normalised}");
        // Should not contain backticks
        assert!(!normalised.contains('`'), "no backticks: {normalised}");
    }

    #[test]
    fn multiline_sink_joined_and_normalised() {
        let raw = "Command::new(\"tar\")\n        .arg(\"-czf\")\n        .arg(\"/backups/nightly.tar.gz\")\n        .arg(\"/var/data\")\n        .output()";
        let normalised = normalize_snippet(raw);
        assert_eq!(
            normalised,
            "Command::new(\"tar\").arg(\"-czf\").arg(\"/backups/nightly.tar.gz\").arg(\"/var/data\").output()"
        );
    }

    // ── confidence display ──────────────────────────────────────────────

    #[test]
    fn confidence_after_score_on_header_line() {
        let d = Diag {
            path: "src/a.rs".into(),
            line: 510,
            col: 5,
            severity: Severity::Medium,
            id: "cfg-unguarded-sink".into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: Some("dangerous sink".into()),
            labels: vec![],
            confidence: Some(crate::evidence::Confidence::Medium),
            evidence: None,
            rank_score: Some(36.0),
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        let output = render_diag(&d, 120);
        let stripped = strip_ansi(&output);
        // Header line should contain score and confidence together
        let header = stripped.lines().next().unwrap();
        assert!(
            header.contains("(Score: 36, Confidence: Medium)"),
            "header should contain '(Score: 36, Confidence: Medium)': {header}"
        );
        // No standalone Confidence line
        let non_header_lines: Vec<&str> = stripped.lines().skip(1).collect();
        assert!(
            !non_header_lines
                .iter()
                .any(|l| l.trim().starts_with("Confidence:")),
            "should not have standalone Confidence line"
        );
    }

    #[test]
    fn confidence_title_case() {
        for (conf, expected) in [
            (crate::evidence::Confidence::Low, "Confidence: Low"),
            (crate::evidence::Confidence::Medium, "Confidence: Medium"),
            (crate::evidence::Confidence::High, "Confidence: High"),
        ] {
            let d = Diag {
                path: "x.rs".into(),
                line: 1,
                col: 1,
                severity: Severity::Low,
                id: "test".into(),
                category: crate::patterns::FindingCategory::Security,
                path_validated: false,
                guard_kind: None,
                message: None,
                labels: vec![],
                confidence: Some(conf),
                evidence: None,
                rank_score: None,
                rank_reason: None,
                suppressed: false,
                suppression: None,
                rollup: None,
                finding_id: String::new(),
                alternative_finding_ids: Vec::new(),
                stable_hash: 0,
            };
            let output = render_diag(&d, 100);
            let stripped = strip_ansi(&output);
            assert!(
                stripped.contains(expected),
                "expected '{expected}' in: {stripped}"
            );
        }
    }

    #[test]
    fn confidence_none_only_score() {
        let d = Diag {
            path: "src/a.rs".into(),
            line: 10,
            col: 5,
            severity: Severity::High,
            id: "test-rule".into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: Some("test message".into()),
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: Some(42.0),
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        let output = render_diag(&d, 100);
        let stripped = strip_ansi(&output);
        let header = stripped.lines().next().unwrap();
        assert!(
            header.contains("(Score: 42)"),
            "should show score without confidence: {header}"
        );
        assert!(
            !header.contains("Confidence"),
            "should not mention confidence when None: {header}"
        );
    }

    #[test]
    fn confidence_only_no_score() {
        let d = Diag {
            path: "src/a.rs".into(),
            line: 10,
            col: 5,
            severity: Severity::High,
            id: "test-rule".into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: Some(crate::evidence::Confidence::High),
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        let output = render_diag(&d, 100);
        let stripped = strip_ansi(&output);
        let header = stripped.lines().next().unwrap();
        assert!(
            header.contains("(Confidence: High)"),
            "should show confidence without score: {header}"
        );
    }

    #[test]
    fn json_omits_confidence_when_none() {
        let d = Diag {
            path: "x.rs".into(),
            line: 1,
            col: 1,
            severity: Severity::Low,
            id: "test".into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: None,
            labels: vec![],
            confidence: None,
            evidence: None,
            rank_score: None,
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            !json.contains("confidence"),
            "confidence should be omitted when None: {json}"
        );
    }

    // ── state evidence rendering ─────────────────────────────────────

    fn make_state_diag(
        rule_id: &str,
        machine: &str,
        subject: Option<&str>,
        from: &str,
        to: &str,
    ) -> Diag {
        use crate::evidence::{Evidence, StateEvidence};
        Diag {
            path: "src/main.c".into(),
            line: 12,
            col: 5,
            severity: Severity::High,
            id: rule_id.into(),
            category: crate::patterns::FindingCategory::Security,
            path_validated: false,
            guard_kind: None,
            message: Some(format!("variable `f` {to} after {from}")),
            labels: vec![],
            confidence: Some(crate::evidence::Confidence::High),
            evidence: Some(Evidence {
                state: Some(StateEvidence {
                    machine: machine.into(),
                    subject: subject.map(|s| s.into()),
                    from_state: from.into(),
                    to_state: to.into(),
                }),
                ..Default::default()
            }),
            rank_score: Some(47.0),
            rank_reason: None,
            suppressed: false,
            suppression: None,
            rollup: None,
            finding_id: String::new(),
            alternative_finding_ids: Vec::new(),
            stable_hash: 0,
        }
    }

    #[test]
    fn render_state_evidence_use_after_close() {
        let d = make_state_diag(
            "state-use-after-close",
            "resource",
            Some("f"),
            "closed",
            "used",
        );
        let output = render_diag(&d, 120);
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("State:"), "should contain State label");
        assert!(stripped.contains("resource"), "should contain machine name");
        assert!(
            stripped.contains("[closed \u{2192} used]"),
            "should contain transition: {stripped}"
        );
        assert!(
            stripped.contains("subject: f"),
            "should contain subject: {stripped}"
        );
    }

    #[test]
    fn render_state_evidence_leak_with_location() {
        use crate::evidence::{Evidence, SpanEvidence, StateEvidence};
        let d = Diag {
            evidence: Some(Evidence {
                state: Some(StateEvidence {
                    machine: "resource".into(),
                    subject: Some("f".into()),
                    from_state: "open".into(),
                    to_state: "leaked".into(),
                }),
                sink: Some(SpanEvidence {
                    path: "src/main.c".into(),
                    line: 5,
                    col: 10,
                    kind: "sink".into(),
                    snippet: None,
                }),
                ..Default::default()
            }),
            ..make_state_diag(
                "state-resource-leak",
                "resource",
                Some("f"),
                "open",
                "leaked",
            )
        };
        let output = render_diag(&d, 120);
        let stripped = strip_ansi(&output);
        assert!(
            stripped.contains("Acquired:"),
            "should contain Acquired label: {stripped}"
        );
        assert!(
            stripped.contains("src/main.c"),
            "should contain file path: {stripped}"
        );
    }

    #[test]
    fn render_state_evidence_no_subject() {
        let d = make_state_diag("state-resource-leak", "resource", None, "open", "leaked");
        let output = render_diag(&d, 120);
        let stripped = strip_ansi(&output);
        assert!(
            !stripped.contains("subject:"),
            "should not contain subject: {stripped}"
        );
    }

    #[test]
    fn render_state_evidence_auth() {
        let d = make_state_diag("state-unauthed-access", "auth", None, "unauthed", "access");
        let output = render_diag(&d, 120);
        let stripped = strip_ansi(&output);
        assert!(stripped.contains("auth"), "should contain auth: {stripped}");
        assert!(
            stripped.contains("[unauthed \u{2192} access]"),
            "should contain transition: {stripped}"
        );
    }

    #[test]
    fn remediation_hint_present_for_state_rules() {
        for id in &[
            "state-use-after-close",
            "state-double-close",
            "state-resource-leak",
            "state-resource-leak-possible",
            "state-unauthed-access",
        ] {
            assert!(
                state_remediation_hint(id).is_some(),
                "should have hint for {id}"
            );
        }
    }

    #[test]
    fn remediation_hint_absent_for_non_state() {
        assert!(state_remediation_hint("taint-unsanitised-flow").is_none());
        assert!(state_remediation_hint("cfg-unguarded-sink").is_none());
    }

    #[test]
    fn render_diag_shows_hint() {
        let d = make_state_diag(
            "state-resource-leak",
            "resource",
            Some("f"),
            "open",
            "leaked",
        );
        let output = render_diag(&d, 120);
        let stripped = strip_ansi(&output);
        assert!(
            stripped.contains("Hint:"),
            "should contain Hint label: {stripped}"
        );
        assert!(
            stripped.contains("close/free"),
            "should contain remediation text: {stripped}"
        );
    }
}
