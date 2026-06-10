//! Text-based scanner for EJS template files.
//!
//! EJS templates use `<%- expr %>` for **unescaped** (raw HTML) output and
//! `<%= expr %>` for auto-escaped output.  The `<%-` form is an XSS sink when
//! the expression contains user-controlled data.
//!
//! Since tree-sitter has no EJS grammar, this module uses simple text scanning
//! instead of AST queries.

use crate::commands::scan::Diag;
use crate::evidence::{Confidence, Evidence, SpanEvidence};
use crate::patterns::{FindingCategory, Severity};
use std::path::Path;

pub const RULE_ID: &str = "js.xss.ejs_unescaped";

/// Scan an EJS file for unescaped output tags.
///
/// Returns a [`Diag`] for each `<%- expr %>` occurrence that is not an
/// `include()` call.
pub fn scan_ejs_file(path: &Path, bytes: &[u8]) -> Vec<Diag> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return vec![];
    };

    let path_str = path.to_string_lossy().into_owned();
    let mut out = Vec::new();

    for (line_idx, line) in text.lines().enumerate() {
        let line_no = line_idx + 1;
        let mut search_from = 0;

        while let Some(start) = line[search_from..].find("<%-") {
            let abs_start = search_from + start;
            let after_tag = abs_start + 3; // skip "<%-"

            let Some(end) = line[after_tag..].find("%>") else {
                break; // no closing %> on this line
            };
            let abs_end = after_tag + end;
            let expr = &line[after_tag..abs_end];

            // Advance past this match for the next iteration.
            search_from = abs_end + 2; // skip "%>"

            // Skip <%- include(...) %>, EJS partial inclusion, not user-controlled.
            if is_include_call(expr) {
                continue;
            }

            let col = abs_start + 1; // 1-based
            let expr_trimmed = expr.trim();
            let snippet = &line[abs_start..abs_end + 2]; // "<%- ... %>"

            out.push(Diag {
                path: path_str.clone(),
                line: line_no,
                col,
                severity: Severity::Medium,
                id: RULE_ID.to_owned(),
                category: FindingCategory::Security,
                path_validated: false,
                guard_kind: None,
                message: Some(format!(
                    "Unescaped EJS output `<%- {expr_trimmed} %>` renders raw HTML. \
                     If the expression contains user-controlled data, this is an XSS \
                     sink. Use `<%= ... %>` for auto-escaped output."
                )),
                labels: vec![("expression".into(), expr_trimmed.to_owned())],
                confidence: Some(Confidence::Medium),
                evidence: Some(Evidence {
                    sink: Some(SpanEvidence {
                        path: path_str.clone(),
                        line: line_no as u32,
                        col: col as u32,
                        kind: "sink".into(),
                        snippet: Some(snippet.to_owned()),
                    }),
                    ..Default::default()
                }),
                rank_score: None,
                rank_reason: None,
                exposure: None,
                suppressed: false,
                suppression: None,
                triage_state: "open".to_string(),
                triage_note: String::new(),
                rollup: None,
                finding_id: String::new(),
                alternative_finding_ids: Vec::new(),
                stable_hash: 0,
            });
        }
    }

    out
}

/// Returns `true` if the expression is an EJS `include(...)` call.
fn is_include_call(expr: &str) -> bool {
    let trimmed = expr.trim_start();
    if !trimmed.starts_with("include") {
        return false;
    }
    let rest = trimmed["include".len()..].trim_start();
    rest.starts_with('(')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_unescaped_variable() {
        let src = b"<h1><%- query %></h1>";
        let path = PathBuf::from("views/search.ejs");
        let diags = scan_ejs_file(&path, src);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].id, RULE_ID);
        assert_eq!(diags[0].line, 1);
        assert_eq!(diags[0].severity, Severity::Medium);
        assert!(diags[0].message.as_ref().unwrap().contains("query"));
    }

    #[test]
    fn skips_escaped_output() {
        let src = b"<h1><%= safe %></h1>";
        let path = PathBuf::from("views/safe.ejs");
        let diags = scan_ejs_file(&path, src);
        assert!(diags.is_empty());
    }

    #[test]
    fn skips_include_calls() {
        let src = b"<%- include('header') %>\n<%- include(\"footer\") %>";
        let path = PathBuf::from("views/layout.ejs");
        let diags = scan_ejs_file(&path, src);
        assert!(diags.is_empty());
    }

    #[test]
    fn detects_multiple_on_same_line() {
        let src = b"<%- first %> and <%- second %>";
        let path = PathBuf::from("views/multi.ejs");
        let diags = scan_ejs_file(&path, src);
        assert_eq!(diags.len(), 2);
    }

    #[test]
    fn detects_complex_expression() {
        let src = b"<%- user.name.toUpperCase() %>";
        let path = PathBuf::from("views/profile.ejs");
        let diags = scan_ejs_file(&path, src);
        assert_eq!(diags.len(), 1);
        assert!(
            diags[0]
                .message
                .as_ref()
                .unwrap()
                .contains("user.name.toUpperCase()")
        );
    }

    #[test]
    fn correct_line_numbers() {
        let src = b"line 1\nline 2\n<%- danger %>\nline 4";
        let path = PathBuf::from("views/lines.ejs");
        let diags = scan_ejs_file(&path, src);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].line, 3);
    }

    #[test]
    fn handles_non_utf8() {
        let src = &[0xff, 0xfe, 0x00];
        let path = PathBuf::from("views/binary.ejs");
        let diags = scan_ejs_file(&path, src);
        assert!(diags.is_empty());
    }

    #[test]
    fn is_include_call_positive() {
        assert!(is_include_call(" include('header') "));
        assert!(is_include_call("include(\"footer\")"));
        assert!(is_include_call("  include( 'partials/nav' )"));
    }

    #[test]
    fn is_include_call_negative() {
        assert!(!is_include_call(" query "));
        assert!(!is_include_call(" includes.header "));
        assert!(!is_include_call(" user.name "));
    }
}
