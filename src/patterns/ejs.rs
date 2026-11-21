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
/// Returns a [`Diag`] for each `<%- expr %>` occurrence that is not a
/// partial include, sits outside a `<%# ... %>` comment, and is not one of
/// the express-ejs-layouts locals in a layout file.
pub fn scan_ejs_file(path: &Path, bytes: &[u8]) -> Vec<Diag> {
    let Ok(raw) = std::str::from_utf8(bytes) else {
        return vec![];
    };
    let masked = mask_ejs_comments(raw);
    let text = masked.as_str();
    let layout = is_layout_template(text);

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
            // The rendered view and its blocks in an express-ejs-layouts
            // layout; their content was escaped where it was produced.
            if layout && is_layout_local(expr) {
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

/// Returns `true` if the expression includes a partial: the `include(...)`
/// call, its awaited form in async templates (`await include(...)`), or the
/// legacy EJS 1/2 directive `include path/to/partial`.
fn is_include_call(expr: &str) -> bool {
    let mut trimmed = expr.trim_start();
    if let Some(rest) = trimmed.strip_prefix("await") {
        if rest.starts_with(char::is_whitespace) {
            trimmed = rest.trim_start();
        }
    }
    let Some(rest) = trimmed.strip_prefix("include") else {
        return false;
    };
    if rest.trim_start().starts_with('(') {
        return true;
    }
    // Legacy directive: whitespace, then a single path token.
    rest.starts_with(char::is_whitespace) && {
        let path = rest.trim();
        !path.is_empty()
            && path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    }
}

/// Replace every `<%# ... %>` comment with spaces, keeping newlines so line
/// numbers stay put.  EJS ends a comment at the first `%>`.
fn mask_ejs_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("<%#") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let end = after.find("%>").map(|e| e + 2).unwrap_or(after.len());
        for c in after[..end].chars() {
            if c == '\n' {
                out.push('\n');
            } else {
                // One space per byte keeps later byte columns on the line.
                out.extend(std::iter::repeat_n(' ', c.len_utf8()));
            }
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// An express-ejs-layouts layout: a full HTML document that renders the
/// view through `<%- body %>`.
fn is_layout_template(text: &str) -> bool {
    let has_body = text.match_indices("<%-").any(|(i, _)| {
        text[i + 3..]
            .split("%>")
            .next()
            .is_some_and(|e| e.trim() == "body")
    });
    has_body && text.to_ascii_lowercase().contains("<html")
}

/// Locals that express-ejs-layouts fills with rendered markup: the view
/// (`body`), the blocks it extracted (`style`, `script`, `meta`), and named
/// sections (`defineContent('name')`).
fn is_layout_local(expr: &str) -> bool {
    let e = expr.trim();
    matches!(e, "body" | "style" | "script" | "meta")
        || e.strip_prefix("defineContent")
            .is_some_and(|r| r.trim_start().starts_with('('))
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
        assert!(!is_include_call(" include + userHtml "));
        assert!(!is_include_call(" awaitinclude('x') "));
    }

    #[test]
    fn is_include_call_accepts_await_and_legacy_directive() {
        assert!(is_include_call(" await include('footer') "));
        assert!(is_include_call(" include header "));
        assert!(is_include_call(" include ../partials/nav "));
    }

    #[test]
    fn skips_comments_and_layout_locals() {
        let src = b"<!DOCTYPE html>\n<html>\n<head><%- style %></head>\n<body>\n\
                    <%- include header %>\n<%- body %>\n<%- script %>\n\
                    <%# <%- commented %> %>\n<%- await include('footer') %>\n\
                    <%- defineContent('sidebar') %>\n</body>\n</html>";
        let diags = scan_ejs_file(&PathBuf::from("views/layout.ejs"), src);
        assert!(
            diags.is_empty(),
            "got {:?}",
            diags.iter().map(|d| d.line).collect::<Vec<_>>()
        );
    }

    #[test]
    fn layout_locals_still_fire_outside_a_layout() {
        // A plain view that happens to output a `body` local raw.
        let src = b"<div><%- body %></div>\n<p><%# note %><%- bio %></p>";
        let diags = scan_ejs_file(&PathBuf::from("views/post.ejs"), src);
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert_eq!(lines, vec![1, 2]);
    }

    #[test]
    fn layout_still_flags_other_unescaped_output() {
        let src = b"<html><body><%- body %><footer><%- user.bio %></footer></body></html>";
        let diags = scan_ejs_file(&PathBuf::from("views/layout.ejs"), src);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.as_ref().unwrap().contains("user.bio"));
    }
}
