//! Inline per-finding suppression via source-code comments.
//!
//! Supports two directive forms:
//! - `nyx:ignore <RULE_ID>[, <RULE_ID>…]` , suppress findings on the same line
//! - `nyx:ignore-next-line <RULE_ID>[, …]`, suppress findings on the next line
//!
//! Comments are detected for all supported languages without tree-sitter,
//! using a lightweight string/comment state machine.

use std::collections::HashMap;

//  Public types

/// Whether the directive suppresses on its own line or the next line.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SuppressionKind {
    SameLine,
    NextLine,
}

/// Metadata attached to a suppressed finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuppressionMeta {
    pub kind: SuppressionKind,
    /// The pattern that matched the finding's rule ID.
    pub matched_pattern: String,
    /// 1-indexed line where the suppression directive appears.
    pub directive_line: usize,
}

//  Internal types

/// A single rule matcher, either exact or wildcard-suffix (`foo.*`).
#[derive(Debug)]
enum RuleMatcher {
    Exact(String),
    /// `prefix` stores everything before the trailing `.*`.
    WildcardSuffix(String),
}

impl RuleMatcher {
    fn matches(&self, rule_id: &str) -> bool {
        match self {
            RuleMatcher::Exact(s) => s == rule_id,
            RuleMatcher::WildcardSuffix(prefix) => {
                rule_id.starts_with(prefix.as_str())
                    && rule_id.len() > prefix.len()
                    && rule_id.as_bytes()[prefix.len()] == b'.'
            }
        }
    }
}

/// A parsed directive from a single comment.
#[derive(Debug)]
struct LineDirective {
    kind: SuppressionKind,
    /// 1-indexed line where the directive comment appears.
    directive_line: usize,
    matchers: Vec<RuleMatcher>,
}

/// Pre-built index of suppression directives keyed by **target line** (the
/// line whose findings should be suppressed, 1-indexed).
pub struct SuppressionIndex {
    directives: HashMap<usize, Vec<LineDirective>>,
}

impl SuppressionIndex {
    /// Check whether a finding at `line` (1-indexed) with `rule_id` is suppressed.
    pub fn check(&self, line: usize, rule_id: &str) -> Option<SuppressionMeta> {
        let canon = canonical_rule_id(rule_id);
        let dirs = self.directives.get(&line)?;
        for dir in dirs {
            for m in &dir.matchers {
                if m.matches(canon) {
                    let display_pattern = match m {
                        RuleMatcher::Exact(s) => s.clone(),
                        RuleMatcher::WildcardSuffix(s) => format!("{s}.*"),
                    };
                    return Some(SuppressionMeta {
                        kind: dir.kind.clone(),
                        matched_pattern: display_pattern,
                        directive_line: dir.directive_line,
                    });
                }
            }
        }
        None
    }

    /// Returns `true` if no directives were found.
    pub fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }
}

//  Canonical rule ID

/// Strip parenthetical suffix from a rule ID:
/// `"taint-unsanitised-flow (source 5:1)"` → `"taint-unsanitised-flow"`.
pub fn canonical_rule_id(id: &str) -> &str {
    let trimmed = id.trim();
    if let Some(idx) = trimmed.find(" (") {
        trimmed[..idx].trim_end()
    } else {
        trimmed
    }
}

//  Comment style per language

#[derive(Clone, Copy)]
enum CommentStyle {
    /// `//` and `/* */`, Rust, C, C++, Java, Go, JS, TS
    CStyle,
    /// `#` only, Python, Ruby
    Hash,
    /// `//`, `#`, and `/* */`, PHP
    PhpStyle,
}

/// Map a file extension to the comment style for that language.
fn comment_style_for_ext(ext: &str) -> Option<CommentStyle> {
    match ext {
        "rs" | "c" | "cpp" | "java" | "go" | "ts" | "js" => Some(CommentStyle::CStyle),
        "py" | "rb" => Some(CommentStyle::Hash),
        "php" => Some(CommentStyle::PhpStyle),
        _ => None,
    }
}

/// Map a file path to its comment style by inspecting the extension.
fn comment_style_for_path(path: &std::path::Path) -> Option<CommentStyle> {
    let ext = path.extension().and_then(|s| s.to_str())?;
    // Normalise common variant extensions
    let norm = match ext {
        "RS" => "rs",
        "c++" => "cpp",
        "PY" => "py",
        "TSX" | "tsx" => "ts",
        other => other,
    };
    comment_style_for_ext(norm)
}

//  Parser

/// Parse inline suppression directives from `source`, using comment syntax
/// appropriate for the given file path.
///
/// Returns an empty index if the source doesn't contain `nyx:ignore` or the
/// language is unsupported.
pub fn parse_inline_suppressions(path: &std::path::Path, source: &str) -> SuppressionIndex {
    // Fast path: no directives possible.
    if !source.as_bytes().windows(10).any(|w| w == b"nyx:ignore") {
        return SuppressionIndex {
            directives: HashMap::new(),
        };
    }

    let Some(style) = comment_style_for_path(path) else {
        return SuppressionIndex {
            directives: HashMap::new(),
        };
    };

    let mut index: HashMap<usize, Vec<LineDirective>> = HashMap::new();
    let total_lines = source.lines().count();

    // State machine for string/comment tracking.
    let mut in_block_comment = false;
    let mut block_comment_start_line: usize = 0;

    for (line_idx, raw_line) in source.lines().enumerate() {
        let line_num = line_idx + 1; // 1-indexed
        let line = raw_line.trim_end_matches('\r');

        if in_block_comment {
            // Check for block comment end.
            if let Some(end_pos) = line.find("*/") {
                // Extract text before `*/`, may contain a directive.
                let block_text = &line[..end_pos];
                if let Some(dir) = try_parse_directive(block_text, line_num) {
                    let target = target_line(&dir, line_num, total_lines);
                    if let Some(t) = target {
                        index.entry(t).or_default().push(dir);
                    }
                }
                in_block_comment = false;
                // After the block comment ends, check the rest of the line
                // for a line comment.
                let rest = &line[end_pos + 2..];
                if let Some(dir) = extract_from_line_rest(rest, line_num, style) {
                    let target = target_line(&dir, line_num, total_lines);
                    if let Some(t) = target {
                        index.entry(t).or_default().push(dir);
                    }
                }
            } else {
                // Still inside block comment, check for directive.
                if let Some(dir) = try_parse_directive(line, line_num) {
                    let target = target_line(&dir, line_num, total_lines);
                    if let Some(t) = target {
                        index.entry(t).or_default().push(dir);
                    }
                }
            }
            let _ = block_comment_start_line; // suppress unused warning
            continue;
        }

        // Not in a block comment, scan the line character by character
        // tracking string state.
        if let Some(dir) = scan_line_for_directive(line, line_num, style, &mut in_block_comment) {
            let target = target_line(&dir, line_num, total_lines);
            if let Some(t) = target {
                index.entry(t).or_default().push(dir);
            }
        }
        if in_block_comment {
            block_comment_start_line = line_num;
        }
    }

    SuppressionIndex { directives: index }
}

/// Compute the target line for a directive. Returns `None` if the directive
/// is `NextLine` but on the last line (EOF, no-op).
fn target_line(dir: &LineDirective, line_num: usize, total_lines: usize) -> Option<usize> {
    match dir.kind {
        SuppressionKind::SameLine => Some(line_num),
        SuppressionKind::NextLine => {
            if line_num < total_lines {
                Some(line_num + 1)
            } else {
                None // EOF, no next line
            }
        }
    }
}

/// Scan a single line (not inside a block comment) for a suppression directive.
/// Tracks string literals to avoid false positives.
///
/// Sets `in_block_comment` to `true` if the line opens a `/* */` block that
/// doesn't close on the same line.
fn scan_line_for_directive(
    line: &str,
    line_num: usize,
    style: CommentStyle,
    in_block_comment: &mut bool,
) -> Option<LineDirective> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    // String state
    let mut in_string: Option<u8> = None; // quote char: b'"', b'\'', b'`'

    while i < len {
        let ch = bytes[i];

        // ── Inside a string literal ─────────────────────────────────────
        if let Some(quote) = in_string {
            if ch == b'\\' {
                i += 2; // skip escaped char
                continue;
            }
            // Python triple quotes
            if (quote == b'"' || quote == b'\'')
                && i + 2 < len
                && bytes[i] == quote
                && bytes[i + 1] == quote
                && bytes[i + 2] == quote
            {
                // Check if this is a triple-quote close
                // (we entered via triple-quote open, but we track single quote char)
                in_string = None;
                i += 3;
                continue;
            }
            if ch == quote {
                in_string = None;
            }
            i += 1;
            continue;
        }

        // ── Not in a string ─────────────────────────────────────────────

        // Rust raw strings: r"..." or r#"..."#
        if ch == b'r' && i + 1 < len {
            let next = bytes[i + 1];
            if next == b'"' {
                // r"...", skip to closing "
                i += 2;
                while i < len && bytes[i] != b'"' {
                    i += 1;
                }
                i += 1; // skip closing "
                continue;
            }
            if next == b'#' {
                // Count hashes
                let hash_start = i + 1;
                let mut j = i + 1;
                while j < len && bytes[j] == b'#' {
                    j += 1;
                }
                let hash_count = j - hash_start;
                if j < len && bytes[j] == b'"' {
                    // Skip to closing "###
                    let close_pat_len = 1 + hash_count; // " + hashes
                    i = j + 1;
                    'raw: while i < len {
                        if bytes[i] == b'"' {
                            // Check for matching hashes
                            let mut k = 1;
                            while k <= hash_count && i + k < len && bytes[i + k] == b'#' {
                                k += 1;
                            }
                            if k > hash_count {
                                i += close_pat_len;
                                break 'raw;
                            }
                        }
                        i += 1;
                    }
                    continue;
                }
            }
        }

        // Python triple quotes: """ or '''
        if (ch == b'"' || ch == b'\'') && i + 2 < len && bytes[i + 1] == ch && bytes[i + 2] == ch {
            in_string = Some(ch);
            i += 3;
            continue;
        }

        // Regular string literals
        if ch == b'"' || ch == b'\'' || ch == b'`' {
            in_string = Some(ch);
            i += 1;
            continue;
        }

        // ── Comment detection ───────────────────────────────────────────

        // C-style line comment: //
        let has_slash_slash = matches!(style, CommentStyle::CStyle | CommentStyle::PhpStyle);
        if has_slash_slash && ch == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            let comment_body = &line[i + 2..];
            return try_parse_directive(comment_body, line_num);
        }

        // Block comment: /*
        let has_block = matches!(style, CommentStyle::CStyle | CommentStyle::PhpStyle);
        if has_block && ch == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            // Look for closing */ on the same line
            let rest = &line[i + 2..];
            if let Some(end) = rest.find("*/") {
                let block_body = &rest[..end];
                // Check directive in block body
                if let Some(dir) = try_parse_directive(block_body, line_num) {
                    return Some(dir);
                }
                // Continue scanning after the block
                i = i + 2 + end + 2;
                continue;
            } else {
                // Block comment extends to next line(s)
                *in_block_comment = true;
                let block_body = rest;
                return try_parse_directive(block_body, line_num);
            }
        }

        // Hash comment: #
        let has_hash = matches!(style, CommentStyle::Hash | CommentStyle::PhpStyle);
        if has_hash && ch == b'#' {
            let comment_body = &line[i + 1..];
            return try_parse_directive(comment_body, line_num);
        }

        i += 1;
    }

    None
}

/// Try to extract a directive from a line rest (after a block comment closes).
fn extract_from_line_rest(
    rest: &str,
    line_num: usize,
    style: CommentStyle,
) -> Option<LineDirective> {
    let mut in_block = false;
    scan_line_for_directive(rest, line_num, style, &mut in_block)
}

/// Try to parse a `nyx:ignore` or `nyx:ignore-next-line` directive from
/// comment body text. Returns `None` if no directive is found.
fn try_parse_directive(text: &str, line_num: usize) -> Option<LineDirective> {
    let trimmed = text.trim();
    // Strip leading `*` or `* ` common in block comments (e.g. ` * nyx:ignore ...`).
    let trimmed = trimmed
        .strip_prefix("* ")
        .or(trimmed.strip_prefix('*'))
        .unwrap_or(trimmed)
        .trim();

    // Check for `nyx:ignore-next-line` first (longer prefix wins).
    if let Some(rest) = strip_directive_prefix(trimmed, "nyx:ignore-next-line") {
        let matchers = parse_rule_ids(rest);
        if matchers.is_empty() {
            return None;
        }
        return Some(LineDirective {
            kind: SuppressionKind::NextLine,
            directive_line: line_num,
            matchers,
        });
    }

    if let Some(rest) = strip_directive_prefix(trimmed, "nyx:ignore") {
        let matchers = parse_rule_ids(rest);
        if matchers.is_empty() {
            return None;
        }
        return Some(LineDirective {
            kind: SuppressionKind::SameLine,
            directive_line: line_num,
            matchers,
        });
    }

    None
}

/// Strip a directive prefix, allowing optional whitespace or the rest of the
/// line to follow.
fn strip_directive_prefix<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(prefix)?;
    // Must be followed by whitespace, end of string, or nothing.
    // If prefix is "nyx:ignore" and rest starts with "-next-line", don't match
    // (handled by checking the longer prefix first).
    if rest.is_empty() || rest.starts_with(char::is_whitespace) {
        Some(rest)
    } else {
        None
    }
}

/// Parse comma-separated rule IDs into matchers.
fn parse_rule_ids(text: &str) -> Vec<RuleMatcher> {
    text.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            if let Some(prefix) = s.strip_suffix(".*") {
                RuleMatcher::WildcardSuffix(prefix.to_string())
            } else {
                RuleMatcher::Exact(s.to_string())
            }
        })
        .collect()
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn rust_path() -> &'static Path {
        Path::new("test.rs")
    }
    fn py_path() -> &'static Path {
        Path::new("test.py")
    }
    fn rb_path() -> &'static Path {
        Path::new("test.rb")
    }
    fn php_path() -> &'static Path {
        Path::new("test.php")
    }
    fn js_path() -> &'static Path {
        Path::new("test.js")
    }

    // 1. `//` comment parsing
    #[test]
    fn slash_slash_comment_suppresses() {
        let src = "let x = 1; // nyx:ignore rule.a\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule.a").is_some());
        assert!(idx.check(1, "rule.b").is_none());
    }

    // 2. `#` comment parsing
    #[test]
    fn hash_comment_suppresses() {
        let src = "x = 1  # nyx:ignore rule.a\n";
        let idx = parse_inline_suppressions(py_path(), src);
        assert!(idx.check(1, "rule.a").is_some());
    }

    // 3. `/* */` block comment
    #[test]
    fn block_comment_suppresses() {
        let src = "let x = 1; /* nyx:ignore rule.a */\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule.a").is_some());
    }

    // 4. Same-line semantics
    #[test]
    fn same_line_only_suppresses_own_line() {
        let src = "line1\nlet x = 1; // nyx:ignore rule.a\nline3\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule.a").is_none());
        assert!(idx.check(2, "rule.a").is_some());
        assert!(idx.check(3, "rule.a").is_none());
    }

    // 5. Next-line semantics
    #[test]
    fn next_line_suppresses_following_line() {
        let src = "// nyx:ignore-next-line rule.a\nlet x = dangerous();\nline3\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule.a").is_none());
        assert!(idx.check(2, "rule.a").is_some());
        assert!(idx.check(3, "rule.a").is_none());
    }

    // 6. Multiple rule IDs
    #[test]
    fn multiple_rule_ids() {
        let src = "let x = 1; // nyx:ignore a.b.c, x.y.z\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "a.b.c").is_some());
        assert!(idx.check(1, "x.y.z").is_some());
        assert!(idx.check(1, "other").is_none());
    }

    // 7. Wildcard suffix
    #[test]
    fn wildcard_suffix_matching() {
        let src = "let x = 1; // nyx:ignore rs.quality.*\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rs.quality.foo").is_some());
        assert!(idx.check(1, "rs.quality.bar").is_some());
        assert!(idx.check(1, "rs.other.foo").is_none());
        // Exact match of prefix without the dot should not match
        assert!(idx.check(1, "rs.quality").is_none());
    }

    // 8. String literal guard
    #[test]
    fn string_literal_not_suppressed() {
        let src = "let x = \"// nyx:ignore rule.a\";\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule.a").is_none());
    }

    // 9. Rust raw string guard
    #[test]
    fn rust_raw_string_not_suppressed() {
        let src = "let x = r#\"// nyx:ignore rule.a\"#;\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule.a").is_none());
    }

    // 10. Rule ID mismatch
    #[test]
    fn rule_id_mismatch() {
        let src = "let x = 1; // nyx:ignore rule-a\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule-a").is_some());
        assert!(idx.check(1, "rule-b").is_none());
    }

    // 11. Taint rule ID canonicalization
    #[test]
    fn taint_rule_id_canonicalization() {
        let src = "let x = 1; // nyx:ignore taint-unsanitised-flow\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(
            idx.check(1, "taint-unsanitised-flow (source 5:1)")
                .is_some()
        );
        assert!(idx.check(1, "taint-unsanitised-flow").is_some());
    }

    // 12. Multiple directives targeting the same line
    #[test]
    fn multiple_directives_same_target() {
        let src = "// nyx:ignore-next-line rule-a\n// nyx:ignore-next-line rule-b\nlet x = dangerous();\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        // First ignore-next-line targets line 2, second targets line 3
        assert!(idx.check(2, "rule-a").is_some());
        assert!(idx.check(3, "rule-b").is_some());
    }

    // 13. Block comment with ignore-next-line
    #[test]
    fn block_comment_next_line() {
        let src = "/* nyx:ignore-next-line rule.a */\nlet x = dangerous();\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(2, "rule.a").is_some());
    }

    // 14. EOF ignore-next-line is a no-op
    #[test]
    fn eof_next_line_no_panic() {
        let src = "// nyx:ignore-next-line rule.a";
        let idx = parse_inline_suppressions(rust_path(), src);
        // Line 1 is the last line, so ignore-next-line targets line 2 which doesn't exist
        assert!(idx.check(1, "rule.a").is_none());
        assert!(idx.check(2, "rule.a").is_none());
    }

    // 15. CRLF input
    #[test]
    fn crlf_line_endings() {
        let src = "let x = 1; // nyx:ignore rule.a\r\nlet y = 2;\r\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule.a").is_some());
        assert!(idx.check(2, "rule.a").is_none());
    }

    // 16. Whitespace tolerance
    #[test]
    fn whitespace_tolerance() {
        let src = "let x = 1; //  nyx:ignore   rule.a,  rule.b  \n";
        let idx = parse_inline_suppressions(rust_path(), src);
        assert!(idx.check(1, "rule.a").is_some());
        assert!(idx.check(1, "rule.b").is_some());
    }

    // 17. PHP multi-style comments
    #[test]
    fn php_multi_style() {
        let src_hash = "<?php\n$x = 1; # nyx:ignore rule.a\n";
        let src_slash = "<?php\n$x = 1; // nyx:ignore rule.b\n";
        let idx_hash = parse_inline_suppressions(php_path(), src_hash);
        let idx_slash = parse_inline_suppressions(php_path(), src_slash);
        assert!(idx_hash.check(2, "rule.a").is_some());
        assert!(idx_slash.check(2, "rule.b").is_some());
    }

    // ── canonical_rule_id tests ─────────────────────────────────────────

    #[test]
    fn canonical_strips_parenthetical() {
        assert_eq!(
            canonical_rule_id("taint-unsanitised-flow (source 5:1)"),
            "taint-unsanitised-flow"
        );
    }

    #[test]
    fn canonical_no_parenthetical_unchanged() {
        assert_eq!(canonical_rule_id("rs.quality.unwrap"), "rs.quality.unwrap");
    }

    #[test]
    fn canonical_trims_whitespace() {
        assert_eq!(canonical_rule_id("  rule.a  "), "rule.a");
    }

    // ── Ruby hash comment ───────────────────────────────────────────────

    #[test]
    fn ruby_hash_comment() {
        let src = "x = dangerous # nyx:ignore rule.a\n";
        let idx = parse_inline_suppressions(rb_path(), src);
        assert!(idx.check(1, "rule.a").is_some());
    }

    // ── JS template literal guard ───────────────────────────────────────

    #[test]
    fn js_template_literal_not_suppressed() {
        let src = "let x = `// nyx:ignore rule.a`;\n";
        let idx = parse_inline_suppressions(js_path(), src);
        assert!(idx.check(1, "rule.a").is_none());
    }

    // ── Multiline block comment ─────────────────────────────────────────

    #[test]
    fn multiline_block_comment() {
        let src = "/*\n * nyx:ignore rule.a\n */\nlet x = dangerous;\n";
        let idx = parse_inline_suppressions(rust_path(), src);
        // The directive is on line 2, same-line → targets line 2
        assert!(idx.check(2, "rule.a").is_some());
    }
}
