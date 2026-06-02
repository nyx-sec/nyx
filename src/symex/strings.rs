//! String method recognition, concrete evaluation, sanitizer detection,
//! and encoding/decoding transform classification.
//!
//! Symbolic string theory maps callee names to semantic string operations
//! across languages.
//!
//! Encoding/decoding models recognize transforms (HTML escape, URL encode,
//! etc.) for witness enrichment and heuristic mismatch diagnostics. They do
//! NOT affect taint semantics.

use crate::labels::{Cap, bare_method_name};
use crate::symbol::Lang;

use super::value::SymbolicValue;

//  Types

/// Recognized string operation semantic.
#[derive(Clone, Debug, PartialEq)]
pub enum StringMethod {
    Trim,
    ToLower,
    ToUpper,
    Replace {
        pattern: String,
        replacement: String,
    },
    Substr,
    StrLen,
}

/// Where the string operand comes from in the call.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StringOperandSource {
    /// `receiver.method()`, JS, Java, Ruby, Rust
    Receiver,
    /// `func(string, ...)`, Python `len()`, Go `strings.*`, PHP `strlen()`
    FirstArg,
}

/// Result of classifying a callee as a string method.
#[derive(Clone, Debug)]
pub struct StringMethodInfo {
    pub method: StringMethod,
    pub operand_source: StringOperandSource,
}

/// Information about a Replace operation that acts as a sanitizer.
#[derive(Clone, Debug)]
pub struct SanitizerInfo {
    /// Which capability bits this replace sanitizes.
    pub sanitized_caps: Cap,
    /// Whether the replacement is global (replaces all occurrences).
    pub is_global: bool,
}

//  Encoding/decoding transform types

/// Category of encoding/decoding transform for symbolic modeling.
///
/// Split into two groups:
/// - **Protective transforms** (escape-like): have a verified `Cap`
///   correspondence in existing label rules. Used for mismatch diagnostics.
/// - **Representation transforms** (non-protective): witness-only, never
///   used for mismatch reasoning.
///
/// Symex `Encode`/`Decode` nodes preserve taint unconditionally, this enum
/// carries no sanitization authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransformKind {
    // ── Protective transforms ────────────────────────────────────────────
    /// HTML entity escaping: `&` → `&amp;`, `<` → `&lt;`, etc.
    HtmlEscape,
    /// Percent-encoding: non-unreserved → `%XX`.
    UrlEncode,
    /// Shell quoting: single-quote wrapping with internal quote escaping.
    ShellEscape,
    /// SQL string escaping: `'` → `''`. Witness-only, no label rule yet,
    /// so `verified_cap()` returns `Cap::empty()`.
    SqlEscape,
    // ── Representation transforms (non-protective) ───────────────────────
    /// Base64 encoding (representation, not sanitisation).
    Base64Encode,
    /// Base64 decoding.
    Base64Decode,
    /// URL percent-decoding (reverses URL encoding, anti-protective).
    UrlDecode,
}

impl TransformKind {
    /// Human-readable name for Display and witness output.
    pub fn display_name(self) -> &'static str {
        match self {
            TransformKind::HtmlEscape => "htmlEscape",
            TransformKind::UrlEncode => "urlEncode",
            TransformKind::ShellEscape => "shellEscape",
            TransformKind::SqlEscape => "sqlEscape",
            TransformKind::Base64Encode => "base64Encode",
            TransformKind::Base64Decode => "base64Decode",
            TransformKind::UrlDecode => "urlDecode",
        }
    }

    /// The `Cap` this transform is verified to neutralize, based on existing
    /// taint label rules.
    ///
    /// Returns `Cap::empty()` for representation transforms AND for
    /// `SqlEscape` (no verified label rule). Only transforms with a
    /// confirmed sanitizer rule in the label tables return non-empty caps:
    /// - `HtmlEscape` → `Cap::HTML_ESCAPE` (he.encode, html.escape, htmlspecialchars)
    /// - `UrlEncode` → `Cap::URL_ENCODE` (encodeURIComponent, urllib.parse.quote, urlencode)
    /// - `ShellEscape` → `Cap::SHELL_ESCAPE` (shlex.quote, escapeshellarg, shellescape)
    pub fn verified_cap(self) -> Cap {
        match self {
            TransformKind::HtmlEscape => Cap::HTML_ESCAPE,
            TransformKind::UrlEncode => Cap::URL_ENCODE,
            TransformKind::ShellEscape => Cap::SHELL_ESCAPE,
            // SqlEscape: no verified label rule, witness-only
            TransformKind::SqlEscape => Cap::empty(),
            // Representation transforms: not protective
            TransformKind::Base64Encode
            | TransformKind::Base64Decode
            | TransformKind::UrlDecode => Cap::empty(),
        }
    }

    /// Returns `true` for escape-like transforms with non-empty `verified_cap()`.
    pub fn is_protective(self) -> bool {
        !self.verified_cap().is_empty()
    }
}

/// Result of classifying a callee as an encoding/decoding transform.
#[derive(Clone, Debug)]
pub struct TransformMethodInfo {
    pub kind: TransformKind,
    pub operand_source: StringOperandSource,
}

//  String method classification

/// Classify a callee as a recognized string method.
///
/// Returns `None` for unrecognized methods (fall through to opaque `Call`).
/// For `Replace`, only classifies when pattern and replacement args are concrete
/// strings, dynamic patterns produce `None`.
pub fn classify_string_method(
    callee: &str,
    args: &[SymbolicValue],
    lang: Lang,
) -> Option<StringMethodInfo> {
    let method = bare_method_name(callee);

    match lang {
        Lang::JavaScript | Lang::TypeScript => classify_js(method, args),
        Lang::Python => classify_python(method, callee, args),
        Lang::Ruby => classify_ruby(method, args),
        Lang::Java => classify_java(method, args),
        Lang::Go => classify_go(method, callee, args),
        Lang::Php => classify_php(method, callee, args),
        Lang::Rust => classify_rust(method, args),
        Lang::C | Lang::Cpp => classify_c(method),
    }
}

fn classify_js(method: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "trim" | "trimStart" | "trimEnd" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "toLowerCase" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "toUpperCase" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "replace" | "replaceAll" => {
            // args layout: [receiver_sym, pattern_arg, replacement_arg]
            // receiver is prepended by transfer.rs when present
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: Receiver,
            })
        }
        "substring" | "substr" | "slice" => {
            // Only model when indices are concrete
            if has_concrete_index(args, 1) {
                Some(StringMethodInfo {
                    method: Substr,
                    operand_source: Receiver,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

fn classify_python(method: &str, callee: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    // Python builtins: len(s), no receiver
    if callee == "len" {
        return Some(StringMethodInfo {
            method: StrLen,
            operand_source: FirstArg,
        });
    }

    match method {
        "strip" | "lstrip" | "rstrip" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "lower" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "upper" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "replace" => {
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: Receiver,
            })
        }
        _ => None,
    }
}

fn classify_ruby(method: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "strip" | "lstrip" | "rstrip" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "downcase" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "upcase" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "gsub" | "sub" => {
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: Receiver,
            })
        }
        "length" | "size" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: Receiver,
        }),
        _ => None,
    }
}

fn classify_java(method: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "trim" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "toLowerCase" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "toUpperCase" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "replace" | "replaceAll" => {
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: Receiver,
            })
        }
        "substring" => {
            if has_concrete_index(args, 1) {
                Some(StringMethodInfo {
                    method: Substr,
                    operand_source: Receiver,
                })
            } else {
                None
            }
        }
        "length" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: Receiver,
        }),
        _ => None,
    }
}

fn classify_go(method: &str, callee: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    // Go uses package functions: strings.TrimSpace(s), strings.ToLower(s)
    // The full callee is needed to check the package prefix.
    match callee {
        "strings.TrimSpace" => Some(StringMethodInfo {
            method: Trim,
            operand_source: FirstArg,
        }),
        "strings.ToLower" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: FirstArg,
        }),
        "strings.ToUpper" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: FirstArg,
        }),
        "strings.Replace" | "strings.ReplaceAll" => {
            // Go: strings.Replace(s, old, new, n) or strings.ReplaceAll(s, old, new)
            // args[0] = string, args[1] = pattern, args[2] = replacement
            let (pat, rep) = extract_replace_args(args, 1)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: FirstArg,
            })
        }
        _ => {
            // Fallback: check method name for len()
            if method == "len" {
                Some(StringMethodInfo {
                    method: StrLen,
                    operand_source: FirstArg,
                })
            } else {
                None
            }
        }
    }
}

fn classify_php(method: &str, callee: &str, args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    // PHP uses free functions: trim($s), strtolower($s)
    match callee {
        "trim" | "ltrim" | "rtrim" => Some(StringMethodInfo {
            method: Trim,
            operand_source: FirstArg,
        }),
        "strtolower" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: FirstArg,
        }),
        "strtoupper" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: FirstArg,
        }),
        "str_replace" => {
            // PHP: str_replace($search, $replace, $subject), string is arg[2]
            // But in our callee model, receiver is not present for free functions.
            // args[0] = pattern, args[1] = replacement, args[2] = subject
            let (pat, rep) = extract_replace_args(args, 0)?;
            Some(StringMethodInfo {
                method: Replace {
                    pattern: pat,
                    replacement: rep,
                },
                operand_source: FirstArg,
            })
        }
        "strlen" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: FirstArg,
        }),
        "substr" => {
            if has_concrete_index(args, 1) {
                Some(StringMethodInfo {
                    method: Substr,
                    operand_source: FirstArg,
                })
            } else {
                None
            }
        }
        _ => {
            // Fallback: check method name only
            match method {
                "trim" => Some(StringMethodInfo {
                    method: Trim,
                    operand_source: Receiver,
                }),
                _ => None,
            }
        }
    }
}

fn classify_rust(method: &str, _args: &[SymbolicValue]) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "trim" | "trim_start" | "trim_end" => Some(StringMethodInfo {
            method: Trim,
            operand_source: Receiver,
        }),
        "to_lowercase" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: Receiver,
        }),
        "to_uppercase" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: Receiver,
        }),
        "len" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: Receiver,
        }),
        _ => None,
    }
}

fn classify_c(method: &str) -> Option<StringMethodInfo> {
    use StringMethod::*;
    use StringOperandSource::*;

    match method {
        "tolower" => Some(StringMethodInfo {
            method: ToLower,
            operand_source: FirstArg,
        }),
        "toupper" => Some(StringMethodInfo {
            method: ToUpper,
            operand_source: FirstArg,
        }),
        "strlen" => Some(StringMethodInfo {
            method: StrLen,
            operand_source: FirstArg,
        }),
        _ => None,
    }
}

//  Encoding/decoding transform classification

/// Classify a callee as a recognized encoding/decoding transform.
///
/// Returns `None` for unrecognized methods. Rich sanitizers (DOMPurify,
/// bleach, markupsafe, etc.) are intentionally NOT classified here, they
/// are complex library-level sanitizers, not simple character-level escapes.
pub fn classify_transform_method(callee: &str, lang: Lang) -> Option<TransformMethodInfo> {
    match lang {
        Lang::JavaScript | Lang::TypeScript => classify_transform_js(callee),
        Lang::Python => classify_transform_python(callee),
        Lang::Php => classify_transform_php(callee),
        Lang::Java => classify_transform_java(callee),
        Lang::Go => classify_transform_go(callee),
        Lang::Ruby => classify_transform_ruby(callee),
        _ => None,
    }
}

fn classify_transform_js(callee: &str) -> Option<TransformMethodInfo> {
    use StringOperandSource::*;
    use TransformKind::*;

    let method = bare_method_name(callee);
    match method {
        // URL encoding/decoding
        "encodeURIComponent" | "encodeURI" => Some(TransformMethodInfo {
            kind: UrlEncode,
            operand_source: FirstArg,
        }),
        "decodeURIComponent" | "decodeURI" => Some(TransformMethodInfo {
            kind: UrlDecode,
            operand_source: FirstArg,
        }),
        // Base64
        "btoa" => Some(TransformMethodInfo {
            kind: Base64Encode,
            operand_source: FirstArg,
        }),
        "atob" => Some(TransformMethodInfo {
            kind: Base64Decode,
            operand_source: FirstArg,
        }),
        // HTML entity encoding via he library (NOT DOMPurify/sanitizeHtml)
        "encode" | "escape" if callee.starts_with("he.") => Some(TransformMethodInfo {
            kind: HtmlEscape,
            operand_source: FirstArg,
        }),
        _ => None,
    }
}

fn classify_transform_python(callee: &str) -> Option<TransformMethodInfo> {
    use StringOperandSource::*;
    use TransformKind::*;

    match callee {
        // HTML escaping (NOT bleach.clean, markupsafe.escape, django.utils.html.escape)
        "html.escape" | "cgi.escape" => Some(TransformMethodInfo {
            kind: HtmlEscape,
            operand_source: FirstArg,
        }),
        // URL encoding/decoding
        "urllib.parse.quote" | "urllib.parse.quote_plus" => Some(TransformMethodInfo {
            kind: UrlEncode,
            operand_source: FirstArg,
        }),
        "urllib.parse.unquote" => Some(TransformMethodInfo {
            kind: UrlDecode,
            operand_source: FirstArg,
        }),
        // Shell escaping
        "shlex.quote" => Some(TransformMethodInfo {
            kind: ShellEscape,
            operand_source: FirstArg,
        }),
        // Base64
        "base64.b64encode" => Some(TransformMethodInfo {
            kind: Base64Encode,
            operand_source: FirstArg,
        }),
        "base64.b64decode" => Some(TransformMethodInfo {
            kind: Base64Decode,
            operand_source: FirstArg,
        }),
        _ => None,
    }
}

fn classify_transform_php(callee: &str) -> Option<TransformMethodInfo> {
    use StringOperandSource::*;
    use TransformKind::*;

    match callee {
        // HTML escaping
        "htmlspecialchars" | "htmlentities" => Some(TransformMethodInfo {
            kind: HtmlEscape,
            operand_source: FirstArg,
        }),
        // URL encoding/decoding
        "urlencode" | "rawurlencode" => Some(TransformMethodInfo {
            kind: UrlEncode,
            operand_source: FirstArg,
        }),
        "urldecode" | "rawurldecode" => Some(TransformMethodInfo {
            kind: UrlDecode,
            operand_source: FirstArg,
        }),
        // Base64
        "base64_encode" => Some(TransformMethodInfo {
            kind: Base64Encode,
            operand_source: FirstArg,
        }),
        "base64_decode" => Some(TransformMethodInfo {
            kind: Base64Decode,
            operand_source: FirstArg,
        }),
        // Shell escaping
        "escapeshellarg" | "escapeshellcmd" => Some(TransformMethodInfo {
            kind: ShellEscape,
            operand_source: FirstArg,
        }),
        // SQL escaping (witness-only, no verified label rule)
        "addslashes" => Some(TransformMethodInfo {
            kind: SqlEscape,
            operand_source: FirstArg,
        }),
        _ => None,
    }
}

fn classify_transform_java(callee: &str) -> Option<TransformMethodInfo> {
    use StringOperandSource::*;
    use TransformKind::*;

    // Java callees arrive as fully-qualified or dotted forms (e.g.
    // `URLEncoder.encode`, `Base64.getEncoder.encodeToString`). Match on
    // the suffix after the last `.` for the leaf method name, but also
    // examine the dotted callee for receiver-qualified disambiguation.
    let method = bare_method_name(callee);

    // URL encoding/decoding, `java.net.URLEncoder.encode` / `URLDecoder.decode`.
    if callee.ends_with("URLEncoder.encode") {
        return Some(TransformMethodInfo {
            kind: UrlEncode,
            operand_source: FirstArg,
        });
    }
    if callee.ends_with("URLDecoder.decode") {
        return Some(TransformMethodInfo {
            kind: UrlDecode,
            operand_source: FirstArg,
        });
    }

    // Apache commons-text / commons-lang `StringEscapeUtils.escapeHtml4`,
    // `escapeXml11`, `escapeXml10`. These are character-level entity escapes ,
    // NOT rich sanitizers like OWASP ESAPI's `Encoder`.
    if callee.ends_with("StringEscapeUtils.escapeHtml4")
        || callee.ends_with("StringEscapeUtils.escapeHtml")
        || callee.ends_with("StringEscapeUtils.escapeXml11")
        || callee.ends_with("StringEscapeUtils.escapeXml10")
        || callee.ends_with("StringEscapeUtils.escapeXml")
    {
        return Some(TransformMethodInfo {
            kind: HtmlEscape,
            operand_source: FirstArg,
        });
    }

    // Base64, `Base64.getEncoder().encodeToString(bytes)` (and the URL-safe
    // / MIME variants). Match by leaf method name; the encoder/decoder chain
    // before it is opaque to symex, but the operand is still the first arg.
    match method {
        "encodeToString" => Some(TransformMethodInfo {
            kind: Base64Encode,
            operand_source: FirstArg,
        }),
        // `Base64.getDecoder().decode(s)`, the leaf `decode` collides with
        // `URLDecoder.decode` (handled above) so this only matches when the
        // URLDecoder branch did not.
        "decode" if callee.contains("Base64") => Some(TransformMethodInfo {
            kind: Base64Decode,
            operand_source: FirstArg,
        }),
        _ => None,
    }
}

fn classify_transform_go(callee: &str) -> Option<TransformMethodInfo> {
    use StringOperandSource::*;
    use TransformKind::*;

    match callee {
        // URL encoding/decoding, `net/url` package.
        "url.QueryEscape" | "url.PathEscape" => Some(TransformMethodInfo {
            kind: UrlEncode,
            operand_source: FirstArg,
        }),
        "url.QueryUnescape" | "url.PathUnescape" => Some(TransformMethodInfo {
            kind: UrlDecode,
            operand_source: FirstArg,
        }),
        // HTML entity escaping, `html` package (NOT `template.HTMLEscapeString`,
        // which is a context-aware sanitizer). `html.UnescapeString` is
        // intentionally NOT classified: TransformKind has no `HtmlUnescape`
        // variant, and reusing UrlDecode would label the witness wrongly.
        "html.EscapeString" => Some(TransformMethodInfo {
            kind: HtmlEscape,
            operand_source: FirstArg,
        }),
        // Base64, `encoding/base64` package, `StdEncoding`/`URLEncoding`/
        // `RawStdEncoding`/`RawURLEncoding` all expose `EncodeToString`.
        "base64.StdEncoding.EncodeToString"
        | "base64.URLEncoding.EncodeToString"
        | "base64.RawStdEncoding.EncodeToString"
        | "base64.RawURLEncoding.EncodeToString" => Some(TransformMethodInfo {
            kind: Base64Encode,
            operand_source: FirstArg,
        }),
        "base64.StdEncoding.DecodeString"
        | "base64.URLEncoding.DecodeString"
        | "base64.RawStdEncoding.DecodeString"
        | "base64.RawURLEncoding.DecodeString" => Some(TransformMethodInfo {
            kind: Base64Decode,
            operand_source: FirstArg,
        }),
        _ => None,
    }
}

fn classify_transform_ruby(callee: &str) -> Option<TransformMethodInfo> {
    use StringOperandSource::*;
    use TransformKind::*;

    // Ruby callees may arrive as `CGI.escape`, `CGI::escape`, or
    // `ERB::Util.html_escape`. Normalise `::` → `.` for matching.
    let normalised = callee.replace("::", ".");
    match normalised.as_str() {
        // URL percent-encoding. Note: `CGI.escape` in Ruby is percent-encoding
        // (NOT HTML escape, that's `CGI.escapeHTML`).
        "CGI.escape" | "URI.encode_www_form_component" => Some(TransformMethodInfo {
            kind: UrlEncode,
            operand_source: FirstArg,
        }),
        "CGI.unescape" | "URI.decode_www_form_component" => Some(TransformMethodInfo {
            kind: UrlDecode,
            operand_source: FirstArg,
        }),
        // HTML entity escaping (character-level, NOT Rails `sanitize` or
        // `strip_tags` which are rich sanitizers).
        "ERB::Util.html_escape" | "ERB.Util.html_escape" | "CGI.escapeHTML" => {
            Some(TransformMethodInfo {
                kind: HtmlEscape,
                operand_source: FirstArg,
            })
        }
        // Base64, `Base64.strict_encode64` / `encode64` / `urlsafe_encode64`.
        "Base64.strict_encode64" | "Base64.encode64" | "Base64.urlsafe_encode64" => {
            Some(TransformMethodInfo {
                kind: Base64Encode,
                operand_source: FirstArg,
            })
        }
        "Base64.strict_decode64" | "Base64.decode64" | "Base64.urlsafe_decode64" => {
            Some(TransformMethodInfo {
                kind: Base64Decode,
                operand_source: FirstArg,
            })
        }
        _ => None,
    }
}

//  Concrete encoding/decoding for witness rendering

/// Apply encoding for witness rendering.
///
/// **NOT a spec-complete codec.** These are witness-quality helpers only ,
/// not suitable for security decisions, not reusable outside witness display.
pub fn encode_concrete_for_witness(kind: TransformKind, input: &str) -> Option<String> {
    match kind {
        TransformKind::HtmlEscape => Some(html_escape_witness(input)),
        TransformKind::UrlEncode => url_encode_witness(input),
        TransformKind::ShellEscape => Some(shell_escape_witness(input)),
        TransformKind::SqlEscape => Some(sql_escape_witness(input)),
        TransformKind::Base64Encode => Some(base64_encode_witness(input)),
        // Decoding ops handled by decode_concrete_for_witness
        TransformKind::Base64Decode | TransformKind::UrlDecode => None,
    }
}

/// Apply decoding for witness rendering.
///
/// **NOT a spec-complete codec.** Witness-quality only.
pub fn decode_concrete_for_witness(kind: TransformKind, input: &str) -> Option<String> {
    match kind {
        TransformKind::Base64Decode => base64_decode_witness(input),
        TransformKind::UrlDecode => url_decode_witness(input),
        // Encoding ops handled by encode_concrete_for_witness
        _ => None,
    }
}

/// HTML entity escaping (witness-quality).
fn html_escape_witness(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + input.len() / 4);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// URL percent-encoding (witness-quality, ASCII only).
///
/// Encodes all characters except unreserved set `[A-Za-z0-9-_.~]`.
/// Returns `None` for non-ASCII input (conservative).
fn url_encode_witness(input: &str) -> Option<String> {
    if !input.is_ascii() {
        return None;
    }
    let mut out = String::with_capacity(input.len() * 3);
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX_UPPER[(b >> 4) as usize] as char);
            out.push(HEX_UPPER[(b & 0x0f) as usize] as char);
        }
    }
    Some(out)
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Shell single-quote escaping (witness-quality, POSIX model).
fn shell_escape_witness(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    out.push('\'');
    for ch in input.chars() {
        if ch == '\'' {
            // Close quote, add escaped single quote, reopen
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// SQL single-quote doubling (witness-quality).
fn sql_escape_witness(input: &str) -> String {
    input.replace('\'', "''")
}

/// Base64 encoding (witness-quality, standard alphabet + padding).
fn base64_encode_witness(input: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Base64 decoding (witness-quality). Returns `None` for invalid input.
fn base64_decode_witness(input: &str) -> Option<String> {
    let input = input.trim_end_matches('=');
    let mut bytes = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.chars() {
        let val = match ch {
            'A'..='Z' => ch as u32 - b'A' as u32,
            'a'..='z' => ch as u32 - b'a' as u32 + 26,
            '0'..='9' => ch as u32 - b'0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    String::from_utf8(bytes).ok()
}

/// URL percent-decoding (witness-quality).
fn url_decode_witness(input: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.bytes();

    while let Some(b) = chars.next() {
        match b {
            b'%' => {
                let h = chars.next()?;
                let l = chars.next()?;
                let hi = hex_val(h)?;
                let lo = hex_val(l)?;
                bytes.push((hi << 4) | lo);
            }
            b'+' => bytes.push(b' '),
            other => bytes.push(other),
        }
    }

    String::from_utf8(bytes).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

//  Arg extraction helpers

/// Extract concrete pattern and replacement strings from args at given offset.
///
/// `offset` is the index of the pattern arg (replacement is offset+1).
/// Returns `None` if either is not `ConcreteStr`.
fn extract_replace_args(args: &[SymbolicValue], offset: usize) -> Option<(String, String)> {
    let pat = args.get(offset)?.as_concrete_str()?;
    let rep = args.get(offset + 1)?.as_concrete_str()?;
    Some((pat.to_owned(), rep.to_owned()))
}

/// Check that the arg at `offset` is a concrete integer (for Substr indices).
fn has_concrete_index(args: &[SymbolicValue], offset: usize) -> bool {
    args.get(offset)
        .map(|a| a.as_concrete_int().is_some())
        .unwrap_or(false)
}

//  Concrete evaluation

/// Evaluate a string operation on a concrete receiver string.
///
/// Returns the folded result, or `None` if the receiver is not concrete.
pub fn evaluate_string_op_concrete(method: &StringMethod, receiver: &str) -> Option<SymbolicValue> {
    match method {
        StringMethod::Trim => Some(SymbolicValue::ConcreteStr(receiver.trim().to_owned())),
        StringMethod::ToLower => Some(SymbolicValue::ConcreteStr(receiver.to_lowercase())),
        StringMethod::ToUpper => Some(SymbolicValue::ConcreteStr(receiver.to_uppercase())),
        StringMethod::Replace {
            pattern,
            replacement,
        } => Some(SymbolicValue::ConcreteStr(
            receiver.replace(pattern.as_str(), replacement.as_str()),
        )),
        StringMethod::StrLen => Some(SymbolicValue::Concrete(receiver.len() as i64)),
        StringMethod::Substr => {
            // Substr needs index args, concrete evaluation handled in smart constructor
            None
        }
    }
}

//  Sanitizer detection

/// Detect whether a Replace operation acts as a security sanitizer.
///
/// Returns `None` if the pattern is not security-relevant. This is conservative:
/// the symbolic string theory does NOT clear taint via Replace, detection is
/// informational only for witness quality.
pub fn detect_replace_sanitizer(
    pattern: &str,
    _replacement: &str,
    callee: &str,
    lang: Lang,
) -> Option<SanitizerInfo> {
    let is_global = is_global_replace(callee, lang);

    let mut caps = Cap::empty();

    // XSS: HTML entity escaping patterns
    if pattern == "<"
        || pattern == ">"
        || pattern == "\""
        || pattern == "'"
        || pattern.contains("<script")
        || pattern.contains("<img")
        || pattern.contains("<svg")
    {
        caps |= Cap::HTML_ESCAPE;
    }

    // SQLi: quote escaping patterns
    if pattern == "'" || pattern == "\"" || pattern == "--" || pattern == ";" {
        caps |= Cap::SQL_QUERY;
    }

    // CMDi: shell metachar escaping patterns
    if pattern == "$" || pattern == "`" || pattern == "|" || pattern == ";" || pattern == "&" {
        caps |= Cap::SHELL_ESCAPE;
    }

    if caps.is_empty() {
        None
    } else {
        Some(SanitizerInfo {
            sanitized_caps: caps,
            is_global,
        })
    }
}

/// Detect a call-site Replace sanitizer from syntactic argument literals.
///
/// Used by SSA transfer to recognize replace-based shell/HTML/SQL escapers
/// without requiring a label rule per pattern. Returns the sanitized caps
/// when:
///   * the callee is a recognized Replace string method (per language),
///   * the pattern argument is a concrete string literal, and
///   * the pattern matches a security-relevant escape pattern in
///     [`detect_replace_sanitizer`].
///
/// Non-global replaces (e.g. JS `s.replace(";", "")` only replaces the first
/// occurrence) are excluded because partial replacement does not provide a
/// sanitiser-strength guarantee at the call site.
pub fn detect_call_site_replace_sanitizer(
    callee: &str,
    lang: Lang,
    arg_string_literals: &[Option<String>],
) -> Option<Cap> {
    let pattern_pos = pattern_arg_position(callee, lang)?;
    let pattern = arg_string_literals
        .get(pattern_pos)
        .and_then(|o| o.as_deref())?;
    let replacement = arg_string_literals
        .get(pattern_pos + 1)
        .and_then(|o| o.as_deref())
        .unwrap_or("");
    let info = detect_replace_sanitizer(pattern, replacement, callee, lang)?;
    if !info.is_global || info.sanitized_caps.is_empty() {
        return None;
    }
    Some(info.sanitized_caps)
}

fn pattern_arg_position(callee: &str, lang: Lang) -> Option<usize> {
    let method = bare_method_name(callee);
    match lang {
        Lang::JavaScript | Lang::TypeScript => match method {
            "replace" | "replaceAll" => Some(0),
            _ => None,
        },
        Lang::Python => match method {
            "replace" => Some(0),
            "sub" if callee == "re.sub" => Some(0),
            _ => None,
        },
        Lang::Ruby => match method {
            "gsub" | "sub" => Some(0),
            _ => None,
        },
        Lang::Java => match method {
            "replace" | "replaceAll" => Some(0),
            _ => None,
        },
        Lang::Go => match callee {
            "strings.Replace" | "strings.ReplaceAll" => Some(1),
            _ => None,
        },
        Lang::Php => match callee {
            "str_replace" => Some(0),
            _ => None,
        },
        Lang::Rust => match method {
            "replace" | "replacen" => Some(0),
            _ => None,
        },
        _ => None,
    }
}

/// Determine whether a replace call is global (replaces all occurrences).
fn is_global_replace(callee: &str, lang: Lang) -> bool {
    let method = bare_method_name(callee);
    match lang {
        // JS: replace() is NOT global; replaceAll() IS global
        Lang::JavaScript | Lang::TypeScript => method == "replaceAll",
        // Python: str.replace() is always global
        Lang::Python => true,
        // Ruby: gsub is global, sub is not
        Lang::Ruby => method == "gsub",
        // Java: both replace() and replaceAll() are global for CharSequence
        Lang::Java => true,
        // Go: strings.ReplaceAll is global, strings.Replace with n=-1 is global
        // (conservative: assume not global for strings.Replace)
        Lang::Go => callee == "strings.ReplaceAll",
        // PHP: str_replace() is always global
        Lang::Php => true,
        // Rust: str.replace() is always global
        Lang::Rust => true,
        _ => false,
    }
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_js_trim() {
        let info = classify_string_method("input.trim", &[], Lang::JavaScript).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
        assert_eq!(info.operand_source, StringOperandSource::Receiver);
    }

    #[test]
    fn test_classify_js_to_lower() {
        let info = classify_string_method("s.toLowerCase", &[], Lang::JavaScript).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
    }

    #[test]
    fn test_classify_js_to_upper() {
        let info = classify_string_method("s.toUpperCase", &[], Lang::JavaScript).unwrap();
        assert_eq!(info.method, StringMethod::ToUpper);
    }

    #[test]
    fn test_classify_js_replace_concrete() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)), // receiver
            SymbolicValue::ConcreteStr("<".into()),             // pattern
            SymbolicValue::ConcreteStr("&lt;".into()),          // replacement
        ];
        let info = classify_string_method("s.replace", &args, Lang::JavaScript).unwrap();
        match &info.method {
            StringMethod::Replace {
                pattern,
                replacement,
            } => {
                assert_eq!(pattern, "<");
                assert_eq!(replacement, "&lt;");
            }
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_js_replace_dynamic_pattern() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)), // receiver
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(1)), // dynamic pattern
            SymbolicValue::ConcreteStr("".into()),              // replacement
        ];
        assert!(classify_string_method("s.replace", &args, Lang::JavaScript).is_none());
    }

    #[test]
    fn test_classify_js_substring_concrete_index() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)), // receiver
            SymbolicValue::Concrete(0),                         // start
        ];
        let info = classify_string_method("s.substring", &args, Lang::JavaScript).unwrap();
        assert_eq!(info.method, StringMethod::Substr);
    }

    #[test]
    fn test_classify_js_substring_dynamic_index() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)), // receiver
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(1)), // dynamic index
        ];
        assert!(classify_string_method("s.substring", &args, Lang::JavaScript).is_none());
    }

    #[test]
    fn test_classify_python_strip() {
        let info = classify_string_method("s.strip", &[], Lang::Python).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
        assert_eq!(info.operand_source, StringOperandSource::Receiver);
    }

    #[test]
    fn test_classify_python_lower() {
        let info = classify_string_method("s.lower", &[], Lang::Python).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
    }

    #[test]
    fn test_classify_python_len() {
        let info = classify_string_method("len", &[], Lang::Python).unwrap();
        assert_eq!(info.method, StringMethod::StrLen);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_ruby_downcase() {
        let info = classify_string_method("s.downcase", &[], Lang::Ruby).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
    }

    #[test]
    fn test_classify_ruby_gsub() {
        let args = vec![
            SymbolicValue::Symbol(crate::ssa::ir::SsaValue(0)),
            SymbolicValue::ConcreteStr("<".into()),
            SymbolicValue::ConcreteStr("&lt;".into()),
        ];
        let info = classify_string_method("s.gsub", &args, Lang::Ruby).unwrap();
        match &info.method {
            StringMethod::Replace { .. } => {}
            other => panic!("expected Replace, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_java_trim() {
        let info = classify_string_method("s.trim", &[], Lang::Java).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
    }

    #[test]
    fn test_classify_java_length() {
        let info = classify_string_method("s.length", &[], Lang::Java).unwrap();
        assert_eq!(info.method, StringMethod::StrLen);
    }

    #[test]
    fn test_classify_go_trim_space() {
        let info = classify_string_method("strings.TrimSpace", &[], Lang::Go).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_go_to_lower() {
        let info = classify_string_method("strings.ToLower", &[], Lang::Go).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_php_strtolower() {
        let info = classify_string_method("strtolower", &[], Lang::Php).unwrap();
        assert_eq!(info.method, StringMethod::ToLower);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_php_strlen() {
        let info = classify_string_method("strlen", &[], Lang::Php).unwrap();
        assert_eq!(info.method, StringMethod::StrLen);
    }

    #[test]
    fn test_classify_rust_trim() {
        let info = classify_string_method("s.trim", &[], Lang::Rust).unwrap();
        assert_eq!(info.method, StringMethod::Trim);
    }

    #[test]
    fn test_classify_c_strlen() {
        let info = classify_string_method("strlen", &[], Lang::C).unwrap();
        assert_eq!(info.method, StringMethod::StrLen);
    }

    #[test]
    fn test_classify_unknown_method_returns_none() {
        assert!(classify_string_method("foo.bar", &[], Lang::JavaScript).is_none());
        assert!(classify_string_method("unknown", &[], Lang::Python).is_none());
    }

    // ── Concrete evaluation ────────────────────────────────────────────────

    #[test]
    fn test_evaluate_trim() {
        let result = evaluate_string_op_concrete(&StringMethod::Trim, "  hello  ");
        assert_eq!(result, Some(SymbolicValue::ConcreteStr("hello".into())));
    }

    #[test]
    fn test_evaluate_to_lower() {
        let result = evaluate_string_op_concrete(&StringMethod::ToLower, "ABC");
        assert_eq!(result, Some(SymbolicValue::ConcreteStr("abc".into())));
    }

    #[test]
    fn test_evaluate_to_upper() {
        let result = evaluate_string_op_concrete(&StringMethod::ToUpper, "abc");
        assert_eq!(result, Some(SymbolicValue::ConcreteStr("ABC".into())));
    }

    #[test]
    fn test_evaluate_replace() {
        let method = StringMethod::Replace {
            pattern: "<script>".into(),
            replacement: "".into(),
        };
        let result = evaluate_string_op_concrete(&method, "a<script>b");
        assert_eq!(result, Some(SymbolicValue::ConcreteStr("ab".into())));
    }

    #[test]
    fn test_evaluate_strlen() {
        let result = evaluate_string_op_concrete(&StringMethod::StrLen, "hello");
        assert_eq!(result, Some(SymbolicValue::Concrete(5)));
    }

    #[test]
    fn test_evaluate_substr_returns_none() {
        // Substr needs index args, concrete eval handled in smart constructor
        let result = evaluate_string_op_concrete(&StringMethod::Substr, "hello");
        assert_eq!(result, None);
    }

    // ── Sanitizer detection ────────────────────────────────────────────────

    #[test]
    fn test_detect_xss_sanitizer() {
        let info = detect_replace_sanitizer("<", "&lt;", "s.replaceAll", Lang::JavaScript).unwrap();
        assert!(info.sanitized_caps.contains(Cap::HTML_ESCAPE));
        assert!(info.is_global);
    }

    #[test]
    fn test_detect_xss_non_global() {
        let info = detect_replace_sanitizer("<", "&lt;", "s.replace", Lang::JavaScript).unwrap();
        assert!(info.sanitized_caps.contains(Cap::HTML_ESCAPE));
        assert!(!info.is_global);
    }

    #[test]
    fn test_detect_sqli_sanitizer() {
        let info = detect_replace_sanitizer("'", "''", "s.replace", Lang::Python).unwrap();
        assert!(info.sanitized_caps.contains(Cap::SQL_QUERY));
        assert!(info.is_global); // Python replace is global
    }

    #[test]
    fn test_detect_cmdi_sanitizer() {
        let info = detect_replace_sanitizer("|", "", "s.replace", Lang::Python).unwrap();
        assert!(info.sanitized_caps.contains(Cap::SHELL_ESCAPE));
    }

    #[test]
    fn test_detect_no_sanitizer_for_neutral_pattern() {
        assert!(detect_replace_sanitizer("foo", "bar", "s.replace", Lang::JavaScript).is_none());
    }

    #[test]
    fn test_global_replace_ruby_gsub() {
        assert!(is_global_replace("s.gsub", Lang::Ruby));
        assert!(!is_global_replace("s.sub", Lang::Ruby));
    }

    #[test]
    fn test_global_replace_go() {
        assert!(is_global_replace("strings.ReplaceAll", Lang::Go));
        assert!(!is_global_replace("strings.Replace", Lang::Go));
    }

    // ── Transform classification ───────────────────────────────

    #[test]
    fn test_classify_transform_js_encode_uri_component() {
        let info = classify_transform_method("encodeURIComponent", Lang::JavaScript).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_transform_js_decode_uri_component() {
        let info = classify_transform_method("decodeURIComponent", Lang::JavaScript).unwrap();
        assert_eq!(info.kind, TransformKind::UrlDecode);
    }

    #[test]
    fn test_classify_transform_js_btoa() {
        let info = classify_transform_method("btoa", Lang::JavaScript).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Encode);
    }

    #[test]
    fn test_classify_transform_js_atob() {
        let info = classify_transform_method("atob", Lang::JavaScript).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Decode);
    }

    #[test]
    fn test_classify_transform_js_he_encode() {
        let info = classify_transform_method("he.encode", Lang::JavaScript).unwrap();
        assert_eq!(info.kind, TransformKind::HtmlEscape);
    }

    #[test]
    fn test_classify_transform_js_he_escape() {
        let info = classify_transform_method("he.escape", Lang::TypeScript).unwrap();
        assert_eq!(info.kind, TransformKind::HtmlEscape);
    }

    #[test]
    fn test_classify_transform_js_rich_sanitizer_not_matched() {
        // DOMPurify.sanitize is a rich sanitizer, NOT a simple escape
        assert!(classify_transform_method("DOMPurify.sanitize", Lang::JavaScript).is_none());
        assert!(classify_transform_method("sanitizeHtml", Lang::JavaScript).is_none());
        assert!(classify_transform_method("xss", Lang::JavaScript).is_none());
    }

    #[test]
    fn test_classify_transform_python_html_escape() {
        let info = classify_transform_method("html.escape", Lang::Python).unwrap();
        assert_eq!(info.kind, TransformKind::HtmlEscape);
    }

    #[test]
    fn test_classify_transform_python_shlex_quote() {
        let info = classify_transform_method("shlex.quote", Lang::Python).unwrap();
        assert_eq!(info.kind, TransformKind::ShellEscape);
    }

    #[test]
    fn test_classify_transform_python_urllib_quote() {
        let info = classify_transform_method("urllib.parse.quote", Lang::Python).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
    }

    #[test]
    fn test_classify_transform_python_base64() {
        let info = classify_transform_method("base64.b64encode", Lang::Python).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Encode);
        let info = classify_transform_method("base64.b64decode", Lang::Python).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Decode);
    }

    #[test]
    fn test_classify_transform_python_rich_sanitizer_not_matched() {
        assert!(classify_transform_method("bleach.clean", Lang::Python).is_none());
        assert!(classify_transform_method("markupsafe.escape", Lang::Python).is_none());
    }

    #[test]
    fn test_classify_transform_php_htmlspecialchars() {
        let info = classify_transform_method("htmlspecialchars", Lang::Php).unwrap();
        assert_eq!(info.kind, TransformKind::HtmlEscape);
    }

    #[test]
    fn test_classify_transform_php_urlencode() {
        let info = classify_transform_method("urlencode", Lang::Php).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
    }

    #[test]
    fn test_classify_transform_php_base64_encode() {
        let info = classify_transform_method("base64_encode", Lang::Php).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Encode);
    }

    #[test]
    fn test_classify_transform_php_escapeshellarg() {
        let info = classify_transform_method("escapeshellarg", Lang::Php).unwrap();
        assert_eq!(info.kind, TransformKind::ShellEscape);
    }

    #[test]
    fn test_classify_transform_php_addslashes() {
        let info = classify_transform_method("addslashes", Lang::Php).unwrap();
        assert_eq!(info.kind, TransformKind::SqlEscape);
    }

    #[test]
    fn test_classify_transform_unknown_returns_none() {
        assert!(classify_transform_method("foobar", Lang::JavaScript).is_none());
        assert!(classify_transform_method("unknown", Lang::Python).is_none());
        assert!(classify_transform_method("blah", Lang::Php).is_none());
    }

    #[test]
    fn test_classify_transform_java_url_encoder() {
        let info = classify_transform_method("URLEncoder.encode", Lang::Java).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
        let info = classify_transform_method("java.net.URLEncoder.encode", Lang::Java).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
    }

    #[test]
    fn test_classify_transform_java_url_decoder() {
        let info = classify_transform_method("URLDecoder.decode", Lang::Java).unwrap();
        assert_eq!(info.kind, TransformKind::UrlDecode);
    }

    #[test]
    fn test_classify_transform_java_string_escape_utils() {
        let info = classify_transform_method("StringEscapeUtils.escapeHtml4", Lang::Java).unwrap();
        assert_eq!(info.kind, TransformKind::HtmlEscape);
        let info = classify_transform_method("StringEscapeUtils.escapeXml11", Lang::Java).unwrap();
        assert_eq!(info.kind, TransformKind::HtmlEscape);
    }

    #[test]
    fn test_classify_transform_java_base64() {
        let info =
            classify_transform_method("Base64.getEncoder.encodeToString", Lang::Java).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Encode);
        let info = classify_transform_method("Base64.getDecoder.decode", Lang::Java).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Decode);
    }

    #[test]
    fn test_classify_transform_go_url_query_escape() {
        let info = classify_transform_method("url.QueryEscape", Lang::Go).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
        assert_eq!(info.operand_source, StringOperandSource::FirstArg);
    }

    #[test]
    fn test_classify_transform_go_url_path_escape() {
        let info = classify_transform_method("url.PathEscape", Lang::Go).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
    }

    #[test]
    fn test_classify_transform_go_html_escape() {
        let info = classify_transform_method("html.EscapeString", Lang::Go).unwrap();
        assert_eq!(info.kind, TransformKind::HtmlEscape);
    }

    #[test]
    fn test_classify_transform_go_base64() {
        let info =
            classify_transform_method("base64.StdEncoding.EncodeToString", Lang::Go).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Encode);
    }

    #[test]
    fn test_classify_transform_ruby_cgi_escape() {
        let info = classify_transform_method("CGI.escape", Lang::Ruby).unwrap();
        // CGI.escape is percent-encoding in Ruby (not HTML escape, that's
        // CGI.escapeHTML).
        assert_eq!(info.kind, TransformKind::UrlEncode);
        let info = classify_transform_method("CGI::escape", Lang::Ruby).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
    }

    #[test]
    fn test_classify_transform_ruby_cgi_unescape() {
        let info = classify_transform_method("CGI.unescape", Lang::Ruby).unwrap();
        assert_eq!(info.kind, TransformKind::UrlDecode);
    }

    #[test]
    fn test_classify_transform_ruby_erb_html_escape() {
        let info = classify_transform_method("ERB::Util.html_escape", Lang::Ruby).unwrap();
        assert_eq!(info.kind, TransformKind::HtmlEscape);
    }

    #[test]
    fn test_classify_transform_ruby_uri_encode_form() {
        let info = classify_transform_method("URI.encode_www_form_component", Lang::Ruby).unwrap();
        assert_eq!(info.kind, TransformKind::UrlEncode);
    }

    #[test]
    fn test_classify_transform_ruby_base64() {
        let info = classify_transform_method("Base64.strict_encode64", Lang::Ruby).unwrap();
        assert_eq!(info.kind, TransformKind::Base64Encode);
    }

    #[test]
    fn test_classify_transform_ruby_rich_sanitizer_not_matched() {
        // Rails `sanitize` / `strip_tags` are rich library sanitizers, NOT
        // simple character-level escapes.
        assert!(classify_transform_method("sanitize", Lang::Ruby).is_none());
        assert!(classify_transform_method("strip_tags", Lang::Ruby).is_none());
    }

    #[test]
    fn test_classify_transform_unknown_callee_returns_none_for_new_langs() {
        // Residual guard: truly unknown callees still return None for
        // Java/Go/Ruby (no over-eager wildcard matching).
        assert!(classify_transform_method("com.example.Foo.bar", Lang::Java).is_none());
        assert!(classify_transform_method("mypkg.Quux", Lang::Go).is_none());
        assert!(classify_transform_method("MyClass.unknown_method", Lang::Ruby).is_none());
    }

    // ── Concrete encoding ──────────────────────────────────────

    #[test]
    fn test_encode_concrete_html_escape() {
        let result =
            encode_concrete_for_witness(TransformKind::HtmlEscape, "<script>alert('xss')</script>");
        assert_eq!(
            result.unwrap(),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_encode_concrete_html_escape_ampersand() {
        let result = encode_concrete_for_witness(TransformKind::HtmlEscape, "a & b < c");
        assert_eq!(result.unwrap(), "a &amp; b &lt; c");
    }

    #[test]
    fn test_encode_concrete_url_encode() {
        let result = encode_concrete_for_witness(TransformKind::UrlEncode, "hello world");
        assert_eq!(result.unwrap(), "hello%20world");
    }

    #[test]
    fn test_encode_concrete_url_encode_special_chars() {
        let result = encode_concrete_for_witness(TransformKind::UrlEncode, "a=b&c=d");
        assert_eq!(result.unwrap(), "a%3Db%26c%3Dd");
    }

    #[test]
    fn test_encode_concrete_shell_escape() {
        let result = encode_concrete_for_witness(TransformKind::ShellEscape, "hello world");
        assert_eq!(result.unwrap(), "'hello world'");
    }

    #[test]
    fn test_encode_concrete_shell_escape_with_quotes() {
        let result = encode_concrete_for_witness(TransformKind::ShellEscape, "it's");
        assert_eq!(result.unwrap(), "'it'\\''s'");
    }

    #[test]
    fn test_encode_concrete_sql_escape() {
        let result = encode_concrete_for_witness(TransformKind::SqlEscape, "O'Brien");
        assert_eq!(result.unwrap(), "O''Brien");
    }

    #[test]
    fn test_encode_concrete_base64() {
        let result = encode_concrete_for_witness(TransformKind::Base64Encode, "hello");
        assert_eq!(result.unwrap(), "aGVsbG8=");
    }

    #[test]
    fn test_encode_concrete_base64_roundtrip() {
        let encoded = encode_concrete_for_witness(TransformKind::Base64Encode, "test123").unwrap();
        let decoded = decode_concrete_for_witness(TransformKind::Base64Decode, &encoded).unwrap();
        assert_eq!(decoded, "test123");
    }

    #[test]
    fn test_decode_concrete_url_decode() {
        let result = decode_concrete_for_witness(TransformKind::UrlDecode, "hello%20world");
        assert_eq!(result.unwrap(), "hello world");
    }

    #[test]
    fn test_decode_concrete_url_decode_plus() {
        let result = decode_concrete_for_witness(TransformKind::UrlDecode, "hello+world");
        assert_eq!(result.unwrap(), "hello world");
    }

    // ── verified_cap ───────────────────────────────────────────

    #[test]
    fn test_verified_cap_html_escape() {
        assert_eq!(TransformKind::HtmlEscape.verified_cap(), Cap::HTML_ESCAPE);
        assert!(TransformKind::HtmlEscape.is_protective());
    }

    #[test]
    fn test_verified_cap_url_encode() {
        assert_eq!(TransformKind::UrlEncode.verified_cap(), Cap::URL_ENCODE);
        assert!(TransformKind::UrlEncode.is_protective());
    }

    #[test]
    fn test_verified_cap_shell_escape() {
        assert_eq!(TransformKind::ShellEscape.verified_cap(), Cap::SHELL_ESCAPE);
        assert!(TransformKind::ShellEscape.is_protective());
    }

    #[test]
    fn test_verified_cap_sql_escape_is_empty() {
        // SqlEscape has no verified label rule, witness-only
        assert_eq!(TransformKind::SqlEscape.verified_cap(), Cap::empty());
        assert!(!TransformKind::SqlEscape.is_protective());
    }

    #[test]
    fn test_verified_cap_base64_is_empty() {
        assert_eq!(TransformKind::Base64Encode.verified_cap(), Cap::empty());
        assert!(!TransformKind::Base64Encode.is_protective());
    }

    #[test]
    fn test_verified_cap_url_decode_is_empty() {
        assert_eq!(TransformKind::UrlDecode.verified_cap(), Cap::empty());
        assert!(!TransformKind::UrlDecode.is_protective());
    }
}
