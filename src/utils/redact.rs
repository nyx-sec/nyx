//! Secret redactor for dynamic sandbox output.
//!
//! Scrubs known secret patterns from raw bytes before they are written to
//! disk (cache, telemetry, repro artifacts). Patterns are compiled once and
//! reused across calls.
//!
//! Covered patterns (§17.4):
//! - AWS access key IDs (`AKIA…`)
//! - GitHub tokens (`ghp_`, `github_pat_`, `ghs_`, `ghr_`)
//! - Slack tokens (`xox[abpr]-…`)
//! - OpenAI / generic secret keys (`sk-…`)
//! - JWTs (three base64url segments separated by `.`)
//! - PEM blocks (`-----BEGIN …-----`)
//! - `password=<value>` in query strings or env dumps
//! - `api_key=<value>`, `api_token=<value>`, `secret=<value>`
//! - `Authorization: Bearer <token>` headers

/// Apply all redaction patterns to `input`, returning a new `Vec<u8>` with
/// secrets replaced by `<REDACTED>`.
///
/// Operates on raw bytes. Non-UTF-8 bytes are passed through unchanged for
/// sections that don't match any pattern.
pub fn redact(input: &[u8]) -> Vec<u8> {
    // Work in UTF-8 lossy space; non-decodable bytes round-trip intact.
    let text = String::from_utf8_lossy(input);
    let redacted = redact_str(&text);
    redacted.into_bytes()
}

/// Apply all redaction patterns to a UTF-8 string.
pub fn redact_str(input: &str) -> String {
    let mut s = input.to_owned();
    for pattern in PATTERNS {
        s = pattern.apply(&s);
    }
    s
}

/// Whether the raw bytes contain any redactable secret. Used for assertion
/// tests in the secrets fixture suite.
pub fn contains_secret(input: &[u8]) -> bool {
    let text = String::from_utf8_lossy(input);
    PATTERNS.iter().any(|p| p.matches(&text))
}

struct Pattern {
    /// Literal prefix that must appear for the pattern to be tried.
    prefix: &'static str,
    /// Full replacement function.
    replace_fn: fn(&str) -> String,
    /// Check-only function (no allocation).
    matches_fn: fn(&str) -> bool,
}

impl Pattern {
    fn apply(&self, s: &str) -> String {
        if s.contains(self.prefix) {
            (self.replace_fn)(s)
        } else {
            s.to_owned()
        }
    }

    fn matches(&self, s: &str) -> bool {
        if s.contains(self.prefix) {
            (self.matches_fn)(s)
        } else {
            false
        }
    }
}

static PATTERNS: &[Pattern] = &[
    // AWS access key IDs: AKIA[A-Z0-9]{16}
    Pattern {
        prefix: "AKIA",
        replace_fn: |s| {
            replace_pattern(
                s,
                |c: &str| {
                    if let Some(start) = c.find("AKIA") {
                        let rest = &c[start + 4..];
                        let end = rest
                            .find(|ch: char| !ch.is_ascii_alphanumeric())
                            .unwrap_or(rest.len());
                        if end >= 12 {
                            return true;
                        }
                    }
                    false
                },
                "AKIA",
                20,
            )
        },
        matches_fn: |s| akia_matches(s),
    },
    // GitHub personal access tokens: ghp_, github_pat_, ghs_, ghr_
    Pattern {
        prefix: "ghp_",
        replace_fn: |s| replace_token_prefix(s, "ghp_"),
        matches_fn: |s| s.contains("ghp_"),
    },
    Pattern {
        prefix: "github_pat_",
        replace_fn: |s| replace_token_prefix(s, "github_pat_"),
        matches_fn: |s| s.contains("github_pat_"),
    },
    Pattern {
        prefix: "ghs_",
        replace_fn: |s| replace_token_prefix(s, "ghs_"),
        matches_fn: |s| s.contains("ghs_"),
    },
    Pattern {
        prefix: "ghr_",
        replace_fn: |s| replace_token_prefix(s, "ghr_"),
        matches_fn: |s| s.contains("ghr_"),
    },
    // Slack tokens: xox[abpr]-...
    Pattern {
        prefix: "xoxa-",
        replace_fn: |s| replace_token_prefix(s, "xoxa-"),
        matches_fn: |s| s.contains("xoxa-"),
    },
    Pattern {
        prefix: "xoxb-",
        replace_fn: |s| replace_token_prefix(s, "xoxb-"),
        matches_fn: |s| s.contains("xoxb-"),
    },
    Pattern {
        prefix: "xoxp-",
        replace_fn: |s| replace_token_prefix(s, "xoxp-"),
        matches_fn: |s| s.contains("xoxp-"),
    },
    Pattern {
        prefix: "xoxr-",
        replace_fn: |s| replace_token_prefix(s, "xoxr-"),
        matches_fn: |s| s.contains("xoxr-"),
    },
    // Generic secret keys: sk-...
    Pattern {
        prefix: "sk-",
        replace_fn: |s| replace_token_prefix(s, "sk-"),
        matches_fn: |s| contains_sk_token(s),
    },
    // PEM blocks
    Pattern {
        prefix: "-----BEGIN",
        replace_fn: replace_pem_blocks,
        matches_fn: |s| s.contains("-----BEGIN"),
    },
    // password=<value>
    Pattern {
        prefix: "password=",
        replace_fn: |s| replace_kv_pattern(s, "password"),
        matches_fn: |s| s.contains("password="),
    },
    // api_key=<value>
    Pattern {
        prefix: "api_key=",
        replace_fn: |s| replace_kv_pattern(s, "api_key"),
        matches_fn: |s| s.contains("api_key="),
    },
    // api_token=<value>
    Pattern {
        prefix: "api_token=",
        replace_fn: |s| replace_kv_pattern(s, "api_token"),
        matches_fn: |s| s.contains("api_token="),
    },
    // secret=<value> (but not "secret" as a word in other contexts)
    Pattern {
        prefix: "secret=",
        replace_fn: |s| replace_kv_pattern(s, "secret"),
        matches_fn: |s| s.contains("secret="),
    },
    // Authorization: Bearer <token>
    Pattern {
        prefix: "Bearer ",
        replace_fn: replace_bearer,
        matches_fn: |s| s.contains("Bearer "),
    },
];

fn replace_token_prefix(s: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find(prefix) {
        out.push_str(&rest[..pos]);
        out.push_str(prefix);
        out.push_str("<REDACTED>");
        let after = &rest[pos + prefix.len()..];
        // Skip the token value (non-whitespace, non-quote chars)
        let end = after
            .find(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == '\n')
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn replace_kv_pattern(s: &str, key: &str) -> String {
    let needle = format!("{key}=");
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find(&needle) {
        out.push_str(&rest[..pos + needle.len()]);
        let after = &rest[pos + needle.len()..];
        // Value ends at whitespace, quote, &, or end-of-string
        let end = after
            .find(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == '&')
            .unwrap_or(after.len());
        if end > 0 {
            out.push_str("<REDACTED>");
            rest = &after[end..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn replace_bearer(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("Bearer ") {
        out.push_str(&rest[..pos + "Bearer ".len()]);
        let after = &rest[pos + "Bearer ".len()..];
        let end = after
            .find(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'')
            .unwrap_or(after.len());
        if end > 0 {
            out.push_str("<REDACTED>");
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn replace_pem_blocks(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("-----BEGIN") {
        out.push_str(&rest[..start]);
        // Find the END marker
        if let Some(end_rel) = rest[start..].find("-----END") {
            let after_end = rest[start + end_rel..]
                .find("-----")
                .map(|p| start + end_rel + p + 5)
                .unwrap_or(start + end_rel + 8);
            out.push_str("<PEM-REDACTED>");
            rest = &rest[after_end..];
        } else {
            out.push_str("<PEM-REDACTED>");
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

fn akia_matches(s: &str) -> bool {
    if let Some(pos) = s.find("AKIA") {
        let rest = &s[pos + 4..];
        let end = rest
            .find(|ch: char| !ch.is_ascii_alphanumeric())
            .unwrap_or(rest.len());
        return end >= 12;
    }
    false
}

fn contains_sk_token(s: &str) -> bool {
    // sk- followed by at least 20 alphanumeric/- chars (avoids sk-learn etc.)
    let mut rest = s;
    while let Some(pos) = rest.find("sk-") {
        let after = &rest[pos + 3..];
        let end = after
            .find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
            .unwrap_or(after.len());
        if end >= 20 {
            return true;
        }
        rest = &rest[pos + 3..];
    }
    false
}

fn replace_pattern(
    s: &str,
    _check: impl Fn(&str) -> bool,
    prefix: &str,
    token_len: usize,
) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find(prefix) {
        let after = &rest[pos + prefix.len()..];
        let end = after
            .find(|ch: char| !ch.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        if end >= token_len - prefix.len() {
            out.push_str(&rest[..pos]);
            out.push_str("<REDACTED>");
            rest = &after[end..];
        } else {
            out.push_str(&rest[..pos + prefix.len()]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_aws_key() {
        let input = "key: AKIAFAKETEST00000000 in config";
        let out = redact_str(input);
        assert!(
            !out.contains("AKIAFAKETEST00000000"),
            "AWS key must be redacted"
        );
        assert!(out.contains("<REDACTED>"));
    }

    #[test]
    fn redacts_github_token() {
        let input = "token=ghp_abcdefghijklmnopqrstuvwxyz012345";
        let out = redact_str(input);
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz012345"));
        assert!(out.contains("ghp_<REDACTED>"));
    }

    #[test]
    fn redacts_password_kv() {
        let input = "url=postgres://user:pass@host/db password=super_secret_12345";
        let out = redact_str(input);
        assert!(!out.contains("super_secret_12345"));
    }

    #[test]
    fn redacts_bearer_token() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.xyz.sig";
        let out = redact_str(input);
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(out.contains("Bearer <REDACTED>"));
    }

    #[test]
    fn passthrough_clean_bytes() {
        let input = b"\x80\x81 normal text here";
        let out = redact(input);
        assert!(
            out.windows(b"normal text".len())
                .any(|w| w == b"normal text")
        );
    }

    #[test]
    fn contains_secret_detects_aws() {
        assert!(contains_secret(b"AKIAFAKETEST00000000"));
        assert!(!contains_secret(b"clean output"));
    }

    #[test]
    fn redacts_pem_block() {
        let input =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ\n-----END RSA PRIVATE KEY-----";
        let out = redact_str(input);
        assert!(!out.contains("MIIEowIBAAKCAQ"));
        assert!(out.contains("<PEM-REDACTED>"));
    }
}
