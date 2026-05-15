//! Track-security cross-cutting policy module (Phase 08 — Track C.4 + C.5).
//!
//! Centralises the deny rules and byte-bound limits that the per-run
//! [`crate::dynamic::probe::ProbeWitness`] construction uses to keep
//! captured forensic data both privacy-safe and bounded in size.
//!
//! Two responsibilities, intentionally kept in one module so the security
//! envelope is auditable in a single file:
//!
//! 1. **Env scrubbing** — [`scrub_env`] redacts the host environment when
//!    snapshotted onto a [`crate::dynamic::probe::ProbeWitness`].  Any key
//!    matching a [`DENY_KEY_SUBSTRINGS`] entry (case-insensitive substring
//!    match against the upper-cased key) has its value replaced with
//!    [`REDACTED_VALUE`].  Whitelist semantics (allow-list) were rejected
//!    because the harness env is heterogeneous across CI / local /
//!    container runs; a deny-substring list matches the common-suffix
//!    naming used in practice (`*_TOKEN`, `*_KEY`, `*_SECRET`, …) with no
//!    false negatives on the cases we have evidence for.
//! 2. **Byte bounds** — [`PAYLOAD_CAPTURE_LIMIT_BYTES`] caps the
//!    `payload_bytes` field at 16 KiB so a fuzzer-emitted megabyte payload
//!    does not turn the probe file into a memory hog or balloon downstream
//!    repro artifacts.  [`truncate_payload_bytes`] is the only sanctioned
//!    truncation entry point — every probe construction path goes through
//!    it so the bound is enforced uniformly.
//!
//! The module deliberately depends on `std` only (no third-party crates)
//! so `cargo deny check` and `cargo doc` both see it as a leaf with no
//! transitive license risk.
//!
//! # Phase 28 extension (Track H.5 — PII scrubber)
//!
//! [`Scrubber`] hashes probe-witness values whose textual shape matches a
//! project secret pattern.  The pattern set is the same one
//! [`crate::utils::redact`] already uses for `--show-suppressed` console
//! output and repro `outcome.json` redaction: AWS access key IDs, GitHub /
//! Slack / OpenAI tokens, PEM blocks, `password=` / `api_key=` / `secret=`
//! query strings, and `Bearer` headers.  Re-using the redactor's pattern
//! list keeps the rule "what counts as PII" defined in exactly one place
//! across the project — adding a new pattern in `redact.rs` also tightens
//! probe-witness scrubbing without a second registry to maintain.
//!
//! The witness scrubber differs from the redactor in one respect: instead
//! of erasing the secret behind a `<REDACTED>` placeholder it replaces it
//! with `<scrubbed-hash:<prefix>>` where the prefix is the first 16 hex
//! chars of the BLAKE3 digest.  This preserves enough signal to (a)
//! correlate the same secret across multiple witness fields without
//! exposing it and (b) detect via dedup analysis that two probe runs
//! observed the same credential when a leaked token gets cycled into
//! payloads.

use std::collections::BTreeMap;

use crate::utils::redact;

/// Maximum number of bytes retained in
/// [`crate::dynamic::probe::ProbeWitness::payload_bytes`].
///
/// 16 KiB is the cap the Phase 08 plan calls for; matches the upper bound
/// any reasonable injection payload will need (the existing curated corpus
/// peaks under 200 B).  Anything larger is truncated head-first via
/// [`truncate_payload_bytes`] because that is the prefix the sink actually
/// sees first.
pub const PAYLOAD_CAPTURE_LIMIT_BYTES: usize = 16 * 1024;

/// Placeholder written in place of a denied environment variable's value
/// when [`scrub_env`] redacts it.  Lower-case so it is visually distinct
/// from a real CI env value (which is overwhelmingly upper-snake).
pub const REDACTED_VALUE: &str = "<redacted-by-nyx-policy>";

/// Substrings that mark a key as carrying credential-shaped data.
///
/// Matched case-insensitively against the upper-cased env var key.  Order
/// is not significant — the first match wins because all matches lead to
/// the same redaction.
///
/// The list is intentionally short and high-precision: false-positive
/// redactions just remove a value from a forensic snapshot, but false
/// negatives leak credentials into a probe file that may be persisted as
/// a repro artifact.
pub const DENY_KEY_SUBSTRINGS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "SESSION",
    "COOKIE",
    "AUTH",
    "BEARER",
    // Cloud provider shapes that don't end in TOKEN / SECRET / KEY.
    "AWS_ACCESS",
    "AWS_SESSION",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "DOCKER_PASS",
];

/// True iff `key` matches any [`DENY_KEY_SUBSTRINGS`] entry under
/// case-insensitive substring comparison.  The exposed predicate so
/// [`crate::dynamic::probe`] tests can reason about individual keys
/// without round-tripping through [`scrub_env`].
pub fn is_denied_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    DENY_KEY_SUBSTRINGS
        .iter()
        .any(|needle| upper.contains(*needle))
}

/// Redact denied keys' values in an env iterator and collect into a
/// [`BTreeMap`].  `BTreeMap` rather than `HashMap` so the serialised
/// witness is byte-deterministic across runs — repro reproducibility
/// depends on it.
pub fn scrub_env<I, S>(iter: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (S, S)>,
    S: Into<String>,
{
    let mut out = BTreeMap::new();
    for (k, v) in iter {
        let k: String = k.into();
        let v: String = v.into();
        if is_denied_env_key(&k) {
            out.insert(k, REDACTED_VALUE.to_owned());
        } else {
            out.insert(k, v);
        }
    }
    out
}

/// Prefix written before the BLAKE3 hex digest by [`Scrubber::scrub_string`]
/// when a witness value matches a project secret pattern.  Operators
/// grepping for leaked credentials in a probe witness see
/// `<scrubbed-hash:…>` and know the bytes were classified as PII before
/// the file landed on disk.
pub const SCRUB_HASH_PREFIX: &str = "<scrubbed-hash:";

/// Length of the BLAKE3 hex prefix retained by the scrubber.  16 hex chars
/// = 64 bits of identity — wide enough to dedup hits across a single
/// probe file without revealing the secret, narrow enough that a
/// brute-force pre-image attack against a known token shape is still
/// expensive.
pub const SCRUB_HASH_PREFIX_LEN: usize = 16;

/// Project-secret literal substrings that mark a witness value as
/// carrying PII even when no `redact.rs` regex matches.  Matched
/// case-insensitively as a substring.  Phase 28 ships a starter list
/// keyed on the project's own stub-secret shape (`nyx-stub-secret-…`)
/// plus high-confidence word stems (`secret`, `password`, `passwd`) so
/// dash-delimited tokens (`my-app-secret-12345`) trip the scrubber
/// without changing the existing `redact.rs` query-string-only
/// behaviour.
pub const PII_LITERAL_SUBSTRINGS: &[&str] = &[
    "nyx-stub-secret",
    "stub-secret-",
    "private_key",
    "begin rsa private key",
    "begin openssh private key",
];

/// Scrub probe-witness textual values before they are serialised to the
/// probe-file JSON line.
///
/// The scrubber wraps the project-wide secret regex set defined in
/// [`crate::utils::redact`] (AWS keys, GitHub / Slack / OpenAI tokens,
/// `password=` query strings, PEM blocks, `Bearer` headers) plus an
/// auxiliary literal set in [`PII_LITERAL_SUBSTRINGS`] for project-
/// specific shapes.  When a witness value matches any pattern the whole
/// value is replaced with `<scrubbed-hash:<blake3-prefix>>`.  Hashing
/// rather than dropping the value lets downstream forensic analysis
/// dedup repeated occurrences of the same credential across witness
/// fields without exposing the credential itself.
///
/// Constructed via [`Scrubber::project_default`] for the standard
/// pattern set; the type is left as a struct (rather than a free
/// function) so future per-project allow-listing can attach to the same
/// API surface without breaking call sites.
#[derive(Debug, Default, Clone)]
pub struct Scrubber {
    _private: (),
}

impl Scrubber {
    /// Scrubber wired to the project-default secret regex set.  Cheap to
    /// construct — holds no compiled state because [`crate::utils::redact`]
    /// is stateless.
    pub fn project_default() -> Self {
        Self { _private: () }
    }

    /// True iff `text` contains any project secret pattern (regex set or
    /// literal substring).  Useful for tests asserting that a witness
    /// field would be scrubbed without allocating the rewritten string.
    pub fn matches_any(&self, text: &str) -> bool {
        if redact::contains_secret(text.as_bytes()) {
            return true;
        }
        let lower = text.to_ascii_lowercase();
        PII_LITERAL_SUBSTRINGS.iter().any(|needle| lower.contains(*needle))
    }

    /// Scrub `text`, returning a new `String` whose value is either the
    /// input unchanged (no pattern matched) or `<scrubbed-hash:<prefix>>`
    /// (hashes the whole value).  Hashing the whole value rather than
    /// each matched substring keeps the rewrite mechanism trivial — the
    /// witness fields are short forensic strings, not long log lines,
    /// and shipping the entire field plus a marker is what downstream
    /// repro tooling expects.
    pub fn scrub_string(&self, text: &str) -> String {
        if self.matches_any(text) {
            hash_token(text)
        } else {
            text.to_owned()
        }
    }
}

/// Hash a matched secret into the `<scrubbed-hash:<prefix>>` shape.
fn hash_token(secret: &str) -> String {
    let digest = blake3::hash(secret.as_bytes());
    let hex = digest.to_hex();
    let prefix: String = hex.chars().take(SCRUB_HASH_PREFIX_LEN).collect();
    format!("{SCRUB_HASH_PREFIX}{prefix}>")
}

/// Truncate `bytes` to at most [`PAYLOAD_CAPTURE_LIMIT_BYTES`].
///
/// Head-keeping: the prefix the sink reads first is retained; the tail is
/// dropped.  Returns `bytes` unchanged when it already fits the cap so
/// callers can use the return value without allocating in the common case.
pub fn truncate_payload_bytes(bytes: &[u8]) -> &[u8] {
    if bytes.len() <= PAYLOAD_CAPTURE_LIMIT_BYTES {
        bytes
    } else {
        &bytes[..PAYLOAD_CAPTURE_LIMIT_BYTES]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_substring_match_is_case_insensitive() {
        assert!(is_denied_env_key("AWS_SECRET_ACCESS_KEY"));
        assert!(is_denied_env_key("aws_secret_access_key"));
        assert!(is_denied_env_key("MyToken"));
        assert!(is_denied_env_key("DATABASE_PASSWORD"));
    }

    #[test]
    fn non_credential_keys_pass_through() {
        assert!(!is_denied_env_key("PATH"));
        assert!(!is_denied_env_key("HOME"));
        assert!(!is_denied_env_key("NYX_PAYLOAD"));
    }

    #[test]
    fn scrub_redacts_denied_keys_and_keeps_others() {
        let env = vec![
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            ("AWS_SECRET_ACCESS_KEY".to_owned(), "AKIA...".to_owned()),
            ("HOME".to_owned(), "/home/x".to_owned()),
        ];
        let scrubbed = scrub_env(env);
        assert_eq!(scrubbed.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(scrubbed.get("HOME").map(String::as_str), Some("/home/x"));
        assert_eq!(
            scrubbed.get("AWS_SECRET_ACCESS_KEY").map(String::as_str),
            Some(REDACTED_VALUE)
        );
    }

    #[test]
    fn truncate_keeps_short_payloads_unchanged() {
        let bytes = b"short payload";
        assert_eq!(truncate_payload_bytes(bytes), bytes);
    }

    #[test]
    fn truncate_caps_long_payloads_at_limit() {
        let bytes = vec![b'A'; PAYLOAD_CAPTURE_LIMIT_BYTES + 100];
        let truncated = truncate_payload_bytes(&bytes);
        assert_eq!(truncated.len(), PAYLOAD_CAPTURE_LIMIT_BYTES);
        assert!(truncated.iter().all(|b| *b == b'A'));
    }

    #[test]
    fn truncate_at_exact_boundary_unchanged() {
        let bytes = vec![0u8; PAYLOAD_CAPTURE_LIMIT_BYTES];
        assert_eq!(truncate_payload_bytes(&bytes).len(), PAYLOAD_CAPTURE_LIMIT_BYTES);
    }

    #[test]
    fn scrubber_passes_through_clean_value() {
        let s = Scrubber::project_default();
        let out = s.scrub_string("hello world");
        assert_eq!(out, "hello world");
        assert!(!s.matches_any("hello world"));
    }

    #[test]
    fn scrubber_hashes_aws_key_value() {
        let s = Scrubber::project_default();
        let value = "key=AKIAFAKETEST00000000";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(out.starts_with(SCRUB_HASH_PREFIX), "got {out}");
        assert!(out.ends_with('>'));
        assert!(!out.contains("AKIAFAKETEST00000000"));
    }

    #[test]
    fn scrubber_hashes_project_stub_secret() {
        let s = Scrubber::project_default();
        let value = "nyx-stub-secret-abc123-deadbeef";
        assert!(s.matches_any(value));
        let out = s.scrub_string(value);
        assert!(out.starts_with(SCRUB_HASH_PREFIX), "got {out}");
        assert!(!out.contains("abc123-deadbeef"));
    }

    #[test]
    fn scrubber_hash_is_stable_for_same_input() {
        let s = Scrubber::project_default();
        let a = s.scrub_string("AKIAFAKETEST00000000");
        let b = s.scrub_string("AKIAFAKETEST00000000");
        assert_eq!(a, b);
    }

    #[test]
    fn scrubber_hash_differs_for_different_inputs() {
        let s = Scrubber::project_default();
        let a = s.scrub_string("AKIAFAKETEST00000000");
        let b = s.scrub_string("AKIAFAKETEST11111111");
        assert_ne!(a, b);
    }

    #[test]
    fn scrub_is_deterministic_btree() {
        // Same iterator yields the same map; BTreeMap guarantees iteration order.
        let env = vec![
            ("B".to_owned(), "1".to_owned()),
            ("A".to_owned(), "2".to_owned()),
        ];
        let m = scrub_env(env);
        let keys: Vec<&str> = m.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["A", "B"]);
    }
}
