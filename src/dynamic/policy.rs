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

use std::collections::BTreeMap;

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
