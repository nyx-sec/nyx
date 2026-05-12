//! Per-capability payload corpus.
//!
//! Each [`Cap`] maps to a small set of canonical payloads plus a matching
//! detection oracle. Payloads are static data — adding a new one is a code
//! review, not a runtime config knob, so they cannot drift between versions.
//!
//! Differential confirmation (§4.1): for `HTML_ESCAPE` and `FILE_IO`, a
//! mandatory benign payload is included. `Confirmed` requires the vuln oracle
//! to fire AND the benign oracle NOT to fire. This prevents false-positives
//! from coincidental output matches.
//!
//! # Corpus governance (§16.1)
//!
//! Every payload carries [`PayloadProvenance`], a [`since_corpus_version`],
//! and at least one [`fixture_paths`] entry.  The [`CORPUS_VERSION`] const
//! tracks the history of incompatible corpus changes; bumping it invalidates
//! all `dynamic_verdict_cache` entries whose spec touched the changed cap.

use crate::labels::Cap;

/// Bump when the corpus content changes in a way that invalidates previously-
/// computed [`crate::dynamic::spec::HarnessSpec::spec_hash`] values.
///
/// # Bump history
///
/// | Version | Date       | Change                                        |
/// |---------|------------|-----------------------------------------------|
/// | 1       | 2025-11-01 | Initial corpus (SQLi, CMDI, PATH_TRAV, SSRF, XSS) |
/// | 2       | 2025-12-15 | SSRF OOB-variant added; oracle semantics tightened |
/// | 3       | 2026-05-12 | Migrated to `CuratedPayload`; provenance + fixture_paths enforced; SSRF OOB-nonce slot added |
pub const CORPUS_VERSION: u32 = 3;

/// Where a payload originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadProvenance {
    /// Manually written and reviewed by the Nyx team.
    Curated,
    /// Produced by the internal mutation fuzzer (`fuzz/dynamic_corpus/`).
    /// Still requires human promotion review (§16.4) before landing here.
    InternalFuzzer,
    /// Derived from a public CVE or external security report.
    ExternalReport,
}

/// A single payload entry in the curated corpus.
///
/// Governs both static payload bytes (or an OOB-nonce template) and the
/// oracle used to confirm the vulnerability fired.  All fields are
/// `'static` so the corpus can live in read-only memory.
#[derive(Debug, Clone)]
pub struct CuratedPayload {
    /// Bytes injected into the [`crate::dynamic::spec::PayloadSlot`].
    ///
    /// When [`oob_nonce_slot`] is `true` this field is ignored; the runner
    /// materialises the actual bytes from the OOB listener URL at call time.
    pub bytes: &'static [u8],
    /// Human label for logs and reports.
    pub label: &'static str,
    /// How we decide the sink fired. See [`Oracle`].
    pub oracle: Oracle,
    /// If `true`, this is a benign control payload.
    /// `Confirmed` requires the vuln payload to trigger AND the benign payload
    /// NOT to trigger (differential confirmation, §4.1).
    pub is_benign: bool,
    /// Where this payload came from.
    pub provenance: PayloadProvenance,
    /// `CORPUS_VERSION` when this payload was added.
    pub since_corpus_version: u32,
    /// `CORPUS_VERSION` at which this payload was deprecated, if any.
    pub deprecated_at_corpus_version: Option<u32>,
    /// Source files that exercise this payload in the dynamic harness.
    /// At least one entry required per §16.1.
    pub fixture_paths: &'static [&'static str],
    /// When `true`, the runner generates the actual bytes from the OOB
    /// listener URL + per-finding nonce at execution time (SSRF OOB variant).
    /// The `bytes` field is unused for such payloads.
    pub oob_nonce_slot: bool,
}

/// Backward-compatible type alias.
pub type Payload = CuratedPayload;

/// Detection strategy.
#[derive(Debug, Clone)]
pub enum Oracle {
    /// Substring on stdout/stderr.
    OutputContains(&'static str),
    /// Process exited with a crash signal (SIGSEGV, SIGABRT).
    Crash,
    /// Outbound network connection observed to a controlled sink host.
    OobCallback { host: &'static str },
    /// File written outside the sandbox root.
    FileEscape,
    /// Non-zero exit with specific status.
    ExitStatus(i32),
}

/// Pick the payload set for a given cap. Empty slice = unsupported cap.
///
/// # Cap coverage (update when adding/removing Cap bits)
///
/// | Cap                | Supported | Notes                              |
/// |--------------------|-----------|-----------------------------------|
/// | SQL_QUERY          | yes       | SQLI payloads (echo-query style)   |
/// | CODE_EXEC          | yes       | command injection echo marker      |
/// | FILE_IO            | yes       | path traversal + benign control    |
/// | SSRF               | yes       | file:// scheme + OOB nonce slot    |
/// | HTML_ESCAPE        | yes       | XSS script marker + benign control |
/// | ENV_VAR            | no        | source-only cap; no sink oracle    |
/// | SHELL_ESCAPE       | no        | sanitizer cap; no sink oracle      |
/// | URL_ENCODE         | no        | sanitizer cap; no sink oracle      |
/// | JSON_PARSE         | no        | no reliable oracle                 |
/// | FMT_STRING         | no        | no reliable oracle                 |
/// | DESERIALIZE        | no        | no reliable oracle                 |
/// | CRYPTO             | no        | no reliable oracle                 |
/// | UNAUTHORIZED_ID    | no        | auth bypass; no oracle             |
/// | DATA_EXFIL         | no        | exfil; no oracle                   |
/// | LDAP_INJECTION     | no        | no oracle                          |
/// | XPATH_INJECTION    | no        | no oracle                          |
/// | HEADER_INJECTION   | no        | no oracle                          |
/// | OPEN_REDIRECT      | no        | no oracle                          |
/// | SSTI               | no        | no oracle                          |
/// | XXE                | no        | no oracle                          |
/// | PROTOTYPE_POLLUTION| no        | JS-runtime; no oracle              |
///
/// Compile-time exhaustiveness guard: `CORPUS_SUPPORTED | CORPUS_UNSUPPORTED`
/// must equal `Cap::all()`.
const CORPUS_SUPPORTED: u32 = Cap::SQL_QUERY.bits()
    | Cap::CODE_EXEC.bits()
    | Cap::FILE_IO.bits()
    | Cap::SSRF.bits()
    | Cap::HTML_ESCAPE.bits();

const CORPUS_UNSUPPORTED: u32 = Cap::ENV_VAR.bits()
    | Cap::SHELL_ESCAPE.bits()
    | Cap::URL_ENCODE.bits()
    | Cap::JSON_PARSE.bits()
    | Cap::FMT_STRING.bits()
    | Cap::DESERIALIZE.bits()
    | Cap::CRYPTO.bits()
    | Cap::UNAUTHORIZED_ID.bits()
    | Cap::DATA_EXFIL.bits()
    | Cap::LDAP_INJECTION.bits()
    | Cap::XPATH_INJECTION.bits()
    | Cap::HEADER_INJECTION.bits()
    | Cap::OPEN_REDIRECT.bits()
    | Cap::SSTI.bits()
    | Cap::XXE.bits()
    | Cap::PROTOTYPE_POLLUTION.bits();

const _: () = assert!(
    CORPUS_SUPPORTED | CORPUS_UNSUPPORTED == Cap::all().bits(),
    "Cap bit missing from corpus coverage table; \
     add to CORPUS_SUPPORTED or CORPUS_UNSUPPORTED and update payloads_for",
);

pub fn payloads_for(cap: Cap) -> &'static [CuratedPayload] {
    if cap.contains(Cap::SQL_QUERY) {
        return SQLI;
    }
    if cap.contains(Cap::CODE_EXEC) {
        return CMDI;
    }
    if cap.contains(Cap::FILE_IO) {
        return PATH_TRAV;
    }
    if cap.contains(Cap::SSRF) {
        return SSRF_PAYLOADS;
    }
    if cap.contains(Cap::HTML_ESCAPE) {
        return XSS;
    }
    &[]
}

/// Return the benign control payload for a cap, if one exists.
pub fn benign_payload_for(cap: Cap) -> Option<&'static CuratedPayload> {
    payloads_for(cap).iter().find(|p| p.is_benign)
}

/// Materialise the effective bytes for a payload.
///
/// For static payloads (`oob_nonce_slot == false`) returns the `bytes` slice
/// directly.  For OOB-nonce payloads, constructs the callback URL from the
/// listener and nonce; returns `None` when no listener is configured.
pub fn materialise_bytes<'a>(
    payload: &'a CuratedPayload,
    oob_url: Option<&str>,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    if payload.oob_nonce_slot {
        oob_url.map(|u| std::borrow::Cow::Owned(u.as_bytes().to_vec()))
    } else {
        Some(std::borrow::Cow::Borrowed(payload.bytes))
    }
}

/// Run a marker-collision audit on all corpus payloads.
///
/// Returns a list of `(cap_name, label, conflicting_cap_name)` triples where
/// a payload's oracle marker string also appears in a different cap's payload
/// bytes.  An empty result is the expected (passing) state.
pub fn audit_marker_collisions() -> Vec<(&'static str, &'static str, &'static str)> {
    // Build (cap_name, label, marker_bytes) triples for OutputContains oracles.
    let entries: &[(&str, &[CuratedPayload])] = &[
        ("SQL_QUERY", SQLI),
        ("CODE_EXEC", CMDI),
        ("FILE_IO", PATH_TRAV),
        ("SSRF", SSRF_PAYLOADS),
        ("HTML_ESCAPE", XSS),
    ];

    let mut collisions = Vec::new();
    for &(cap_name, payloads) in entries {
        for p in payloads {
            if p.is_benign {
                continue;
            }
            let Oracle::OutputContains(marker) = &p.oracle else {
                continue;
            };
            let marker_bytes = marker.as_bytes();
            // Check if this marker appears in ANY other cap's payload bytes.
            for &(other_cap, other_payloads) in entries {
                if other_cap == cap_name {
                    continue;
                }
                for op in other_payloads {
                    if op.is_benign {
                        continue;
                    }
                    if op.bytes.windows(marker_bytes.len()).any(|w| w == marker_bytes) {
                        collisions.push((cap_name, p.label, other_cap));
                    }
                }
            }
        }
    }
    collisions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_caps_have_payloads() {
        assert!(!payloads_for(Cap::SQL_QUERY).is_empty());
        assert!(!payloads_for(Cap::CODE_EXEC).is_empty());
        assert!(!payloads_for(Cap::FILE_IO).is_empty());
        assert!(!payloads_for(Cap::SSRF).is_empty());
        assert!(!payloads_for(Cap::HTML_ESCAPE).is_empty());
    }

    #[test]
    fn unsupported_caps_return_empty() {
        let unsupported = [
            Cap::ENV_VAR, Cap::SHELL_ESCAPE, Cap::URL_ENCODE, Cap::JSON_PARSE,
            Cap::FMT_STRING, Cap::DESERIALIZE, Cap::CRYPTO, Cap::UNAUTHORIZED_ID,
            Cap::DATA_EXFIL, Cap::LDAP_INJECTION, Cap::XPATH_INJECTION,
            Cap::HEADER_INJECTION, Cap::OPEN_REDIRECT, Cap::SSTI, Cap::XXE,
            Cap::PROTOTYPE_POLLUTION,
        ];
        for cap in unsupported {
            assert!(
                payloads_for(cap).is_empty(),
                "expected {cap:?} to return empty payloads",
            );
        }
    }

    #[test]
    fn fileio_has_benign_payload() {
        assert!(benign_payload_for(Cap::FILE_IO).is_some());
    }

    #[test]
    fn html_escape_has_benign_payload() {
        assert!(benign_payload_for(Cap::HTML_ESCAPE).is_some());
    }

    #[test]
    fn vuln_payloads_not_benign() {
        for cap in [Cap::SQL_QUERY, Cap::CODE_EXEC, Cap::FILE_IO, Cap::HTML_ESCAPE] {
            let has_vuln = payloads_for(cap).iter().any(|p| !p.is_benign);
            assert!(has_vuln, "{cap:?} must have at least one vuln (non-benign) payload");
        }
    }

    #[test]
    fn marker_uniqueness_sqli() {
        for p in SQLI {
            assert!(!p.bytes.windows(7).any(|w| w == b"NYX_PWN"),
                "NYX_PWN (CODE_EXEC marker) must not appear in SQLI payloads");
        }
    }

    #[test]
    fn all_payloads_have_fixture_paths() {
        let caps = [Cap::SQL_QUERY, Cap::CODE_EXEC, Cap::FILE_IO, Cap::SSRF, Cap::HTML_ESCAPE];
        for cap in caps {
            for p in payloads_for(cap) {
                assert!(
                    !p.fixture_paths.is_empty(),
                    "payload '{}' for {cap:?} must have at least one fixture_path (§16.1)",
                    p.label,
                );
            }
        }
    }

    #[test]
    fn all_payloads_have_valid_since_corpus_version() {
        let caps = [Cap::SQL_QUERY, Cap::CODE_EXEC, Cap::FILE_IO, Cap::SSRF, Cap::HTML_ESCAPE];
        for cap in caps {
            for p in payloads_for(cap) {
                assert!(
                    p.since_corpus_version >= 1 && p.since_corpus_version <= CORPUS_VERSION,
                    "payload '{}': since_corpus_version {} out of range [1, {}]",
                    p.label, p.since_corpus_version, CORPUS_VERSION,
                );
            }
        }
    }

    #[test]
    fn no_marker_collisions() {
        let collisions = audit_marker_collisions();
        assert!(
            collisions.is_empty(),
            "marker collisions detected (§16.3): {collisions:?}",
        );
    }

    #[test]
    fn ssrf_has_oob_nonce_slot() {
        let has_oob = payloads_for(Cap::SSRF).iter().any(|p| p.oob_nonce_slot);
        assert!(has_oob, "SSRF corpus must include an OOB-nonce-slot payload");
    }

    #[test]
    fn materialise_static_payload() {
        let p = &SQLI[0];
        assert!(!p.oob_nonce_slot);
        let bytes = materialise_bytes(p, None).expect("static payload must materialise without OOB");
        assert_eq!(&*bytes, p.bytes);
    }

    #[test]
    fn materialise_oob_payload_with_url() {
        let p = SSRF_PAYLOADS.iter().find(|p| p.oob_nonce_slot).expect("must have OOB payload");
        let url = "http://127.0.0.1:54321/mynonce";
        let bytes = materialise_bytes(p, Some(url)).expect("OOB payload materialises with URL");
        assert_eq!(&*bytes, url.as_bytes());
    }

    #[test]
    fn materialise_oob_payload_without_listener_returns_none() {
        let p = SSRF_PAYLOADS.iter().find(|p| p.oob_nonce_slot).expect("must have OOB payload");
        assert!(materialise_bytes(p, None).is_none(), "no OOB URL → None");
    }
}

// ── SQLi ─────────────────────────────────────────────────────────────────────
// Payloads designed to cause the target code to echo a query containing "NYX".
// Fixtures should print the raw query or error message to stdout/stderr.
const SQLI: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"' OR '1'='1",
        label: "sqli-tautology",
        oracle: Oracle::OutputContains("NYX_SQL_CONFIRMED"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/sqli/sqli_rusqlite_format.rs"],
        oob_nonce_slot: false,
    },
    CuratedPayload {
        bytes: b"' UNION SELECT 'NYX_SQL_CONFIRMED'--",
        label: "sqli-union-nyx",
        oracle: Oracle::OutputContains("NYX_SQL_CONFIRMED"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/sqli/sqli_rusqlite_format.rs"],
        oob_nonce_slot: false,
    },
];

// ── Command injection ─────────────────────────────────────────────────────────
const CMDI: &[CuratedPayload] = &[CuratedPayload {
    bytes: b"; echo NYX_PWN_CMDI",
    label: "cmdi-echo-marker",
    oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
    is_benign: false,
    provenance: PayloadProvenance::Curated,
    since_corpus_version: 1,
    deprecated_at_corpus_version: None,
    fixture_paths: &[
        "tests/benchmark/corpus/rust/cmdi/cmdi_command.rs",
        "tests/benchmark/corpus/rust/cmdi/cmdi_args.rs",
    ],
    oob_nonce_slot: false,
}];

// ── Path traversal ────────────────────────────────────────────────────────────
// Benign payload reads a known-safe file (Python's os module source path).
// Differential confirmation: vuln fires on /etc/passwd; benign fires on a
// non-sensitive file and must NOT fire the same oracle (different file content).
const PATH_TRAV: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"../../../../etc/passwd",
        label: "path-traversal-passwd",
        oracle: Oracle::OutputContains("root:"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &[
            "tests/benchmark/corpus/rust/path_traversal/path_file_open.rs",
            "tests/benchmark/corpus/rust/path_traversal/path_read.rs",
        ],
        oob_nonce_slot: false,
    },
    CuratedPayload {
        bytes: b"benign_safe_file_that_does_not_exist_NYX_BENIGN",
        label: "path-traversal-benign",
        oracle: Oracle::OutputContains("root:"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/path_traversal/path_file_open.rs"],
        oob_nonce_slot: false,
    },
];

// ── SSRF ─────────────────────────────────────────────────────────────────────
// Two SSRF variants:
//   1. file:// scheme — static payload, OutputContains oracle. Works in
//      the process backend without OOB infrastructure.
//   2. OOB nonce slot — URL generated at runtime from the OOB listener.
//      Confirms SSRF by recording the callback nonce.
//
// Oracle notes:
//   OutputContains("daemon:") matches both Linux (`daemon:x:1:1:`) and
//   macOS (`daemon:*:1:1:`) /etc/passwd formats and must NOT collide with
//   FILE_IO's "root:" marker (see marker_uniqueness test).
const SSRF_PAYLOADS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"file:///etc/passwd",
        label: "ssrf-file-scheme",
        oracle: Oracle::OutputContains("daemon:"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/ssrf/ssrf_reqwest.rs"],
        oob_nonce_slot: false,
    },
    CuratedPayload {
        // `bytes` is unused when `oob_nonce_slot = true`; the runner
        // materialises the URL from the OOB listener at call time.
        bytes: b"",
        label: "ssrf-oob-nonce",
        oracle: Oracle::OobCallback { host: "127.0.0.1" },
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 2,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/ssrf/ssrf_reqwest.rs"],
        oob_nonce_slot: true,
    },
];

// ── XSS ──────────────────────────────────────────────────────────────────────
// Vuln: raw script tag echoed to output.
// Benign: harmless text that should NOT produce the XSS marker.
const XSS: &[CuratedPayload] = &[
    CuratedPayload {
        bytes: b"<script>NYX_XSS_CONFIRMED</script>",
        label: "xss-script-marker",
        oracle: Oracle::OutputContains("<script>NYX_XSS_CONFIRMED</script>"),
        is_benign: false,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/xss/axum_html/main.rs"],
        oob_nonce_slot: false,
    },
    CuratedPayload {
        bytes: b"Hello World",
        label: "xss-benign-text",
        oracle: Oracle::OutputContains("<script>NYX_XSS_CONFIRMED</script>"),
        is_benign: true,
        provenance: PayloadProvenance::Curated,
        since_corpus_version: 1,
        deprecated_at_corpus_version: None,
        fixture_paths: &["tests/benchmark/corpus/rust/xss/axum_html/main.rs"],
        oob_nonce_slot: false,
    },
];
