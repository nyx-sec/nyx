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

use crate::labels::Cap;

/// Bump when the corpus content changes in a way that invalidates previously-
/// computed [`crate::dynamic::spec::HarnessSpec::spec_hash`] values.
pub const CORPUS_VERSION: u32 = 2;

/// A single payload + the oracle that confirms it fired.
#[derive(Debug, Clone)]
pub struct Payload {
    /// Bytes injected into the [`crate::dynamic::spec::PayloadSlot`].
    pub bytes: &'static [u8],
    /// Human label for logs and reports.
    pub label: &'static str,
    /// How we decide the sink fired. See [`Oracle`].
    pub oracle: Oracle,
    /// If `true`, this is a benign control payload.
    /// `Confirmed` requires the vuln payload to trigger AND the benign payload
    /// NOT to trigger (differential confirmation, §4.1).
    pub is_benign: bool,
}

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
/// | SSRF               | yes       | file:// scheme + OutputContains    |
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

pub fn payloads_for(cap: Cap) -> &'static [Payload] {
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
pub fn benign_payload_for(cap: Cap) -> Option<&'static Payload> {
    payloads_for(cap).iter().find(|p| p.is_benign)
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
        // At least one non-benign payload per supported cap.
        for cap in [Cap::SQL_QUERY, Cap::CODE_EXEC, Cap::FILE_IO, Cap::HTML_ESCAPE] {
            let has_vuln = payloads_for(cap).iter().any(|p| !p.is_benign);
            assert!(has_vuln, "{cap:?} must have at least one vuln (non-benign) payload");
        }
    }

    #[test]
    fn marker_uniqueness_sqli() {
        // NYX_PWN must not appear in SQLI payloads (see marker_uniqueness test).
        for p in SQLI {
            assert!(!p.bytes.windows(7).any(|w| w == b"NYX_PWN"),
                "NYX_PWN (CODE_EXEC marker) must not appear in SQLI payloads");
        }
    }
}

// ── SQLi ─────────────────────────────────────────────────────────────────────
// Payloads designed to cause the target code to echo a query containing "NYX".
// Fixtures should print the raw query or error message to stdout/stderr.
const SQLI: &[Payload] = &[
    Payload {
        bytes: b"' OR '1'='1",
        label: "sqli-tautology",
        oracle: Oracle::OutputContains("NYX_SQL_CONFIRMED"),
        is_benign: false,
    },
    Payload {
        bytes: b"' UNION SELECT 'NYX_SQL_CONFIRMED'--",
        label: "sqli-union-nyx",
        oracle: Oracle::OutputContains("NYX_SQL_CONFIRMED"),
        is_benign: false,
    },
];

// ── Command injection ─────────────────────────────────────────────────────────
const CMDI: &[Payload] = &[Payload {
    bytes: b"; echo NYX_PWN_CMDI",
    label: "cmdi-echo-marker",
    oracle: Oracle::OutputContains("NYX_PWN_CMDI"),
    is_benign: false,
}];

// ── Path traversal ────────────────────────────────────────────────────────────
// Benign payload reads a known-safe file (Python's os module source path).
// Differential confirmation: vuln fires on /etc/passwd; benign fires on a
// non-sensitive file and must NOT fire the same oracle (different file content).
const PATH_TRAV: &[Payload] = &[
    Payload {
        bytes: b"../../../../etc/passwd",
        label: "path-traversal-passwd",
        oracle: Oracle::OutputContains("root:"),
        is_benign: false,
    },
    Payload {
        bytes: b"benign_safe_file_that_does_not_exist_NYX_BENIGN",
        label: "path-traversal-benign",
        oracle: Oracle::OutputContains("root:"),
        is_benign: true,
    },
];

// ── SSRF ─────────────────────────────────────────────────────────────────────
// Uses file:// scheme which is supported by Python's urllib out of the box.
// Oracle: OutputContains("daemon:") — a distinct /etc/passwd substring that
// matches both Linux (`daemon:x:1:1:`) and macOS (`daemon:*:1:1:`) formats.
// Must NOT collide with FILE_IO's "root:" marker (see marker_uniqueness test).
const SSRF_PAYLOADS: &[Payload] = &[Payload {
    bytes: b"file:///etc/passwd",
    label: "ssrf-file-scheme",
    oracle: Oracle::OutputContains("daemon:"),
    is_benign: false,
}];

// ── XSS ──────────────────────────────────────────────────────────────────────
// Vuln: raw script tag echoed to output.
// Benign: harmless text that should NOT produce the XSS marker.
const XSS: &[Payload] = &[
    Payload {
        bytes: b"<script>NYX_XSS_CONFIRMED</script>",
        label: "xss-script-marker",
        oracle: Oracle::OutputContains("<script>NYX_XSS_CONFIRMED</script>"),
        is_benign: false,
    },
    Payload {
        bytes: b"Hello World",
        label: "xss-benign-text",
        oracle: Oracle::OutputContains("<script>NYX_XSS_CONFIRMED</script>"),
        is_benign: true,
    },
];
