//! Per-capability payload corpus.
//!
//! Each [`Cap`] maps to a small set of canonical payloads plus a matching
//! detection oracle. Payloads are static data — adding a new one is a code
//! review, not a runtime config knob, so they cannot drift between versions.
//!
//! The corpus is intentionally minimal at the start. Goal is one payload
//! per cap that triggers reliably on the obvious case; tuning happens once
//! we have real targets.

use crate::labels::Cap;

/// Bump when the corpus content changes in a way that invalidates previously-
/// computed [`crate::dynamic::spec::HarnessSpec::spec_hash`] values (e.g.
/// payloads renamed, oracle semantics changed, new cap entries added).
pub const CORPUS_VERSION: u32 = 1;

/// A single payload + the oracle that confirms it fired.
#[derive(Debug, Clone)]
pub struct Payload {
    /// Bytes injected into the [`crate::dynamic::spec::PayloadSlot`].
    pub bytes: &'static [u8],
    /// Human label for logs and reports (`"sqli-quote-or-1"` etc.).
    pub label: &'static str,
    /// How we decide the sink fired. See [`Oracle`].
    pub oracle: Oracle,
}

/// Detection strategy. Multiple oracles run in parallel; first hit wins.
#[derive(Debug, Clone)]
pub enum Oracle {
    /// Substring on stdout/stderr (e.g. `"PAYLOAD-MARKER"`, SQL error text).
    OutputContains(&'static str),
    /// Process exited with a crash signal (SIGSEGV, SIGABRT).
    Crash,
    /// Outbound network connection observed to a controlled sink host.
    OobCallback { host: &'static str },
    /// File written outside the sandbox sandbox root.
    FileEscape,
    /// Non-zero exit with specific status (e.g. shell command success).
    ExitStatus(i32),
}

/// Pick the payload set for a given cap. Empty slice = unsupported cap.
///
/// # Cap coverage (update when adding/removing Cap bits)
///
/// | Cap                | Supported | Notes                          |
/// |--------------------|-----------|--------------------------------|
/// | SQL_QUERY          | yes       | SQLI payloads                  |
/// | CODE_EXEC          | yes       | command injection echo marker  |
/// | FILE_IO            | yes       | path traversal to /etc/passwd  |
/// | SSRF               | yes       | OOB callback probe             |
/// | HTML_ESCAPE        | yes       | XSS script marker              |
/// | ENV_VAR            | no        | source-only cap; no sink oracle|
/// | SHELL_ESCAPE       | no        | sanitizer cap; no sink oracle  |
/// | URL_ENCODE         | no        | sanitizer cap; no sink oracle  |
/// | JSON_PARSE         | no        | no reliable oracle             |
/// | FMT_STRING         | no        | no reliable oracle             |
/// | DESERIALIZE        | no        | no reliable oracle             |
/// | CRYPTO             | no        | no reliable oracle             |
/// | UNAUTHORIZED_ID    | no        | auth bypass; no oracle         |
/// | DATA_EXFIL         | no        | exfil; no oracle               |
/// | LDAP_INJECTION     | no        | no oracle                      |
/// | XPATH_INJECTION    | no        | no oracle                      |
/// | HEADER_INJECTION   | no        | no oracle                      |
/// | OPEN_REDIRECT      | no        | no oracle                      |
/// | SSTI               | no        | no oracle                      |
/// | XXE                | no        | no oracle                      |
/// | PROTOTYPE_POLLUTION| no        | JS-runtime; no oracle          |
///
/// When adding a new `Cap` bit: add a row above, update this function, and
/// bump [`CORPUS_VERSION`] if you add payload support.
///
/// Compile-time exhaustiveness guard: `CORPUS_SUPPORTED | CORPUS_UNSUPPORTED`
/// must equal `Cap::all()`. Adding a new Cap bit without updating this table
/// triggers a `const` assertion failure at build time.
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
            Cap::ENV_VAR,
            Cap::SHELL_ESCAPE,
            Cap::URL_ENCODE,
            Cap::JSON_PARSE,
            Cap::FMT_STRING,
            Cap::DESERIALIZE,
            Cap::CRYPTO,
            Cap::UNAUTHORIZED_ID,
            Cap::DATA_EXFIL,
            Cap::LDAP_INJECTION,
            Cap::XPATH_INJECTION,
            Cap::HEADER_INJECTION,
            Cap::OPEN_REDIRECT,
            Cap::SSTI,
            Cap::XXE,
            Cap::PROTOTYPE_POLLUTION,
        ];
        for cap in unsupported {
            assert!(
                payloads_for(cap).is_empty(),
                "expected {cap:?} to return empty payloads; update coverage table if adding support"
            );
        }
    }
}

const SQLI: &[Payload] = &[Payload {
    bytes: b"' OR 1=1-- NYX",
    label: "sqli-or-1",
    oracle: Oracle::OutputContains("NYX"),
}];

const CMDI: &[Payload] = &[Payload {
    bytes: b"; echo NYX_PWN",
    label: "cmdi-echo-marker",
    oracle: Oracle::OutputContains("NYX_PWN"),
}];

const PATH_TRAV: &[Payload] = &[Payload {
    bytes: b"../../../../etc/passwd",
    label: "path-traversal-passwd",
    oracle: Oracle::OutputContains("root:"),
}];

const SSRF_PAYLOADS: &[Payload] = &[Payload {
    bytes: b"http://nyx-oob.invalid/probe",
    label: "ssrf-oob",
    oracle: Oracle::OobCallback {
        host: "nyx-oob.invalid",
    },
}];

const XSS: &[Payload] = &[Payload {
    bytes: b"<script>NYX_XSS</script>",
    label: "xss-script-marker",
    oracle: Oracle::OutputContains("<script>NYX_XSS</script>"),
}];
