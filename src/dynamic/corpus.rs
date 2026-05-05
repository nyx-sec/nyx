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
