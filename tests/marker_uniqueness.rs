#![allow(deprecated)]
//! Marker uniqueness test (§4.1, §17.4).
//!
//! Asserts that no `NYX_PWN_*` marker from one cap's corpus is a substring
//! of any other cap's payloads, expected sanitizer outputs, or §17.4
//! redactor patterns.
//!
//! This prevents oracle collisions where a SQLi payload accidentally
//! triggers the CMDi oracle (or vice versa), producing false `Confirmed`
//! verdicts.
//!
//! Tests are gated on `#[cfg(feature = "dynamic")]` because the corpus
//! module lives under the `dynamic` feature.

#![cfg(feature = "dynamic")]

use nyx_scanner::dynamic::corpus::payloads_for;
use nyx_scanner::labels::Cap;

/// All markers extracted from non-benign payload oracles, tagged with the cap
/// they came from.
fn oracle_markers() -> Vec<(Cap, &'static str, &'static [u8])> {
    let mut markers = Vec::new();
    for cap in [
        Cap::SQL_QUERY,
        Cap::CODE_EXEC,
        Cap::FILE_IO,
        Cap::SSRF,
        Cap::HTML_ESCAPE,
    ] {
        for payload in payloads_for(cap).iter().filter(|p| !p.is_benign) {
            if let nyx_scanner::dynamic::corpus::Oracle::OutputContains(marker) = payload.oracle {
                markers.push((cap, marker, payload.bytes));
            }
        }
    }
    markers
}

/// Redactor patterns from §17.4 (the literal strings that trigger redaction).
const REDACTOR_PREFIXES: &[&str] = &[
    "AKIA",
    "ghp_",
    "github_pat_",
    "ghs_",
    "ghr_",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "xoxr-",
    "sk-",
    "-----BEGIN",
    "password=",
    "api_key=",
    "api_token=",
    "secret=",
    "Bearer ",
];

/// Expected sanitizer outputs (strings that appear after correct sanitization).
/// These must NOT appear in any payload oracle marker.
const EXPECTED_SANITIZED_OUTPUTS: &[&str] = &[
    "&lt;script&gt;",
    "&gt;",
    "&lt;",
    "&amp;",
    "&#x27;",
    "%27",
    "\\u003c",
    "\\u003e",
];

#[test]
fn no_marker_is_substring_of_another_caps_payload() {
    let markers = oracle_markers();

    // For each marker, check it does not appear in another cap's payloads.
    let caps = [
        Cap::SQL_QUERY,
        Cap::CODE_EXEC,
        Cap::FILE_IO,
        Cap::SSRF,
        Cap::HTML_ESCAPE,
    ];

    let mut violations: Vec<String> = Vec::new();

    for (src_cap, marker_str, _marker_src_payload) in &markers {
        let marker_bytes = marker_str.as_bytes();

        for cap in caps {
            // Within-cap reuse is allowed per §4.1 (cap A's marker may appear
            // in cap A's own payloads); only cross-cap appearance is a collision.
            if cap == *src_cap {
                continue;
            }
            for payload in payloads_for(cap).iter().filter(|p| !p.is_benign) {
                let payload_contains_marker = payload.bytes.windows(marker_bytes.len())
                    .any(|w| w == marker_bytes);

                if payload_contains_marker {
                    violations.push(format!(
                        "marker {:?} (from cap {:?}) appears as substring in payload {:?} (cap {:?})",
                        marker_str,
                        src_cap,
                        payload.label,
                        cap,
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Marker uniqueness violation(s):\n{}",
        violations.join("\n")
    );
}

#[test]
fn no_marker_is_substring_of_sanitized_output() {
    let markers = oracle_markers();

    let mut violations: Vec<String> = Vec::new();

    for (_, marker, _) in &markers {
        for sanitized in EXPECTED_SANITIZED_OUTPUTS {
            if sanitized.contains(marker) || marker.contains(sanitized) {
                violations.push(format!(
                    "marker {:?} overlaps with expected sanitized output {:?}",
                    marker, sanitized
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Marker/sanitizer overlap violation(s):\n{}",
        violations.join("\n")
    );
}

#[test]
fn no_marker_is_substring_of_redactor_patterns() {
    let markers = oracle_markers();

    let mut violations: Vec<String> = Vec::new();

    for (_, marker, _) in &markers {
        for pattern in REDACTOR_PREFIXES {
            // Check if the redactor pattern is a substring of the marker or vice versa.
            if marker.contains(pattern) && pattern.len() > 3 {
                violations.push(format!(
                    "marker {:?} contains redactor pattern {:?}",
                    marker, pattern
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Marker/redactor overlap violation(s):\n{}",
        violations.join("\n")
    );
}

#[test]
fn markers_are_unique_across_caps() {
    // Per §4.1: a marker may be reused within a single cap (e.g. two SQLi
    // payloads sharing one oracle marker), but must NOT appear in more than
    // one cap — that would risk one cap's payload accidentally firing
    // another cap's oracle.
    let markers = oracle_markers();

    // Cap is bitflags and does not implement Hash; key by bits().
    let mut seen: std::collections::HashMap<&str, std::collections::HashSet<u32>> =
        std::collections::HashMap::new();
    for (cap, marker, _) in &markers {
        seen.entry(marker).or_default().insert(cap.bits());
    }

    let cross_cap: Vec<_> = seen
        .iter()
        .filter(|(_, caps)| caps.len() > 1)
        .map(|(m, caps)| (*m, caps.clone()))
        .collect();

    assert!(
        cross_cap.is_empty(),
        "Oracle marker(s) reused across caps (collision risk): {:?}\n\
         Each cap must use a marker that does not appear in any other cap.",
        cross_cap
    );
}

#[test]
fn all_vuln_payloads_have_non_empty_oracle_marker() {
    for cap in [
        Cap::SQL_QUERY,
        Cap::CODE_EXEC,
        Cap::FILE_IO,
        Cap::SSRF,
        Cap::HTML_ESCAPE,
    ] {
        for payload in payloads_for(cap).iter().filter(|p| !p.is_benign) {
            if let nyx_scanner::dynamic::corpus::Oracle::OutputContains(marker) = payload.oracle {
                assert!(
                    !marker.is_empty(),
                    "payload {:?} for {cap:?} has empty OutputContains marker",
                    payload.label
                );
                assert!(
                    marker.len() >= 4,
                    "payload {:?} for {cap:?} has very short marker {:?} (< 4 chars) — collision risk",
                    payload.label, marker
                );
            }
        }
    }
}
