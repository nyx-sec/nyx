//! `(Cap, Lang)` payload registry.
//!
//! [`CORPUS`] is the canonical, const-built lookup table.  Track J phases
//! 03–11 land each cap independently by adding new per-`(cap, lang)` slice
//! files under `src/dynamic/corpus/<cap>/<lang>.rs` and wiring them in
//! here.
//!
//! Public surface:
//!
//! * [`payloads_for_lang`] — per-language lookup (new API).
//! * [`payloads_for`] — back-compatible union shim that flattens every
//!   language registered for a cap.  Returns `&'static [CuratedPayload]`
//!   so existing call sites in [`crate::dynamic::runner`],
//!   [`crate::dynamic::verify`], and the fuzzer compile unchanged.
//! * [`benign_payload_for`], [`resolve_benign_control`],
//!   [`materialise_bytes`], [`audit_marker_collisions`] — unchanged
//!   semantics; all route through the registry.

// Legacy [`Oracle::OutputContains`] is intentionally retained for
// pre-Phase-06 corpus entries; the deprecation warning is informational.
#![allow(deprecated)]

use std::collections::HashMap;
use std::sync::OnceLock;

use super::{
    cmdi, deserialize, fmt_string, header_injection, ldap, path_trav, sqli, ssrf, ssti, xpath,
    xss, xxe,
};
use super::{CapCorpus, CuratedPayload, Oracle};
use crate::dynamic::oracle::ProbePredicate;
use crate::labels::Cap;
use crate::symbol::Lang;

/// Caps with no payloads of their own — source-only sources, sanitizers,
/// and sinks we cannot yet model with a reliable oracle.  The
/// [`super::audit`] module asserts that the union of caps covered by
/// [`CORPUS::entries`] and this constant equals [`Cap::all`].
pub const CORPUS_UNSUPPORTED_LANG_NEUTRAL: u32 = Cap::ENV_VAR.bits()
    | Cap::SHELL_ESCAPE.bits()
    | Cap::URL_ENCODE.bits()
    | Cap::JSON_PARSE.bits()
    | Cap::CRYPTO.bits()
    | Cap::UNAUTHORIZED_ID.bits()
    | Cap::DATA_EXFIL.bits()
    | Cap::OPEN_REDIRECT.bits()
    | Cap::PROTOTYPE_POLLUTION.bits();

/// Flat `(Cap, Lang, slice)` table.  A single cap can carry per-language
/// variants — that's the whole reason this layer exists.
const ENTRIES: &[(Cap, Lang, &[CuratedPayload])] = &[
    (Cap::SQL_QUERY, Lang::Rust, sqli::rust::PAYLOADS),
    (Cap::CODE_EXEC, Lang::Rust, cmdi::rust::PAYLOADS),
    (Cap::FILE_IO, Lang::Rust, path_trav::rust::PAYLOADS),
    (Cap::SSRF, Lang::Rust, ssrf::rust::PAYLOADS),
    (Cap::HTML_ESCAPE, Lang::Rust, xss::rust::PAYLOADS),
    (Cap::FMT_STRING, Lang::C, fmt_string::c::PAYLOADS),
    (Cap::DESERIALIZE, Lang::Java, deserialize::java::PAYLOADS),
    (Cap::DESERIALIZE, Lang::Python, deserialize::python::PAYLOADS),
    (Cap::DESERIALIZE, Lang::Php, deserialize::php::PAYLOADS),
    (Cap::DESERIALIZE, Lang::Ruby, deserialize::ruby::PAYLOADS),
    (Cap::SSTI, Lang::Python, ssti::python_jinja2::PAYLOADS),
    (Cap::SSTI, Lang::Ruby, ssti::ruby_erb::PAYLOADS),
    (Cap::SSTI, Lang::Php, ssti::php_twig::PAYLOADS),
    (Cap::SSTI, Lang::Java, ssti::java_thymeleaf::PAYLOADS),
    (Cap::SSTI, Lang::JavaScript, ssti::js_handlebars::PAYLOADS),
    (Cap::XXE, Lang::Java, xxe::java::PAYLOADS),
    (Cap::XXE, Lang::Python, xxe::python::PAYLOADS),
    (Cap::XXE, Lang::Php, xxe::php::PAYLOADS),
    (Cap::XXE, Lang::Ruby, xxe::ruby::PAYLOADS),
    (Cap::XXE, Lang::Go, xxe::go::PAYLOADS),
    (Cap::LDAP_INJECTION, Lang::Java, ldap::java::PAYLOADS),
    (Cap::LDAP_INJECTION, Lang::Python, ldap::python::PAYLOADS),
    (Cap::LDAP_INJECTION, Lang::Php, ldap::php::PAYLOADS),
    (Cap::XPATH_INJECTION, Lang::Java, xpath::java::PAYLOADS),
    (Cap::XPATH_INJECTION, Lang::Python, xpath::python::PAYLOADS),
    (Cap::XPATH_INJECTION, Lang::Php, xpath::php::PAYLOADS),
    (Cap::XPATH_INJECTION, Lang::JavaScript, xpath::js::PAYLOADS),
    (Cap::HEADER_INJECTION, Lang::Java, header_injection::java::PAYLOADS),
    (Cap::HEADER_INJECTION, Lang::Python, header_injection::python::PAYLOADS),
    (Cap::HEADER_INJECTION, Lang::Php, header_injection::php::PAYLOADS),
    (Cap::HEADER_INJECTION, Lang::Ruby, header_injection::ruby::PAYLOADS),
    (Cap::HEADER_INJECTION, Lang::JavaScript, header_injection::js::PAYLOADS),
    (Cap::HEADER_INJECTION, Lang::Go, header_injection::go::PAYLOADS),
    (Cap::HEADER_INJECTION, Lang::Rust, header_injection::rust::PAYLOADS),
];

/// Reserved for per-cap oracle defaults.  Empty in Phase 02; populated by
/// later Track J phases that hoist a cap-wide
/// [`ProbePredicate`](crate::dynamic::oracle::ProbePredicate) set off the
/// individual [`CuratedPayload::probe_predicates`] fields.
const ORACLES: &[(Cap, &[ProbePredicate])] = &[];

/// The canonical registry instance.
pub const CORPUS: CapCorpus = CapCorpus {
    entries: ENTRIES,
    oracles: ORACLES,
};

/// Per-language payload lookup.
///
/// Returns an empty slice when no payloads are registered for the requested
/// `(cap, lang)` pair.  This is the new API; existing callers go through
/// [`payloads_for`] until they need per-language precision.
pub fn payloads_for_lang(cap: Cap, lang: Lang) -> &'static [CuratedPayload] {
    for &(c, l, slice) in CORPUS.entries {
        if c == cap && l == lang {
            return slice;
        }
    }
    &[]
}

/// Back-compatible union shim: returns every payload registered against
/// `cap`, across all languages.
///
/// The union is leaked once per cap on first access.  All payload data is
/// `&'static`, so each `CuratedPayload` clone is a cheap shallow copy and
/// the leaked allocation stays bounded by the corpus size (under 1 KiB).
pub fn payloads_for(cap: Cap) -> &'static [CuratedPayload] {
    static CACHE: OnceLock<HashMap<u32, &'static [CuratedPayload]>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        let mut grouped: HashMap<u32, Vec<CuratedPayload>> = HashMap::new();
        for &(c, _lang, slice) in CORPUS.entries {
            grouped
                .entry(c.bits())
                .or_default()
                .extend(slice.iter().cloned());
        }
        grouped
            .into_iter()
            .map(|(k, v)| {
                let leaked: &'static [CuratedPayload] = Box::leak(v.into_boxed_slice());
                (k, leaked)
            })
            .collect()
    });
    cache.get(&cap.bits()).copied().unwrap_or(&[])
}

/// Return the (first) benign control payload for a cap, if one exists.
///
/// Lang-agnostic union shim — searches every registered `(cap, lang)`
/// slice in declaration order.  Prefer [`benign_payload_for_lang`] when
/// the caller knows the harness's [`Lang`] so cross-language label
/// collisions (e.g. an `ssrf-benign` label registered for both Rust and
/// Python) cannot resolve to a wrong-language fixture.
pub fn benign_payload_for(cap: Cap) -> Option<&'static CuratedPayload> {
    payloads_for(cap).iter().find(|p| p.is_benign)
}

/// Lang-aware [`benign_payload_for`].  Restricts the search to the
/// requested `(cap, lang)` slice so a payload's benign control is
/// always resolved inside the same language vertical.
pub fn benign_payload_for_lang(cap: Cap, lang: Lang) -> Option<&'static CuratedPayload> {
    payloads_for_lang(cap, lang).iter().find(|p| p.is_benign)
}

/// Resolve a [`CuratedPayload::benign_control`] reference to the matching
/// benign entry inside the same cap's payload slice (across all langs).
///
/// Returns `None` when the vulnerable payload has no paired control
/// (`benign_control == None`) or when the named label is missing /
/// non-benign in the corpus.  The runner treats the `None` result as
/// `NoControl` and downgrades the verdict to
/// [`crate::evidence::InconclusiveReason::NoBenignControl`].
///
/// Lang-agnostic union shim — kept for the small set of pre-Phase-03
/// callers that do not carry a [`Lang`] at the call site.  Prefer
/// [`resolve_benign_control_lang`] in any new code: with multiple
/// `(cap, lang)` slices registered for the same cap, the union shim
/// can match a wrong-language fixture's label and silently confirm
/// against a benign that never ran.
pub fn resolve_benign_control(
    vuln_payload: &CuratedPayload,
    cap: Cap,
) -> Option<&'static CuratedPayload> {
    let r = vuln_payload.benign_control?;
    payloads_for(cap)
        .iter()
        .find(|p| p.is_benign && p.label == r.label)
}

/// Lang-aware [`resolve_benign_control`].  Restricts the search to the
/// `(cap, lang)` slice that produced the vuln payload so the
/// differential rule (§4.1) can never compare against a wrong-language
/// benign even when two language slices share a label.  Phase 03 wires
/// this through [`crate::dynamic::runner`].
pub fn resolve_benign_control_lang(
    vuln_payload: &CuratedPayload,
    cap: Cap,
    lang: Lang,
) -> Option<&'static CuratedPayload> {
    let r = vuln_payload.benign_control?;
    payloads_for_lang(cap, lang)
        .iter()
        .find(|p| p.is_benign && p.label == r.label)
}

/// Materialise the effective bytes for a payload.
///
/// For static payloads (`oob_nonce_slot == false`) returns the `bytes`
/// slice directly.  For OOB-nonce payloads, constructs the callback URL
/// from the listener and nonce; returns `None` when no listener is
/// configured.
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

/// Marker-collision audit (§16.3).
///
/// Returns `(cap_name, label, conflicting_cap_name)` triples where a
/// non-benign payload's `OutputContains` marker also appears in another
/// cap's payload bytes.  Empty result = passing.
pub fn audit_marker_collisions() -> Vec<(&'static str, &'static str, &'static str)> {
    fn cap_label(cap: Cap) -> Option<&'static str> {
        match cap {
            Cap::SQL_QUERY => Some("SQL_QUERY"),
            Cap::CODE_EXEC => Some("CODE_EXEC"),
            Cap::FILE_IO => Some("FILE_IO"),
            Cap::SSRF => Some("SSRF"),
            Cap::HTML_ESCAPE => Some("HTML_ESCAPE"),
            Cap::FMT_STRING => Some("FMT_STRING"),
            _ => None,
        }
    }

    let mut cap_payloads: Vec<(Cap, &'static str, &'static [CuratedPayload])> = Vec::new();
    let mut seen_bits: u32 = 0;
    for &(c, _lang, _slice) in CORPUS.entries {
        if seen_bits & c.bits() != 0 {
            continue;
        }
        seen_bits |= c.bits();
        if let Some(name) = cap_label(c) {
            cap_payloads.push((c, name, payloads_for(c)));
        }
    }

    let mut collisions = Vec::new();
    for &(src_cap, src_name, src_slice) in &cap_payloads {
        for p in src_slice {
            if p.is_benign {
                continue;
            }
            let Oracle::OutputContains(marker) = &p.oracle else {
                continue;
            };
            let marker_bytes = marker.as_bytes();
            for &(other_cap, other_name, other_slice) in &cap_payloads {
                if other_cap == src_cap {
                    continue;
                }
                for op in other_slice {
                    if op.is_benign {
                        continue;
                    }
                    if op
                        .bytes
                        .windows(marker_bytes.len())
                        .any(|w| w == marker_bytes)
                    {
                        collisions.push((src_name, p.label, other_name));
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
    use crate::dynamic::corpus::{benign_payload_for, CORPUS_VERSION};

    #[test]
    fn supported_caps_have_payloads() {
        assert!(!payloads_for(Cap::SQL_QUERY).is_empty());
        assert!(!payloads_for(Cap::CODE_EXEC).is_empty());
        assert!(!payloads_for(Cap::FILE_IO).is_empty());
        assert!(!payloads_for(Cap::SSRF).is_empty());
        assert!(!payloads_for(Cap::HTML_ESCAPE).is_empty());
        assert!(!payloads_for(Cap::FMT_STRING).is_empty());
        assert!(!payloads_for(Cap::DESERIALIZE).is_empty());
        assert!(!payloads_for(Cap::SSTI).is_empty());
        assert!(!payloads_for(Cap::XXE).is_empty());
        assert!(!payloads_for(Cap::LDAP_INJECTION).is_empty());
        assert!(!payloads_for(Cap::XPATH_INJECTION).is_empty());
        assert!(!payloads_for(Cap::HEADER_INJECTION).is_empty());
    }

    #[test]
    fn unsupported_caps_return_empty() {
        let unsupported = [
            Cap::ENV_VAR,
            Cap::SHELL_ESCAPE,
            Cap::URL_ENCODE,
            Cap::JSON_PARSE,
            Cap::CRYPTO,
            Cap::UNAUTHORIZED_ID,
            Cap::DATA_EXFIL,
            Cap::OPEN_REDIRECT,
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
        for cap in [
            Cap::SQL_QUERY,
            Cap::CODE_EXEC,
            Cap::FILE_IO,
            Cap::HTML_ESCAPE,
            Cap::FMT_STRING,
            Cap::DESERIALIZE,
            Cap::SSTI,
            Cap::XXE,
            Cap::LDAP_INJECTION,
            Cap::XPATH_INJECTION,
            Cap::HEADER_INJECTION,
        ] {
            let has_vuln = payloads_for(cap).iter().any(|p| !p.is_benign);
            assert!(has_vuln, "{cap:?} must have at least one vuln payload");
        }
    }

    #[test]
    fn fmt_string_has_sink_crash_oracle_and_benign_control() {
        let payloads = payloads_for(Cap::FMT_STRING);
        let vuln = payloads
            .iter()
            .find(|p| !p.is_benign)
            .expect("FMT_STRING must have a vuln payload");
        assert!(
            matches!(vuln.oracle, Oracle::SinkCrash { .. }),
            "FMT_STRING vuln payload oracle must be SinkCrash (Phase 08)"
        );
        let bref = vuln
            .benign_control
            .expect("FMT_STRING vuln must reference a benign control");
        assert!(
            resolve_benign_control(vuln, Cap::FMT_STRING).is_some(),
            "FMT_STRING benign-control label '{}' must resolve",
            bref.label,
        );
    }

    #[test]
    fn marker_uniqueness_sqli() {
        for p in payloads_for(Cap::SQL_QUERY) {
            assert!(
                !p.bytes.windows(7).any(|w| w == b"NYX_PWN"),
                "NYX_PWN (CODE_EXEC marker) must not appear in SQLI payloads",
            );
        }
    }

    #[test]
    fn all_payloads_have_fixture_paths() {
        let caps = [
            Cap::SQL_QUERY,
            Cap::CODE_EXEC,
            Cap::FILE_IO,
            Cap::SSRF,
            Cap::HTML_ESCAPE,
            Cap::FMT_STRING,
            Cap::DESERIALIZE,
            Cap::SSTI,
            Cap::XXE,
            Cap::LDAP_INJECTION,
            Cap::XPATH_INJECTION,
            Cap::HEADER_INJECTION,
        ];
        for cap in caps {
            for p in payloads_for(cap) {
                assert!(
                    !p.fixture_paths.is_empty(),
                    "payload '{}' for {cap:?} must have ≥1 fixture_path (§16.1)",
                    p.label,
                );
            }
        }
    }

    #[test]
    fn all_payloads_have_valid_since_corpus_version() {
        let caps = [
            Cap::SQL_QUERY,
            Cap::CODE_EXEC,
            Cap::FILE_IO,
            Cap::SSRF,
            Cap::HTML_ESCAPE,
            Cap::FMT_STRING,
            Cap::DESERIALIZE,
            Cap::SSTI,
            Cap::XXE,
            Cap::LDAP_INJECTION,
            Cap::XPATH_INJECTION,
            Cap::HEADER_INJECTION,
        ];
        for cap in caps {
            for p in payloads_for(cap) {
                assert!(
                    p.since_corpus_version >= 1 && p.since_corpus_version <= CORPUS_VERSION,
                    "payload '{}': since_corpus_version {} out of [1, {}]",
                    p.label,
                    p.since_corpus_version,
                    CORPUS_VERSION,
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
        let p = payloads_for(Cap::SQL_QUERY)
            .iter()
            .find(|p| !p.is_benign && !p.oob_nonce_slot)
            .expect("must have static SQLi payload");
        let bytes =
            materialise_bytes(p, None).expect("static payload must materialise without OOB");
        assert_eq!(&*bytes, p.bytes);
    }

    #[test]
    fn materialise_oob_payload_with_url() {
        let p = payloads_for(Cap::SSRF)
            .iter()
            .find(|p| p.oob_nonce_slot)
            .expect("must have OOB payload");
        let url = "http://127.0.0.1:54321/mynonce";
        let bytes =
            materialise_bytes(p, Some(url)).expect("OOB payload materialises with URL");
        assert_eq!(&*bytes, url.as_bytes());
    }

    #[test]
    fn materialise_oob_payload_without_listener_returns_none() {
        let p = payloads_for(Cap::SSRF)
            .iter()
            .find(|p| p.oob_nonce_slot)
            .expect("must have OOB payload");
        assert!(materialise_bytes(p, None).is_none(), "no OOB URL → None");
    }

    #[test]
    fn benign_control_refs_resolve_for_paired_caps() {
        let cases: &[(Cap, &str, &str)] = &[
            (Cap::SQL_QUERY, "sqli-tautology", "sqli-benign"),
            (Cap::SQL_QUERY, "sqli-union-nyx", "sqli-benign"),
            (Cap::CODE_EXEC, "cmdi-echo-marker", "cmdi-benign"),
            (Cap::FILE_IO, "path-traversal-passwd", "path-traversal-benign"),
            (Cap::SSRF, "ssrf-file-scheme", "ssrf-benign"),
            (Cap::HTML_ESCAPE, "xss-script-marker", "xss-benign-text"),
        ];
        for (cap, vuln_label, benign_label) in cases {
            let payloads = payloads_for(*cap);
            let vuln = payloads
                .iter()
                .find(|p| p.label == *vuln_label)
                .unwrap_or_else(|| panic!("missing vuln payload {vuln_label} for {cap:?}"));
            let resolved = resolve_benign_control(vuln, *cap)
                .unwrap_or_else(|| panic!("missing benign control for {vuln_label}"));
            assert_eq!(resolved.label, *benign_label);
            assert!(resolved.is_benign, "resolved control must be marked benign");
        }
    }

    #[test]
    fn oob_payload_has_no_benign_control() {
        let payloads = payloads_for(Cap::SSRF);
        let p = payloads
            .iter()
            .find(|p| p.oob_nonce_slot)
            .expect("OOB payload");
        assert!(p.benign_control.is_none(), "OOB-nonce → NoControl");
        assert!(resolve_benign_control(p, Cap::SSRF).is_none());
        assert!(
            p.no_benign_control_rationale.is_some(),
            "OOB-nonce must carry written no_benign_control_rationale",
        );
    }

    #[test]
    fn benign_entries_are_terminal() {
        let caps = [
            Cap::SQL_QUERY,
            Cap::CODE_EXEC,
            Cap::FILE_IO,
            Cap::SSRF,
            Cap::HTML_ESCAPE,
            Cap::FMT_STRING,
            Cap::DESERIALIZE,
            Cap::SSTI,
            Cap::XXE,
            Cap::LDAP_INJECTION,
            Cap::XPATH_INJECTION,
            Cap::HEADER_INJECTION,
        ];
        for cap in caps {
            for p in payloads_for(cap).iter().filter(|p| p.is_benign) {
                assert!(
                    p.benign_control.is_none(),
                    "benign payload {} must not chain to another control",
                    p.label,
                );
            }
        }
    }

    #[test]
    fn payloads_for_lang_filters() {
        // SQL_QUERY currently only registered for Rust.
        assert!(!payloads_for_lang(Cap::SQL_QUERY, Lang::Rust).is_empty());
        assert!(payloads_for_lang(Cap::SQL_QUERY, Lang::Python).is_empty());
        // FMT_STRING is C-only.
        assert!(!payloads_for_lang(Cap::FMT_STRING, Lang::C).is_empty());
        assert!(payloads_for_lang(Cap::FMT_STRING, Lang::Rust).is_empty());
    }

    #[test]
    fn back_compat_union_matches_registered_entry() {
        // For caps with one (cap, lang) entry only, the lang-agnostic
        // union must contain the same labels as the underlying slice
        // (byte-identical verdict requirement, Phase 02 acceptance).
        // Phase 03 introduces multi-lang caps (DESERIALIZE), so single-
        // entry caps are filtered separately from the union check.
        use std::collections::HashMap;
        let mut entries_by_cap: HashMap<u32, Vec<(Lang, &'static [CuratedPayload])>> =
            HashMap::new();
        for &(cap, lang, slice) in CORPUS.entries {
            entries_by_cap.entry(cap.bits()).or_default().push((lang, slice));
        }
        for (cap_bits, langs) in &entries_by_cap {
            if langs.len() != 1 {
                continue;
            }
            let (lang, slice) = langs[0];
            let cap = Cap::from_bits_truncate(*cap_bits);
            let union = payloads_for(cap);
            assert_eq!(
                union.len(),
                slice.len(),
                "union for {cap:?} differs from {lang:?} slice",
            );
            for (u, s) in union.iter().zip(slice.iter()) {
                assert_eq!(u.label, s.label);
                assert_eq!(u.bytes, s.bytes);
            }
        }
    }

    #[test]
    fn deserialize_has_per_lang_slices_for_phase_03() {
        // Phase 03 (Track J.1) acceptance: DESERIALIZE registers
        // payloads in Java / Python / PHP / Ruby and the lang-aware
        // lookup never returns empty for any of them.
        for lang in [Lang::Java, Lang::Python, Lang::Php, Lang::Ruby] {
            assert!(
                !payloads_for_lang(Cap::DESERIALIZE, lang).is_empty(),
                "DESERIALIZE must have at least one payload for {lang:?}",
            );
        }
        // Rust / C / Go / JS / TS / Cpp not yet covered — those slices
        // remain empty.
        for lang in [
            Lang::Rust,
            Lang::C,
            Lang::Cpp,
            Lang::Go,
            Lang::JavaScript,
            Lang::TypeScript,
        ] {
            assert!(
                payloads_for_lang(Cap::DESERIALIZE, lang).is_empty(),
                "DESERIALIZE has unexpected payloads for {lang:?}",
            );
        }
    }

    #[test]
    fn ssti_has_per_lang_slices_for_phase_04() {
        // Phase 04 (Track J.2) acceptance: SSTI registers payloads in
        // Python / Ruby / PHP / Java / JavaScript and the lang-aware
        // lookup never returns empty for any of them.
        for lang in [
            Lang::Python,
            Lang::Ruby,
            Lang::Php,
            Lang::Java,
            Lang::JavaScript,
        ] {
            assert!(
                !payloads_for_lang(Cap::SSTI, lang).is_empty(),
                "SSTI must have at least one payload for {lang:?}",
            );
        }
        // Rust / C / Cpp / Go / TypeScript not yet covered.
        for lang in [Lang::Rust, Lang::C, Lang::Cpp, Lang::Go, Lang::TypeScript] {
            assert!(
                payloads_for_lang(Cap::SSTI, lang).is_empty(),
                "SSTI has unexpected payloads for {lang:?}",
            );
        }
    }

    #[test]
    fn ssti_payloads_pair_benign_controls_per_lang() {
        for lang in [
            Lang::Python,
            Lang::Ruby,
            Lang::Php,
            Lang::Java,
            Lang::JavaScript,
        ] {
            let slice = payloads_for_lang(Cap::SSTI, lang);
            let vuln = slice
                .iter()
                .find(|p| !p.is_benign)
                .expect("each lang must have an SSTI vuln payload");
            let resolved = super::resolve_benign_control_lang(vuln, Cap::SSTI, lang)
                .expect("lang-aware benign control must resolve");
            assert!(resolved.is_benign);
        }
    }

    #[test]
    fn xxe_has_per_lang_slices_for_phase_05() {
        // Phase 05 (Track J.3) acceptance: XXE registers payloads in
        // Java / Python / PHP / Ruby / Go and the lang-aware lookup
        // never returns empty for any of them.
        for lang in [Lang::Java, Lang::Python, Lang::Php, Lang::Ruby, Lang::Go] {
            assert!(
                !payloads_for_lang(Cap::XXE, lang).is_empty(),
                "XXE must have at least one payload for {lang:?}",
            );
        }
        // Rust / C / Cpp / JS / TS not yet covered.
        for lang in [
            Lang::Rust,
            Lang::C,
            Lang::Cpp,
            Lang::JavaScript,
            Lang::TypeScript,
        ] {
            assert!(
                payloads_for_lang(Cap::XXE, lang).is_empty(),
                "XXE has unexpected payloads for {lang:?}",
            );
        }
    }

    #[test]
    fn xxe_payloads_pair_benign_controls_per_lang() {
        for lang in [Lang::Java, Lang::Python, Lang::Php, Lang::Ruby, Lang::Go] {
            let slice = payloads_for_lang(Cap::XXE, lang);
            let vuln = slice
                .iter()
                .find(|p| !p.is_benign)
                .expect("each lang must have an XXE vuln payload");
            let resolved = super::resolve_benign_control_lang(vuln, Cap::XXE, lang)
                .expect("lang-aware benign control must resolve");
            assert!(resolved.is_benign);
        }
    }

    #[test]
    fn ldap_has_per_lang_slices_for_phase_06() {
        // Phase 06 (Track J.4) acceptance: LDAP_INJECTION registers
        // payloads in Java / Python / PHP and the lang-aware lookup
        // never returns empty for any of them.
        for lang in [Lang::Java, Lang::Python, Lang::Php] {
            assert!(
                !payloads_for_lang(Cap::LDAP_INJECTION, lang).is_empty(),
                "LDAP_INJECTION must have at least one payload for {lang:?}",
            );
        }
        // Rust / C / Cpp / Ruby / Go / JS / TS not yet covered.
        for lang in [
            Lang::Rust,
            Lang::C,
            Lang::Cpp,
            Lang::Ruby,
            Lang::Go,
            Lang::JavaScript,
            Lang::TypeScript,
        ] {
            assert!(
                payloads_for_lang(Cap::LDAP_INJECTION, lang).is_empty(),
                "LDAP_INJECTION has unexpected payloads for {lang:?}",
            );
        }
    }

    #[test]
    fn ldap_payloads_pair_benign_controls_per_lang() {
        for lang in [Lang::Java, Lang::Python, Lang::Php] {
            let slice = payloads_for_lang(Cap::LDAP_INJECTION, lang);
            let vuln = slice
                .iter()
                .find(|p| !p.is_benign)
                .expect("each lang must have an LDAP vuln payload");
            let resolved =
                super::resolve_benign_control_lang(vuln, Cap::LDAP_INJECTION, lang)
                    .expect("lang-aware benign control must resolve");
            assert!(resolved.is_benign);
        }
    }

    #[test]
    fn xpath_has_per_lang_slices_for_phase_07() {
        // Phase 07 (Track J.5) acceptance: XPATH_INJECTION registers
        // payloads in Java / Python / PHP / JavaScript and the
        // lang-aware lookup never returns empty for any of them.
        for lang in [Lang::Java, Lang::Python, Lang::Php, Lang::JavaScript] {
            assert!(
                !payloads_for_lang(Cap::XPATH_INJECTION, lang).is_empty(),
                "XPATH_INJECTION must have at least one payload for {lang:?}",
            );
        }
        // Rust / C / Cpp / Ruby / Go / TS not yet covered.
        for lang in [
            Lang::Rust,
            Lang::C,
            Lang::Cpp,
            Lang::Ruby,
            Lang::Go,
            Lang::TypeScript,
        ] {
            assert!(
                payloads_for_lang(Cap::XPATH_INJECTION, lang).is_empty(),
                "XPATH_INJECTION has unexpected payloads for {lang:?}",
            );
        }
    }

    #[test]
    fn xpath_payloads_pair_benign_controls_per_lang() {
        for lang in [Lang::Java, Lang::Python, Lang::Php, Lang::JavaScript] {
            let slice = payloads_for_lang(Cap::XPATH_INJECTION, lang);
            let vuln = slice
                .iter()
                .find(|p| !p.is_benign)
                .expect("each lang must have an XPath vuln payload");
            let resolved =
                super::resolve_benign_control_lang(vuln, Cap::XPATH_INJECTION, lang)
                    .expect("lang-aware benign control must resolve");
            assert!(resolved.is_benign);
        }
    }

    #[test]
    fn header_injection_has_per_lang_slices_for_phase_08() {
        // Phase 08 (Track J.6) acceptance: HEADER_INJECTION registers
        // payloads in Java / Python / PHP / Ruby / JS / Go / Rust and
        // the lang-aware lookup never returns empty for any of them.
        for lang in [
            Lang::Java,
            Lang::Python,
            Lang::Php,
            Lang::Ruby,
            Lang::JavaScript,
            Lang::Go,
            Lang::Rust,
        ] {
            assert!(
                !payloads_for_lang(Cap::HEADER_INJECTION, lang).is_empty(),
                "HEADER_INJECTION must have at least one payload for {lang:?}",
            );
        }
        // C / Cpp / TypeScript not yet covered.
        for lang in [Lang::C, Lang::Cpp, Lang::TypeScript] {
            assert!(
                payloads_for_lang(Cap::HEADER_INJECTION, lang).is_empty(),
                "HEADER_INJECTION has unexpected payloads for {lang:?}",
            );
        }
    }

    #[test]
    fn header_injection_payloads_pair_benign_controls_per_lang() {
        for lang in [
            Lang::Java,
            Lang::Python,
            Lang::Php,
            Lang::Ruby,
            Lang::JavaScript,
            Lang::Go,
            Lang::Rust,
        ] {
            let slice = payloads_for_lang(Cap::HEADER_INJECTION, lang);
            let vuln = slice
                .iter()
                .find(|p| !p.is_benign)
                .expect("each lang must have a HEADER_INJECTION vuln payload");
            let resolved =
                super::resolve_benign_control_lang(vuln, Cap::HEADER_INJECTION, lang)
                    .expect("lang-aware benign control must resolve");
            assert!(resolved.is_benign);
        }
    }

    #[test]
    fn deserialize_payloads_pair_benign_controls_per_lang() {
        // The lang-aware resolver must find the paired benign control
        // inside its own slice — proves the Phase-03 deferred-fix
        // wiring (see audit_benign_label_uniqueness_runtime).
        for lang in [Lang::Java, Lang::Python, Lang::Php, Lang::Ruby] {
            let slice = payloads_for_lang(Cap::DESERIALIZE, lang);
            let vuln = slice
                .iter()
                .find(|p| !p.is_benign)
                .expect("each lang must have a vuln payload");
            let resolved = super::resolve_benign_control_lang(vuln, Cap::DESERIALIZE, lang)
                .expect("lang-aware benign control must resolve");
            assert!(resolved.is_benign);
        }
    }
}
