//! Phase XXE integration tests for `Cap::XXE`.
//!
//! Fixtures under `tests/fixtures/xxe/<lang>/`:
//!
//! * `unsafe_xxe.*` — taint flows from a request source into a parser
//!   entry point that resolves external entities (Java DocumentBuilder,
//!   Python `xml.sax.parseString`, PHP `simplexml_load_string` with
//!   `LIBXML_NOENT`, JS `xml2js.parseString` with `processEntities: true`,
//!   Ruby `REXML::Document.new`).  Must produce >=1 `taint-xxe` finding.
//! * `safe_xxe.*` — same flow routed through a hardened API
//!   (defusedxml, default-options `simplexml_load_string`, etc.).
//!   Must produce 0 findings.
//!
//! Layer 2 (config-check pattern via abstract-interp) is deferred — see
//! `.pitboss/play/deferred.md`.

mod common;

use common::count_by_prefix;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::{AnalysisMode, Config};
use std::path::{Path, PathBuf};

const RULE_PREFIX: &str = "taint-xxe";

fn fixture_dir(lang: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("xxe")
        .join(lang)
}

fn test_config() -> Config {
    let mut cfg = Config::default();
    cfg.scanner.mode = AnalysisMode::Full;
    cfg.scanner.read_vcsignore = false;
    cfg.scanner.require_git_to_read_vcsignore = false;
    cfg.scanner.enable_state_analysis = true;
    cfg.scanner.enable_auth_analysis = true;
    cfg.scanner.include_nonprod = true;
    cfg.performance.worker_threads = Some(1);
    cfg.performance.batch_size = 64;
    cfg.performance.channel_multiplier = 1;
    cfg
}

fn scan_dir(path: &Path) -> Vec<Diag> {
    nyx_scanner::scan_no_index(path, &test_config()).expect("scan_no_index should succeed")
}

fn diags_for_file(dir: &Path, file_suffix: &str) -> Vec<Diag> {
    scan_dir(dir)
        .into_iter()
        .filter(|d| {
            std::path::Path::new(&d.path)
                .file_name()
                .and_then(|s| s.to_str())
                == Some(file_suffix)
        })
        .collect()
}

fn assert_unsafe(lang: &str, file_suffix: &str) {
    let dir = fixture_dir(lang);
    let diags = diags_for_file(&dir, file_suffix);
    let count = count_by_prefix(&diags, RULE_PREFIX);
    assert!(
        count >= 1,
        "{lang}/{file_suffix}: expected >=1 {RULE_PREFIX} finding, got {count}.\n\
         All diags: {:#?}",
        diags
            .iter()
            .map(|d| format!(
                "{}:{} [{}] {}",
                d.path,
                d.line,
                d.severity.as_db_str(),
                d.id
            ))
            .collect::<Vec<_>>(),
    );
}

fn assert_clean(lang: &str, file_suffix: &str) {
    let dir = fixture_dir(lang);
    let diags = diags_for_file(&dir, file_suffix);
    let matching: Vec<_> = diags
        .iter()
        .filter(|d| d.id.starts_with(RULE_PREFIX))
        .collect();
    assert!(
        matching.is_empty(),
        "{lang}/{file_suffix}: expected 0 {RULE_PREFIX} findings, got {}:\n{:#?}",
        matching.len(),
        matching
            .iter()
            .map(|d| format!("{}:{} {}", d.path, d.line, d.id))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn java_document_builder_parse_with_tainted_xml_fires() {
    assert_unsafe("java", "UnsafeXxe.java");
}

#[test]
fn java_no_xml_parser_clean() {
    assert_clean("java", "SafeXxe.java");
}

/// Phase 07 acceptance: a `factory.setFeature(FEATURE_SECURE_PROCESSING,
/// true)` before `builder.parse(...)` produces zero `taint-xxe`
/// findings.  The hardening fact is recorded on the factory's SSA
/// value, propagated to the builder via `newDocumentBuilder()`, and
/// consulted at the parse sink.
#[test]
fn java_set_feature_secure_processing_clean() {
    assert_clean("java", "SafeXxeConfig.java");
}

/// Phase 07 acceptance: parser variable reassigned across two branches
/// that both harden the receiver — the SSA phi-meet preserves
/// `secure_processing = true`, and the downstream parse sink stays
/// silent.
#[test]
fn java_phi_reassigned_factory_clean() {
    assert_clean("java", "SafeXxePhi.java");
}

/// Baseline: tainted body wrapped in a string concat, no XML parser
/// entry point.  `taint-xxe` must not surface from XML-adjacent string
/// operations.
#[test]
fn java_irrelevant_xml_call_clean() {
    assert_clean("java", "IrrelevantXmlCall.java");
}

/// Log4Shell XXE-leg shape (CVE-2022-23305 / CVE-2022-23307 lineage):
/// DOMConfigurator-style loader takes an XML config path from the
/// request, parses through an unhardened `DocumentBuilder`.  Exercises
/// the TypeFacts-tagged builder receiver + xml_config sidecar end-to-end.
#[test]
fn java_log4j_config_loader_with_tainted_path_fires() {
    assert_unsafe("java", "UnsafeLog4jConfig.java");
}

/// Log4Shell XXE-leg hardened: same DOMConfigurator-style loader but
/// `factory.setFeature(FEATURE_SECURE_PROCESSING, true)` and
/// `disallow-doctype-decl` precede the `newDocumentBuilder()` call.
/// xml_config sidecar propagates the hardening fact to the builder so
/// the parse sink suppresses the XXE bit.
#[test]
fn java_log4j_config_loader_secure_processing_clean() {
    assert_clean("java", "SafeLog4jConfig.java");
}

#[test]
fn python_sax_parse_with_tainted_xml_fires() {
    assert_unsafe("python", "unsafe_xxe.py");
}

#[test]
fn python_lxml_resolve_entities_fires() {
    assert_unsafe("python", "unsafe_lxml_resolve_entities.py");
}

#[test]
fn python_defusedxml_sanitizes() {
    assert_clean("python", "safe_xxe.py");
}

/// Phase 07 acceptance: `lxml.etree.parse` is XXE-safe by default in
/// modern lxml (external entity resolution requires explicit
/// `XMLParser(resolve_entities=True)`).  No `taint-xxe` finding.
#[test]
fn python_lxml_default_clean() {
    assert_clean("python", "safe_lxml.py");
}

#[test]
fn python_irrelevant_xml_call_clean() {
    assert_clean("python", "irrelevant_xml_call.py");
}

#[test]
fn php_simplexml_load_string_with_noent_fires() {
    assert_unsafe("php", "unsafe_xxe.php");
}

#[test]
fn php_simplexml_load_string_default_options_clean() {
    assert_clean("php", "safe_xxe.php");
}

#[test]
fn php_irrelevant_xml_call_clean() {
    assert_clean("php", "irrelevant_xml_call.php");
}

#[test]
fn javascript_xml2js_with_process_entities_fires() {
    assert_unsafe("javascript", "unsafe_xxe.js");
}

#[test]
fn javascript_xml2js_default_options_clean() {
    assert_clean("javascript", "safe_xxe.js");
}

#[test]
fn javascript_fast_xml_parser_with_process_entities_fires() {
    assert_unsafe("javascript", "unsafe_fast_xml_parser.js");
}

#[test]
fn javascript_irrelevant_xml_call_clean() {
    assert_clean("javascript", "irrelevant_xml_call.js");
}

#[test]
fn typescript_xml2js_with_process_entities_fires() {
    assert_unsafe("typescript", "unsafe_xxe.ts");
}

#[test]
fn typescript_xml2js_default_options_clean() {
    assert_clean("typescript", "safe_xxe.ts");
}

#[test]
fn typescript_fast_xml_parser_with_process_entities_fires() {
    assert_unsafe("typescript", "unsafe_fast_xml_parser.ts");
}

#[test]
fn typescript_irrelevant_xml_call_clean() {
    assert_clean("typescript", "irrelevant_xml_call.ts");
}

#[test]
fn ruby_rexml_document_with_tainted_xml_fires() {
    assert_unsafe("ruby", "unsafe_xxe.rb");
}

#[test]
fn ruby_nokogiri_xml_with_noent_fires() {
    assert_unsafe("ruby", "unsafe_xxe_nokogiri.rb");
}

#[test]
fn ruby_nokogiri_xml_default_options_clean() {
    assert_clean("ruby", "safe_xxe_nokogiri.rb");
}

#[test]
fn ruby_irrelevant_xml_call_clean() {
    assert_clean("ruby", "irrelevant_xml_call.rb");
}
