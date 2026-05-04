//! Pattern sanity tests and positive/negative fixture validation.
//!
//! These tests verify that:
//! 1. All pattern IDs are globally unique.
//! 2. All tree-sitter queries compile without error.
//! 3. All patterns have non-empty descriptions and valid severity/tier/category.
//! 4. Positive fixtures trigger expected patterns.
//! 5. Negative fixtures do NOT trigger security patterns.

use nyx_scanner::patterns::{self, PatternTier, Severity};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tree_sitter::{Language, Query, QueryCursor, StreamingIterator};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn fixture_path(lang: &str, kind: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/patterns")
        .join(lang)
        .join(kind)
}

fn ts_lang_for(slug: &str) -> Language {
    match slug {
        "rust" => Language::from(tree_sitter_rust::LANGUAGE),
        "java" => Language::from(tree_sitter_java::LANGUAGE),
        "python" => Language::from(tree_sitter_python::LANGUAGE),
        "javascript" => Language::from(tree_sitter_javascript::LANGUAGE),
        "typescript" => Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        "c" => Language::from(tree_sitter_c::LANGUAGE),
        "cpp" => Language::from(tree_sitter_cpp::LANGUAGE),
        "go" => Language::from(tree_sitter_go::LANGUAGE),
        "php" => Language::from(tree_sitter_php::LANGUAGE_PHP),
        "ruby" => Language::from(tree_sitter_ruby::LANGUAGE),
        _ => panic!("unknown language: {slug}"),
    }
}

/// Run all patterns for a language against source bytes.
/// Returns the set of pattern IDs that matched at least once.
fn run_patterns(slug: &str, source: &[u8]) -> HashSet<String> {
    let ts_lang = ts_lang_for(slug);
    let pats = patterns::load(slug);
    let mut matched = HashSet::new();

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_lang).expect("set language");
    let tree = parser.parse(source, None).expect("parse");
    let root = tree.root_node();

    for pat in &pats {
        let query = match Query::new(&ts_lang, pat.query) {
            Ok(q) => q,
            Err(_) => continue,
        };
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source);
        if matches.next().is_some() {
            matched.insert(pat.id.to_string());
        }
    }

    matched
}

// ── All languages for iteration ──────────────────────────────────────────────

const ALL_LANGS: &[&str] = &[
    "rust",
    "java",
    "python",
    "javascript",
    "typescript",
    "c",
    "cpp",
    "go",
    "php",
    "ruby",
];

// ── Sanity tests ─────────────────────────────────────────────────────────────

#[test]
fn all_pattern_ids_are_globally_unique() {
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut dupes = Vec::new();

    for &lang in ALL_LANGS {
        for pat in patterns::load(lang) {
            if let Some(prev_lang) = seen.insert(pat.id.to_string(), lang.to_string()) {
                // Same lang alias is ok (e.g. "js" and "javascript" share patterns)
                if prev_lang != lang {
                    dupes.push(format!("{} (in {} and {})", pat.id, prev_lang, lang));
                }
            }
        }
    }

    assert!(
        dupes.is_empty(),
        "Duplicate pattern IDs across languages:\n  {}",
        dupes.join("\n  ")
    );
}

#[test]
fn all_queries_compile() {
    let mut errors = Vec::new();

    for &lang in ALL_LANGS {
        let ts_lang = ts_lang_for(lang);
        for pat in patterns::load(lang) {
            if let Err(e) = Query::new(&ts_lang, pat.query) {
                errors.push(format!("[{}] {}: {}", lang, pat.id, e));
            }
        }
    }

    assert!(
        errors.is_empty(),
        "Pattern query compilation errors:\n  {}",
        errors.join("\n  ")
    );
}

#[test]
fn all_descriptions_non_empty() {
    for &lang in ALL_LANGS {
        for pat in patterns::load(lang) {
            assert!(
                !pat.description.trim().is_empty(),
                "Pattern {} has empty description",
                pat.id
            );
        }
    }
}

#[test]
fn all_ids_follow_naming_convention() {
    // IDs should be <lang>.<category>.<specific> with dots
    for &lang in ALL_LANGS {
        for pat in patterns::load(lang) {
            let parts: Vec<&str> = pat.id.split('.').collect();
            assert!(
                parts.len() == 3,
                "Pattern ID '{}' should have 3 dot-separated parts (lang.category.specific), got {}",
                pat.id,
                parts.len()
            );
            // First part should be a short lang prefix
            assert!(
                parts[0].len() <= 4,
                "Pattern ID '{}' language prefix '{}' too long (max 4 chars)",
                pat.id,
                parts[0]
            );
        }
    }
}

#[test]
fn severity_distribution_reasonable() {
    // Sanity: no language should have ALL patterns at the same severity
    for &lang in ALL_LANGS {
        let pats = patterns::load(lang);
        if pats.len() < 3 {
            continue;
        }
        let severities: HashSet<_> = pats.iter().map(|p| p.severity).collect();
        // At least 2 different severity levels if >= 5 patterns
        if pats.len() >= 5 {
            assert!(
                severities.len() >= 2,
                "{} has {} patterns but only 1 severity level",
                lang,
                pats.len()
            );
        }
    }
}

#[test]
fn tier_a_patterns_have_no_heuristic_in_description() {
    // Tier A patterns should not reference "concatenation" or "format" heuristics
    // (that's Tier B territory). This is a soft check.
    let heuristic_words = ["concatenat", "non-literal", "heuristic"];
    let mut violations = Vec::new();

    for &lang in ALL_LANGS {
        for pat in patterns::load(lang) {
            if pat.tier == PatternTier::A {
                let desc_lower = pat.description.to_lowercase();
                for word in &heuristic_words {
                    if desc_lower.contains(word) {
                        violations.push(format!(
                            "{}: Tier A but description mentions '{}'",
                            pat.id, word
                        ));
                    }
                }
            }
        }
    }

    // Warn but don't fail, descriptions are informational
    if !violations.is_empty() {
        eprintln!(
            "WARNING: Tier A patterns with heuristic-like descriptions:\n  {}",
            violations.join("\n  ")
        );
    }
}

// ── Positive fixture tests ───────────────────────────────────────────────────
// Each test verifies that the positive fixture triggers at least the listed IDs.

fn assert_positive_match(lang: &str, fixture_file: &str, expected_ids: &[&str]) {
    let path = fixture_path(lang, fixture_file);
    if !path.exists() {
        eprintln!("SKIP: fixture not found: {}", path.display());
        return;
    }
    let source = std::fs::read(&path).expect("read fixture");
    let matched = run_patterns(lang, &source);

    let mut missing = Vec::new();
    for &id in expected_ids {
        if !matched.contains(id) {
            missing.push(id);
        }
    }

    assert!(
        missing.is_empty(),
        "[{}] Positive fixture '{}' did not trigger expected patterns:\n  missing: {:?}\n  matched: {:?}",
        lang,
        fixture_file,
        missing,
        matched
    );
}

#[test]
fn positive_rust() {
    assert_positive_match(
        "rust",
        "positive.rs",
        &[
            "rs.memory.transmute",
            "rs.memory.copy_nonoverlapping",
            "rs.memory.get_unchecked",
            "rs.memory.mem_zeroed",
            "rs.memory.ptr_read",
            "rs.quality.unsafe_block",
            "rs.quality.unsafe_fn",
            "rs.quality.unwrap",
            "rs.quality.expect",
            "rs.quality.panic_macro",
            "rs.quality.todo",
            "rs.memory.narrow_cast",
            "rs.memory.mem_forget",
        ],
    );
}

#[test]
fn positive_java() {
    assert_positive_match(
        "java",
        "positive.java",
        &[
            "java.deser.readobject",
            "java.cmdi.runtime_exec",
            "java.reflection.class_forname",
            "java.reflection.method_invoke",
            "java.sqli.execute_concat",
            "java.crypto.insecure_random",
            // CVE-2022-1471 SnakeYAML / CVE-2022-42889 Text4Shell.
            "java.deser.snakeyaml_unsafe_constructor",
            "java.code_exec.text4shell_interpolator",
        ],
    );
}

#[test]
fn positive_python() {
    assert_positive_match(
        "python",
        "positive.py",
        &[
            "py.code_exec.eval",
            "py.code_exec.exec",
            "py.cmdi.os_system",
            "py.cmdi.os_popen",
            "py.deser.pickle_loads",
            "py.deser.yaml_load",
            // CVE-2025-69662 / CVE-2025-24793 motivated f-string SQLi.
            // py.sqli.execute_format must fire on the f-string shape and
            // py.sqli.text_format must fire on the SQLAlchemy text() shape.
            "py.sqli.execute_format",
            "py.sqli.text_format",
            // CVE-2023-6568 (mlflow) reflected XSS via make_response f-string;
            // also catches the `+`-concat shape in xss_reflected.py.
            "py.xss.make_response_format",
        ],
    );
}

#[test]
fn positive_javascript() {
    assert_positive_match(
        "javascript",
        "positive.js",
        &[
            "js.code_exec.eval",
            "js.code_exec.new_function",
            "js.code_exec.settimeout_string",
            "js.xss.document_write",
            "js.xss.outer_html",
            "js.xss.insert_adjacent_html",
            "js.prototype.proto_assignment",
            "js.secrets.hardcoded_secret",
            "js.crypto.weak_hash",
            "js.crypto.weak_hash_import",
            "js.xss.cookie_write",
            "js.config.reject_unauthorized",
            "js.secrets.fallback_secret",
            "js.config.verbose_error_response",
            "js.config.cors_dynamic_origin",
        ],
    );
}

#[test]
fn positive_typescript() {
    assert_positive_match(
        "typescript",
        "positive.ts",
        &[
            "ts.code_exec.eval",
            "ts.code_exec.new_function",
            "ts.code_exec.settimeout_string",
            "ts.xss.document_write",
            "ts.xss.outer_html",
            "ts.xss.insert_adjacent_html",
            "ts.quality.any_annotation",
            "ts.quality.as_any",
            "ts.prototype.proto_assignment",
            "ts.secrets.hardcoded_secret",
            "ts.crypto.weak_hash",
            "ts.crypto.weak_hash_import",
            "ts.xss.cookie_write",
            "ts.config.reject_unauthorized",
            "ts.secrets.fallback_secret",
            "ts.config.verbose_error_response",
            "ts.config.cors_dynamic_origin",
        ],
    );
}

#[test]
fn positive_c() {
    assert_positive_match(
        "c",
        "positive.c",
        &[
            "c.memory.gets",
            "c.memory.strcpy",
            "c.memory.strcat",
            "c.memory.sprintf",
            "c.memory.scanf_percent_s",
            "c.cmdi.system",
            "c.cmdi.popen",
            "c.memory.printf_no_fmt",
        ],
    );
}

#[test]
fn positive_cpp() {
    assert_positive_match(
        "cpp",
        "positive.cpp",
        &[
            "cpp.memory.gets",
            "cpp.memory.strcpy",
            "cpp.memory.strcat",
            "cpp.memory.sprintf",
            "cpp.cmdi.system",
            "cpp.memory.reinterpret_cast",
            "cpp.memory.const_cast",
            "cpp.memory.printf_no_fmt",
        ],
    );
}

#[test]
fn positive_go() {
    assert_positive_match(
        "go",
        "positive.go",
        &["go.cmdi.exec_command", "go.crypto.md5", "go.crypto.sha1"],
    );
}

#[test]
fn positive_php() {
    assert_positive_match(
        "php",
        "positive.php",
        &[
            "php.code_exec.eval",
            "php.code_exec.create_function",
            "php.cmdi.system",
            "php.deser.unserialize",
        ],
    );
}

#[test]
fn positive_ruby() {
    assert_positive_match(
        "ruby",
        "positive.rb",
        &[
            "rb.code_exec.eval",
            "rb.code_exec.instance_eval",
            "rb.code_exec.class_eval",
            "rb.cmdi.backtick",
            "rb.deser.yaml_load",
            "rb.deser.marshal_load",
            "rb.reflection.constantize",
        ],
    );
}

// ── Negative fixture tests ───────────────────────────────────────────────────
// Negative fixtures should produce zero matches for High/Medium security patterns.

fn get_security_pattern_ids(lang: &str) -> HashSet<String> {
    patterns::load(lang)
        .into_iter()
        .filter(|p| {
            p.severity != Severity::Low
                && !matches!(
                    p.category,
                    nyx_scanner::patterns::PatternCategory::CodeQuality
                )
        })
        .map(|p| p.id.to_string())
        .collect()
}

fn assert_negative_no_security_match(lang: &str, fixture_file: &str) {
    let path = fixture_path(lang, fixture_file);
    if !path.exists() {
        eprintln!("SKIP: fixture not found: {}", path.display());
        return;
    }
    let source = std::fs::read(&path).expect("read fixture");
    let matched = run_patterns(lang, &source);
    let security_ids = get_security_pattern_ids(lang);

    let false_positives: Vec<_> = matched.intersection(&security_ids).collect();

    assert!(
        false_positives.is_empty(),
        "[{}] Negative fixture '{}' triggered security patterns (false positives):\n  {:?}",
        lang,
        fixture_file,
        false_positives
    );
}

#[test]
fn negative_rust() {
    assert_negative_no_security_match("rust", "negative.rs");
}

#[test]
fn negative_java() {
    assert_negative_no_security_match("java", "negative.java");
}

#[test]
fn negative_python() {
    assert_negative_no_security_match("python", "negative.py");
}

#[test]
fn negative_javascript() {
    assert_negative_no_security_match("javascript", "negative.js");
}

#[test]
fn negative_typescript() {
    assert_negative_no_security_match("typescript", "negative.ts");
}

#[test]
fn negative_c() {
    assert_negative_no_security_match("c", "negative.c");
}

#[test]
fn negative_cpp() {
    assert_negative_no_security_match("cpp", "negative.cpp");
}

#[test]
fn negative_go() {
    assert_negative_no_security_match("go", "negative.go");
}

#[test]
fn negative_php() {
    assert_negative_no_security_match("php", "negative.php");
}

#[test]
fn negative_ruby() {
    assert_negative_no_security_match("ruby", "negative.rb");
}
