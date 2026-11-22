//! Real-world vulnerability fixture test suite.
//!
//! Scans realistic code snippets (20–120 lines) across all 10 supported languages
//! and compares findings against `.expect.json` expectation files.
//!
//! # Environment Variables
//!
//! - `NYX_TEST_LANG=python`    , run only fixtures for one language
//! - `NYX_TEST_FIXTURE=cmdi_subprocess`, run only fixtures whose name contains this string
//! - `NYX_TEST_VERBOSE=1`      , print full diff details for every fixture
//! - `NYX_TEST_CATEGORY=taint` , run only one category (taint/cfg/state/mixed/safe/auth)
//!
//! # Known-failure handling
//!
//! Expectations with `"must_match": false` are tracked but do not cause test failure.
//! A summary of soft misses is always printed at the end.

mod common;

use common::test_config;
use nyx_scanner::commands::scan::Diag;
use nyx_scanner::utils::config::AnalysisMode;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ── Expectation schema ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct RealWorldExpectations {
    /// Human description of what this fixture tests.
    #[serde(default)]
    description: String,
    /// Tags for coverage matrix (e.g. ["taint", "cmdi", "express"]).
    #[serde(default)]
    tags: Vec<String>,
    /// Which analysis modes this fixture targets.
    #[serde(default = "default_modes")]
    modes: Vec<String>,
    /// Rule-id prefixes whose unexpected findings promote from
    /// informational to hard failure. A diag is "unexpected" if it is
    /// not consumed by any `expected` entry; if its `id` starts with any
    /// prefix here, the suite fails. Default empty → all extras remain
    /// informational (pre-existing behavior).
    ///
    /// Use this to lock in precision for fixtures whose expected set is
    /// exhaustive for a given rule family. Typical value:
    /// `["taint-unsanitised-flow"]`, any extra taint flow is a
    /// precision regression. AST-pattern families (`*.code_exec.*`,
    /// `*.quality.*`) are intentionally excluded by default since they
    /// fire syntactically and bystander triggers aren't precision drift.
    #[serde(default)]
    strict_unexpected: Vec<String>,
    /// Expected findings.
    expected: Vec<ExpectedFinding>,
}

fn default_modes() -> Vec<String> {
    vec!["full".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
struct ExpectedFinding {
    /// Rule ID substring to match (e.g. "taint-" or "js.xss.innerhtml").
    rule_id: String,
    /// Severity (optional, not checked if absent).
    #[serde(default)]
    severity: Option<String>,
    /// If true, missing this finding is a hard failure. If false, it's a soft miss.
    #[serde(default = "default_must_match")]
    must_match: bool,
    /// If true, presence of a matching finding is a hard failure (regression guard).
    /// Overrides `must_match`. Useful for locking in FP suppressions, sanitizer
    /// wrappers, gated sinks, field-aware absence, Layer-B suppressions, etc.
    #[serde(default)]
    must_not_match: bool,
    /// Line number or range [start, end] where finding should appear.
    #[serde(default)]
    line_range: Option<(usize, usize)>,
    /// Substrings that must appear in message or evidence fields.
    #[serde(default)]
    evidence_contains: Vec<String>,
    /// Human explanation of this expectation.
    #[serde(default)]
    notes: String,
    /// Optional per-expectation mode filter.  When absent, the expectation
    /// applies in every mode listed at the fixture level.  When present,
    /// only the listed modes evaluate this expectation, useful when a
    /// finding is mode-specific (e.g. a taint flow only resolves in `full`
    /// mode while the fixture also runs in `ast` mode for AST-pattern
    /// coverage).
    #[serde(default)]
    modes: Option<Vec<String>>,
    /// Upper bound on matching diags. When set, the count of diags that
    /// match this expectation's filters (rule_id / severity / line_range /
    /// evidence_contains) must not exceed this value. Composes with
    /// `must_match: true`, a `must_match: true, max_count: 1` expectation
    /// means "exactly one matching finding must exist". Mutually exclusive
    /// with `must_not_match: true`; the combination is rejected at parse
    /// time.
    #[serde(default)]
    max_count: Option<usize>,
}

fn default_must_match() -> bool {
    true
}

// ── Fixture discovery ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Fixture {
    /// Language slug (rust, c, cpp, java, go, php, python, ruby, typescript, javascript).
    lang: String,
    /// Category (taint, cfg, state, mixed, safe).
    category: String,
    /// Fixture name (stem of source file).
    name: String,
    /// Path to the source fixture file.
    source_path: PathBuf,
    /// Parsed expectations.
    expectations: RealWorldExpectations,
}

fn discover_fixtures() -> Vec<Fixture> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real_world");
    let mut fixtures = Vec::new();

    let langs = [
        "rust",
        "c",
        "cpp",
        "java",
        "go",
        "php",
        "python",
        "ruby",
        "typescript",
        "javascript",
    ];
    let categories = ["taint", "cfg", "state", "mixed", "safe", "auth"];

    for lang in &langs {
        for category in &categories {
            let dir = base.join(lang).join(category);
            if !dir.is_dir() {
                continue;
            }

            // Find all .expect.json files, derive source file from them.
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let fname = path.file_name().unwrap().to_string_lossy().to_string();
                if !fname.ends_with(".expect.json") {
                    continue;
                }

                let stem = fname.trim_end_matches(".expect.json");

                // Find the corresponding source file (any extension).
                let source_path = find_source_file(&dir, stem);
                let Some(source_path) = source_path else {
                    eprintln!(
                        "WARN: no source file for {}/{}/{}/{}",
                        lang, category, stem, fname
                    );
                    continue;
                };

                let expect_content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                    panic!("Failed to read {}: {e}", path.display());
                });
                let expectations: RealWorldExpectations = serde_json::from_str(&expect_content)
                    .unwrap_or_else(|e| {
                        panic!("Failed to parse {}: {e}", path.display());
                    });

                fixtures.push(Fixture {
                    lang: lang.to_string(),
                    category: category.to_string(),
                    name: stem.to_string(),
                    source_path,
                    expectations,
                });
            }
        }
    }

    // Sort for deterministic ordering.
    fixtures.sort_by(|a, b| {
        a.lang
            .cmp(&b.lang)
            .then(a.category.cmp(&b.category))
            .then(a.name.cmp(&b.name))
    });

    fixtures
}

fn find_source_file(dir: &Path, stem: &str) -> Option<PathBuf> {
    let extensions = [
        "rs", "c", "cpp", "cc", "cxx", "java", "go", "php", "py", "rb", "ts", "tsx", "js", "jsx",
    ];
    for ext in &extensions {
        let candidate = dir.join(format!("{stem}.{ext}"));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// ── Scanning ─────────────────────────────────────────────────────────────────

fn scan_fixture(fixture: &Fixture, mode: AnalysisMode) -> Vec<Diag> {
    // We scan the parent directory containing just this fixture file.
    // To isolate, we copy the fixture to a temp dir.
    let tmp = tempfile::TempDir::with_prefix("nyx_rw_test_").expect("tempdir");
    let dest = tmp.path().join(fixture.source_path.file_name().unwrap());
    std::fs::copy(&fixture.source_path, &dest).expect("copy fixture");

    let cfg = test_config(mode);
    let mut diags =
        nyx_scanner::scan_no_index(tmp.path(), &cfg).expect("scan_no_index should succeed");

    // Normalize paths to just the filename for comparison.
    for d in &mut diags {
        if let Some(fname) = Path::new(&d.path).file_name() {
            d.path = fname.to_string_lossy().to_string();
        }
    }

    // Sort deterministically.
    diags.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.line.cmp(&b.line))
            .then(a.id.cmp(&b.id))
            .then(a.col.cmp(&b.col))
    });

    diags
}

// ── Matching ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct MatchResult {
    hard_misses: Vec<(ExpectedFinding, String)>,
    soft_misses: Vec<(ExpectedFinding, String)>,
    forbidden_violations: Vec<(ExpectedFinding, Diag)>,
    count_violations: Vec<(ExpectedFinding, usize)>,
    unexpected: Vec<Diag>,
    /// Subset of `unexpected` whose rule-id matched a `strict_unexpected`
    /// prefix for this fixture, these cause hard failure.
    strict_unexpected: Vec<Diag>,
    matched: usize,
}

fn diag_matches_expectation(d: &Diag, exp: &ExpectedFinding, fixture_file: &str) -> bool {
    if !d.id.contains(&exp.rule_id) {
        return false;
    }
    if !d.path.contains(fixture_file) && fixture_file != d.path {
        return false;
    }
    if let Some(ref sev) = exp.severity
        && d.severity.as_db_str() != sev.to_uppercase()
    {
        return false;
    }
    if let Some((start, end)) = exp.line_range
        && (d.line < start || d.line > end)
    {
        return false;
    }
    for substr in &exp.evidence_contains {
        let msg = d.message.as_deref().unwrap_or("");
        let ev_text = if let Some(ev) = &d.evidence {
            let mut parts = Vec::new();
            if let Some(src) = &ev.source {
                parts.push(format!(
                    "source: {}",
                    src.snippet.as_deref().unwrap_or(&src.kind)
                ));
            }
            if let Some(snk) = &ev.sink {
                parts.push(format!(
                    "sink: {}",
                    snk.snippet.as_deref().unwrap_or(&snk.kind)
                ));
            }
            for note in &ev.notes {
                parts.push(note.clone());
            }
            if let Some(ref sym) = ev.symbolic
                && let Some(ref w) = sym.witness
            {
                parts.push(w.clone());
            }
            parts.join(" ")
        } else {
            String::new()
        };
        let combined = format!("{msg} {ev_text}");
        if !combined.to_lowercase().contains(&substr.to_lowercase()) {
            return false;
        }
    }
    true
}

fn match_expectations(
    diags: &[Diag],
    expectations: &[ExpectedFinding],
    fixture_file: &str,
    active_mode: &str,
    strict_prefixes: &[String],
) -> MatchResult {
    let mut hard_misses = Vec::new();
    let mut soft_misses = Vec::new();
    let mut forbidden_violations = Vec::new();
    let mut count_violations: Vec<(ExpectedFinding, usize)> = Vec::new();
    let mut matched_indices: Vec<bool> = vec![false; diags.len()];
    let mut matched = 0;

    for exp in expectations {
        if let Some(ref m) = exp.modes
            && !m.iter().any(|s| s.eq_ignore_ascii_case(active_mode))
        {
            continue;
        }

        // must_not_match wins over any other assertion combo.
        if exp.must_not_match {
            // Forbidden-finding assertion: non-consuming scan for any matching diag.
            // Presence = hard failure (regression guard).
            for d in diags {
                if diag_matches_expectation(d, exp, fixture_file) {
                    forbidden_violations.push((exp.clone(), d.clone()));
                }
            }
            continue;
        }

        // When max_count is set, count all diags matching the expectation's
        // filter (regardless of prior consumption) and validate against the
        // cap. Then consume the first unmatched matching diag like the
        // normal path so later expectations still see the rest.
        if let Some(cap) = exp.max_count {
            let total_matches = diags
                .iter()
                .filter(|d| diag_matches_expectation(d, exp, fixture_file))
                .count();
            if total_matches > cap {
                count_violations.push((exp.clone(), total_matches));
            }

            let mut found_idx: Option<usize> = None;
            for (i, d) in diags.iter().enumerate() {
                if matched_indices[i] {
                    continue;
                }
                if diag_matches_expectation(d, exp, fixture_file) {
                    found_idx = Some(i);
                    break;
                }
            }
            if let Some(i) = found_idx {
                matched_indices[i] = true;
                matched += 1;
            } else if exp.must_match {
                hard_misses.push((
                    exp.clone(),
                    format!(
                        "rule_id='{}' severity={:?} line_range={:?} max_count={}",
                        exp.rule_id, exp.severity, exp.line_range, cap
                    ),
                ));
            }
            continue;
        }

        let mut found_idx: Option<usize> = None;
        for (i, d) in diags.iter().enumerate() {
            if matched_indices[i] {
                continue;
            }
            if diag_matches_expectation(d, exp, fixture_file) {
                found_idx = Some(i);
                break;
            }
        }

        if let Some(i) = found_idx {
            matched_indices[i] = true;
            matched += 1;
        } else {
            let reason = format!(
                "rule_id='{}' severity={:?} line_range={:?}",
                exp.rule_id, exp.severity, exp.line_range
            );
            if exp.must_match {
                hard_misses.push((exp.clone(), reason));
            } else {
                soft_misses.push((exp.clone(), reason));
            }
        }
    }

    // Unexpected = diags not matched by any expectation. Informational by
    // default; promoted to hard-failure if the fixture's `strict_unexpected`
    // list contains a prefix of the diag's rule-id.
    let unexpected: Vec<Diag> = diags
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_indices[*i])
        .map(|(_, d)| d.clone())
        .collect();

    let strict_unexpected: Vec<Diag> = if strict_prefixes.is_empty() {
        Vec::new()
    } else {
        unexpected
            .iter()
            .filter(|d| strict_prefixes.iter().any(|p| d.id.starts_with(p)))
            .cloned()
            .collect()
    };

    MatchResult {
        hard_misses,
        soft_misses,
        forbidden_violations,
        count_violations,
        unexpected,
        strict_unexpected,
        matched,
    }
}

// ── Mode resolution ──────────────────────────────────────────────────────────

fn resolve_mode(mode_str: &str) -> AnalysisMode {
    match mode_str.to_lowercase().as_str() {
        "ast" => AnalysisMode::Ast,
        "cfg" => AnalysisMode::Cfg,
        "taint" => AnalysisMode::Taint,
        "full" => AnalysisMode::Full,
        _ => AnalysisMode::Full,
    }
}

// ── Coverage matrix ──────────────────────────────────────────────────────────

fn print_coverage_matrix(fixtures: &[Fixture]) {
    let mut matrix: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut tag_counts: BTreeMap<String, usize> = BTreeMap::new();

    for f in fixtures {
        *matrix
            .entry(f.lang.clone())
            .or_default()
            .entry(f.category.clone())
            .or_default() += 1;
        for tag in &f.expectations.tags {
            *tag_counts.entry(tag.clone()).or_default() += 1;
        }
    }

    eprintln!("\n╔══════════════════════════════════════════════════════════╗");
    eprintln!("║           REAL-WORLD TEST COVERAGE MATRIX               ║");
    eprintln!("╠══════════════╦════════╦══════╦════════╦════════╦════════╣");
    eprintln!("║ Language     ║ Taint  ║ CFG  ║ State  ║ Mixed  ║ Total  ║");
    eprintln!("╠══════════════╬════════╬══════╬════════╬════════╬════════╣");

    let mut grand_total = 0;
    for (lang, cats) in &matrix {
        let t = cats.get("taint").unwrap_or(&0);
        let c = cats.get("cfg").unwrap_or(&0);
        let s = cats.get("state").unwrap_or(&0);
        let m = cats.get("mixed").unwrap_or(&0);
        let total = t + c + s + m;
        grand_total += total;
        eprintln!(
            "║ {:<12} ║ {:>4}   ║ {:>3}  ║ {:>4}   ║ {:>4}   ║ {:>4}   ║",
            lang, t, c, s, m, total
        );
    }
    eprintln!("╠══════════════╬════════╬══════╬════════╬════════╬════════╣");
    eprintln!(
        "║ TOTAL        ║        ║      ║        ║        ║ {:>4}   ║",
        grand_total
    );
    eprintln!("╚══════════════╩════════╩══════╩════════╩════════╩════════╝");

    if !tag_counts.is_empty() {
        eprintln!("\nTag distribution:");
        for (tag, count) in &tag_counts {
            eprintln!("  {tag}: {count}");
        }
    }
}

// ── Main test ────────────────────────────────────────────────────────────────

static ALL_FIXTURES: OnceLock<Vec<Fixture>> = OnceLock::new();

fn get_fixtures() -> &'static [Fixture] {
    ALL_FIXTURES.get_or_init(discover_fixtures)
}

fn should_run(fixture: &Fixture) -> bool {
    if let Ok(lang) = std::env::var("NYX_TEST_LANG")
        && !fixture.lang.eq_ignore_ascii_case(&lang)
    {
        return false;
    }
    if let Ok(name) = std::env::var("NYX_TEST_FIXTURE")
        && !fixture.name.contains(&name)
    {
        return false;
    }
    if let Ok(cat) = std::env::var("NYX_TEST_CATEGORY")
        && !fixture.category.eq_ignore_ascii_case(&cat)
    {
        return false;
    }
    true
}

fn is_verbose() -> bool {
    std::env::var("NYX_TEST_VERBOSE").is_ok()
}

#[test]
fn real_world_fixture_suite() {
    let fixtures = get_fixtures();
    let verbose = is_verbose();

    let active: Vec<&Fixture> = fixtures.iter().filter(|f| should_run(f)).collect();

    if active.is_empty() {
        eprintln!(
            "No fixtures matched filters. Total available: {}",
            fixtures.len()
        );
        print_coverage_matrix(fixtures);
        return;
    }

    eprintln!(
        "\nRunning {} real-world fixtures (of {} total)\n",
        active.len(),
        fixtures.len()
    );

    let mut total_hard_fails = 0;
    let mut total_soft_misses = 0;
    let mut total_forbidden = 0;
    let mut total_count_violations = 0;
    let mut total_strict_unexpected = 0;
    let mut total_matched = 0;
    let mut total_unexpected = 0;
    let mut failure_details: Vec<String> = Vec::new();
    let mut soft_miss_details: Vec<String> = Vec::new();
    let mut forbidden_details: Vec<String> = Vec::new();
    let mut count_violation_details: Vec<String> = Vec::new();
    let mut strict_unexpected_details: Vec<String> = Vec::new();

    // Reject (must_not_match && max_count) at parse time. `must_not_match`
    // overrides `must_match` in `match_expectations` (pre-existing semantics),
    // but there is no sensible interpretation of "forbidden, up to N of".
    for fixture in &active {
        let fixture_label = format!("{}/{}/{}", fixture.lang, fixture.category, fixture.name);
        for (idx, exp) in fixture.expectations.expected.iter().enumerate() {
            if exp.must_not_match && exp.max_count.is_some() {
                panic!(
                    "{}: expectation[{}] rule_id='{}' has both must_not_match and max_count set — these are mutually exclusive",
                    fixture_label, idx, exp.rule_id
                );
            }
        }
    }

    for fixture in &active {
        let fixture_label = format!("{}/{}/{}", fixture.lang, fixture.category, fixture.name);

        for mode_str in &fixture.expectations.modes {
            let mode = resolve_mode(mode_str);
            let diags = scan_fixture(fixture, mode);
            let fixture_file = fixture
                .source_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();

            let result = match_expectations(
                &diags,
                &fixture.expectations.expected,
                &fixture_file,
                mode_str,
                &fixture.expectations.strict_unexpected,
            );

            total_matched += result.matched;
            total_unexpected += result.unexpected.len();

            if !result.hard_misses.is_empty() {
                let mut msg = format!("FAIL  {fixture_label} [{mode_str}]:");
                for (exp, reason) in &result.hard_misses {
                    msg.push_str(&format!(
                        "\n       MISSING (must_match): {} — {}",
                        reason, exp.notes
                    ));
                }
                failure_details.push(msg);
                total_hard_fails += result.hard_misses.len();
            }

            if !result.forbidden_violations.is_empty() {
                let mut msg = format!("FORB  {fixture_label} [{mode_str}]:");
                for (exp, diag) in &result.forbidden_violations {
                    msg.push_str(&format!(
                        "\n       FORBIDDEN (must_not_match): {}:{} [{}] {} matched rule_id='{}' — {}",
                        diag.path,
                        diag.line,
                        diag.severity.as_db_str(),
                        diag.id,
                        exp.rule_id,
                        exp.notes
                    ));
                }
                forbidden_details.push(msg);
                total_forbidden += result.forbidden_violations.len();
            }

            if !result.strict_unexpected.is_empty() {
                let prefixes = fixture.expectations.strict_unexpected.join(",");
                let mut msg =
                    format!("STRICT {fixture_label} [{mode_str}] (prefixes=[{prefixes}]):");
                for d in &result.strict_unexpected {
                    msg.push_str(&format!(
                        "\n       STRICT unexpected: {}:{} [{}] {} — not consumed by any expectation",
                        d.path,
                        d.line,
                        d.severity.as_db_str(),
                        d.id
                    ));
                }
                strict_unexpected_details.push(msg);
                total_strict_unexpected += result.strict_unexpected.len();
            }

            if !result.count_violations.is_empty() {
                let mut msg = format!("COUNT {fixture_label} [{mode_str}]:");
                for (exp, count) in &result.count_violations {
                    msg.push_str(&format!(
                        "\n       COUNT violation: rule_id='{}' severity={:?} line_range={:?} — {} matches exceed max_count={} — {}",
                        exp.rule_id,
                        exp.severity,
                        exp.line_range,
                        count,
                        exp.max_count.unwrap_or(0),
                        exp.notes
                    ));
                }
                count_violation_details.push(msg);
                total_count_violations += result.count_violations.len();
            }

            if !result.soft_misses.is_empty() {
                let mut msg = format!("SOFT  {fixture_label} [{mode_str}]:");
                for (exp, reason) in &result.soft_misses {
                    msg.push_str(&format!("\n       soft miss: {} — {}", reason, exp.notes));
                }
                soft_miss_details.push(msg);
                total_soft_misses += result.soft_misses.len();
            }

            if verbose {
                eprintln!(
                    "  {fixture_label} [{mode_str}]: {} matched, {} hard misses, {} forbidden, {} count violations, {} strict unexpected, {} soft misses, {} unexpected",
                    result.matched,
                    result.hard_misses.len(),
                    result.forbidden_violations.len(),
                    result.count_violations.len(),
                    result.strict_unexpected.len(),
                    result.soft_misses.len(),
                    result.unexpected.len()
                );
                if !result.unexpected.is_empty() {
                    for d in &result.unexpected {
                        eprintln!(
                            "       EXTRA: {}:{} [{}] {}",
                            d.path,
                            d.line,
                            d.severity.as_db_str(),
                            d.id
                        );
                    }
                }
            }
        }
    }

    // Print coverage matrix.
    print_coverage_matrix(fixtures);

    // Print summary.
    eprintln!("\n────────────────────────────────────────────────────");
    eprintln!(
        "RESULTS: {} matched, {} hard failures, {} forbidden violations, {} count violations, {} strict unexpected, {} soft misses, {} unexpected",
        total_matched,
        total_hard_fails,
        total_forbidden,
        total_count_violations,
        total_strict_unexpected,
        total_soft_misses,
        total_unexpected
    );
    eprintln!("────────────────────────────────────────────────────");

    if !failure_details.is_empty() {
        eprintln!("\n=== HARD FAILURES (must_match=true) ===");
        for msg in &failure_details {
            eprintln!("{msg}");
        }
    }

    if !forbidden_details.is_empty() {
        eprintln!("\n=== FORBIDDEN VIOLATIONS (must_not_match=true) ===");
        for msg in &forbidden_details {
            eprintln!("{msg}");
        }
    }

    if !count_violation_details.is_empty() {
        eprintln!("\n=== COUNT VIOLATIONS (max_count exceeded) ===");
        for msg in &count_violation_details {
            eprintln!("{msg}");
        }
    }

    if !strict_unexpected_details.is_empty() {
        eprintln!(
            "\n=== STRICT UNEXPECTED (unconsumed diag matched fixture's strict_unexpected prefix) ==="
        );
        for msg in &strict_unexpected_details {
            eprintln!("{msg}");
        }
    }

    if !soft_miss_details.is_empty() {
        eprintln!("\n=== SOFT MISSES (must_match=false, informational) ===");
        for msg in &soft_miss_details {
            eprintln!("{msg}");
        }
    }

    // Hard failures, forbidden violations, count violations, and strict
    // unexpected findings all cause failure. Soft misses and unexpected diags
    // outside the strict_unexpected prefix set remain informational.
    assert_eq!(
        total_hard_fails + total_forbidden + total_count_violations + total_strict_unexpected,
        0,
        "{total_hard_fails} expected findings not found (must_match=true); \
         {total_forbidden} forbidden findings present (must_not_match=true); \
         {total_count_violations} count violations (max_count exceeded); \
         {total_strict_unexpected} strict-unexpected diags (unconsumed finding matched a \
         fixture's strict_unexpected prefix). \
         Run with NYX_TEST_VERBOSE=1 for details."
    );
}
