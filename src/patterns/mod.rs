//! AST pattern matching: tree-sitter queries over dangerous structural shapes.
//!
//! Patterns match constructs based on syntax alone, with no dataflow or CFG.
//! A match means the construct is present; it is not proof that it is
//! reachable or exploitable. Patterns run in every analysis mode and are the
//! only active detector in `--mode ast`.
//!
//! # Rule ID format
//!
//! ```text
//! <lang>.<category>.<name>
//! ```
//!
//! Examples: `js.code_exec.eval`, `py.deser.pickle_loads`, `c.memory.gets`,
//! `java.sqli.execute_concat`.
//!
//! # Tiers
//!
//! - **Tier A**: structural presence alone is high-signal. `gets`, `eval`,
//!   `pickle.loads`, `mem::transmute`. No guard needed.
//! - **Tier B**: pattern includes a tree-sitter heuristic guard.
//!   `java.sqli.execute_concat` fires only when `executeQuery` receives a
//!   `binary_expression` (concatenation), not a literal or parameterized call.
//!
//! # Categories
//!
//! | Category | Examples |
//! |----------|---------|
//! | `CommandExec` | `system`, `os.system`, `Runtime.exec`, backticks |
//! | `CodeExec` | `eval`, `Function`, PHP `assert("string")`, `class_eval` |
//! | `Deserialization` | `pickle.loads`, `yaml.load`, `Marshal.load`, `readObject` |
//! | `SqlInjection` | `executeQuery` with concatenated argument (Tier B) |
//! | `PathTraversal` | PHP `include $var` |
//! | `Xss` | `innerHTML`, `document.write`, `insertAdjacentHTML` |
//! | `Crypto` | `md5`, `sha1`, `Math.random` for security use |
//! | `Secrets` | Hardcoded API keys (Go, JS, TS) |
//! | `InsecureTransport` | `InsecureSkipVerify`, `fetch("http://...")` |
//! | `Reflection` | `Class.forName`, `Method.invoke`, `constantize` |
//! | `MemorySafety` | `transmute`, `unsafe`, `gets`, `strcpy`, `sprintf` |
//! | `Prototype` | `__proto__` assignment, `Object.prototype.*` |
//! | `Config` | CORS dynamic origin, `rejectUnauthorized: false` |
//! | `CodeQuality` | `unwrap`, `panic!`, `as any` |
//!
//! # Pattern loading
//!
//! Each language submodule exports a `patterns()` function returning
//! `&'static [Pattern]`. [`load`] dispatches to the correct submodule by
//! language slug. [`Pattern`] carries the rule ID, severity, confidence,
//! category, and the tree-sitter query string.

pub mod c;
pub mod cpp;
pub mod ejs;
mod go;
mod java;
pub mod javascript;
mod php;
mod python;
mod ruby;
pub mod rust;
pub mod typescript;

use crate::evidence::Confidence;
use console::style;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    /// Bracketed, colored, fixed-width tag for aligned console output.
    ///
    /// Returns e.g. `"[HIGH]  "` or `"[MEDIUM]"`, always 8 visible characters
    /// so the column after the tag lines up regardless of severity.
    #[allow(dead_code)] // public API for lib consumers
    pub fn colored_tag(self) -> String {
        // Visible widths: "[HIGH]" = 6, "[MEDIUM]" = 8, "[LOW]" = 5.
        // Pad the *whole* tag to 8 visible chars (the longest, "[MEDIUM]").
        let (label, styled_fn): (&str, fn(&str) -> String) = match self {
            Severity::High => ("HIGH", |s| style(s).red().bold().to_string()),
            Severity::Medium => ("MEDIUM", |s| style(s).color256(208).bold().to_string()),
            Severity::Low => ("LOW", |s| style(s).color256(67).to_string()),
        };
        let bracket_len = label.len() + 2; // "[" + label + "]"
        let pad = 8usize.saturating_sub(bracket_len);
        format!("[{}]{:pad$}", styled_fn(label), "", pad = pad)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let styled = match *self {
            Severity::High => style("HIGH").red().bold().to_string(),
            Severity::Medium => style("MEDIUM").color256(208).bold().to_string(),
            Severity::Low => style("LOW").color256(67).to_string(),
        };
        f.write_str(&styled)
    }
}

impl Severity {
    /// Textual value stored in SQLite.
    pub fn as_db_str(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.trim().to_ascii_uppercase().as_str() {
            "HIGH" => Ok(Severity::High),
            "MEDIUM" | "MED" => Ok(Severity::Medium),
            "LOW" => Ok(Severity::Low),
            other => Err(format!("unknown severity: '{other}'")),
        }
    }
}

/// A parsed severity filter expression.
///
/// Supports three forms:
///   - Single level: `"HIGH"`, matches only that level
///   - Comma list: `"HIGH,MEDIUM"`, matches any listed level
///   - Threshold: `">=MEDIUM"`, matches that level and above
///
/// Parsing is case-insensitive and tolerates whitespace around tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeverityFilter {
    /// Match findings at or above this level (High >= Medium >= Low).
    AtLeast(Severity),
    /// Match findings whose severity is in this exact set.
    AnyOf(Vec<Severity>),
}

impl SeverityFilter {
    /// Parse a severity filter expression.
    ///
    /// Examples: `"HIGH"`, `"high,medium"`, `">=MEDIUM"`, `">= low"`.
    pub fn parse(expr: &str) -> Result<Self, String> {
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return Err("empty severity expression".into());
        }

        // Threshold form: >=LEVEL
        if let Some(rest) = trimmed.strip_prefix(">=") {
            let level: Severity = rest.parse()?;
            return Ok(SeverityFilter::AtLeast(level));
        }

        // Comma-separated list (also handles single value)
        let levels: Result<Vec<Severity>, String> = trimmed
            .split(',')
            .map(|tok| tok.trim().parse::<Severity>())
            .collect();
        let levels = levels?;
        if levels.is_empty() {
            return Err("empty severity expression".into());
        }
        // Optimise single-value list
        if levels.len() == 1 {
            return Ok(SeverityFilter::AnyOf(levels));
        }
        Ok(SeverityFilter::AnyOf(levels))
    }

    /// Returns `true` if the given severity passes this filter.
    pub fn matches(&self, sev: Severity) -> bool {
        match self {
            SeverityFilter::AtLeast(threshold) => {
                // Severity ordering: High < Medium < Low (derived Ord).
                // "at least Medium" means sev <= Medium in Ord terms.
                sev <= *threshold
            }
            SeverityFilter::AnyOf(set) => set.contains(&sev),
        }
    }
}

/// Pattern confidence tier.
///
/// * **A**: structural presence alone is high-signal (e.g. `gets()`, `eval()`).
/// * **B**: requires a simple heuristic guard in the query (e.g. SQL with
///   concatenated arg, file-open with non-literal path).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PatternTier {
    A,
    B,
}

/// High-level finding category for noise reduction and prioritization.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    Security,
    Reliability,
    Quality,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingCategory::Security => write!(f, "Security"),
            FindingCategory::Reliability => write!(f, "Reliability"),
            FindingCategory::Quality => write!(f, "Quality"),
        }
    }
}

impl FindingCategory {
    /// Category for a structural / state-machine finding identified by its
    /// rule id.
    ///
    /// Resource-management and error-handling defects (`state-resource-leak`,
    /// `cfg-resource-leak`, `cfg-error-fallthrough`) are *reliability* bugs,
    /// not security vulnerabilities: a leaked file handle or an unhandled
    /// error path is a correctness/robustness issue, not an exploitable flow.
    /// Emitting them as `Security` floods security reports (and security
    /// benchmarks) with non-security noise.  Everything else routed through
    /// the structural/state pipeline — taint sinks (`cfg-unguarded-sink`),
    /// authorization gaps (`cfg-auth-gap`, `state-unauthed-access`) and
    /// memory-safety state errors (`state-use-after-close`,
    /// `state-double-close`) — stays `Security`.
    pub fn for_structural_rule(rule_id: &str) -> FindingCategory {
        match rule_id {
            "state-resource-leak"
            | "state-resource-leak-possible"
            | "cfg-resource-leak"
            | "cfg-error-fallthrough" => FindingCategory::Reliability,
            _ => FindingCategory::Security,
        }
    }
}

/// Vulnerability class that a pattern detects.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PatternCategory {
    CommandExec,
    CodeExec,
    Deserialization,
    SqlInjection,
    PathTraversal,
    Xss,
    Crypto,
    Secrets,
    InsecureTransport,
    Reflection,
    MemorySafety,
    Prototype,
    InsecureConfig,
    CodeQuality,
}

impl PatternCategory {
    /// Map this vulnerability class to a high-level finding category.
    pub fn finding_category(self) -> FindingCategory {
        match self {
            PatternCategory::CodeQuality => FindingCategory::Quality,
            _ => FindingCategory::Security,
        }
    }
}

/// One AST pattern with a tree-sitter query and meta-data.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Pattern {
    /// Unique identifier, `<lang>.<category>.<specific>` preferred.
    pub id: &'static str,
    /// Human-readable explanation.
    pub description: &'static str,
    /// tree-sitter query string.
    pub query: &'static str,
    /// Rough severity bucket.
    pub severity: Severity,
    /// Confidence tier (A = structural, B = heuristic-guarded).
    pub tier: PatternTier,
    /// Vulnerability class.
    pub category: PatternCategory,
    /// Confidence level for findings produced by this pattern.
    pub confidence: Confidence,
}

/// Global, lazily-initialised registry: lang-name → pattern slice
static REGISTRY: Lazy<HashMap<&'static str, &'static [Pattern]>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // ---- Rust ----
    m.insert("rust", rust::PATTERNS);

    // ---- TypeScript ----
    m.insert("typescript", typescript::PATTERNS);
    m.insert("ts", typescript::PATTERNS);
    m.insert("tsx", typescript::PATTERNS);

    // ---- JavaScript ----
    m.insert("javascript", javascript::PATTERNS);
    m.insert("js", javascript::PATTERNS);

    // ---- C & C++ ----
    m.insert("c", c::PATTERNS);
    m.insert("cpp", cpp::PATTERNS);
    m.insert("c++", cpp::PATTERNS);

    // ---- Other patterns in the folder ----
    m.insert("java", java::PATTERNS);
    m.insert("go", go::PATTERNS);
    m.insert("php", php::PATTERNS);
    m.insert("python", python::PATTERNS);
    m.insert("py", python::PATTERNS);
    m.insert("ruby", ruby::PATTERNS);
    m.insert("rb", ruby::PATTERNS);

    tracing::debug!("AST-pattern registry initialised ({} patterns)", m.len());

    m
});

/// Return all patterns for the requested language (case-insensitive).
///
/// Unknown languages yield an **empty** `Vec`. This function cannot
/// fail: the registry is pure static data (no tree-sitter queries are
/// compiled here). Compilation is deferred to `crate::utils::query_cache`,
/// which drops malformed queries via `filter_map` + warn-log rather
/// than panicking.
pub fn load(lang: &str) -> Vec<Pattern> {
    let key = lang.to_ascii_lowercase();
    REGISTRY.get(key.as_str()).copied().unwrap_or(&[]).to_vec()
}

#[test]
fn severity_as_db_str_roundtrip() {
    for &s in &[Severity::High, Severity::Medium, Severity::Low] {
        let db = s.as_db_str();
        assert!(matches!(db, "HIGH" | "MEDIUM" | "LOW"));

        assert_eq!(db.parse::<Severity>().unwrap(), s);
        assert_eq!(db.to_lowercase().parse::<Severity>().unwrap(), s);
    }
}

#[test]
fn severity_display_contains_uppercase_name() {
    assert!(Severity::High.to_string().contains("HIGH"));
    assert!(Severity::Medium.to_string().contains("MEDIUM"));
    assert!(Severity::Low.to_string().contains("LOW"));
}

#[test]
fn load_returns_correct_pattern_slices() {
    let rust = load("rust");
    assert!(!rust.is_empty(), "Rust patterns should be loaded");

    let ts = load("typescript");
    let tsx = load("tsx");
    assert_eq!(ts, tsx, "alias ‘tsx’ must map to TypeScript patterns");

    assert_eq!(load("RUST"), rust);

    assert!(load("brainfuck").is_empty());
}

#[test]
fn severity_from_str_rejects_unknown() {
    assert!("garbage".parse::<Severity>().is_err());
}

#[test]
fn severity_filter_single() {
    let f = SeverityFilter::parse("HIGH").unwrap();
    assert!(f.matches(Severity::High));
    assert!(!f.matches(Severity::Medium));
    assert!(!f.matches(Severity::Low));
}

#[test]
fn severity_filter_comma_list() {
    let f = SeverityFilter::parse("HIGH,MEDIUM").unwrap();
    assert!(f.matches(Severity::High));
    assert!(f.matches(Severity::Medium));
    assert!(!f.matches(Severity::Low));
}

#[test]
fn severity_filter_threshold() {
    let f = SeverityFilter::parse(">=MEDIUM").unwrap();
    assert!(f.matches(Severity::High));
    assert!(f.matches(Severity::Medium));
    assert!(!f.matches(Severity::Low));

    let f2 = SeverityFilter::parse(">=LOW").unwrap();
    assert!(f2.matches(Severity::High));
    assert!(f2.matches(Severity::Medium));
    assert!(f2.matches(Severity::Low));

    let f3 = SeverityFilter::parse(">=HIGH").unwrap();
    assert!(f3.matches(Severity::High));
    assert!(!f3.matches(Severity::Medium));
}

#[test]
fn severity_filter_case_insensitive_and_whitespace() {
    let f = SeverityFilter::parse("  high , medium  ").unwrap();
    assert!(f.matches(Severity::High));
    assert!(f.matches(Severity::Medium));
    assert!(!f.matches(Severity::Low));

    let f2 = SeverityFilter::parse(">= medium").unwrap();
    assert!(f2.matches(Severity::High));
    assert!(f2.matches(Severity::Medium));
}

#[test]
fn severity_filter_rejects_empty() {
    assert!(SeverityFilter::parse("").is_err());
    assert!(SeverityFilter::parse("  ").is_err());
}

#[test]
fn severity_filter_rejects_invalid_level() {
    assert!(SeverityFilter::parse("CRITICAL").is_err());
    assert!(SeverityFilter::parse("HIGH,CRITICAL").is_err());
    assert!(SeverityFilter::parse(">=BOGUS").is_err());
}
