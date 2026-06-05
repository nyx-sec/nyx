use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// Python AST patterns.
///
/// Taint rules cover `eval`/`exec`, `os.system`/`os.popen`/`subprocess.*`,
/// and `cursor.execute`. AST patterns here add coverage for **deserialization**,
/// **subprocess shell=True** (Tier B, taint doesn't check keyword args), and
/// **code execution** sinks that taint cannot structurally verify.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "py.code_exec.eval",
        description: "eval() runs dynamic code",
        query: r#"(call function: (identifier) @id (#eq? @id "eval")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "py.code_exec.exec",
        description: "exec() runs dynamic code",
        query: r#"(call function: (identifier) @id (#eq? @id "exec")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "py.code_exec.compile",
        description: "compile() with exec/eval mode compiles code from a string",
        query: r#"(call function: (identifier) @id (#eq? @id "compile")) @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "py.cmdi.os_system",
        description: "os.system() runs a shell command",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "os")
                       attribute: (identifier) @fn (#eq? @fn "system")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "py.cmdi.os_popen",
        description: "os.popen() runs a shell command",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "os")
                       attribute: (identifier) @fn (#eq? @fn "popen")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    // ── Tier B: subprocess with shell=True ─────────────────────────────
    Pattern {
        id: "py.cmdi.subprocess_shell",
        description: "subprocess call with shell=True",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "subprocess"))
                     arguments: (argument_list
                       (keyword_argument
                         name: (identifier) @k (#eq? @k "shell")
                         value: (true))))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::B,
        category: PatternCategory::CommandExec,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Deserialization ────────────────────────────────────────
    Pattern {
        id: "py.deser.pickle_loads",
        description: "pickle.loads/load deserializes arbitrary objects",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "pickle")
                       attribute: (identifier) @fn (#match? @fn "^loads?$")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    Pattern {
        id: "py.deser.yaml_load",
        description: "yaml.load() without SafeLoader instantiates arbitrary objects",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "yaml")
                       attribute: (identifier) @fn (#eq? @fn "load")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    Pattern {
        id: "py.deser.shelve_open",
        description: "shelve.open() performs pickle-backed deserialization",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "shelve")
                       attribute: (identifier) @fn (#eq? @fn "open")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    // ── Tier B: SQL injection (format/concat heuristic) ────────────────
    // Catches both `cursor.execute(query + user)` (binary_operator concat)
    // and `cursor.execute(f"... {user} ...")` (f-string with interpolation).
    // f-strings appear as a `string` node with `interpolation` children in
    // tree-sitter-python; the alternation lets the same pattern cover both
    // the historical % / + concat shapes and the modern f-string SQLi shape
    // that surfaces in CVE-2025-24793 (snowflake-connector-python),
    // CVE-2025-69662 (geopandas), and dozens of similar cursor.execute
    // call sites across the corpus.
    Pattern {
        id: "py.sqli.execute_format",
        description: "cursor.execute with string concatenation or f-string risks SQL injection",
        query: r#"(call
                     function: (attribute
                       attribute: (identifier) @fn (#eq? @fn "execute"))
                     arguments: (argument_list
                       [(binary_operator)
                        (string (interpolation))] @arg))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::SqlInjection,
        confidence: Confidence::Medium,
    },
    // SQLAlchemy `text(<concat-or-fstring>)`, same Tier B heuristic
    // applied to the SQLAlchemy raw-SQL constructor.  Catches the
    // CVE-2025-69662 (geopandas) shape:
    //   connection.execute(text(f"SELECT … '{geom_name}' …"))
    // where the f-string interpolation is the injection point and the
    // surrounding `connection.execute` would otherwise hide the unsafe
    // construction from the simple execute_format pattern.
    Pattern {
        id: "py.sqli.text_format",
        description: "sqlalchemy text() with f-string or string concat risks SQL injection",
        query: r#"(call
                     function: [(identifier) @fn (attribute attribute: (identifier) @fn)]
                     (#eq? @fn "text")
                     arguments: (argument_list
                       [(binary_operator)
                        (string (interpolation))] @arg))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::SqlInjection,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "py.crypto.md5",
        description: "hashlib.md5() uses a weak hash algorithm",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "hashlib")
                       attribute: (identifier) @fn (#eq? @fn "md5")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "py.crypto.sha1",
        description: "hashlib.sha1() uses a weak hash algorithm",
        query: r#"(call
                     function: (attribute
                       object: (identifier) @pkg (#eq? @pkg "hashlib")
                       attribute: (identifier) @fn (#eq? @fn "sha1")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    // Bare-call forms after `from hashlib import md5, sha1` (the qualified
    // `hashlib.md5(...)` form above is an `attribute` call and never matches
    // these `identifier`-function queries, so there is no double-count). Closes
    // the dvpwa weak-hash recall gap. Held at Low confidence: a project-local
    // function literally named `md5`/`sha1` is a rare incidental FP, so this
    // sits below the default high-confidence surface.
    Pattern {
        id: "py.crypto.md5_bare",
        description: "md5() (from hashlib) uses a weak hash algorithm",
        query: r#"(call
                     function: (identifier) @fn (#eq? @fn "md5"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Low,
    },
    Pattern {
        id: "py.crypto.sha1_bare",
        description: "sha1() (from hashlib) uses a weak hash algorithm",
        query: r#"(call
                     function: (identifier) @fn (#eq? @fn "sha1"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Low,
    },
    // ── Tier A: Template injection ─────────────────────────────────────
    Pattern {
        id: "py.xss.jinja_from_string",
        description: "jinja2.Template from string risks template injection",
        query: r#"(call
                     function: (attribute
                       attribute: (identifier) @fn (#eq? @fn "from_string")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::High,
    },
    // Flask `make_response(<f-string-or-concat>)` reflection — Tier B
    // heuristic mirroring `py.sqli.execute_format` / `py.sqli.text_format`.
    // Catches CVE-2023-6568 (mlflow auth `create_user` reflected the
    // attacker-controlled `Content-Type` header into the response body
    // via `make_response(f"Invalid content type: '{content_type}'", 400)`)
    // and the equivalent `+`-concat shape.  Recognises both bare
    // `make_response(...)` and `flask.make_response(...)`.
    Pattern {
        id: "py.xss.make_response_format",
        description: "flask make_response with f-string or concat risks reflected XSS",
        query: r#"(call
                     function: [(identifier) @fn (attribute attribute: (identifier) @fn)]
                     (#eq? @fn "make_response")
                     arguments: (argument_list
                       [(binary_operator)
                        (string (interpolation))] @arg))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::Xss,
        confidence: Confidence::Medium,
    },
];
