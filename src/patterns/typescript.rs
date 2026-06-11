use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// TypeScript AST patterns.
///
/// TypeScript shares most patterns with JavaScript. Taint rules cover `eval`,
/// `innerHTML`, and `child_process.*` sinks. AST patterns here mirror JS
/// patterns plus TS-specific `any` type-safety escapes.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "ts.code_exec.eval",
        description: "eval() runs dynamic code",
        query: r#"(call_expression
                     function: (identifier) @id (#eq? @id "eval"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "ts.code_exec.new_function",
        description: "new Function() constructor is equivalent to eval",
        query: r#"(new_expression
                     constructor: (identifier) @id (#eq? @id "Function"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "ts.code_exec.settimeout_string",
        description: "setTimeout/setInterval with a string argument runs implicit eval",
        query: r#"(call_expression
                     function: (identifier) @id (#match? @id "^(setTimeout|setInterval)$")
                     arguments: (arguments (string) @code))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    // ── Tier A: XSS sinks ──────────────────────────────────────────────
    Pattern {
        id: "ts.xss.document_write",
        description: "document.write() is an XSS sink",
        query: r#"(call_expression
                     function: (member_expression
                       object: (identifier) @obj (#eq? @obj "document")
                       property: (property_identifier) @prop (#match? @prop "^(write|writeln)$")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::High,
    },
    Pattern {
        id: "ts.xss.outer_html",
        description: "Assignment to .outerHTML is an XSS sink",
        query: r#"(assignment_expression
                     left: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "outerHTML")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::High,
    },
    Pattern {
        id: "ts.xss.insert_adjacent_html",
        description: "insertAdjacentHTML() is an XSS sink",
        query: r#"(call_expression
                     function: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "insertAdjacentHTML")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::High,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "ts.crypto.weak_hash",
        description: "crypto.createHash with weak algorithm (md5/sha1)",
        query: r#"(call_expression
                     function: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "createHash"))
                     arguments: (arguments
                       (string) @alg (#match? @alg "^[\"'](md5|sha1)[\"']$")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "ts.crypto.weak_hash_import",
        description: "Direct md5()/sha1() call uses a weak hash from an imported package",
        query: r#"(call_expression
                     function: (identifier) @id (#match? @id "^(md5|sha1)$"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "ts.crypto.math_random",
        description: "Math.random() is not cryptographically secure",
        query: r#"(call_expression
                     function: (member_expression
                       object: (identifier) @obj (#eq? @obj "Math")
                       property: (property_identifier) @prop (#eq? @prop "random")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Hardcoded secrets ───────────────────────────────────────
    Pattern {
        id: "ts.secrets.hardcoded_secret",
        description: "Hardcoded secret/password/API key in source code",
        query: r#"(pair
                     key: (property_identifier) @key
                       (#match? @key "^(secret|password|api_key|apiKey|apiSecret|api_secret|SESSION_SECRET|secretKey|secret_key|privateKey|private_key)$")
                     value: (string) @val)
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Secrets,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Hardcoded cryptographic key/secret config ──────────────
    // Crypto-key-shaped keys the anchored `hardcoded_secret` regex misses;
    // emits a `crypto`-bucketing rule id.  See javascript.rs for rationale.
    Pattern {
        id: "ts.crypto.hardcoded_key",
        description: "Hardcoded cryptographic key/secret in source config",
        query: r#"(pair
                     key: (property_identifier) @key
                       (#match? @key "(?i)^([a-z0-9]+secret|(crypto|cookie|session|signing|encryption|encrypt|private|master|jwt|hmac|secret)key|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|encryption[_-]?key|signing[_-]?key)$")
                     value: (string) @val (#match? @val "[^\"']{3,}"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    // ── Tier A: TypeScript-specific type-safety escapes ────────────────
    Pattern {
        id: "ts.quality.any_annotation",
        description: "Type annotation of `any` disables type checking",
        query: r#"(type_annotation (predefined_type) @t (#eq? @t "any")) @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "ts.quality.as_any",
        description: "Type assertion `as any` is a type-safety escape hatch",
        query: r#"(as_expression (predefined_type) @t (#eq? @t "any")) @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Prototype pollution ────────────────────────────────────
    Pattern {
        id: "ts.prototype.proto_assignment",
        description: "Assignment to __proto__ causes prototype pollution",
        query: r#"(assignment_expression
                     left: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "__proto__")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Prototype,
        confidence: Confidence::High,
    },
    // ── Tier A: Open redirect ──────────────────────────────────────────
    Pattern {
        id: "ts.xss.location_assign",
        description: "Assignment to location/location.href is an open-redirect sink",
        query: r#"(assignment_expression
                     left: (member_expression
                       object: (identifier) @obj (#match? @obj "^(window|location|document)$")
                       property: (property_identifier) @prop (#match? @prop "^(location|href)$")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::High,
    },
    // ── Tier A: Cookie manipulation ────────────────────────────────────
    Pattern {
        id: "ts.xss.cookie_write",
        description: "Write to document.cookie",
        query: r#"(assignment_expression
                     left: (member_expression
                       object: (identifier) @obj (#eq? @obj "document")
                       property: (property_identifier) @prop (#eq? @prop "cookie")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Insecure session / cookie configuration ─────────────────
    Pattern {
        id: "ts.config.insecure_session_httponly",
        description: "Session cookie with httpOnly: false allows XSS-based session theft",
        query: r#"(pair
                     key: (property_identifier) @key (#eq? @key "httpOnly")
                     value: (false) @val)
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::InsecureConfig,
        confidence: Confidence::High,
    },
    Pattern {
        id: "ts.config.insecure_session_secure",
        description: "Session cookie with secure: false sends the cookie over plain HTTP",
        query: r#"(pair
                     key: (property_identifier) @key (#eq? @key "secure")
                     value: (false) @val)
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::InsecureConfig,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "ts.config.insecure_session_samesite",
        description: "sameSite: \"none\" allows cross-origin cookie sending, increasing CSRF risk",
        query: r#"(pair
                     key: (property_identifier) @key (#eq? @key "sameSite")
                     value: (string) @val (#match? @val "^[\"']none[\"']$"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::InsecureConfig,
        confidence: Confidence::High,
    },
    // ── Tier A: TLS verification disabled ─────────────────────────────
    Pattern {
        id: "ts.config.reject_unauthorized",
        description: "TLS certificate verification disabled via rejectUnauthorized: false",
        query: r#"(pair
                     key: (property_identifier) @key (#eq? @key "rejectUnauthorized")
                     value: (false) @val)
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::InsecureConfig,
        confidence: Confidence::High,
    },
    // ── Tier A: Hardcoded fallback secret ──────────────────────────────
    // The `(#match? @fallback "[^\"']")` predicate excludes empty-string
    // fallbacks (`process.env.X || ""`), which are the dominant FP shape
    // in production TypeScript: developers write `|| ""` to satisfy the
    // non-undefined string type without committing a real secret.
    Pattern {
        id: "ts.secrets.fallback_secret",
        description: "Environment variable with secret-like name has hardcoded fallback value",
        query: r#"(binary_expression
                     left: (member_expression
                       object: (member_expression
                         object: (identifier) @proc (#eq? @proc "process")
                         property: (property_identifier) @env (#eq? @env "env"))
                       property: (property_identifier) @key
                         (#match? @key "(?i)(secret|password|key|token)"))
                     operator: "||"
                     right: (string) @fallback (#match? @fallback "[^\"']"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Secrets,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Verbose error response ────────────────────────────────
    Pattern {
        id: "ts.config.verbose_error_response",
        description: "Error object passed to response renderer can leak stack traces to users",
        query: r#"(call_expression
                     function: (member_expression
                       property: (property_identifier) @method
                         (#match? @method "^(render|send|json)$"))
                     arguments: (arguments
                       (_)
                       (object
                         (shorthand_property_identifier) @prop
                           (#eq? @prop "error"))))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::InsecureConfig,
        confidence: Confidence::Medium,
    },
    // ── Tier B: CORS dynamic origin reflection ────────────────────────
    Pattern {
        id: "ts.config.cors_dynamic_origin",
        description: "CORS Access-Control-Allow-Origin set to a dynamic value can reflect arbitrary origins",
        query: r#"(call_expression
                     function: (member_expression
                       property: (property_identifier) @method (#eq? @method "setHeader"))
                     arguments: (arguments
                       (string) @header_name (#match? @header_name "Access-Control-Allow-Origin")
                       . (identifier) @value))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::InsecureConfig,
        confidence: Confidence::Medium,
    },
];
