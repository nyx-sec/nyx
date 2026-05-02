use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// JavaScript AST patterns.
///
/// Taint rules cover `eval` (code injection), `innerHTML` (XSS),
/// `location.href` (open redirect), and `child_process.exec/spawn` (command
/// injection).  AST patterns here add **new Function()**, **document.write**,
/// **setTimeout with string**, **deserialization**, **prototype pollution**,
/// **XSS sinks** not covered by taint, and **weak crypto**.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "js.code_exec.eval",
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
        id: "js.code_exec.new_function",
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
        id: "js.code_exec.settimeout_string",
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
        id: "js.xss.document_write",
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
        id: "js.xss.outer_html",
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
        id: "js.xss.insert_adjacent_html",
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
    // ── Tier A: Prototype pollution ────────────────────────────────────
    Pattern {
        id: "js.prototype.proto_assignment",
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
    Pattern {
        id: "js.prototype.extend_object",
        description: "Assignment to Object.prototype mutates the prototype",
        query: r#"(assignment_expression
                     left: (member_expression
                       object: (member_expression
                         object: (identifier) @obj (#eq? @obj "Object")
                         property: (property_identifier) @mid (#eq? @mid "prototype"))))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Prototype,
        confidence: Confidence::High,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    Pattern {
        id: "js.crypto.weak_hash",
        description: "crypto.createHash with weak algorithm (md5/sha1)",
        query: r#"(call_expression
                     function: (member_expression
                       property: (property_identifier) @prop (#eq? @prop "createHash"))
                     arguments: (arguments
                       (string) @alg (#match? @alg "\"(md5|sha1)\"")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "js.crypto.weak_hash_import",
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
        id: "js.crypto.math_random",
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
        id: "js.secrets.hardcoded_secret",
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
    // ── Tier A: Open redirect ──────────────────────────────────────────
    Pattern {
        id: "js.xss.location_assign",
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
    // ── Tier A: Insecure transport ─────────────────────────────────────
    Pattern {
        id: "js.transport.fetch_http",
        description: "fetch() over plain HTTP",
        query: r#"(call_expression
                     function: (identifier) @id (#eq? @id "fetch")
                     arguments: (arguments
                       (string) @url (#match? @url "^\"http://")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::InsecureTransport,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Cookie manipulation ────────────────────────────────────
    Pattern {
        id: "js.xss.cookie_write",
        description: "Write to document.cookie",
        query: r#"(assignment_expression
                     left: (member_expression
                       object: (identifier) @obj (#eq? @obj "document")
                       property: (property_identifier) @prop (#eq? @prop "cookie")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Xss,
        confidence: Confidence::High,
    },
    // ── Tier A: Insecure session / cookie configuration ─────────────────
    Pattern {
        id: "js.config.insecure_session_httponly",
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
        id: "js.config.insecure_session_secure",
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
        id: "js.config.insecure_session_samesite",
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
        id: "js.config.reject_unauthorized",
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
    // Empty-string fallback (`|| ""`) is excluded — see typescript.rs for rationale.
    Pattern {
        id: "js.secrets.fallback_secret",
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
        id: "js.config.verbose_error_response",
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
        id: "js.config.cors_dynamic_origin",
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
