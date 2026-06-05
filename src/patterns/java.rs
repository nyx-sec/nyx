use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// Java AST patterns.
///
/// Taint rules cover `Runtime.exec` (command injection) and
/// `executeQuery`/`executeUpdate`/`prepareStatement` (SQL sinks).
/// AST patterns here focus on **deserialization**, **reflection**,
/// **SQL with concatenation** (Tier B heuristic), and **weak crypto**.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Deserialization ────────────────────────────────────────
    Pattern {
        id: "java.deser.readobject",
        description: "ObjectInputStream.readObject() performs unsafe deserialization",
        // Match any .readObject() call, the method name is specific enough.
        query: r#"(method_invocation
                     name: (identifier) @id (#eq? @id "readObject"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    // ── Tier A: SnakeYAML deserialization (CVE-2022-1471) ──────────────
    // `new Yaml()` constructed without a `SafeConstructor` argument
    // accepts arbitrary YAML tags (`!!javax.script.ScriptEngineManager`,
    // `!!java.net.URLClassLoader`, …) and instantiates any class via
    // reflection. SnakeYAML 2.0 swapped the default to SafeConstructor
    // but pre-2.0 deployments stay vulnerable until call sites are
    // patched. We match the empty-arg form `new Yaml()` only, so the
    // explicit-SafeConstructor remediation form
    // `new Yaml(new SafeConstructor(new LoaderOptions()))` is silent.
    Pattern {
        id: "java.deser.snakeyaml_unsafe_constructor",
        description: "new Yaml() without SafeConstructor accepts arbitrary class tags (CVE-2022-1471)",
        query: r#"(object_creation_expression
                     type: (type_identifier) @t (#eq? @t "Yaml")
                     arguments: (argument_list) @args (#eq? @args "()"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    // ── Tier A: Apache Commons Text Text4Shell (CVE-2022-42889) ────────
    // `StringSubstitutor.createInterpolator()` enables `script:`,
    // `dns:`, and `url:` lookups by default, `${script:js:…}`
    // evaluates JavaScript via the JSR-223 ScriptEngineManager. The
    // factory call is itself the structural bug; the recommended app-
    // side mitigation builds a `StringSubstitutor` directly with a
    // restricted lookup map.
    Pattern {
        id: "java.code_exec.text4shell_interpolator",
        description: "StringSubstitutor.createInterpolator() enables script:/dns:/url: evaluation (CVE-2022-42889)",
        query: r#"(method_invocation
                     object: (identifier) @c (#eq? @c "StringSubstitutor")
                     name: (identifier) @id (#eq? @id "createInterpolator"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "java.cmdi.runtime_exec",
        description: "Runtime.getRuntime().exec() runs a shell command",
        query: r#"(method_invocation
                     object: (method_invocation
                       name: (identifier) @n (#eq? @n "getRuntime"))
                     name: (identifier) @id (#eq? @id "exec"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Reflection ─────────────────────────────────────────────
    Pattern {
        id: "java.reflection.class_forname",
        description: "Class.forName() performs dynamic class loading",
        query: r#"(method_invocation
                     object: (identifier) @c (#eq? @c "Class")
                     name: (identifier) @id (#eq? @id "forName"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Reflection,
        confidence: Confidence::High,
    },
    Pattern {
        id: "java.reflection.method_invoke",
        description: "Method.invoke() is a reflective method invocation",
        query: r#"(method_invocation
                     name: (identifier) @id (#eq? @id "invoke"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Reflection,
        confidence: Confidence::High,
    },
    // ── Tier B: SQL injection (concatenation heuristic) ────────────────
    Pattern {
        id: "java.sqli.execute_concat",
        description: "SQL execute with concatenated string argument",
        query: r#"(method_invocation
                     name: (identifier) @id (#match? @id "^execute(Query|Update)?$")
                     arguments: (argument_list
                       (binary_expression) @concat))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::SqlInjection,
        confidence: Confidence::Medium,
    },
    // ── Tier A: Weak crypto ────────────────────────────────────────────
    //
    // The `type:`/`object:` node is matched with the `(_)` wildcard and a
    // text `#match?` rather than a bare `(type_identifier) (#eq? …)` so the
    // fully-qualified call shapes that dominate real code (and the entire
    // OWASP Benchmark) are caught: `new java.util.Random()` parses the type
    // as a `scoped_type_identifier`, not a `type_identifier`, which the old
    // `#eq? @t "Random"` query silently never matched (0 crypto findings on
    // the whole corpus).  The fix keeps the reliable `#eq?` but captures the
    // LAST type-name segment from either a bare `(type_identifier)` or the
    // direct `(type_identifier)` child of a `(scoped_type_identifier)`, so
    // both `new Random()` and `new java.util.Random()` match while
    // `SecureRandom` (a different whole segment) does not.
    Pattern {
        id: "java.crypto.insecure_random",
        description: "new Random() (java.util.Random) is not cryptographically secure",
        query: r#"(object_creation_expression
                     type: [
                       (type_identifier) @t
                       (scoped_type_identifier (type_identifier) @t)
                     ]
                     (#eq? @t "Random"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    // Weak crypto algorithm passed to a `getInstance("…")` factory, keyed on
    // the algorithm string so the qualifier (`javax.crypto.Cipher` /
    // `java.security.MessageDigest` FQN or a bare class) does not matter — the
    // old per-class queries pinned `object: (identifier) "MessageDigest"` /
    // `"Random"` and silently never matched the fully-qualified call shapes
    // that dominate real code (0 crypto findings on the whole OWASP corpus).
    // Three alternations, all proven to fire from this `(string_literal)`
    // position:
    //   * `^.des/` — single-DES *cipher transforms* (`"DES/CBC/PKCS5Padding"`).
    //     The trailing `/` (mode separator) is required so the genuinely-weak
    //     single-DES Cipher fires while a bare `KeyGenerator.getInstance("DES")`
    //     key-spec and the stronger triple-DES `"DESede/…"` (which the OWASP
    //     Benchmark labels benign) do NOT — `"DESe"` has no `/` after `des`.
    //   * `^.(rc2|rc4|blowfish)` — broken stream/block ciphers (rare, real).
    //   * `^.(md2|md4|md5|sha1|sha-1).$` — broken hash digests as the WHOLE
    //     algorithm string (the trailing `.$` matches the closing quote so
    //     `"SHA1PRNG"` / `"HmacSHA1"` / `"SHA-256"` do NOT match).
    // `getInstance` with any of these is `Cipher`/`MessageDigest` by
    // construction; strong transforms (`AES/CBC`, `AES/GCM`, `SHA-256`) miss.
    Pattern {
        id: "java.crypto.weak_algorithm",
        description: "Cipher/MessageDigest.getInstance with a broken algorithm (DES/RC4/MD5/SHA-1)",
        query: r#"(method_invocation
                     name: (identifier) @id (#eq? @id "getInstance")
                     arguments: (argument_list
                       (string_literal) @alg (#match? @alg "(?i)(^.des/|^.(rc2|rc4|blowfish)|^.(md2|md4|md5|sha1|sha-1).$)")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
    // Tier A reflected-XSS was previously a bare syntactic match on every
    // `response.getWriter().print/println/write(...)` regardless of whether the
    // written value was attacker-controlled or already HTML-encoded.  On the
    // OWASP Benchmark that fired ~4400 times at precision 0.05 (it flagged
    // constant strings and `ESAPI.encoder().encodeForHTML(...)`-wrapped output
    // identically to a raw tainted write).  Reflected XSS is now a taint sink
    // (`Sink(Cap::HTML_ESCAPE)` on the servlet writer verbs in
    // `labels/java.rs`), which fires only when an un-encoded tainted value
    // reaches the writer, so the syntactic pattern is retired.
];
