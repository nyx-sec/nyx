use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// Ruby AST patterns.
///
/// Taint rules cover `system`/`exec` (command injection), `eval` (code
/// execution), and `puts`/`print` (output sinks).  AST patterns here focus on
/// **deserialization** (YAML.load, Marshal.load), **instance_eval/class_eval**,
/// **backtick shell**, **send with dynamic arg**, and **constantize**.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Code execution ─────────────────────────────────────────
    Pattern {
        id: "rb.code_exec.eval",
        description: "Kernel#eval runs dynamic code",
        query: r#"(call (identifier) @id (#eq? @id "eval")) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rb.code_exec.instance_eval",
        description: "instance_eval evaluates a string in object context",
        query: r#"(call
                     method: (identifier) @id (#eq? @id "instance_eval"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rb.code_exec.class_eval",
        description: "class_eval / module_eval evaluates a string in class context",
        query: r#"(call
                     method: (identifier) @id (#match? @id "^(class_eval|module_eval)$"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CodeExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Command execution ──────────────────────────────────────
    Pattern {
        id: "rb.cmdi.backtick",
        description: "Backtick shell execution with interpolation",
        // A backtick string with no `#{...}` is a fixed command and carries no
        // caller-controlled data.
        query: r#"(subshell (interpolation)) @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Shell execution ─────────────────────────────────────────
    Pattern {
        id: "rb.cmdi.system_interp",
        description: "system/exec call runs a shell command",
        // `!receiver` restricts the match to the receiver-less Kernel#system /
        // Kernel#exec primitives.  A same-named method on a typed receiver
        // (`conn.exec(sql)` on a `PG::Connection`, `obj.system(...)`) is not a
        // shell-execution sink and must not fire this cmdi rule — it is routed
        // by its receiver type instead.  Motivated by CVE-2026-42087.
        //
        // The `arguments` alternatives drop only the shell-free argv form:
        // two or more command words whose program is a fixed string that is
        // not a shell, interpreter or wrapper (`system("git", "log", x)`),
        // which execs the program directly.  They keep the single command
        // string (optionally after an environment hash and before option
        // pairs), a dynamic program (`system(cmd, "x")`), and a shell,
        // interpreter or wrapper program (`system("sh", "-c", x)`).  The
        // program list mirrors `labels::is_command_runner_program`.
        query: r##"(call
                     !receiver
                     method: (identifier) @m (#match? @m "^(system|exec)$")
                     arguments: [
                       (argument_list . (_) .)
                       (argument_list . (_) . (pair))
                       (argument_list . (hash) . (_) .)
                       (argument_list . (hash) . (_) . (pair))
                     ])
                   @vuln
                   (call
                     !receiver
                     method: (identifier) @m (#match? @m "^(system|exec)$")
                     arguments: [
                       (argument_list . (_) @first . (_))
                       (argument_list . (hash) . (_) @first . (_))
                     ]
                     (#not-match? @first "(?s)^(\"[^\"#]*\"|'[^']*'|\\{.*)$"))
                   @vuln
                   (call
                     !receiver
                     method: (identifier) @m (#match? @m "^(system|exec)$")
                     arguments: [
                       (argument_list . (_) @first)
                       (argument_list . (hash) . (_) @first)
                     ]
                     (#match? @first "(?i)^[\"'](.*[/\\\\])?(sh|bash|zsh|dash|ksh|ash|fish|csh|tcsh|cmd|powershell|pwsh|python[0-9.]*|pypy[0-9.]*|ruby[0-9.]*|perl[0-9.]*|php[0-9.]*|lua[0-9.]*|node|nodejs|deno|bun|env|sudo|doas|nice|nohup|timeout|stdbuf|setsid|xargs|busybox|command|exec|time|ionice|chroot|su|runuser)(\\.exe)?[\"']$"))
                   @vuln"##,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::CommandExec,
        confidence: Confidence::High,
    },
    // ── Tier A: Deserialization ────────────────────────────────────────
    Pattern {
        id: "rb.deser.yaml_load",
        description: "YAML.load deserializes arbitrary objects (use safe_load instead)",
        query: r#"(call
                     receiver: (constant) @recv (#match? @recv "^(YAML|Psych)$")
                     method: (identifier) @m (#eq? @m "load"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rb.deser.marshal_load",
        description: "Marshal.load deserializes arbitrary Ruby objects",
        query: r#"(call
                     receiver: (constant) @recv (#eq? @recv "Marshal")
                     method: (identifier) @m (#eq? @m "load"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::Deserialization,
        confidence: Confidence::High,
    },
    // ── Tier A: Reflection ─────────────────────────────────────────────
    Pattern {
        id: "rb.reflection.send_dynamic",
        description: "send() with a non-symbol first argument is arbitrary method dispatch",
        query: r#"(call
                     method: (identifier) @m (#eq? @m "send")
                     arguments: (argument_list
                       . [(identifier) (string (interpolation)+)] @vuln))
        "#,
        severity: Severity::Medium,
        tier: PatternTier::B,
        category: PatternCategory::Reflection,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "rb.reflection.constantize",
        description: "constantize / safe_constantize performs dynamic class resolution",
        query: r#"(call
                     method: (identifier) @m (#match? @m "^(constantize|safe_constantize)$"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::Reflection,
        confidence: Confidence::High,
    },
    // ── Tier A: SSRF ───────────────────────────────────────────────────
    Pattern {
        id: "rb.ssrf.open_uri",
        description: "Kernel#open with an HTTP URL is an SSRF sink via open-uri",
        query: r#"(call
                     method: (identifier) @m (#eq? @m "open")
                     arguments: (argument_list
                       (string) @url (#match? @url "^[\"']https?://")))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::InsecureTransport,
        confidence: Confidence::High,
    },
    // ── Tier A: Crypto ─────────────────────────────────────────────────
    Pattern {
        id: "rb.crypto.md5",
        description: "Digest::MD5 is a weak hash algorithm",
        query: r#"(scope_resolution
                     name: (constant) @c (#eq? @c "MD5"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::Crypto,
        confidence: Confidence::Medium,
    },
];
