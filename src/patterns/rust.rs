use crate::evidence::Confidence;
use crate::patterns::{Pattern, PatternCategory, PatternTier, Severity};

/// Rust AST patterns.
///
/// Rust taint rules already cover `Command::new`/`arg`/`status`/`output` sinks
/// and `env::var` / `fs::read_to_string` sources, so we do NOT duplicate those.
/// Patterns here focus on **unsafe memory**, **panicking APIs**, and structural
/// code-quality signals specific to Rust.
pub const PATTERNS: &[Pattern] = &[
    // ── Tier A: Memory Safety (unsafe) ─────────────────────────────────
    Pattern {
        id: "rs.memory.transmute",
        description: "std::mem::transmute performs unchecked type reinterpretation",
        // `mem::`, `std::mem::`, `core::mem::` and the turbofish form.  A bare
        // `transmute(..)` is not matched: without import resolution it cannot
        // be told apart from a user-defined helper of the same name.
        query: r#"(call_expression
                     function: (_) @fn
                     (#match? @fn "(?s)^((::)?(std|core)::)?mem::transmute(::\\s*<.*>)?$"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.memory.copy_nonoverlapping",
        description: "ptr::copy_nonoverlapping is a raw pointer memcpy",
        query: r#"(call_expression
                     function: (_) @fn
                     (#match? @fn "(?s)^((::)?(std|core)::)?ptr::copy_nonoverlapping(::\\s*<.*>)?$"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.memory.get_unchecked",
        description: "get_unchecked / get_unchecked_mut performs unchecked indexing",
        query: r#"(call_expression
                     function: (field_expression
                       field: (field_identifier) @m
                       (#match? @m "^get_unchecked(_mut)?$")))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.memory.mem_zeroed",
        description: "std::mem::zeroed is UB for non-POD types since the zero pattern may not be a valid value",
        query: r#"(call_expression
                     function: (_) @fn
                     (#match? @fn "(?s)^((::)?(std|core)::)?mem::zeroed(::\\s*<.*>)?$"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.memory.ptr_read",
        description: "ptr::read / ptr::read_volatile dereferences a raw pointer",
        query: r#"(call_expression
                     function: (_) @fn
                     (#match? @fn "(?s)^((::)?(std|core)::)?ptr::read(_volatile)?(::\\s*<.*>)?$"))
                   @vuln"#,
        severity: Severity::High,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    // ── Tier A: Code quality / robustness ──────────────────────────────
    Pattern {
        id: "rs.quality.unsafe_block",
        description: "unsafe block carries a manual memory safety obligation",
        query: "(unsafe_block) @vuln",
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.quality.unsafe_fn",
        description: "unsafe fn declaration",
        query: r#"(function_item
                     (function_modifiers) @mods
                     (#match? @mods "^unsafe"))
                   @vuln"#,
        severity: Severity::Medium,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.quality.unwrap",
        description: ".unwrap() panics on None/Err",
        query: r#"(call_expression
                     function: (field_expression
                       field: (field_identifier) @name (#eq? @name "unwrap")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.quality.expect",
        description: ".expect() panics on None/Err",
        query: r#"(call_expression
                     function: (field_expression
                       field: (field_identifier) @name (#eq? @name "expect")))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.quality.panic_macro",
        description: "panic! macro invocation",
        query: r#"(macro_invocation (identifier) @id (#eq? @id "panic")) @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
        confidence: Confidence::High,
    },
    Pattern {
        id: "rs.quality.todo",
        description: "todo!() / unimplemented!() placeholder left in code",
        query: r#"(macro_invocation
                     (identifier) @id
                     (#match? @id "^(todo|unimplemented)$"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::CodeQuality,
        confidence: Confidence::High,
    },
    // ── Tier A: Narrowing cast ─────────────────────────────────────────
    Pattern {
        id: "rs.memory.narrow_cast",
        description: "`as` cast to 8/16-bit integer can truncate",
        query: r#"(type_cast_expression
                     type: (primitive_type) @to
                     (#match? @to "^(u8|i8|u16|i16)$"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::Medium,
    },
    Pattern {
        id: "rs.memory.mem_forget",
        description: "std::mem::forget can leak resources",
        query: r#"(call_expression
                     function: (_) @fn
                     (#match? @fn "(?s)^((::)?(std|core)::)?mem::forget(::\\s*<.*>)?$"))
                   @vuln"#,
        severity: Severity::Low,
        tier: PatternTier::A,
        category: PatternCategory::MemorySafety,
        confidence: Confidence::High,
    },
];
