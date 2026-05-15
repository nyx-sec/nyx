//! Layering boundary test: ensures the dynamic module is only referenced from
//! the allowed crossing points in the static codebase.
//!
//! The dynamic module is feature-gated (`--features dynamic`).  Call sites
//! outside the allowed set create an implicit dependency on the feature flag
//! that the static-analysis path must never have.  This test fails fast when
//! new code accidentally reaches into `crate::dynamic` from a module that
//! should remain feature-agnostic.
//!
//! # Allowed crossings
//!
//! | File                         | Reason                                    |
//! |------------------------------|-------------------------------------------|
//! | `src/main.rs`                | binary entry point; wires --features dynamic|
//! | `src/lib.rs`                 | crate root; `#[cfg(feature="dynamic")]` mod|
//! | `src/commands/scan.rs`       | enrichment loop lives here                |
//! | `src/commands/mod.rs`        | `verify-feedback` subcommand (§21.2)      |
//! | `src/server/` (any file)     | server start_scan verify wiring           |
//! | `src/rank.rs`                | M7 rank-delta telemetry hook (§21 / M7)   |
//! | `src/chain/reverify.rs`      | Phase 26 — composite chain re-verification |

use std::fs;
use std::path::{Path, PathBuf};

/// Files/prefixes that are allowed to reference `crate::dynamic` (or
/// `dynamic::`) directly. Paths are relative to `src/` (no leading `src/`).
const ALLOWED: &[&str] = &[
    "main.rs",
    "lib.rs",
    "commands/scan.rs",
    "commands/mod.rs",
    "server/",
    "rank.rs",
    // Phase 26 — Track G.3: composite chain re-verification is the
    // public bridge between the chain composer and the dynamic verifier.
    "chain/reverify.rs",
    // The dynamic module itself is obviously allowed.
    "dynamic/",
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn is_allowed(path: &Path, src_root: &Path) -> bool {
    let rel = path
        .strip_prefix(src_root)
        .unwrap_or(path)
        .to_string_lossy();
    ALLOWED
        .iter()
        .any(|allowed| rel.starts_with(allowed) || rel.as_ref() == *allowed)
}

#[test]
fn dynamic_module_only_referenced_from_allowed_files() {
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files);

    let mut violations: Vec<String> = Vec::new();

    for path in &files {
        if is_allowed(path, &src_root) {
            continue;
        }

        let content = fs::read_to_string(path).unwrap_or_default();
        // Look for any reference to the dynamic module.
        // Exclude `// dynamic` style comments and doc strings.
        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            // Skip comment lines.
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }
            if trimmed.contains("crate::dynamic")
                || trimmed.contains("dynamic::")
                || trimmed.contains("use crate::dynamic")
            {
                let rel = path
                    .strip_prefix(&src_root)
                    .unwrap_or(path)
                    .display()
                    .to_string();
                violations.push(format!("{}:{}: {}", rel, lineno + 1, trimmed));
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "Files outside allowed crossings reference `crate::dynamic`:\n{}\n\
             Add the file to ALLOWED in tests/dynamic_layering.rs if the \
             reference is intentional.",
            violations.join("\n")
        );
    }
}
