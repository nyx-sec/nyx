//! Phase 19 (Track E.3) — `nyx-image-builder`.
//!
//! Reads `tools/image-builder/images.toml`, drives `docker pull` / `docker
//! inspect` for each entry, and writes the resolved `sha256:…` digest back
//! into the same TOML file so the digest pin is reproducible from source.
//!
//! Subcommands:
//!
//! - `build [--all | <toolchain_id>…]` — pull each requested image, capture
//!   its `RepoDigests` digest, and rewrite `images.toml` in place when the
//!   digest differs from the recorded pin.  The daily CI workflow runs
//!   `build --all` and opens a PR with the changes when any entry drifts.
//! - `verify` — assert that every entry in `images.toml` has a non-empty
//!   `digest` field and that the digest matches the locally-pulled image.
//!   Exit code 0 on success, 1 on any mismatch.
//! - `list` — print every entry with its current `(base, digest)` pair to
//!   stdout, one entry per line, for human inspection.
//!
//! Usage:
//!
//! ```text
//! cargo run -F image-builder --bin nyx-image-builder -- list
//! cargo run -F image-builder --bin nyx-image-builder -- build --all
//! cargo run -F image-builder --bin nyx-image-builder -- build python-3.11 node-20
//! cargo run -F image-builder --bin nyx-image-builder -- verify
//! ```
//!
//! The tool is host-side only; nothing in the Nyx scanner build depends on
//! it at runtime.  The codegen in `build.rs` reads `images.toml` directly,
//! so updating digests is a two-step "run nyx-image-builder build → cargo
//! build" cycle.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const IMAGES_TOML: &str = "tools/image-builder/images.toml";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("nyx-image-builder: missing subcommand");
        print_usage();
        return ExitCode::from(2);
    }

    let toml_path = catalogue_path();

    match args[0].as_str() {
        "list" => cmd_list(&toml_path),
        "build" => cmd_build(&toml_path, &args[1..]),
        "verify" => cmd_verify(&toml_path),
        "-h" | "--help" | "help" => {
            print_usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("nyx-image-builder: unknown subcommand `{other}`");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage: nyx-image-builder <list | build [--all|<id>…] | verify>\n\n\
         Reads `{IMAGES_TOML}` and pins per-toolchain Docker images by sha256\n\
         digest.  Run `build --all` on a host that can reach docker daemon to\n\
         refresh the digests; commit the resulting diff."
    );
}

/// Resolve the catalogue path relative to the workspace root.
///
/// Cargo runs binaries with CWD set to the workspace root by default, so the
/// straight relative path works for the common case.  We also walk upward
/// from `current_dir` so the tool functions correctly when invoked from a
/// nested directory (e.g. CI step that `cd tools/`).
fn catalogue_path() -> PathBuf {
    if Path::new(IMAGES_TOML).exists() {
        return PathBuf::from(IMAGES_TOML);
    }
    if let Ok(cwd) = env::current_dir() {
        let mut probe = cwd.as_path();
        loop {
            let candidate = probe.join(IMAGES_TOML);
            if candidate.exists() {
                return candidate;
            }
            match probe.parent() {
                Some(p) => probe = p,
                None => break,
            }
        }
    }
    PathBuf::from(IMAGES_TOML)
}

// ── Subcommands ──────────────────────────────────────────────────────────────

fn cmd_list(toml_path: &Path) -> ExitCode {
    let entries = match read_catalogue(toml_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("nyx-image-builder: cannot read {}: {e}", toml_path.display());
            return ExitCode::FAILURE;
        }
    };

    for e in &entries {
        let digest = if e.digest.is_empty() { "<unpinned>" } else { &e.digest };
        println!("{:<20} {:<40} {}", e.toolchain_id, e.base, digest);
    }
    ExitCode::SUCCESS
}

fn cmd_build(toml_path: &Path, args: &[String]) -> ExitCode {
    let entries = match read_catalogue(toml_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("nyx-image-builder: cannot read {}: {e}", toml_path.display());
            return ExitCode::FAILURE;
        }
    };

    let targets: Vec<&ImageEntry> = if args.iter().any(|a| a == "--all") {
        entries.iter().collect()
    } else if args.is_empty() {
        eprintln!("nyx-image-builder build: expected --all or one or more toolchain IDs");
        return ExitCode::from(2);
    } else {
        let mut out = Vec::with_capacity(args.len());
        for id in args {
            if id == "--all" {
                continue;
            }
            match entries.iter().find(|e| &e.toolchain_id == id) {
                Some(e) => out.push(e),
                None => {
                    eprintln!("nyx-image-builder build: unknown toolchain_id `{id}`");
                    return ExitCode::FAILURE;
                }
            }
        }
        out
    };

    let mut updates: Vec<(String, String)> = Vec::new();
    let mut failures = 0usize;

    for entry in &targets {
        eprintln!("==> pulling {} ({})", entry.toolchain_id, entry.base);
        if !docker_pull(&entry.base) {
            eprintln!("    pull failed for {}", entry.base);
            failures += 1;
            continue;
        }
        match resolve_image_digest(&entry.base) {
            Some(digest) => {
                eprintln!("    {} → {}", entry.base, digest);
                updates.push((entry.toolchain_id.clone(), digest));
            }
            None => {
                eprintln!("    docker inspect produced no digest for {}", entry.base);
                failures += 1;
            }
        }
    }

    if !updates.is_empty() {
        let original = match std::fs::read_to_string(toml_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("nyx-image-builder build: cannot read {}: {e}", toml_path.display());
                return ExitCode::FAILURE;
            }
        };
        let updated = rewrite_digests(&original, &updates);
        if updated != original {
            if let Err(e) = std::fs::write(toml_path, updated) {
                eprintln!(
                    "nyx-image-builder build: cannot write {}: {e}",
                    toml_path.display()
                );
                return ExitCode::FAILURE;
            }
            eprintln!("==> updated {} ({} entries)", toml_path.display(), updates.len());
        } else {
            eprintln!("==> {} unchanged (digests already pinned)", toml_path.display());
        }
    }

    if failures > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_verify(toml_path: &Path) -> ExitCode {
    let entries = match read_catalogue(toml_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("nyx-image-builder: cannot read {}: {e}", toml_path.display());
            return ExitCode::FAILURE;
        }
    };

    let mut failures = 0usize;
    let mut unpinned = 0usize;

    for entry in &entries {
        if entry.digest.is_empty() {
            eprintln!("MISS {}: digest unpinned in {}", entry.toolchain_id, IMAGES_TOML);
            unpinned += 1;
            continue;
        }
        match resolve_image_digest(&entry.base) {
            Some(local) if local == entry.digest => {
                eprintln!("OK   {}: {}", entry.toolchain_id, entry.digest);
            }
            Some(local) => {
                eprintln!(
                    "DIFF {}: pinned={} local={}",
                    entry.toolchain_id, entry.digest, local,
                );
                failures += 1;
            }
            None => {
                eprintln!(
                    "MISS {}: docker inspect returned no digest (image not pulled?)",
                    entry.toolchain_id
                );
                failures += 1;
            }
        }
    }

    if failures == 0 && unpinned == 0 {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "nyx-image-builder verify: {failures} mismatch(es), {unpinned} unpinned entry(ies)",
        );
        ExitCode::FAILURE
    }
}

// ── Docker shellouts ─────────────────────────────────────────────────────────

fn docker_bin() -> String {
    env::var("NYX_DOCKER_BIN").unwrap_or_else(|_| "docker".to_owned())
}

fn docker_pull(image: &str) -> bool {
    Command::new(docker_bin())
        .args(["pull", image])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Resolve the immutable content digest of a locally-pulled image.
///
/// We prefer `RepoDigests` (`name@sha256:…`) because that is the form
/// `docker pull <image>@sha256:…` accepts directly.  When the local image
/// has no remote digest yet (e.g. fresh build), we fall back to the `.Id`
/// which carries the local sha256 of the manifest.
fn resolve_image_digest(image: &str) -> Option<String> {
    // Try RepoDigests first.
    let repo = Command::new(docker_bin())
        .args([
            "inspect",
            "--format={{index .RepoDigests 0}}",
            image,
        ])
        .output()
        .ok()?;
    if repo.status.success() {
        let line = std::str::from_utf8(&repo.stdout).unwrap_or("").trim();
        if !line.is_empty() && line != "<no value>" {
            // RepoDigests is "name@sha256:…"; the caller stores the
            // sha256:… portion alongside `base` so we just keep the
            // digest tail.
            if let Some(idx) = line.rfind("@") {
                let digest = &line[idx + 1..];
                if !digest.is_empty() {
                    return Some(digest.to_owned());
                }
            }
        }
    }

    // Fall back to .Id (image manifest digest).
    let id = Command::new(docker_bin())
        .args(["inspect", "--format={{.Id}}", image])
        .output()
        .ok()?;
    if !id.status.success() {
        return None;
    }
    let line = std::str::from_utf8(&id.stdout).unwrap_or("").trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_owned())
    }
}

// ── images.toml parser + rewriter ────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct ImageEntry {
    toolchain_id: String,
    base: String,
    digest: String,
}

fn read_catalogue(path: &Path) -> std::io::Result<Vec<ImageEntry>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_catalogue(&text))
}

fn parse_catalogue(src: &str) -> Vec<ImageEntry> {
    let mut entries: Vec<ImageEntry> = Vec::new();
    let mut current: Option<ImageEntry> = None;

    for raw in src.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[image]]" {
            if let Some(prev) = current.take()
                && !prev.toolchain_id.is_empty()
            {
                entries.push(prev);
            }
            current = Some(ImageEntry::default());
            continue;
        }
        if line.starts_with("[[") || line.starts_with('[') {
            if let Some(prev) = current.take()
                && !prev.toolchain_id.is_empty()
            {
                entries.push(prev);
            }
            continue;
        }
        let Some(slot) = current.as_mut() else { continue };
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        let value = value.trim().trim_matches('"').trim_matches('\'');
        match key {
            "toolchain_id" => slot.toolchain_id = value.to_owned(),
            "base" => slot.base = value.to_owned(),
            "digest" => slot.digest = value.to_owned(),
            _ => {}
        }
    }
    if let Some(prev) = current.take()
        && !prev.toolchain_id.is_empty()
    {
        entries.push(prev);
    }
    entries
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (i, b) in line.bytes().enumerate() {
        match b {
            b'"' => in_string = !in_string,
            b'#' if !in_string => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Rewrite the `digest = "…"` line for each `(toolchain_id, new_digest)` in
/// `updates`, leaving every other byte of the original TOML untouched.
///
/// Algorithm: stream the original line-by-line, track which `[[image]]`
/// block we are in by reading `toolchain_id`, and when we hit `digest = "…"`
/// inside a block whose `toolchain_id` is in `updates`, replace the value
/// while preserving the original indentation.
fn rewrite_digests(src: &str, updates: &[(String, String)]) -> String {
    let mut out = String::with_capacity(src.len());
    let mut current_tid: Option<String> = None;
    let mut in_image_block = false;

    for raw in src.lines() {
        let trimmed = raw.trim();
        if trimmed == "[[image]]" {
            in_image_block = true;
            current_tid = None;
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        if trimmed.starts_with("[[") || trimmed.starts_with('[') {
            in_image_block = false;
            current_tid = None;
            out.push_str(raw);
            out.push('\n');
            continue;
        }

        if in_image_block {
            if let Some(value) = parse_toml_string_value(trimmed, "toolchain_id") {
                current_tid = Some(value);
            }

            if parse_toml_string_value(trimmed, "digest").is_some()
                && let Some(tid) = &current_tid
                && let Some((_, new_digest)) = updates.iter().find(|(id, _)| id == tid)
            {
                let indent_len = raw.len() - raw.trim_start().len();
                out.push_str(&raw[..indent_len]);
                out.push_str(&format!("digest = \"{new_digest}\""));
                out.push('\n');
                continue;
            }
        }

        out.push_str(raw);
        out.push('\n');
    }

    // Preserve trailing-newline behaviour of the original file: if the
    // source did not end in '\n' we should not introduce one.
    if !src.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

fn parse_toml_string_value(line: &str, key: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_catalogue_extracts_three_fields() {
        let src = r#"
[[image]]
toolchain_id = "python-3.11"
base = "python:3.11-slim"
toolchain = "Python 3.11"
packages = {}
digest = ""

[[image]]
toolchain_id = "node-20"
base = "node:20-slim"
toolchain = "Node.js 20"
packages = {}
digest = "sha256:cafebabe"
"#;
        let entries = parse_catalogue(src);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].toolchain_id, "python-3.11");
        assert_eq!(entries[0].base, "python:3.11-slim");
        assert_eq!(entries[0].digest, "");
        assert_eq!(entries[1].toolchain_id, "node-20");
        assert_eq!(entries[1].digest, "sha256:cafebabe");
    }

    #[test]
    fn rewrite_digests_replaces_only_named_entries() {
        let src = r#"[[image]]
toolchain_id = "python-3.11"
base = "python:3.11-slim"
digest = ""

[[image]]
toolchain_id = "node-20"
base = "node:20-slim"
digest = ""
"#;
        let updates = vec![("node-20".to_owned(), "sha256:deadbeef".to_owned())];
        let out = rewrite_digests(src, &updates);
        assert!(out.contains("digest = \"sha256:deadbeef\""));
        // python-3.11 must remain unpinned.
        let python_block = out
            .split("[[image]]")
            .find(|b| b.contains("python-3.11"))
            .unwrap();
        assert!(python_block.contains("digest = \"\""));
    }

    #[test]
    fn rewrite_digests_preserves_indentation_and_comments() {
        let src = "# header\n[[image]]\n    toolchain_id = \"go\"\n    digest = \"\"\n";
        let updates = vec![("go".to_owned(), "sha256:1234".to_owned())];
        let out = rewrite_digests(src, &updates);
        assert!(out.contains("    digest = \"sha256:1234\""));
        assert!(out.starts_with("# header\n"));
    }

    #[test]
    fn rewrite_digests_no_op_when_no_targets() {
        let src = "[[image]]\ntoolchain_id = \"x\"\ndigest = \"sha256:keep\"\n";
        let out = rewrite_digests(src, &[]);
        assert_eq!(out, src);
    }

    #[test]
    fn parse_toml_string_value_handles_trailing_garbage() {
        assert_eq!(
            parse_toml_string_value("digest = \"sha256:abc\"", "digest"),
            Some("sha256:abc".to_owned())
        );
        assert_eq!(parse_toml_string_value("other = \"x\"", "digest"), None);
    }

    #[test]
    fn strip_comment_keeps_hash_inside_strings() {
        assert_eq!(strip_comment("foo = \"a#b\" # tail"), "foo = \"a#b\" ");
    }
}
