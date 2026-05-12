//! Dynamic corpus mutation fuzzer.
//!
//! Seeds from [`nyx_scanner::dynamic::corpus::payloads_for`], mutates bytes,
//! runs against an instrumented fixture harness, and writes candidates to
//! `fuzz-discovered/{spec_hash}/` when `sink_hit && oracle_fired`.
//!
//! # Usage
//!
//! ```text
//! # Run against the SSRF corpus with an OOB listener
//! cargo run -p nyx-dynamic-corpus -- \
//!     --cap ssrf \
//!     --spec-hash 0123456789abcdef \
//!     --output ../../fuzz-discovered \
//!     --iterations 1000 \
//!     --harness-cmd "python3 tests/dynamic_fixtures/ssrf_harness.py"
//! ```
//!
//! Discovered candidates land in `{output}/{spec_hash}/` with a JSON
//! provenance sidecar (see §16.1 / §16.4 rationale for manual review gate).

use nyx_scanner::dynamic::corpus::{
    audit_marker_collisions, materialise_bytes, payloads_for, CuratedPayload, Oracle,
    PayloadProvenance, CORPUS_VERSION,
};
use nyx_scanner::labels::Cap;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command>", args[0]);
        eprintln!("Commands:");
        eprintln!("  run --cap <cap> --spec-hash <hash> [--output <dir>] [--iterations <n>]");
        eprintln!("  audit-markers");
        eprintln!("  list-caps");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "audit-markers" => cmd_audit_markers(),
        "list-caps" => cmd_list_caps(),
        "run" => cmd_run(&args[2..]),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn cmd_audit_markers() {
    let collisions = audit_marker_collisions();
    if collisions.is_empty() {
        println!("OK: no marker collisions detected (corpus_version={})", CORPUS_VERSION);
    } else {
        eprintln!("FAIL: {} marker collision(s) detected:", collisions.len());
        for (cap, label, other_cap) in &collisions {
            eprintln!("  {cap}/{label} marker appears in {other_cap} payload bytes");
        }
        std::process::exit(1);
    }
}

fn cmd_list_caps() {
    let supported = [
        ("sql_query", Cap::SQL_QUERY),
        ("code_exec", Cap::CODE_EXEC),
        ("file_io", Cap::FILE_IO),
        ("ssrf", Cap::SSRF),
        ("html_escape", Cap::HTML_ESCAPE),
    ];
    println!("Supported caps (corpus_version={}):", CORPUS_VERSION);
    for (name, cap) in &supported {
        let payloads = payloads_for(*cap);
        println!("  {name}: {} payload(s)", payloads.len());
        for p in payloads {
            println!(
                "    - {} [{}] oob_nonce_slot={}",
                p.label,
                if p.is_benign { "benign" } else { "vuln" },
                p.oob_nonce_slot
            );
        }
    }
}

fn cmd_run(args: &[String]) {
    let cap_name = get_arg(args, "--cap").unwrap_or_else(|| {
        eprintln!("--cap required"); std::process::exit(1);
    });
    let spec_hash = get_arg(args, "--spec-hash").unwrap_or_else(|| {
        eprintln!("--spec-hash required"); std::process::exit(1);
    });
    let output_dir = get_arg(args, "--output").unwrap_or_else(|| "fuzz-discovered".to_owned());
    let iterations: u64 = get_arg(args, "--iterations")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let harness_cmd = get_arg(args, "--harness-cmd");

    let cap = parse_cap(&cap_name).unwrap_or_else(|| {
        eprintln!("Unknown cap: {cap_name}. Use list-caps to see supported caps.");
        std::process::exit(1);
    });

    let payloads = payloads_for(cap);
    if payloads.is_empty() {
        eprintln!("No payloads for cap {cap_name}");
        std::process::exit(1);
    }

    let out_path = PathBuf::from(&output_dir).join(&spec_hash);
    std::fs::create_dir_all(&out_path).unwrap_or_else(|e| {
        eprintln!("Cannot create output dir {}: {e}", out_path.display());
        std::process::exit(1);
    });

    println!(
        "Dynamic corpus fuzzer: cap={cap_name} spec_hash={spec_hash} \
         iterations={iterations} output={}",
        out_path.display()
    );

    let mut discovered = 0u64;
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    // Seed the fuzzer from the corpus payloads.
    let seed_bytes: Vec<Vec<u8>> = payloads
        .iter()
        .filter(|p| !p.is_benign && !p.oob_nonce_slot)
        .map(|p| p.bytes.to_vec())
        .collect();

    if seed_bytes.is_empty() {
        println!("No static seed payloads for {cap_name} (all are OOB or benign). Skipping.");
        return;
    }

    let mut corpus: Vec<Vec<u8>> = seed_bytes.clone();
    let mut rng_state: u64 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(12345);

    for iter in 0..iterations {
        let seed = &corpus[lcg_next(&mut rng_state) as usize % corpus.len()];
        let candidate = mutate_bytes(seed, &mut rng_state);

        if seen.contains(&candidate) {
            continue;
        }
        seen.insert(candidate.clone());

        let interesting = if let Some(ref cmd) = harness_cmd {
            run_candidate_against_harness(&candidate, cmd, payloads)
        } else {
            // Headless mode: check heuristically whether the candidate is
            // structurally plausible for the cap (bypass the subprocess cost).
            is_structurally_interesting(&candidate, cap)
        };

        if interesting {
            discovered += 1;
            let filename = format!("candidate-{:016x}", lcg_next(&mut rng_state));
            let candidate_path = out_path.join(&filename);
            std::fs::write(&candidate_path, &candidate).unwrap_or_else(|e| {
                eprintln!("Failed to write candidate: {e}");
            });
            // Write provenance sidecar.
            let sidecar = serde_json::json!({
                "source": "InternalFuzzer",
                "references": [format!("fuzzer-run-{}", iter)],
                "since_corpus_version": CORPUS_VERSION,
                "spec_hash": spec_hash,
                "cap": cap_name,
                "bytes_hex": hex_encode(&candidate),
            });
            let sidecar_path = out_path.join(format!("{filename}.json"));
            let _ = std::fs::write(sidecar_path, sidecar.to_string());
            println!("  [+] iter={iter} candidate={filename}");
        }
    }

    println!(
        "Done: {iterations} iterations, {discovered} candidates written to {}",
        out_path.display()
    );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn get_arg(args: &[String], name: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == name)?;
    args.get(pos + 1).cloned()
}

fn parse_cap(name: &str) -> Option<Cap> {
    match name.to_ascii_lowercase().as_str() {
        "sql_query" | "sqli" | "sql" => Some(Cap::SQL_QUERY),
        "code_exec" | "cmdi" | "rce" => Some(Cap::CODE_EXEC),
        "file_io" | "path_traversal" | "lfi" => Some(Cap::FILE_IO),
        "ssrf" => Some(Cap::SSRF),
        "html_escape" | "xss" => Some(Cap::HTML_ESCAPE),
        _ => None,
    }
}

fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state
}

fn mutate_bytes(input: &[u8], rng: &mut u64) -> Vec<u8> {
    let mut out = input.to_vec();
    if out.is_empty() {
        return out;
    }
    match lcg_next(rng) % 5 {
        0 => {
            // Flip a random byte.
            let idx = (lcg_next(rng) as usize) % out.len();
            out[idx] ^= (lcg_next(rng) as u8) | 1;
        }
        1 => {
            // Insert a byte.
            let idx = (lcg_next(rng) as usize) % (out.len() + 1);
            out.insert(idx, lcg_next(rng) as u8);
        }
        2 => {
            // Delete a byte.
            if out.len() > 1 {
                let idx = (lcg_next(rng) as usize) % out.len();
                out.remove(idx);
            }
        }
        3 => {
            // Append known-interesting bytes.
            let suffixes: &[&[u8]] = &[
                b"'", b"\"", b";", b"--", b" OR 1=1", b"<script>", b"../",
                b"\x00", b"{{", b"|", b"`",
            ];
            let s = suffixes[(lcg_next(rng) as usize) % suffixes.len()];
            out.extend_from_slice(s);
        }
        _ => {
            // Replace a slice with an interesting pattern.
            let interesting: &[&[u8]] = &[b"'", b"\"", b"<", b">", b"%00", b"../", b"//"];
            if !out.is_empty() {
                let idx = (lcg_next(rng) as usize) % out.len();
                let pat = interesting[(lcg_next(rng) as usize) % interesting.len()];
                let end = (idx + pat.len()).min(out.len());
                out[idx..end].copy_from_slice(&pat[..end - idx]);
            }
        }
    }
    out
}

/// Heuristic: does the candidate look structurally plausible for the cap?
/// Used in headless (no-harness) mode.
fn is_structurally_interesting(candidate: &[u8], cap: Cap) -> bool {
    if cap.contains(Cap::SQL_QUERY) {
        let s = String::from_utf8_lossy(candidate);
        s.contains('\'') || s.contains("--") || s.to_ascii_uppercase().contains("UNION")
    } else if cap.contains(Cap::CODE_EXEC) {
        candidate.contains(&b';') || candidate.contains(&b'|') || candidate.contains(&b'`')
    } else if cap.contains(Cap::FILE_IO) {
        let s = String::from_utf8_lossy(candidate);
        s.contains("../") || s.contains("/etc/")
    } else if cap.contains(Cap::HTML_ESCAPE) {
        let s = String::from_utf8_lossy(candidate);
        s.contains('<') || s.contains('>')
    } else {
        false
    }
}

/// Run a candidate against an external harness subprocess.
///
/// Passes the candidate via `NYX_PAYLOAD_B64` env var and checks for
/// `__NYX_SINK_HIT__` sentinel in output.
fn run_candidate_against_harness(
    candidate: &[u8],
    harness_cmd: &str,
    payloads: &[CuratedPayload],
) -> bool {
    let b64 = base64_encode(candidate);
    let oracle_marker = payloads
        .iter()
        .filter(|p| !p.is_benign && !p.oob_nonce_slot)
        .find_map(|p| {
            if let Oracle::OutputContains(m) = &p.oracle {
                Some(*m)
            } else {
                None
            }
        });

    let parts: Vec<&str> = harness_cmd.split_whitespace().collect();
    let (cmd, cmd_args) = match parts.split_first() {
        Some(s) => s,
        None => return false,
    };

    let output = std::process::Command::new(cmd)
        .args(cmd_args)
        .env("NYX_PAYLOAD_B64", &b64)
        .output();

    let Ok(out) = output else { return false };

    let combined: Vec<u8> = out.stdout.iter().chain(out.stderr.iter()).copied().collect();
    let sink_hit = combined.windows(16).any(|w| w == b"__NYX_SINK_HIT__");
    let oracle = oracle_marker
        .map(|m| combined.windows(m.len()).any(|w| w == m.as_bytes()))
        .unwrap_or(false);

    sink_hit && oracle
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 { out.push(ALPHABET[((n >> 6) & 63) as usize] as char); } else { out.push('='); }
        if chunk.len() > 2 { out.push(ALPHABET[(n & 63) as usize] as char); } else { out.push('='); }
    }
    out
}
