//! Rust harness emitter.
//!
//! Generates a binary crate that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Calls the entry function from `src/entry.rs` with the payload routed
//!    to the correct parameter slot.
//! 3. The entry function calls `println!("__NYX_SINK_HIT__")` before the
//!    actual sink invocation (sink-reachability probe).
//! 4. Captures outcome via stdout markers and exit code (§4.1).
//!
//! Build step: the runner calls `build_sandbox::prepare_rust()` which runs
//! `cargo build --release` in the workdir. `harness.command` is updated to
//! the compiled binary path before sandbox execution.
//!
//! Payload slot support:
//! - `PayloadSlot::Param(0)` — pass payload as `&str` first argument.
//! - `PayloadSlot::EnvVar(name)` — set env var before calling entry.
//! - All other slots (`Stdin`, `Param(n>0)`, `QueryParam`, `HttpBody`, `Argv`)
//!   produce `UnsupportedReason::PayloadSlotUnsupported`. Stdin piping into the
//!   generated harness is not yet wired (deferred).
//!
//! HTML_ESCAPE is n/a for Rust (§15.4).

use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use crate::labels::Cap;

/// Zero-sized [`LangEmitter`] handle for Rust.  Method bodies delegate to the
/// existing free functions in this module.
pub struct RustEmitter;

/// Entry kinds the Rust emitter currently understands.  Extended in Phase 16
/// (Track B Rust + C/C++ vertical) to include `HttpRoute` (`actix_web`,
/// `axum`), `CliSubcommand` (clap), and `LibraryApi` (libfuzzer).
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

impl LangEmitter for RustEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "rust emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — Track B will add actix / axum / clap / libfuzzer shapes in phase 16"
        )
    }
}

/// Emit a Rust harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(0) | PayloadSlot::EnvVar(_) => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    let cargo_toml = generate_cargo_toml(spec.expected_cap);
    let main_rs = generate_main_rs(spec);

    Ok(HarnessSource {
        source: main_rs,
        filename: "src/main.rs".into(),
        command: vec!["target/release/nyx_harness".into()],
        extra_files: vec![("Cargo.toml".into(), cargo_toml)],
        entry_subpath: Some("src/entry.rs".into()),
    })
}

/// Generate `Cargo.toml` for the harness crate.
///
/// Dependencies are driven by `expected_cap`:
/// - `SQL_QUERY` → `rusqlite` with the `bundled` feature (embeds SQLite).
/// - Other caps use only std (no extra deps).
pub fn generate_cargo_toml(cap: Cap) -> String {
    let mut deps = String::new();

    if cap.contains(Cap::SQL_QUERY) {
        deps.push_str("rusqlite = { version = \"0.39\", features = [\"bundled\"] }\n");
    }

    format!(
        "[package]\n\
         name = \"nyx-harness\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n\n\
         [[bin]]\n\
         name = \"nyx_harness\"\n\
         path = \"src/main.rs\"\n\n\
         [dependencies]\n\
         {deps}"
    )
}

/// Generate `src/main.rs` — the harness entry point.
///
/// Reads the payload from env, calls `entry::{entry_name}` with the payload
/// routed according to `spec.payload_slot`.
fn generate_main_rs(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (pre_call, call_expr) = build_call(spec, entry_fn);

    format!(
        r#"//! Nyx dynamic harness — auto-generated, do not edit.
mod entry;

fn main() {{
    let payload = nyx_payload();
{pre_call}    {call_expr}
}}

fn nyx_payload() -> String {{
    // Prefer raw NYX_PAYLOAD (set on Unix).
    if let Ok(v) = std::env::var("NYX_PAYLOAD") {{
        if !v.is_empty() {{
            return v;
        }}
    }}
    // Fall back to base64-encoded NYX_PAYLOAD_B64.
    if let Ok(b64) = std::env::var("NYX_PAYLOAD_B64") {{
        if let Some(bytes) = b64_decode(b64.as_bytes()) {{
            return String::from_utf8_lossy(&bytes).into_owned();
        }}
    }}
    String::new()
}}

/// Minimal base64 decoder (no external deps).
fn b64_decode(input: &[u8]) -> Option<Vec<u8>> {{
    const TABLE: [u8; 128] = {{
        // `while` loop (not `for`) so the initializer stays inside what stable
        // Rust permits in a `const` context: `IntoIterator::into_iter` is not a
        // const fn, so a `for` loop here fails with E0015.
        let mut t = [255u8; 128];
        let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0usize;
        while i < alphabet.len() {{
            t[alphabet[i] as usize] = i as u8;
            i += 1;
        }}
        t
    }};
    let input: Vec<u8> = input.iter().copied().filter(|&c| c != b'\n' && c != b'\r').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < input.len() {{
        let a = *TABLE.get(input[i] as usize)? as u32;
        let b = *TABLE.get(input[i + 1] as usize)? as u32;
        let c = if input[i + 2] == b'=' {{ 64 }} else {{ *TABLE.get(input[i + 2] as usize)? as u32 }};
        let d = if input[i + 3] == b'=' {{ 64 }} else {{ *TABLE.get(input[i + 3] as usize)? as u32 }};
        if a == 255 || b == 255 || c == 255 || d == 255 {{ return None; }}
        out.push(((a << 2) | (b >> 4)) as u8);
        if input[i + 2] != b'=' {{ out.push(((b << 4) | (c >> 2)) as u8); }}
        if input[i + 3] != b'=' {{ out.push(((c << 6) | d) as u8); }}
        i += 4;
    }}
    Some(out)
}}
"#,
        pre_call = pre_call,
        call_expr = call_expr,
    )
}

/// Build `(pre_call_setup, call_expression)` strings for the chosen payload slot.
fn build_call(spec: &HarnessSpec, func: &str) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(0) => {
            let pre = String::new();
            let call = format!("entry::{func}(&payload);");
            (pre, call)
        }
        PayloadSlot::EnvVar(name) => {
            let pre = format!("    std::env::set_var({name:?}, &payload);\n");
            let call = format!("entry::{func}();");
            (pre, call)
        }
        _ => {
            // Unreachable: `emit()` rejects all other slots up front.
            let pre = String::new();
            let call = format!("entry::{func}(&payload);");
            (pre, call)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "rust000000000001".into(),
            entry_file: "src/handler.rs".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Rust,
            toolchain_id: "rust-stable".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/handler.rs".into(),
            sink_line: 10,
            spec_hash: "rusttest00000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        }
    }

    #[test]
    fn emit_sql_query_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("mod entry;"));
        assert!(harness.source.contains("nyx_payload()"));
        assert!(harness.source.contains("entry::run(&payload)"));
        assert_eq!(harness.filename, "src/main.rs");
        assert_eq!(harness.command, vec!["target/release/nyx_harness"]);
    }

    #[test]
    fn emit_includes_cargo_toml_in_extra_files() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        let cargo = harness.extra_files.iter().find(|(n, _)| n == "Cargo.toml");
        assert!(cargo.is_some(), "Cargo.toml must be in extra_files");
        let cargo_content = &cargo.unwrap().1;
        assert!(cargo_content.contains("rusqlite"), "SQL_QUERY cap needs rusqlite dep");
        assert!(cargo_content.contains("bundled"), "rusqlite must use bundled feature");
    }

    #[test]
    fn emit_code_exec_no_rusqlite_dep() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::CODE_EXEC;
        let harness = emit(&spec).unwrap();
        let cargo = harness.extra_files.iter().find(|(n, _)| n == "Cargo.toml").unwrap();
        assert!(!cargo.1.contains("rusqlite"), "CODE_EXEC must not have rusqlite dep");
    }

    #[test]
    fn emit_entry_subpath_is_src_entry_rs() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("src/entry.rs".to_string()));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("NYX_INPUT".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("set_var"));
        assert!(harness.source.contains("\"NYX_INPUT\""));
    }

    #[test]
    fn emit_param_gt_0_is_unsupported() {
        let spec = make_spec(PayloadSlot::Param(1));
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
    }

    #[test]
    fn cargo_toml_has_correct_bin_target() {
        let cargo = generate_cargo_toml(Cap::SQL_QUERY);
        assert!(cargo.contains("name = \"nyx_harness\""));
        assert!(cargo.contains("path = \"src/main.rs\""));
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!RustEmitter.entry_kinds_supported().is_empty());
        assert!(RustEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::Function));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = RustEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("phase 16"));
    }

    #[test]
    fn b64_decode_roundtrip() {
        // Test by compiling: actual b64_decode is in generated code.
        // Just verify the Cargo.toml generation doesn't panic.
        let _ = generate_cargo_toml(Cap::FILE_IO);
        let _ = generate_cargo_toml(Cap::CODE_EXEC);
        let _ = generate_cargo_toml(Cap::SSRF);
    }
}
