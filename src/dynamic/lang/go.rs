//! Go harness emitter.
//!
//! Generates a Go `main` package that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Imports the entry package from `./entry/` and calls the entry function.
//! 3. Uses `runtime.Caller`-style wrapping in fixtures for sink-reachability
//!    probes (fixtures explicitly emit `__NYX_SINK_HIT__` before the sink).
//!
//! Build step: `prepare_go()` in `build_sandbox.rs` runs `go build -o nyx_harness .`
//! in the workdir. The harness command is updated to the compiled binary path.
//!
//! File layout in workdir:
//! ```text
//! main.go         ← harness entry point (generated)
//! go.mod          ← module definition (generated)
//! entry/
//!   entry.go      ← entry function (copied from project; must have `package entry`)
//! ```
//!
//! Payload slot support:
//! - `PayloadSlot::Param(0)` — pass payload as `string` first argument.
//! - `PayloadSlot::EnvVar(name)` — set env var before calling entry.
//! - Other slots produce `UnsupportedReason::EntryKindUnsupported`.
//!
//! Build container: `nyx-build-go:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::lang::HarnessSource;
use crate::dynamic::spec::{HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;

/// Emit a Go harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(0) | PayloadSlot::EnvVar(_) => {}
        _ => return Err(UnsupportedReason::EntryKindUnsupported),
    }

    let main_go = generate_main_go(spec);
    let go_mod = generate_go_mod();

    Ok(HarnessSource {
        source: main_go,
        filename: "main.go".to_owned(),
        command: vec!["./nyx_harness".to_owned()],
        extra_files: vec![("go.mod".to_owned(), go_mod)],
        entry_subpath: Some("entry/entry.go".to_owned()),
    })
}

fn generate_main_go(spec: &HarnessSpec) -> String {
    let entry_fn = capitalize_first(&spec.entry_name);
    let (pre_call, call_expr) = build_call(spec, &entry_fn);

    // Determine which imports are needed.
    let env_import = if matches!(&spec.payload_slot, PayloadSlot::EnvVar(_)) {
        ""
    } else {
        ""
    };
    let _ = env_import;

    format!(
        r#"// Nyx dynamic harness — auto-generated, do not edit.
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"nyx-harness/entry"
)

func main() {{
	payload := nyxPayload()
{pre_call}	{call_expr}
	_ = fmt.Sprintf("") // suppress unused import if call_expr uses fmt directly
	_ = os.Stderr       // suppress unused import
}}

func nyxPayload() string {{
	if v := os.Getenv("NYX_PAYLOAD"); v != "" {{
		return v
	}}
	if b64 := os.Getenv("NYX_PAYLOAD_B64"); b64 != "" {{
		if data, err := base64.StdEncoding.DecodeString(b64); err == nil {{
			return string(data)
		}}
	}}
	return ""
}}
"#,
        pre_call = pre_call,
        call_expr = call_expr,
    )
}

fn generate_go_mod() -> String {
    "module nyx-harness\n\ngo 1.21\n".to_owned()
}

/// Build `(pre_call_setup, call_expression)` for the chosen payload slot.
fn build_call(spec: &HarnessSpec, entry_fn: &str) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(0) => {
            let pre = String::new();
            let call = format!("entry.{entry_fn}(payload)");
            (pre, call)
        }
        PayloadSlot::EnvVar(name) => {
            let pre = format!("\tos.Setenv({name:?}, payload)\n");
            let call = format!("entry.{entry_fn}()");
            (pre, call)
        }
        _ => {
            let pre = String::new();
            let call = format!("entry.{entry_fn}(payload)");
            (pre, call)
        }
    }
}

/// Capitalize the first character of a string (Go exported names must start uppercase).
pub fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
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
            finding_id: "go0000000000001".into(),
            entry_file: "cmd/server/main.go".into(),
            entry_name: "handleRequest".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Go,
            toolchain_id: "go-stable".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "cmd/server/main.go".into(),
            sink_line: 20,
            spec_hash: "go0000000000001".into(),
        }
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("nyx-harness/entry"));
        assert!(harness.source.contains("nyxPayload()"));
        assert!(harness.source.contains("entry.HandleRequest(payload)"));
        assert_eq!(harness.filename, "main.go");
        assert_eq!(harness.command, vec!["./nyx_harness"]);
    }

    #[test]
    fn emit_includes_go_mod_in_extra_files() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        let go_mod = harness.extra_files.iter().find(|(n, _)| n == "go.mod");
        assert!(go_mod.is_some(), "go.mod must be in extra_files");
        assert!(go_mod.unwrap().1.contains("module nyx-harness"));
    }

    #[test]
    fn emit_entry_subpath_is_entry_go() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("entry/entry.go".to_owned()));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("DB_USER".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("os.Setenv"));
        assert!(harness.source.contains("\"DB_USER\""));
    }

    #[test]
    fn emit_param_gt_0_is_unsupported() {
        let spec = make_spec(PayloadSlot::Param(1));
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::EntryKindUnsupported);
    }

    #[test]
    fn emit_stdin_is_unsupported() {
        let spec = make_spec(PayloadSlot::Stdin);
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::EntryKindUnsupported);
    }

    #[test]
    fn capitalize_first_handles_lowercase() {
        assert_eq!(capitalize_first("handleRequest"), "HandleRequest");
        assert_eq!(capitalize_first("run"), "Run");
        assert_eq!(capitalize_first(""), "");
        assert_eq!(capitalize_first("A"), "A");
    }

    #[test]
    fn go_mod_has_correct_module() {
        let go_mod = generate_go_mod();
        assert!(go_mod.contains("module nyx-harness"));
        assert!(go_mod.contains("go 1.21"));
    }
}
