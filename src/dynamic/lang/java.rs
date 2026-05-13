//! Java harness emitter.
//!
//! Generates a Java `NyxHarness.java` that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. Calls `Entry.{entry_name}(payload)` from the co-located `Entry.java`.
//! 3. Catches all exceptions to prevent harness crashes from masking results.
//!
//! Sink-reachability probe: fixtures explicitly emit `System.out.println("__NYX_SINK_HIT__")`
//! before the actual sink call (same pattern as Rust and Go fixtures).
//!
//! Build step: `prepare_java()` in `build_sandbox.rs` runs `javac NyxHarness.java Entry.java`
//! in the workdir. The compiled `.class` files land in the workdir.
//!
//! File layout in workdir:
//! ```text
//! NyxHarness.java   ← harness main class (generated)
//! Entry.java        ← entry class (copied from project)
//! NyxHarness.class  ← compiled by prepare_java()
//! Entry.class       ← compiled by prepare_java()
//! ```
//!
//! Payload slot support:
//! - `PayloadSlot::Param(0)` — pass payload as `String` first argument.
//! - `PayloadSlot::EnvVar(name)` — set system property before calling entry.
//! - Other slots produce `UnsupportedReason::EntryKindUnsupported`.
//!
//! Build container: `nyx-build-java:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::lang::HarnessSource;
use crate::dynamic::spec::{HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;

/// Emit a Java harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(0) | PayloadSlot::EnvVar(_) => {}
        _ => return Err(UnsupportedReason::EntryKindUnsupported),
    }

    let source = generate_harness_java(spec);

    Ok(HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        // Use absolute workdir classpath set by runner.rs after compilation.
        // Before runner.rs updates it, '.' works for process backend when run
        // from the workdir.
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files: vec![],
        entry_subpath: Some("Entry.java".to_owned()),
    })
}

fn generate_harness_java(spec: &HarnessSpec) -> String {
    let entry_method = &spec.entry_name;
    let (pre_call, call_expr) = build_call(spec, entry_method);

    format!(
        r#"// Nyx dynamic harness — auto-generated, do not edit.
public class NyxHarness {{
    public static void main(String[] args) throws Exception {{
        String payload = nyxPayload();
{pre_call}        try {{
            {call_expr}
        }} catch (Exception e) {{
            System.err.println("NYX_EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
        }}
    }}

    static String nyxPayload() {{
        String v = System.getenv("NYX_PAYLOAD");
        if (v != null && !v.isEmpty()) {{
            return v;
        }}
        String b64 = System.getenv("NYX_PAYLOAD_B64");
        if (b64 != null && !b64.isEmpty()) {{
            byte[] decoded = java.util.Base64.getDecoder().decode(b64);
            return new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        }}
        return "";
    }}
}}
"#,
        pre_call = pre_call,
        call_expr = call_expr,
    )
}

/// Build `(pre_call_setup, call_expression)` for the chosen payload slot.
fn build_call(spec: &HarnessSpec, method: &str) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(0) => {
            let pre = String::new();
            let call = format!("Entry.{method}(payload);");
            (pre, call)
        }
        PayloadSlot::EnvVar(name) => {
            // Use System.setProperty since env vars cannot be set post-JVM-launch
            // via standard Java APIs. Fixtures that read env vars must use
            // System.getProperty as a fallback, or read NYX_PAYLOAD_PROP_{name}.
            let pre = format!(
                "        System.setProperty({name:?}, payload);\n"
            );
            let call = format!("Entry.{method}();");
            (pre, call)
        }
        _ => {
            let pre = String::new();
            let call = format!("Entry.{method}(payload);");
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
            finding_id: "java00000000001".into(),
            entry_file: "src/main/java/App.java".into(),
            entry_name: "processInput".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Java,
            toolchain_id: "java-21".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/main/java/App.java".into(),
            sink_line: 25,
            spec_hash: "java00000000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
        }
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("public class NyxHarness"));
        assert!(harness.source.contains("nyxPayload()"));
        assert!(harness.source.contains("Entry.processInput(payload)"));
        assert_eq!(harness.filename, "NyxHarness.java");
        assert_eq!(harness.command, vec!["java", "-cp", ".", "NyxHarness"]);
    }

    #[test]
    fn emit_entry_subpath_is_entry_java() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("Entry.java".to_owned()));
    }

    #[test]
    fn emit_env_var_slot() {
        let spec = make_spec(PayloadSlot::EnvVar("DB_PASSWORD".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("System.setProperty"));
        assert!(harness.source.contains("\"DB_PASSWORD\""));
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
    fn harness_has_base64_decoder() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("Base64.getDecoder()"));
        assert!(harness.source.contains("NYX_PAYLOAD_B64"));
    }
}
