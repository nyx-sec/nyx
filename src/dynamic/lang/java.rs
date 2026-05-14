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
//! - Other slots produce `UnsupportedReason::PayloadSlotUnsupported`.
//!
//! Build container: `nyx-build-java:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for Java.  Method bodies delegate to the
/// existing free functions in this module.
pub struct JavaEmitter;

/// Entry kinds the Java emitter currently understands.  Extended in Phase 14
/// (Track B Java vertical) to include `HttpRoute` (servlet / Spring /
/// Quarkus) and JUnit static-method shapes.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

impl LangEmitter for JavaEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "java emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — Track B will add servlet / Spring / Quarkus shapes in phase 14"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_java(env)
    }
}

/// Phase 09 — Track D.2: synthesise a minimal `pom.xml` that pins the
/// Java toolchain and lists the direct dep top-level packages as
/// dependencies.  Each direct dep maps to `<groupId>{pkg}</groupId>`
/// with an artifact id matching the package name; this is a best-effort
/// stub and Phase 10 corpus expansion will introduce a known-good
/// group→artifact registry.
pub fn materialize_java(env: &Environment) -> RuntimeArtifacts {
    let mut artifacts = RuntimeArtifacts::new();
    let java_version = env
        .toolchain
        .version_string
        .split('.')
        .next()
        .unwrap_or("21")
        .to_owned();
    let mut deps: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for d in &env.direct_deps {
        if is_java_stdlib(d) {
            continue;
        }
        if seen.insert(d.clone()) {
            deps.push(d.clone());
        }
    }
    deps.sort_unstable();

    let mut body = String::with_capacity(256);
    body.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    body.push_str("<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n");
    body.push_str("  <modelVersion>4.0.0</modelVersion>\n");
    body.push_str("  <groupId>nyx</groupId>\n");
    body.push_str("  <artifactId>harness</artifactId>\n");
    body.push_str("  <version>0.0.1</version>\n");
    body.push_str("  <properties>\n");
    body.push_str(&format!(
        "    <maven.compiler.source>{java_version}</maven.compiler.source>\n"
    ));
    body.push_str(&format!(
        "    <maven.compiler.target>{java_version}</maven.compiler.target>\n"
    ));
    body.push_str("  </properties>\n");
    if !deps.is_empty() {
        body.push_str("  <dependencies>\n");
        for d in &deps {
            body.push_str("    <dependency>\n");
            body.push_str(&format!("      <groupId>{d}</groupId>\n"));
            body.push_str(&format!("      <artifactId>{d}</artifactId>\n"));
            body.push_str("      <version>LATEST</version>\n");
            body.push_str("    </dependency>\n");
        }
        body.push_str("  </dependencies>\n");
    }
    body.push_str("</project>\n");
    artifacts.push("pom.xml", body);
    artifacts
}

fn is_java_stdlib(name: &str) -> bool {
    // Best-effort: only `java` / `javax` / `sun` are guaranteed JDK.
    // `jakarta` ships separately under Jakarta EE so it stays out.
    // Top-level segments `com` / `org` cover both JDK (`com.sun`) and
    // third-party (`com.google`, `org.springframework`) — the import
    // extractor only keeps the first segment, so a richer registry has
    // to land before we can pin a meaningful Maven artifact from these.
    // Phase 10 corpus expansion ships that registry.
    matches!(name, "java" | "javax" | "sun" | "com" | "org" | "jakarta")
}

/// Source of the `__nyx_probe` shim for the Java harness (Phase 06 —
/// Track C.1).
///
/// Splices into the generated harness class as a `static void __nyx_probe(...)`
/// method.  Hand-rolled JSON keeps the shim free of org.json / jackson
/// dependencies; matches the
/// [`crate::dynamic::probe::SinkProbe`] wire format.
pub fn probe_shim() -> &'static str {
    r#"
    // ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ──
    private static final String[] __NYX_DENY = {
        "TOKEN","SECRET","PASSWORD","PASSWD","API_KEY","APIKEY","PRIVATE_KEY",
        "CREDENTIAL","SESSION","COOKIE","AUTH","BEARER","AWS_ACCESS","AWS_SESSION",
        "GH_TOKEN","GITHUB_TOKEN","NPM_TOKEN","PYPI_TOKEN","DOCKER_PASS"
    };
    private static final int __NYX_PAYLOAD_LIMIT = 16 * 1024;
    private static final String __NYX_REDACTED = "<redacted-by-nyx-policy>";

    private static boolean nyxIsDeniedKey(String k) {
        String ku = k.toUpperCase();
        for (String n : __NYX_DENY) {
            if (ku.contains(n)) return true;
        }
        return false;
    }

    private static String nyxWitnessJson(String sinkCallee, String[] args) {
        StringBuilder out = new StringBuilder(256);
        out.append("{\"env_snapshot\":{");
        boolean first = true;
        java.util.TreeMap<String,String> envSorted = new java.util.TreeMap<>(System.getenv());
        for (java.util.Map.Entry<String,String> e : envSorted.entrySet()) {
            if (!first) out.append(',');
            first = false;
            out.append('"'); nyxJsonEscape(e.getKey(), out); out.append("\":\"");
            if (nyxIsDeniedKey(e.getKey())) {
                out.append(__NYX_REDACTED);
            } else {
                nyxJsonEscape(e.getValue() == null ? "" : e.getValue(), out);
            }
            out.append('"');
        }
        out.append("},\"cwd\":\"");
        nyxJsonEscape(System.getProperty("user.dir", ""), out);
        out.append("\",\"payload_bytes\":[");
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload != null) {
            byte[] pb = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            int cap = Math.min(pb.length, __NYX_PAYLOAD_LIMIT);
            for (int i = 0; i < cap; i++) {
                if (i > 0) out.append(',');
                out.append(((int) pb[i]) & 0xff);
            }
        }
        out.append("],\"callee\":\""); nyxJsonEscape(sinkCallee, out);
        out.append("\",\"args_repr\":[");
        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                if (i > 0) out.append(',');
                out.append('"'); nyxJsonEscape(args[i] == null ? "" : args[i], out); out.append('"');
            }
        }
        out.append("]}");
        return out.toString();
    }

    private static void nyxEmit(String line) {
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        try (java.io.FileWriter fw = new java.io.FileWriter(p, true)) {
            fw.write(line);
        } catch (java.io.IOException e) {
            // best-effort
        }
    }

    static void __nyx_probe(String sinkCallee, String... args) {
        long now = System.nanoTime();
        String payloadId = System.getenv("NYX_PAYLOAD_ID");
        if (payloadId == null) payloadId = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{\"sink_callee\":\"");
        nyxJsonEscape(sinkCallee, line);
        line.append("\",\"args\":[");
        for (int i = 0; i < args.length; i++) {
            if (i > 0) line.append(',');
            line.append("{\"kind\":\"String\",\"value\":\"");
            nyxJsonEscape(args[i] == null ? "" : args[i], line);
            line.append("\"}");
        }
        line.append("],\"captured_at_ns\":").append(now).append(",\"payload_id\":\"");
        nyxJsonEscape(payloadId, line);
        line.append("\",\"kind\":{\"kind\":\"Normal\"},\"witness\":");
        line.append(nyxWitnessJson(sinkCallee, args));
        line.append("}\n");
        nyxEmit(line.toString());
    }

    // Phase 08: install a sink-site Throwable handler.  Java cannot catch
    // SIGSEGV / SIGFPE directly (JVM aborts), but it can intercept the
    // uncaught-exception path which fires for any Error / RuntimeException
    // escaping the sink call.  Map them onto SIGABRT for the oracle.
    static void __nyx_install_crash_guard(String sinkCallee) {
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            long now = System.nanoTime();
            String payloadId = System.getenv("NYX_PAYLOAD_ID");
            if (payloadId == null) payloadId = "";
            StringBuilder line = new StringBuilder(256);
            line.append("{\"sink_callee\":\"");
            nyxJsonEscape(sinkCallee, line);
            line.append("\",\"args\":[],\"captured_at_ns\":").append(now)
                .append(",\"payload_id\":\"");
            nyxJsonEscape(payloadId, line);
            line.append("\",\"kind\":{\"kind\":\"Crash\",\"signal\":\"SIGABRT\"},\"witness\":");
            line.append(nyxWitnessJson(sinkCallee, new String[0]));
            line.append("}\n");
            nyxEmit(line.toString());
            System.exit(134);
        });
    }

    private static void nyxJsonEscape(String s, StringBuilder out) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
    }
"#
}

/// Emit a Java harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(0) | PayloadSlot::EnvVar(_) => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
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
            stubs_required: vec![],
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
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
    }

    #[test]
    fn emit_stdin_is_unsupported() {
        let spec = make_spec(PayloadSlot::Stdin);
        let err = emit(&spec).unwrap_err();
        assert_eq!(err, UnsupportedReason::PayloadSlotUnsupported);
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!JavaEmitter.entry_kinds_supported().is_empty());
        assert!(JavaEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::Function));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = JavaEmitter.entry_kind_hint(EntryKind::HttpRoute);
        assert!(hint.contains("HttpRoute"));
        assert!(hint.contains("phase 14"));
    }

    #[test]
    fn harness_has_base64_decoder() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("Base64.getDecoder()"));
        assert!(harness.source.contains("NYX_PAYLOAD_B64"));
    }
}
