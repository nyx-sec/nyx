//! Java harness emitter.
//!
//! Phase 14 (Track B Java vertical) replaces the single legacy `emit`
//! body with dispatch over [`JavaShape`] — the cross product of
//! [`EntryKind`] and a lightweight per-file shape detector that inspects
//! the entry file for servlet / Spring / Quarkus annotations, JUnit
//! markers, and `static main(String[])` signatures.
//!
//! Each shape emits a single `NyxHarness.java` that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64`.
//! 2. Locates the entry class (default-package, derived from the entry
//!    file basename) and invokes its method via the per-shape adapter.
//! 3. Catches all exceptions so the JVM exit shape stays observable.
//!
//! Sink-reachability probe: fixtures explicitly emit
//! `System.out.println("__NYX_SINK_HIT__")` before the actual sink call
//! (same pattern as Rust and Go fixtures).
//!
//! Build step: `prepare_java()` in `build_sandbox.rs` runs `javac` over
//! every `*.java` file in the workdir.  Shape fixtures bundle their own
//! annotation / type stubs (e.g. a minimal `HttpServletRequest.java`
//! when the shape needs servlet plumbing) so the JDK can compile the
//! source without pulling Maven dependencies.
//!
//! Payload slot support:
//! - [`PayloadSlot::Param`] — pass payload as `String` first argument
//!   (n-th positional for `Param(n)` where `n > 0`).
//! - [`PayloadSlot::EnvVar`] — set a system property before invocation.
//! - [`PayloadSlot::QueryParam`] / [`PayloadSlot::HttpBody`] — surfaced
//!   to servlet / Spring / Quarkus adapters as the request body or
//!   query parameter value.
//! - [`PayloadSlot::Argv`] — appended to a `String[] args` for
//!   `static main` shapes.
//! - Other slots produce [`UnsupportedReason::PayloadSlotUnsupported`].
//!
//! Build container: `nyx-build-java:{toolchain_id}` (deferred; §19.1).

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{ChainStepHarness, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for Java.  Method bodies delegate to the
/// existing free functions in this module.
pub struct JavaEmitter;

/// Entry kinds the Java emitter understands after Phase 14.
///
/// `HttpRoute` covers servlet / Spring / Quarkus shapes.  `CliSubcommand`
/// covers `public static void main(String[])`.  `Function` covers JUnit
/// tests and plain static methods.
const SUPPORTED: &[EntryKind] = &[
    EntryKind::Function,
    EntryKind::HttpRoute,
    EntryKind::CliSubcommand,
];

impl LangEmitter for JavaEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "java emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 14 shape dispatch"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_java(env)
    }

    fn compose_chain_step(&self, prev_output: Option<&[u8]>) -> ChainStepHarness {
        chain_step(prev_output)
    }
}

/// Phase 26 — Java chain-step harness.
///
/// Emits a `Step.java` class whose `main` reads `NYX_PREV_OUTPUT` and
/// forwards it on stdout.  The command shell-wraps `javac` + `java` so
/// the step actually runs after the build step completes (the
/// `ChainStepHarness.command` slot models a single process).
///
/// The Java probe shim (`__nyx_probe`, `__nyx_install_crash_guard`,
/// helpers) is spliced as class-member declarations inside `class Step
/// { … }` between the class-open brace and `public static void main`,
/// so a downstream sink rewrite within the step body has the shim
/// helpers already in scope.  The shim uses only `java.lang.*` plus
/// fully-qualified `java.util.TreeMap` / `java.io.FileWriter` /
/// `java.nio.charset.StandardCharsets`, so no extra `import` lines
/// are needed beyond what stock Java implicitly imports.
fn chain_step(prev_output: Option<&[u8]>) -> ChainStepHarness {
    let shim = probe_shim();
    let source = format!(
        "public class Step {{\n{shim}\n    public static void main(String[] args) {{\n        String prev = System.getenv(\"NYX_PREV_OUTPUT\");\n        if (prev == null) prev = \"\";\n        System.out.print(prev);\n    }}\n}}\n"
    );
    ChainStepHarness {
        source,
        filename: "Step.java".to_owned(),
        command: vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "javac Step.java && java Step".to_owned(),
        ],
        extra_env: prev_output
            .map(|bytes| {
                vec![(
                    ChainStepHarness::PREV_OUTPUT_ENV.to_owned(),
                    String::from_utf8_lossy(bytes).into_owned(),
                )]
            })
            .unwrap_or_default(),
        extra_files: Vec::new(),
    }
}

// ── Phase 14: shape detector ─────────────────────────────────────────────────

/// Concrete per-file shape resolved by reading the entry source.
///
/// One harness template per variant.  When the entry file is unreadable
/// or no marker fires the detector defaults to [`JavaShape::StaticMethod`],
/// which preserves the pre-Phase-14 behaviour (direct static method call).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaShape {
    /// `public class … extends HttpServlet { void doGet(req, resp) }`.
    /// Harness instantiates the class via the default constructor and
    /// invokes `doGet` with a minimal `HttpServletRequest` / `Response`
    /// stub-pair via reflection.
    ServletDoGet,
    /// `void doPost(req, resp)` variant.  Same adapter shape as doGet
    /// but uses `POST` semantics for query-vs-body wiring.
    ServletDoPost,
    /// Spring `@RestController` / `@Controller` with a `@RequestMapping`
    /// / `@GetMapping` / `@PostMapping` handler.  Harness instantiates
    /// the controller via reflection (default ctor) and invokes the
    /// handler method with the payload routed into the matching
    /// `String` parameter.
    SpringController,
    /// `public static void main(String[] args)`.  Harness calls
    /// `Class.forName(name).getMethod("main", String[].class)` and
    /// passes a one-element argv populated from the payload.
    StaticMain,
    /// JUnit 4 (`@Test`) or JUnit 5 (`@Test` from `org.junit.jupiter.api`).
    /// Harness instantiates the test class and invokes the annotated
    /// method via reflection — no JUnit runner needed since we drive a
    /// single test method.
    JunitTest,
    /// Quarkus reactive route: `@Path("/foo")` + `@GET`/`@POST` on a
    /// method.  Harness invokes the method via reflection like Spring.
    QuarkusRoute,
    /// Plain static method — legacy default behaviour from before
    /// Phase 14.  Harness directly calls `{Class}.{method}(payload)`.
    StaticMethod,
}

impl JavaShape {
    /// Detect the shape from `(spec, source)`.  `source` is the literal
    /// bytes of the entry file (best-effort — if it could not be read,
    /// pass an empty string and the function returns
    /// [`Self::StaticMethod`]).
    ///
    /// Framework / annotation detection wins over the [`EntryKind`]
    /// axis: when the source clearly imports a servlet or Spring
    /// controller the shape is selected even if the spec derivation
    /// pipeline tagged the entry kind as [`EntryKind::Function`].
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let entry = spec.entry_name.as_str();
        let kind = spec.entry_kind;

        let has_servlet = source.contains("HttpServlet")
            || source.contains("javax.servlet")
            || source.contains("jakarta.servlet");
        let has_spring_controller = source.contains("@RestController")
            || source.contains("@Controller")
            || source.contains("@RequestMapping")
            || source.contains("@GetMapping")
            || source.contains("@PostMapping");
        let has_quarkus = source.contains("@Path(")
            || source.contains("io.quarkus")
            || source.contains("jakarta.ws.rs");
        let has_junit = source.contains("@Test")
            && (source.contains("org.junit") || source.contains("junit.framework"));
        let has_main = entry == "main" || source.contains("static void main(");

        // Servlet beats Spring when both fire (e.g. a Spring app that
        // mounts a raw servlet) — the doGet/doPost signature is more
        // specific.
        if has_servlet {
            if entry == "doPost" || source.contains("void doPost(") {
                return Self::ServletDoPost;
            }
            if entry == "doGet" || source.contains("void doGet(") {
                return Self::ServletDoGet;
            }
            return Self::ServletDoGet;
        }
        if has_quarkus {
            return Self::QuarkusRoute;
        }
        if has_spring_controller {
            return Self::SpringController;
        }
        if has_main {
            return Self::StaticMain;
        }
        if has_junit {
            return Self::JunitTest;
        }

        if kind == EntryKind::CliSubcommand {
            return Self::StaticMain;
        }
        if kind == EntryKind::HttpRoute {
            return Self::SpringController;
        }
        Self::StaticMethod
    }
}

// (Helper retired in Phase 14 — the shape detector now uses direct
// `source.contains` matches against the method-signature head because
// the JDK accepts whitespace / newline / modifier variation that no
// single template captures.)


// ── Probe shim (Phase 06 + Phase 08) ─────────────────────────────────────────

/// Source of the `__nyx_probe` shim for the Java harness (Phase 06 —
/// Track C.1).
///
/// Splices into the generated harness class as a `static void __nyx_probe(...)`
/// method.  Hand-rolled JSON keeps the shim free of org.json / jackson
/// dependencies; matches the
/// [`crate::dynamic::probe::SinkProbe`] wire format.
pub fn probe_shim() -> &'static str {
    r##"
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

    // Phase 10 (Track D.3) HTTP recording helper.  When the verifier spawned an
    // HttpStub it publishes the side-channel log path through NYX_HTTP_LOG; a
    // sink call site whose outbound request never reaches the on-the-wire
    // listener (DNS-mocked, network-isolated sandbox, pre-flight check) can
    // call this helper to surface the attempted call.  Format matches the
    // Python / Node / PHP / Go / Ruby siblings so the host-side HttpStub
    // log-line merger parses all six streams identically.  No-op when
    // NYX_HTTP_LOG is unset so the same harness still runs cleanly under
    // modes that did not spawn a stub.  The hash prefix is emitted via
    // String.valueOf('#') so this method body contains no literal hash-after-
    // double-quote sequence that would terminate the surrounding Rust raw
    // string.
    static void __nyx_stub_http_record(String method, String url, String body, java.util.Map<String,String> detail) {
        String p = System.getenv("NYX_HTTP_LOG");
        if (p == null || p.isEmpty()) return;
        String hashSp = String.valueOf('#') + " ";
        try (java.io.FileWriter fw = new java.io.FileWriter(p, true)) {
            fw.write(hashSp + "method: " + method + "\n");
            fw.write(hashSp + "url: " + url + "\n");
            if (body != null) {
                fw.write(hashSp + "body: " + body + "\n");
            }
            if (detail != null) {
                for (java.util.Map.Entry<String,String> e : detail.entrySet()) {
                    fw.write(hashSp + e.getKey() + ": " + e.getValue() + "\n");
                }
            }
            fw.write(method + " " + url + "\n");
        } catch (java.io.IOException e) {
            // best-effort
        }
    }

    // Phase 10 (Track D.3) SQL recording helper.  When the verifier spawned a
    // SqlStub it publishes the side-channel log path through NYX_SQL_LOG; a
    // sink call site whose query never reaches the on-the-wire SQLite engine
    // (e.g. classpath lacks sqlite-jdbc, or the harness pre-flights the SQL
    // string before opening the connection) can call this helper to surface
    // the attempted query.  Hash-prefixed detail lines followed by the query
    // line so SqlStub::drain_events parses every language stream identically.
    // Same hash-via-String.valueOf trick as __nyx_stub_http_record so this
    // method body contains no literal `"#` sequence that would terminate the
    // surrounding Rust raw string.
    static void __nyx_stub_sql_record(String query, java.util.Map<String,String> detail) {
        String p = System.getenv("NYX_SQL_LOG");
        if (p == null || p.isEmpty()) return;
        String hashSp = String.valueOf('#') + " ";
        try (java.io.FileWriter fw = new java.io.FileWriter(p, true)) {
            if (detail != null) {
                for (java.util.Map.Entry<String,String> e : detail.entrySet()) {
                    fw.write(hashSp + e.getKey() + ": " + e.getValue() + "\n");
                }
            }
            fw.write(query);
            if (!query.endsWith("\n")) {
                fw.write("\n");
            }
        } catch (java.io.IOException e) {
            // best-effort
        }
    }
"##
}

// ── Runtime / pom.xml synthesis (Phase 09) ──────────────────────────────────

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

// ── Public entry: emit() ────────────────────────────────────────────────────

/// Emit a Java harness for `spec`.
///
/// Reads `spec.entry_file` from disk (best-effort), resolves the
/// concrete [`JavaShape`] via [`JavaShape::detect`], and dispatches to
/// the matching per-shape emitter.  When the file cannot be read the
/// dispatcher falls back to [`JavaShape::StaticMethod`], preserving the
/// pre-Phase-14 behaviour.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_)
        | PayloadSlot::EnvVar(_)
        | PayloadSlot::QueryParam(_)
        | PayloadSlot::HttpBody
        | PayloadSlot::Argv(_) => {}
        PayloadSlot::Stdin => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    let entry_source = read_entry_source(&spec.entry_file);
    let shape = JavaShape::detect(spec, &entry_source);
    let entry_class = derive_entry_class(&entry_source);
    let source = generate_harness_java(spec, shape, &entry_class);

    Ok(HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files: vec![],
        // Stage the entry file under the public-class-derived filename
        // so javac's filename-vs-public-class invariant holds for both
        // the legacy `public class Entry` fixtures (which keep being
        // copied to `workdir/Entry.java`) and the Phase 14 shape
        // fixtures (where `public class Vuln` lives in `Vuln.java`).
        entry_subpath: Some(format!("{entry_class}.java")),
    })
}

/// Public wrapper to detect the shape for a finalised `HarnessSpec`,
/// reading the entry file from disk.  Exposed so test helpers can pin a
/// per-fixture shape without round-tripping through [`emit`].
pub fn detect_shape(spec: &HarnessSpec) -> JavaShape {
    let entry_source = read_entry_source(&spec.entry_file);
    JavaShape::detect(spec, &entry_source)
}

fn read_entry_source(entry_file: &str) -> String {
    let candidates = [
        PathBuf::from(entry_file),
        PathBuf::from(".").join(entry_file),
    ];
    for path in &candidates {
        if let Ok(s) = std::fs::read_to_string(path) {
            return s;
        }
    }
    String::new()
}

/// Locate the harness's target class by parsing the entry source for a
/// `public class X` (or `public final class X` / `public abstract class
/// X`) declaration.  Falls back to `"Entry"` when the source is empty
/// or no public-class line is present.
///
/// The returned name drives both the in-harness invocation
/// (`{class}.method(...)` / `Class.forName(class)`) and the
/// `entry_subpath` (`{class}.java`) so javac's filename-vs-public-class
/// invariant holds for both the legacy `public class Entry` fixtures
/// and the Phase 14 shape fixtures that ship `public class Vuln`
/// (or `public class Benign`).
fn derive_entry_class(source: &str) -> String {
    parse_public_class_name(source).unwrap_or_else(|| "Entry".to_owned())
}

fn parse_public_class_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let l = line.trim_start();
        let rest = match l
            .strip_prefix("public class ")
            .or_else(|| l.strip_prefix("public final class "))
            .or_else(|| l.strip_prefix("public abstract class "))
        {
            Some(r) => r,
            None => continue,
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

// ── Per-shape harness generation ────────────────────────────────────────────

fn generate_harness_java(spec: &HarnessSpec, shape: JavaShape, entry_class: &str) -> String {
    let probe = probe_shim();
    let pre_call = pre_call_setup(spec);
    let invocation = invoke_for_shape(spec, shape, entry_class);
    let helpers = shape_helpers(shape);

    // Reflection-driven shapes throw `InvocationTargetException` on
    // user-code failure; non-reflection shapes (`StaticMethod`,
    // `StaticMain`) call the entry directly and would surface an
    // "unreachable catch" javac error if the specific catch clause is
    // kept.  Emit only the broad `Throwable` catch for those shapes.
    let extra_catch = if shape_uses_reflection(shape) {
        r#"        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause() == null ? ite : ite.getCause();
            System.err.println("NYX_EXCEPTION: " + cause.getClass().getName() + ": " + cause.getMessage());
        "#
    } else {
        ""
    };

    // Reflection imports are only used by shapes whose helpers / catch
    // clause reference them; emitting them for `StaticMethod` /
    // `StaticMain` produces unused-import warnings under javac -Xlint.
    let imports = if shape_uses_reflection(shape) {
        "import java.lang.reflect.Method;\nimport java.lang.reflect.Constructor;\nimport java.lang.reflect.InvocationTargetException;\n\n"
    } else {
        ""
    };

    format!(
        r#"// Nyx dynamic harness — auto-generated, do not edit (Phase 14 — JavaShape::{shape:?}).
{imports}public class NyxHarness {{
{probe}
{helpers}
    public static void main(String[] args) {{
        String payload = nyxPayload();
{pre_call}        try {{
{invocation}
{extra_catch}}} catch (Throwable e) {{
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
        shape = shape,
        imports = imports,
        probe = probe,
        helpers = helpers,
        pre_call = pre_call,
        invocation = invocation,
    )
}

fn pre_call_setup(spec: &HarnessSpec) -> String {
    match &spec.payload_slot {
        PayloadSlot::EnvVar(name) => {
            format!("        System.setProperty({name:?}, payload);\n")
        }
        _ => String::new(),
    }
}

/// Emit the per-shape entry-invocation block.  Shapes that need
/// reflection plumbing rely on helpers from [`shape_helpers`].
fn invoke_for_shape(spec: &HarnessSpec, shape: JavaShape, entry_class: &str) -> String {
    let method = spec.entry_name.as_str();
    match shape {
        JavaShape::StaticMethod => format!("            {entry_class}.{method}(payload);"),
        JavaShape::StaticMain => format!(
            "            String[] mainArgs = new String[] {{ payload }};\n            {entry_class}.main(mainArgs);"
        ),
        JavaShape::ServletDoGet => format!(
            "            invokeServlet({entry_class}.class, \"doGet\", payload, \"GET\");"
        ),
        JavaShape::ServletDoPost => format!(
            "            invokeServlet({entry_class}.class, \"doPost\", payload, \"POST\");"
        ),
        JavaShape::SpringController => format!(
            "            invokeReflective({entry_class}.class, \"{method}\", payload);"
        ),
        JavaShape::QuarkusRoute => format!(
            "            invokeReflective({entry_class}.class, \"{method}\", payload);"
        ),
        JavaShape::JunitTest => format!(
            "            invokeJunitTest({entry_class}.class, \"{method}\");"
        ),
    }
}

/// Per-shape helper methods spliced into the harness class.
fn shape_helpers(shape: JavaShape) -> &'static str {
    match shape {
        JavaShape::StaticMethod | JavaShape::StaticMain => "",
        JavaShape::ServletDoGet | JavaShape::ServletDoPost => SERVLET_HELPER,
        JavaShape::SpringController | JavaShape::QuarkusRoute => REFLECTIVE_HELPER,
        JavaShape::JunitTest => JUNIT_HELPER,
    }
}

fn shape_uses_reflection(shape: JavaShape) -> bool {
    !matches!(shape, JavaShape::StaticMethod | JavaShape::StaticMain)
}

/// Reflective servlet invocation.  Walks `cls`'s declared methods for a
/// match on `methodName` and invokes with `(StubReq, StubResp)`.  When
/// the fixture's `doGet`/`doPost` takes only a `String` payload (the
/// stub-free path used by many fixtures), the helper falls back to
/// `invokeReflective`.
const SERVLET_HELPER: &str = r#"
    static void invokeServlet(Class<?> cls, String methodName, String payload, String httpMethod) throws Exception {
        Method match = null;
        for (Method m : cls.getDeclaredMethods()) {
            if (!m.getName().equals(methodName)) continue;
            match = m;
            break;
        }
        if (match == null) {
            throw new NoSuchMethodException(cls.getName() + "." + methodName);
        }
        match.setAccessible(true);
        Object instance = null;
        if (!java.lang.reflect.Modifier.isStatic(match.getModifiers())) {
            instance = newDefaultInstance(cls);
        }
        Class<?>[] params = match.getParameterTypes();
        Object[] args = new Object[params.length];
        for (int i = 0; i < params.length; i++) {
            Class<?> p = params[i];
            if (p.equals(String.class)) {
                args[i] = payload;
            } else if (p.getName().endsWith("HttpServletRequest")) {
                args[i] = buildRequestStub(p, payload, httpMethod);
            } else if (p.getName().endsWith("HttpServletResponse")) {
                args[i] = buildResponseStub(p);
            } else {
                args[i] = null;
            }
        }
        match.invoke(instance, args);
    }

    static Object newDefaultInstance(Class<?> cls) throws Exception {
        Constructor<?> ctor = cls.getDeclaredConstructor();
        ctor.setAccessible(true);
        return ctor.newInstance();
    }

    static Object buildRequestStub(Class<?> reqType, String payload, String method) throws Exception {
        // Best-effort: invoke a no-arg constructor and call any
        // `setParameter`/`setMethod` setters the stub exposes.  When
        // the type cannot be instantiated, fall back to null and let
        // the fixture handle the missing parameter.
        try {
            Constructor<?> ctor = reqType.getDeclaredConstructor();
            ctor.setAccessible(true);
            Object stub = ctor.newInstance();
            try {
                Method setParam = reqType.getMethod("setParameter", String.class, String.class);
                setParam.invoke(stub, "payload", payload);
            } catch (NoSuchMethodException ignore) {}
            try {
                Method setMethod = reqType.getMethod("setMethod", String.class);
                setMethod.invoke(stub, method);
            } catch (NoSuchMethodException ignore) {}
            try {
                Method setBody = reqType.getMethod("setBody", String.class);
                setBody.invoke(stub, payload);
            } catch (NoSuchMethodException ignore) {}
            return stub;
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    static Object buildResponseStub(Class<?> respType) throws Exception {
        try {
            Constructor<?> ctor = respType.getDeclaredConstructor();
            ctor.setAccessible(true);
            return ctor.newInstance();
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    static void invokeReflective(Class<?> cls, String methodName, String payload) throws Exception {
        Method match = null;
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getName().equals(methodName)) { match = m; break; }
        }
        if (match == null) {
            throw new NoSuchMethodException(cls.getName() + "." + methodName);
        }
        match.setAccessible(true);
        Object instance = null;
        if (!java.lang.reflect.Modifier.isStatic(match.getModifiers())) {
            instance = newDefaultInstance(cls);
        }
        Class<?>[] params = match.getParameterTypes();
        Object[] args = new Object[params.length];
        for (int i = 0; i < params.length; i++) {
            args[i] = params[i].equals(String.class) ? payload : null;
        }
        match.invoke(instance, args);
    }
"#;

/// Reflective Spring / Quarkus invocation.  Same shape as the servlet
/// reflective fallback but routed through a dedicated helper for
/// clarity in the generated harness.
const REFLECTIVE_HELPER: &str = r#"
    static Object newDefaultInstance(Class<?> cls) throws Exception {
        Constructor<?> ctor = cls.getDeclaredConstructor();
        ctor.setAccessible(true);
        return ctor.newInstance();
    }

    static void invokeReflective(Class<?> cls, String methodName, String payload) throws Exception {
        Method match = null;
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getName().equals(methodName)) { match = m; break; }
        }
        if (match == null) {
            throw new NoSuchMethodException(cls.getName() + "." + methodName);
        }
        match.setAccessible(true);
        Object instance = null;
        if (!java.lang.reflect.Modifier.isStatic(match.getModifiers())) {
            instance = newDefaultInstance(cls);
        }
        Class<?>[] params = match.getParameterTypes();
        Object[] args = new Object[params.length];
        for (int i = 0; i < params.length; i++) {
            args[i] = params[i].equals(String.class) ? payload : null;
        }
        match.invoke(instance, args);
    }
"#;

/// Reflective JUnit-shape invocation.  Reads the payload from
/// `NYX_PAYLOAD` (no method argument) — JUnit tests typically capture
/// inputs through fields or `System.getenv`.
const JUNIT_HELPER: &str = r#"
    static Object newDefaultInstance(Class<?> cls) throws Exception {
        Constructor<?> ctor = cls.getDeclaredConstructor();
        ctor.setAccessible(true);
        return ctor.newInstance();
    }

    static void invokeJunitTest(Class<?> cls, String methodName) throws Exception {
        Method match = null;
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getName().equals(methodName)) { match = m; break; }
        }
        if (match == null) {
            throw new NoSuchMethodException(cls.getName() + "." + methodName);
        }
        match.setAccessible(true);
        Object instance = null;
        if (!java.lang.reflect.Modifier.isStatic(match.getModifiers())) {
            instance = newDefaultInstance(cls);
        }
        match.invoke(instance);
    }
"#;

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
    fn emit_entry_subpath_default_static_method_is_entry_java() {
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
    fn emit_param_gt_0_is_accepted_for_static_method() {
        // Phase 14: PayloadSlot::Param(n>0) is no longer rejected; the
        // emitter routes the payload via the first-arg slot regardless
        // (the runner has already pinned the slot at spec time).
        let spec = make_spec(PayloadSlot::Param(1));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("processInput(payload)"));
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
        assert!(JavaEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::HttpRoute));
        assert!(JavaEmitter
            .entry_kinds_supported()
            .contains(&EntryKind::CliSubcommand));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = JavaEmitter.entry_kind_hint(EntryKind::LibraryApi);
        assert!(hint.contains("LibraryApi"));
        assert!(hint.contains("Phase 14"));
    }

    #[test]
    fn harness_has_base64_decoder() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("Base64.getDecoder()"));
        assert!(harness.source.contains("NYX_PAYLOAD_B64"));
    }

    // ── Phase 14: shape detection ────────────────────────────────────────────

    fn make_spec_with(kind: EntryKind, name: &str, entry_file: &str) -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.entry_kind = kind;
        s.entry_name = name.to_owned();
        s.entry_file = entry_file.to_owned();
        s
    }

    #[test]
    fn shape_detect_servlet_doget() {
        let src = "import javax.servlet.http.HttpServletRequest;\npublic class V extends HttpServlet { public void doGet(HttpServletRequest r, HttpServletResponse w) {} }";
        let spec = make_spec_with(EntryKind::HttpRoute, "doGet", "V.java");
        assert_eq!(JavaShape::detect(&spec, src), JavaShape::ServletDoGet);
    }

    #[test]
    fn shape_detect_servlet_dopost() {
        let src = "import jakarta.servlet.http.HttpServletRequest;\npublic class V extends HttpServlet { public void doPost(HttpServletRequest r, HttpServletResponse w) {} }";
        let spec = make_spec_with(EntryKind::HttpRoute, "doPost", "V.java");
        assert_eq!(JavaShape::detect(&spec, src), JavaShape::ServletDoPost);
    }

    #[test]
    fn shape_detect_spring_controller() {
        let src = "@RestController\npublic class V { @GetMapping(\"/x\") public String run(String p) { return p; } }";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "V.java");
        assert_eq!(JavaShape::detect(&spec, src), JavaShape::SpringController);
    }

    #[test]
    fn shape_detect_quarkus_route() {
        let src = "import jakarta.ws.rs.GET;\n@Path(\"/x\")\npublic class V { @GET public String run(String p) { return p; } }";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "V.java");
        assert_eq!(JavaShape::detect(&spec, src), JavaShape::QuarkusRoute);
    }

    #[test]
    fn shape_detect_static_main() {
        let src = "public class V { public static void main(String[] args) {} }";
        let spec = make_spec_with(EntryKind::CliSubcommand, "main", "V.java");
        assert_eq!(JavaShape::detect(&spec, src), JavaShape::StaticMain);
    }

    #[test]
    fn shape_detect_junit_test() {
        let src = "import org.junit.jupiter.api.Test;\npublic class V { @Test public void testRun() {} }";
        let spec = make_spec_with(EntryKind::Function, "testRun", "V.java");
        assert_eq!(JavaShape::detect(&spec, src), JavaShape::JunitTest);
    }

    #[test]
    fn shape_detect_static_method_fallback() {
        let src = "public class V { public static void run(String p) {} }";
        let spec = make_spec_with(EntryKind::Function, "run", "V.java");
        assert_eq!(JavaShape::detect(&spec, src), JavaShape::StaticMethod);
    }

    #[test]
    fn servlet_shape_emits_reflective_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "doGet", "Vuln.java");
        let src = generate_harness_java(&spec, JavaShape::ServletDoGet, "Vuln");
        assert!(src.contains("invokeServlet(Vuln.class"));
        assert!(src.contains("buildRequestStub"));
    }

    #[test]
    fn spring_shape_emits_reflective_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "Vuln.java");
        let src = generate_harness_java(&spec, JavaShape::SpringController, "Vuln");
        assert!(src.contains("invokeReflective(Vuln.class, \"run\""));
    }

    #[test]
    fn quarkus_shape_emits_reflective_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "Vuln.java");
        let src = generate_harness_java(&spec, JavaShape::QuarkusRoute, "Vuln");
        assert!(src.contains("invokeReflective(Vuln.class, \"run\""));
    }

    #[test]
    fn static_main_shape_passes_argv() {
        let spec = make_spec_with(EntryKind::CliSubcommand, "main", "Vuln.java");
        let src = generate_harness_java(&spec, JavaShape::StaticMain, "Vuln");
        assert!(src.contains("Vuln.main(mainArgs)"));
        assert!(src.contains("new String[] { payload }"));
    }

    #[test]
    fn junit_shape_emits_reflective_invocation() {
        let spec = make_spec_with(EntryKind::Function, "testRun", "Vuln.java");
        let src = generate_harness_java(&spec, JavaShape::JunitTest, "Vuln");
        assert!(src.contains("invokeJunitTest(Vuln.class"));
    }

    #[test]
    fn entry_class_parses_public_class_declaration() {
        assert_eq!(derive_entry_class("public class Vuln {}"), "Vuln");
        assert_eq!(derive_entry_class("public final class Foo {}"), "Foo");
        assert_eq!(derive_entry_class("public abstract class Bar {}"), "Bar");
        // No public class → "Entry" fallback.
        assert_eq!(derive_entry_class(""), "Entry");
        assert_eq!(derive_entry_class("class Pkg {}"), "Entry");
    }

    #[test]
    fn entry_subpath_matches_public_class() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        // Path does not exist on disk → derive_entry_class falls back
        // to "Entry" → subpath is "Entry.java".
        spec.entry_file = "/nonexistent/Vuln.java".into();
        let harness = emit(&spec).unwrap();
        assert_eq!(harness.entry_subpath, Some("Entry.java".to_owned()));
    }

    #[test]
    fn probe_shim_publishes_stub_http_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("static void __nyx_stub_http_record"),
            "Java probe shim must define __nyx_stub_http_record"
        );
        assert!(
            shim.contains("\"NYX_HTTP_LOG\""),
            "Java HTTP recorder must read NYX_HTTP_LOG to find the side-channel log"
        );
        assert!(
            shim.contains("\"method: \""),
            "Java HTTP recorder must emit a method detail line"
        );
        assert!(
            shim.contains("\"url: \""),
            "Java HTTP recorder must emit a url detail line"
        );
    }

    #[test]
    fn probe_shim_publishes_stub_sql_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("static void __nyx_stub_sql_record"),
            "Java probe shim must define __nyx_stub_sql_record"
        );
        assert!(
            shim.contains("\"NYX_SQL_LOG\""),
            "Java SQL recorder must read NYX_SQL_LOG to find the side-channel log"
        );
        assert!(
            shim.contains("query.endsWith(\"\\n\")"),
            "Java SQL recorder must guarantee a trailing newline on the query line so SqlStub::drain_events frames each record"
        );
    }

    #[test]
    fn chain_step_splices_probe_shim_for_composite_reverify() {
        let step = chain_step(Some(b"<prev>"));
        assert!(
            step.source.contains("__nyx_probe"),
            "Java chain step must splice the probe shim"
        );
        assert!(
            step.source.starts_with("public class Step {"),
            "Java chain step must open with the `public class Step {{` declaration"
        );
        assert!(
            step.source.contains("System.getenv(\"NYX_PREV_OUTPUT\")"),
            "Java chain step must keep its NYX_PREV_OUTPUT forwarder"
        );
        let shim_pos = step.source.find("__nyx_probe").unwrap();
        let driver_pos = step.source.find("System.getenv(\"NYX_PREV_OUTPUT\")").unwrap();
        assert!(
            shim_pos < driver_pos,
            "probe shim must come before the driver so the shim's helpers are in scope when a sink rewrite splices in"
        );
        let main_pos = step.source.find("public static void main").unwrap();
        assert!(
            shim_pos < main_pos,
            "probe shim members must be declared before `main` so the class compiles cleanly"
        );
        assert_eq!(step.filename, "Step.java");
    }

    #[test]
    fn detect_shape_reads_file_and_returns_shape() {
        // Drive the public `detect_shape(spec)` wrapper end-to-end:
        // write a representative source to a tempfile, then assert the
        // wrapper reads it and produces the expected JavaShape variant.
        let dir = std::env::temp_dir().join(format!(
            "nyx_detect_shape_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let cases: &[(&str, &str, &str, EntryKind, JavaShape)] = &[
            (
                "Servlet.java",
                "import javax.servlet.http.HttpServletRequest;\npublic class Servlet extends HttpServlet { public void doGet(HttpServletRequest r, HttpServletResponse w) {} }",
                "doGet",
                EntryKind::HttpRoute,
                JavaShape::ServletDoGet,
            ),
            (
                "Spring.java",
                "@RestController\npublic class Spring { @GetMapping(\"/x\") public String run(String p) { return p; } }",
                "run",
                EntryKind::HttpRoute,
                JavaShape::SpringController,
            ),
            (
                "MainClass.java",
                "public class MainClass { public static void main(String[] args) {} }",
                "main",
                EntryKind::CliSubcommand,
                JavaShape::StaticMain,
            ),
            (
                "Plain.java",
                "public class Plain { public static void run(String p) {} }",
                "run",
                EntryKind::Function,
                JavaShape::StaticMethod,
            ),
        ];
        for (name, body, entry_name, kind, expected) in cases {
            let path = dir.join(name);
            std::fs::write(&path, body).expect("write fixture");
            let spec = make_spec_with(*kind, entry_name, path.to_str().unwrap());
            assert_eq!(detect_shape(&spec), *expected, "case {name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
