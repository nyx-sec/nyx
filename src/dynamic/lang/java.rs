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
use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
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
const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::HttpRoute,
    EntryKindTag::CliSubcommand,
    EntryKindTag::ClassMethod,
];

impl LangEmitter for JavaEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "java emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 14 / 19 / 20 / 21 shape dispatch"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_java(env)
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        chain_step(prev_output, terminal)
    }
}

/// Phase 26 — Java chain-step harness.
///
/// Emits a `Step.java` class whose `main` reads `NYX_PREV_OUTPUT` and
/// forwards it on stdout.  When the step is the chain's terminal step
/// the `main` body also calls `__nyx_probe(callee, prev)` and prints
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] so the runner flips
/// `sink_hit` for the chain.  The command shell-wraps `javac` + `java`
/// so the step actually runs after the build step completes (the
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
fn chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let shim = probe_shim();
    let mut body = String::from(
        "        String prev = System.getenv(\"NYX_PREV_OUTPUT\");\n        if (prev == null) prev = \"\";\n        System.out.print(prev);\n",
    );
    if let Some(t) = terminal {
        let callee = java_string_literal(&t.sink_callee);
        let sentinel = java_string_literal(ChainStepHarness::SINK_HIT_SENTINEL);
        body.push_str(&format!(
            "        __nyx_probe({callee}, prev);\n        System.out.println({sentinel});\n        System.out.flush();\n",
        ));
    }
    let source = format!(
        "public class Step {{\n{shim}\n    public static void main(String[] args) {{\n{body}    }}\n}}\n"
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

/// Escape a string for safe Java double-quoted literal embedding.
fn java_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
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
    /// Micronaut route: `@Controller("/api")` + `@Get`/`@Post`/`@Put`
    /// /`@Delete` on a method.  Harness invokes the method via
    /// reflection like Spring / Quarkus (the brief specifies an
    /// `EmbeddedServer.start` bootstrap, deferred behind the existing
    /// synthetic-harness pattern in [`deferred.md`]).
    MicronautRoute,
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
        let kind = spec.entry_kind.tag();

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
        let has_micronaut = source.contains("io.micronaut");
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
        // Micronaut comes before Quarkus / Spring: Micronaut sources
        // re-use `@Controller` (collides with Spring) and `@Path` is
        // not part of the Micronaut surface (so the Quarkus check
        // does not fire for typical Micronaut files).  Picking
        // Micronaut on a clear `io.micronaut` import is the safest
        // disambiguation.
        if has_micronaut {
            return Self::MicronautRoute;
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

        if kind == EntryKindTag::CliSubcommand {
            return Self::StaticMain;
        }
        if kind == EntryKindTag::HttpRoute {
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

    if spec.expected_cap == crate::labels::Cap::DESERIALIZE {
        return Ok(emit_deserialize_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::SSTI {
        return Ok(emit_ssti_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::XXE {
        return Ok(emit_xxe_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::LDAP_INJECTION {
        return Ok(emit_ldap_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::XPATH_INJECTION {
        return Ok(emit_xpath_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::HEADER_INJECTION {
        return Ok(emit_header_injection_harness(spec));
    }
    if spec.expected_cap == crate::labels::Cap::OPEN_REDIRECT {
        return Ok(emit_open_redirect_harness(spec));
    }

    // Phase 19 (Track M.1): ClassMethod short-circuit.  Routes through
    // the existing `invokeReflective` helper so the harness instantiates
    // the receiver via its no-arg constructor (or null-fills primitive
    // / null-safe-object formals) before dispatching `method(payload)`.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        let entry_source = read_entry_source(&spec.entry_file);
        let entry_class = derive_entry_class(&entry_source);
        return Ok(emit_class_method_harness(spec, class, method, &entry_class));
    }

    let entry_source = read_entry_source(&spec.entry_file);
    let shape = JavaShape::detect(spec, &entry_source);
    let entry_class = derive_entry_class(&entry_source);
    let entry_qualifier = derive_entry_qualifier(&entry_source, &entry_class);
    let source = generate_harness_java(spec, shape, &entry_qualifier);
    let mut extra_files = match shape {
        // Real-world servlet sources import `javax.servlet.*` or
        // `jakarta.servlet.*`; without those symbols on the classpath
        // `javac` reports `package javax.servlet does not exist` and the
        // verifier flips to `BuildFailed`.  Stage minimal stubs alongside
        // the harness so the build step links.
        JavaShape::ServletDoGet | JavaShape::ServletDoPost => {
            crate::dynamic::lang::java_servlet_stubs::servlet_stub_files()
        }
        _ => vec![],
    };
    // OWASP Benchmark v1.2 fixtures and other Spring-flavoured Java
    // entry sources reach for `org.owasp.benchmark.helpers.*`,
    // `org.owasp.esapi.*`, and a small Spring surface (RowMapper,
    // SqlRowSet, DataAccessException, HtmlUtils).  Stage the matching
    // stub bundle when the entry source signals one of those imports;
    // non-OWASP harnesses pay zero workdir cost.
    if crate::dynamic::lang::java_owasp_stubs::entry_needs_owasp_stubs(&entry_source) {
        extra_files.extend(crate::dynamic::lang::java_owasp_stubs::owasp_stub_files());
    }

    Ok(HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files,
        // Stage the entry file under the public-class-derived filename
        // so javac's filename-vs-public-class invariant holds for both
        // the legacy `public class Entry` fixtures (which keep being
        // copied to `workdir/Entry.java`) and the Phase 14 shape
        // fixtures (where `public class Vuln` lives in `Vuln.java`).
        entry_subpath: Some(format!("{entry_class}.java")),
    })
}

/// Phase 03 — Track J.1 deserialize harness for Java.
///
/// Emits a `NyxHarness.java` whose `main` wraps the sink in a
/// `RestrictedObjectInputStream` style guard.  The shim parses the
/// payload (`NYX_GADGET_CLASS:<class>`); any class outside the
/// allowlist (`java.lang.Integer`, `java.lang.String`) writes a
/// [`crate::dynamic::probe::ProbeKind::Deserialize`] probe with
/// `gadget_chain_invoked: true` to `NYX_PROBE_PATH` and aborts the
/// chain — this is the resolveClass-driven boundary the brief calls
/// out.
pub fn emit_deserialize_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let source = format!(
        r#"// Nyx dynamic harness — deserialize (Phase 03 / Track J.1).
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class NyxHarness {{
{shim}

    static final Set<String> NYX_ALLOWLIST =
        new HashSet<>(Arrays.asList("java.lang.Integer", "java.lang.String"));

    static void nyxDeserializeProbe(boolean invoked) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"ObjectInputStream.resolveClass\",\"args\":[],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"Deserialize\",\"gadget_chain_invoked\":").append(invoked ? "true" : "false").append("}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("ObjectInputStream.resolveClass", new String[0]));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String prefix = "NYX_GADGET_CLASS:";
        if (payload.startsWith(prefix)) {{
            String cls = payload.substring(prefix.length());
            if (!NYX_ALLOWLIST.contains(cls)) {{
                // RestrictedObjectInputStream.resolveClass would refuse
                // here; record the gadget invocation before aborting.
                nyxDeserializeProbe(true);
            }}
        }}
        // Sink-reachability sentinel — runner's `vuln_fired && sink_hit`
        // gate consumes this; without it differential confirmation cannot
        // fire even when the probe was written.
        System.out.println("__NYX_SINK_HIT__");
    }}
}}
"#
    );
    HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 04 — Track J.2 SSTI harness for Java (Thymeleaf).
///
/// Reads `NYX_PAYLOAD`, simulates Thymeleaf's `[[${expr}]]` inlined-
/// output evaluation, and writes `{"render":"<result>"}` plus the
/// sink-hit sentinel.  Synthetic renderer keeps the corpus
/// deterministic without bundling Thymeleaf jars in the sandbox.
pub fn emit_ssti_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let source = format!(
        r#"// Nyx dynamic harness — SSTI Thymeleaf (Phase 04 / Track J.2).
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NyxHarness {{
{shim}

    static String nyxThymeleafRender(String payload) {{
        Pattern p = Pattern.compile("\\[\\[\\$\\{{(.+?)\\}}\\]\\]");
        Matcher m = p.matcher(payload);
        StringBuffer out = new StringBuffer(payload.length());
        while (m.find()) {{
            String expr = m.group(1).trim();
            Matcher mul = Pattern.compile("^(\\d+)\\s*\\*\\s*(\\d+)$").matcher(expr);
            Matcher add = Pattern.compile("^(\\d+)\\s*\\+\\s*(\\d+)$").matcher(expr);
            String repl;
            if (mul.matches()) {{
                long a = Long.parseLong(mul.group(1));
                long b = Long.parseLong(mul.group(2));
                repl = Long.toString(a * b);
            }} else if (add.matches()) {{
                long a = Long.parseLong(add.group(1));
                long b = Long.parseLong(add.group(2));
                repl = Long.toString(a + b);
            }} else {{
                repl = Matcher.quoteReplacement(m.group(0));
            }}
            m.appendReplacement(out, Matcher.quoteReplacement(repl));
        }}
        m.appendTail(out);
        return out.toString();
    }}

    static void nyxSstiProbe(String rendered) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"TemplateEngine.process\",\"args\":[{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(rendered, line);
        line.append("\"}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"Normal\"}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("TemplateEngine.process", new String[]{{rendered}}));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String rendered = nyxThymeleafRender(payload);
        nyxSstiProbe(rendered);
        System.out.println("__NYX_SINK_HIT__");
        StringBuilder body = new StringBuilder(64);
        body.append("{{\"render\":\"");
        nyxJsonEscape(rendered, body);
        body.append("\"}}");
        System.out.println(body.toString());
    }}
}}
"#
    );
    HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 05 — Track J.3 XXE harness for Java (`DocumentBuilderFactory`).
///
/// Reads `NYX_PAYLOAD`, scans for `<!ENTITY name SYSTEM "uri">`
/// declarations, expands them inside `&name;` element references
/// (matching `DocumentBuilderFactory` with external-entity resolution
/// enabled), and writes a `ProbeKind::Xxe` probe whose
/// `entity_expanded` flag tracks whether the substitution actually
/// fired.  The synthetic resolver keeps the corpus deterministic
/// without requiring a `javax.xml.parsers` classpath in the sandbox.
pub fn emit_xxe_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let source = format!(
        r#"// Nyx dynamic harness — XXE DocumentBuilderFactory (Phase 05 / Track J.3).
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NyxHarness {{
{shim}

    static boolean nyxLastExpanded = false;

    static String nyxXmlParse(String payload) {{
        Pattern doctype = Pattern.compile(
            "<!ENTITY\\s+(\\w+)\\s+SYSTEM\\s+\"([^\"]+)\"\\s*>"
        );
        Map<String, String> entities = new HashMap<>();
        Matcher dm = doctype.matcher(payload);
        while (dm.find()) {{
            entities.put(dm.group(1), "<" + dm.group(2) + ">");
        }}
        nyxLastExpanded = false;
        Pattern ref = Pattern.compile("&(\\w+);");
        Matcher rm = ref.matcher(payload);
        StringBuffer out = new StringBuffer(payload.length());
        while (rm.find()) {{
            String name = rm.group(1);
            String body = entities.get(name);
            if (body != null) {{
                nyxLastExpanded = true;
                rm.appendReplacement(out, Matcher.quoteReplacement(body));
            }} else {{
                rm.appendReplacement(out, Matcher.quoteReplacement(rm.group(0)));
            }}
        }}
        rm.appendTail(out);
        return out.toString();
    }}

    static void nyxXxeProbe(String rendered, boolean expanded) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"DocumentBuilder.parse\",\"args\":[{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(rendered, line);
        line.append("\"}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"Xxe\",\"entity_expanded\":").append(expanded ? "true" : "false").append("}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("DocumentBuilder.parse", new String[]{{rendered}}));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String rendered = nyxXmlParse(payload);
        nyxXxeProbe(rendered, nyxLastExpanded);
        System.out.println("__NYX_SINK_HIT__");
        StringBuilder body = new StringBuilder(64);
        body.append("{{\"render\":\"");
        nyxJsonEscape(rendered, body);
        body.append("\",\"entity_expanded\":").append(nyxLastExpanded ? "true" : "false").append("}}");
        System.out.println(body.toString());
    }}
}}
"#
    );
    HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 06 — Track J.4 LDAP-injection harness for Java
/// (`LdapTemplate.search` / `DirContext.search`).
///
/// Reads `NYX_PAYLOAD`, splices it into a `(uid=<payload>)` filter
/// template, evaluates the resulting filter against the in-sandbox
/// LDAP directory (three users: `alice`, `bob`, `carol`) using the
/// same RFC-4515 subset the
/// [`crate::dynamic::stubs::ldap_server`] stub implements, and writes
/// a `ProbeKind::Ldap { entries_returned }` probe whose `n` is the
/// count the directory returned.  Mirrors the synthetic-harness
/// pattern used by Phase 03 / 04 / 05; a future structural fix will
/// link real `LdapTemplate` / `DirContext` via the published
/// `NYX_LDAP_ENDPOINT`.
pub fn emit_ldap_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let source = format!(
        r#"// Nyx dynamic harness — LDAP_INJECTION LdapTemplate.search (Phase 06 / Track J.4).
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class NyxHarness {{
{shim}

    static final String[] NYX_LDAP_USERS = new String[] {{ "alice", "bob", "carol" }};

    static boolean nyxAttrMatch(String pattern, String uid) {{
        if (pattern.equals("*")) return true;
        int star = pattern.indexOf('*');
        if (star < 0) return pattern.equals(uid);
        String prefix = pattern.substring(0, star);
        String suffix = pattern.substring(star + 1);
        return uid.startsWith(prefix) && uid.endsWith(suffix);
    }}

    static boolean nyxInnerHasBreak(String inner) {{
        int depth = 0;
        for (int i = 0; i < inner.length(); i++) {{
            char c = inner.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') {{
                depth--;
                if (depth < 0) return true;
            }}
        }}
        return false;
    }}

    static int nyxLdapCount(String filter) {{
        String f = filter == null ? "" : filter.trim();
        if (f.isEmpty()) return 0;
        if (!f.startsWith("(") || !f.endsWith(")")) return NYX_LDAP_USERS.length;
        String inner = f.substring(1, f.length() - 1);
        if (nyxInnerHasBreak(inner)) return NYX_LDAP_USERS.length;
        if (inner.startsWith("&") || inner.startsWith("|")) {{
            List<String> clauses = nyxSplitClauses(inner.substring(1));
            int total = 0;
            for (String u : NYX_LDAP_USERS) {{
                boolean ok = inner.startsWith("&");
                for (String c : clauses) {{
                    boolean m = nyxLdapMatch(c, u);
                    ok = inner.startsWith("&") ? (ok && m) : (ok || m);
                }}
                if (clauses.isEmpty()) ok = false;
                if (ok) total++;
            }}
            return total;
        }}
        int eq = inner.indexOf('=');
        if (eq < 0) return NYX_LDAP_USERS.length;
        String attr = inner.substring(0, eq);
        String pattern = inner.substring(eq + 1);
        if (!attr.equalsIgnoreCase("uid") && !attr.equalsIgnoreCase("cn")) return NYX_LDAP_USERS.length;
        int total = 0;
        for (String u : NYX_LDAP_USERS) {{
            if (nyxAttrMatch(pattern, u)) total++;
        }}
        return total;
    }}

    static boolean nyxLdapMatch(String filter, String uid) {{
        return nyxLdapCount(filter) > 0
            ? nyxLdapMatchOne(filter, uid)
            : false;
    }}

    static boolean nyxLdapMatchOne(String filter, String uid) {{
        String f = filter.trim();
        if (!f.startsWith("(") || !f.endsWith(")")) return true;
        String inner = f.substring(1, f.length() - 1);
        if (nyxInnerHasBreak(inner)) return true;
        if (inner.startsWith("&") || inner.startsWith("|")) {{
            List<String> clauses = nyxSplitClauses(inner.substring(1));
            if (clauses.isEmpty()) return false;
            boolean ok = inner.startsWith("&");
            for (String c : clauses) {{
                boolean m = nyxLdapMatchOne(c, uid);
                ok = inner.startsWith("&") ? (ok && m) : (ok || m);
            }}
            return ok;
        }}
        int eq = inner.indexOf('=');
        if (eq < 0) return true;
        String attr = inner.substring(0, eq);
        String pattern = inner.substring(eq + 1);
        if (!attr.equalsIgnoreCase("uid") && !attr.equalsIgnoreCase("cn")) return true;
        return nyxAttrMatch(pattern, uid);
    }}

    static List<String> nyxSplitClauses(String src) {{
        List<String> out = new ArrayList<>();
        int i = 0;
        while (i < src.length()) {{
            if (src.charAt(i) != '(') {{ i++; continue; }}
            int depth = 0;
            int start = i;
            while (i < src.length()) {{
                char c = src.charAt(i);
                if (c == '(') depth++;
                else if (c == ')') {{
                    depth--;
                    if (depth == 0) {{ i++; break; }}
                }}
                i++;
            }}
            out.add(src.substring(start, i));
        }}
        return out;
    }}

    static void nyxLdapProbe(String filter, int entriesReturned) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"LdapTemplate.search\",\"args\":[{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(filter, line);
        line.append("\"}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"Ldap\",\"entries_returned\":").append(entriesReturned).append("}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("LdapTemplate.search", new String[]{{filter}}));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String filter = "(uid=" + payload + ")";
        int count = nyxLdapCount(filter);
        nyxLdapProbe(filter, count);
        System.out.println("__NYX_SINK_HIT__");
        StringBuilder body = new StringBuilder(64);
        body.append("{{\"filter\":\"");
        nyxJsonEscape(filter, body);
        body.append("\",\"entries_returned\":").append(count).append("}}");
        System.out.println(body.toString());
    }}
}}
"#
    );
    HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 07 — Track J.5 XPath-injection harness for Java
/// (`javax.xml.xpath.XPath.evaluate`).
///
/// Reads `NYX_PAYLOAD`, splices it into a `//user[@name='<payload>']`
/// expression, counts matching `<user>` nodes against the canonical
/// staged document, and writes a `ProbeKind::Xpath { nodes_returned }`
/// probe whose `n` is the count returned.  Mirrors the
/// synthetic-harness pattern used by Phase 03 / 04 / 05 / 06; a
/// future structural fix will link real `javax.xml.xpath` via the
/// staged document.
pub fn emit_xpath_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let corpus_filename = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_FILENAME;
    let corpus_xml = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_XML;
    let source = format!(
        r#"// Nyx dynamic harness — XPATH_INJECTION javax.xml.xpath.XPath.evaluate (Phase 07 / Track J.5).
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NyxHarness {{
{shim}

    static final String[] NYX_XPATH_USERS = new String[] {{ "alice", "bob", "carol" }};

    static int nyxXpathSelect(String expr) {{
        String needle = "//user[@name=";
        if (!expr.startsWith(needle)) return 0;
        String rest = expr.substring(needle.length());
        if (!rest.endsWith("]")) return 0;
        String predicate = rest.substring(0, rest.length() - 1);

        Matcher single = Pattern.compile("^'([^']*)'(.*)$").matcher(predicate);
        if (single.find()) {{
            String literal = single.group(1);
            String tail = single.group(2).trim();
            if (tail.isEmpty() || tail.equals("]")) {{
                int count = 0;
                for (String u : NYX_XPATH_USERS) if (u.equals(literal)) count++;
                return count;
            }}
            if (Pattern.compile("^or\\s+", Pattern.CASE_INSENSITIVE).matcher(tail).find()) {{
                return NYX_XPATH_USERS.length;
            }}
        }}
        Matcher dbl = Pattern.compile("^\"([^\"]*)\"\\s*$").matcher(predicate);
        if (dbl.find()) {{
            String literal = dbl.group(1);
            int count = 0;
            for (String u : NYX_XPATH_USERS) if (u.equals(literal)) count++;
            return count;
        }}
        if (Pattern.compile("^concat\\(", Pattern.CASE_INSENSITIVE).matcher(predicate).find()) {{
            Matcher parts = Pattern.compile("'([^']*)'").matcher(predicate);
            StringBuilder joined = new StringBuilder();
            while (parts.find()) {{
                String p = parts.group(1);
                if (p.equals(",\"")) continue;
                joined.append(p);
            }}
            String result = joined.toString().replace(",\"'\",", "'");
            int count = 0;
            for (String u : NYX_XPATH_USERS) if (u.equals(result)) count++;
            return count;
        }}
        return NYX_XPATH_USERS.length;
    }}

    static void nyxXpathProbe(String expr, int nodesReturned) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"javax.xml.xpath.XPath.evaluate\",\"args\":[{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(expr, line);
        line.append("\"}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"Xpath\",\"nodes_returned\":").append(nodesReturned).append("}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("javax.xml.xpath.XPath.evaluate", new String[]{{expr}}));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String expr = "//user[@name='" + payload + "']";
        int count = nyxXpathSelect(expr);
        nyxXpathProbe(expr, count);
        System.out.println("__NYX_SINK_HIT__");
        StringBuilder body = new StringBuilder(64);
        body.append("{{\"expr\":\"");
        nyxJsonEscape(expr, body);
        body.append("\",\"nodes_returned\":").append(count).append("}}");
        System.out.println(body.toString());
    }}
}}
"#
    );
    let extra_files = vec![(corpus_filename.to_owned(), corpus_xml.to_owned())];
    HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files,
        entry_subpath: None,
    }
}

/// Phase 08 — Track J.6 header-injection harness for Java
/// (`HttpServletResponse.setHeader`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented
/// `response.setHeader("Set-Cookie", value)` shim that records the
/// *unmodified* value bytes (including any embedded `\r\n`) via a
/// `ProbeKind::HeaderEmit` probe.  Mirrors the synthetic-harness
/// pattern used by Phase 03 / 04 / 05 / 06 / 07.
pub fn emit_header_injection_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let extra_files = servlet_stubs_for_entry(&spec.entry_file);
    let source = format!(
        r#"// Nyx dynamic harness — HEADER_INJECTION HttpServletResponse.setHeader (Phase 08 / Track J.6).
import java.io.FileWriter;
import java.io.IOException;

public class NyxHarness {{
{shim}

    static void nyxHeaderProbe(String name, String value) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"HttpServletResponse.setHeader\",\"args\":[");
        line.append("{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(name, line);
        line.append("\"}},{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(value, line);
        line.append("\"}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"HeaderEmit\",\"name\":\"");
        nyxJsonEscape(name, line);
        line.append("\",\"value\":\"");
        nyxJsonEscape(value, line);
        line.append("\"}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("HttpServletResponse.setHeader", new String[]{{name, value}}));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String name = "Set-Cookie";
        String value = payload;
        nyxHeaderProbe(name, value);
        System.out.println("__NYX_SINK_HIT__");
        StringBuilder body = new StringBuilder(64);
        body.append("{{\"name\":\"");
        nyxJsonEscape(name, body);
        body.append("\",\"value\":\"");
        nyxJsonEscape(value, body);
        body.append("\"}}");
        System.out.println(body.toString());
    }}
}}
"#
    );
    HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files,
        entry_subpath: None,
    }
}

/// Phase 09 — Track J.7 open-redirect harness for Java
/// (`HttpServletResponse.sendRedirect`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented
/// `response.sendRedirect(value)` shim that records the *unmodified*
/// `Location:` value plus the request's origin host via a
/// `ProbeKind::Redirect` probe.  Mirrors the synthetic-harness
/// pattern used by Phase 03 / 04 / 05 / 06 / 07 / 08.
pub fn emit_open_redirect_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let extra_files = servlet_stubs_for_entry(&spec.entry_file);
    let source = format!(
        r#"// Nyx dynamic harness — OPEN_REDIRECT HttpServletResponse.sendRedirect (Phase 09 / Track J.7).
import java.io.FileWriter;
import java.io.IOException;

public class NyxHarness {{
{shim}

    static void nyxRedirectProbe(String location, String requestHost) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"HttpServletResponse.sendRedirect\",\"args\":[");
        line.append("{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(location, line);
        line.append("\"}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"Redirect\",\"location\":\"");
        nyxJsonEscape(location, line);
        line.append("\",\"request_host\":\"");
        nyxJsonEscape(requestHost, line);
        line.append("\"}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("HttpServletResponse.sendRedirect", new String[]{{location}}));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String requestHost = "example.com";
        String location = payload;
        nyxRedirectProbe(location, requestHost);
        System.out.println("__NYX_SINK_HIT__");
        StringBuilder body = new StringBuilder(64);
        body.append("{{\"location\":\"");
        nyxJsonEscape(location, body);
        body.append("\",\"request_host\":\"");
        nyxJsonEscape(requestHost, body);
        body.append("\"}}");
        System.out.println(body.toString());
    }}
}}
"#
    );
    HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files,
        entry_subpath: None,
    }
}

/// Stage the `javax.servlet.*` / `jakarta.servlet.*` stub bundle when
/// the entry source imports either namespace.  Phase 08 / 09 fixtures
/// (`HttpServletResponse.setHeader` / `.sendRedirect`) carry the
/// `import javax.servlet.http.HttpServletResponse;` so `javac` over
/// the workdir's `*.java` set needs the symbols on the classpath even
/// though `NyxHarness.java` itself uses no servlet types.  Without the
/// stubs the verifier flips to `BuildFailed` and the per-lang e2e
/// tests silently skip via the SKIP-on-`BuildFailed` branch.
fn servlet_stubs_for_entry(entry_file: &str) -> Vec<(String, String)> {
    let entry_source = read_entry_source(entry_file);
    if entry_source.contains("javax.servlet") || entry_source.contains("jakarta.servlet") {
        crate::dynamic::lang::java_servlet_stubs::servlet_stub_files()
    } else {
        Vec::new()
    }
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

/// Resolve the entry class as a fully-qualified Java name when the
/// entry source declares a `package`.  Falls back to the bare simple
/// name when the source has no package declaration (the legacy
/// default-package fixture path).
///
/// OWASP Benchmark testcases ship with `package
/// org.owasp.benchmark.testcode;` headers; javac compiles their
/// sources into `org/owasp/benchmark/testcode/<Class>.class` under
/// the workdir, so `NyxHarness` (which itself lives in the default
/// package) cannot resolve them via the simple name alone.  Using
/// the FQN in the harness's `Class.forName` / `.class` references
/// keeps both default-package and packaged entries linkable.
fn derive_entry_qualifier(source: &str, simple_name: &str) -> String {
    match parse_package_name(source) {
        Some(pkg) => format!("{pkg}.{simple_name}"),
        None => simple_name.to_owned(),
    }
}

fn parse_package_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim_start();
        let rest = match trimmed.strip_prefix("package ") {
            Some(r) => r,
            None => continue,
        };
        let end = rest.find(';')?;
        let name = rest[..end].trim();
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        {
            return Some(name.to_owned());
        }
        return None;
    }
    None
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
        JavaShape::SpringController => {
            if spec.java_toolchain.with_spring_test {
                // Phase 14 (Track L.12) — `with_spring_test`-enabled
                // Spring shape: the v1 implementation still drives the
                // reflective path because the synthetic harness does
                // not bundle SpringBoot test deps.  The flag flips a
                // marker on stdout so the verifier can confirm the
                // toolchain knob propagated.
                format!(
                    "            System.out.println(\"NYX_SPRING_TEST=1\");\n            invokeReflective({entry_class}.class, \"{method}\", payload);"
                )
            } else {
                format!(
                    "            invokeReflective({entry_class}.class, \"{method}\", payload);"
                )
            }
        }
        JavaShape::QuarkusRoute => format!(
            "            invokeReflective({entry_class}.class, \"{method}\", payload);"
        ),
        JavaShape::MicronautRoute => format!(
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
        JavaShape::SpringController
        | JavaShape::QuarkusRoute
        | JavaShape::MicronautRoute => REFLECTIVE_HELPER,
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

/// Phase 19 (Track M.1) — class-method harness for Java.
///
/// Emits a `NyxHarness.java` whose `main` reflectively constructs the
/// target class via its no-arg constructor (when available) — or
/// fills primitive parameters with defaults + object parameters with
/// the Phase 19 [`crate::dynamic::stubs::MockKind`] doubles when the
/// no-arg path is missing — and invokes `method(payload)`.  The class
/// is loaded via the same FQN qualifier used by the regular Java
/// shapes so it works on both default-package fixtures and packaged
/// OWASP-style entries.
fn emit_class_method_harness(
    spec: &HarnessSpec,
    class: &str,
    method: &str,
    entry_class: &str,
) -> HarnessSource {
    let probe = probe_shim();
    let pre_call = pre_call_setup(spec);
    let mock_http = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::HttpClient,
        crate::symbol::Lang::Java,
    );
    let mock_db = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::DatabaseConnection,
        crate::symbol::Lang::Java,
    );
    let mock_log = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::Logger,
        crate::symbol::Lang::Java,
    );
    let source = format!(
        r#"// Nyx dynamic harness — class method (Phase 19 / Track M.1).
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;

public class NyxHarness {{
{probe}

{mock_http}
{mock_db}
{mock_log}

    static Object nyxBuildReceiver(Class<?> cls) throws Exception {{
        // Preferred path: zero-arg ctor.
        try {{
            Constructor<?> c = cls.getDeclaredConstructor();
            c.setAccessible(true);
            return c.newInstance();
        }} catch (NoSuchMethodException ignore) {{
        }}
        // Fallback path: walk declared ctors and stub each formal.
        for (Constructor<?> c : cls.getDeclaredConstructors()) {{
            c.setAccessible(true);
            Class<?>[] params = c.getParameterTypes();
            Object[] args = new Object[params.length];
            for (int i = 0; i < params.length; i++) {{
                args[i] = nyxStubForType(params[i]);
            }}
            try {{ return c.newInstance(args); }} catch (Exception ignore) {{}}
        }}
        return null;
    }}

    static Object nyxStubForType(Class<?> t) {{
        String n = t.getName().toLowerCase();
        if (n.contains("http") || n.contains("client")) return new MockHttpClient();
        if (n.contains("database") || n.contains("connection") || n.contains("session") || n.contains("repository")) return new MockDatabaseConnection();
        if (n.contains("logger") || n.contains("log")) return new MockLogger();
        if (t.equals(String.class)) return "";
        if (t.equals(int.class) || t.equals(Integer.class)) return 0;
        if (t.equals(long.class) || t.equals(Long.class)) return 0L;
        if (t.equals(boolean.class) || t.equals(Boolean.class)) return false;
        return null;
    }}

    public static void main(String[] args) {{
        String payload = nyxPayload();
{pre_call}        try {{
            Class<?> cls;
            try {{
                cls = Class.forName({class_fqn:?});
            }} catch (ClassNotFoundException cnfe) {{
                cls = Class.forName({entry_class_fqn:?});
            }}
            Object instance = nyxBuildReceiver(cls);
            if (instance == null) {{
                System.err.println("NYX_CLASS_CTOR_FAILED: " + cls.getName());
                System.exit(78);
            }}
            Method match = null;
            for (Method m : cls.getDeclaredMethods()) {{
                if (m.getName().equals({method:?})) {{ match = m; break; }}
            }}
            if (match == null) {{
                System.err.println("NYX_METHOD_NOT_FOUND: " + {method:?});
                System.exit(78);
            }}
            match.setAccessible(true);
            Class<?>[] params = match.getParameterTypes();
            Object[] mArgs = new Object[params.length];
            for (int i = 0; i < params.length; i++) {{
                mArgs[i] = params[i].equals(String.class) ? payload : nyxStubForType(params[i]);
            }}
            match.invoke(instance, mArgs);
        }} catch (InvocationTargetException ite) {{
            Throwable cause = ite.getCause() == null ? ite : ite.getCause();
            System.err.println("NYX_EXCEPTION: " + cause.getClass().getName() + ": " + cause.getMessage());
        }} catch (Throwable e) {{
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
        class_fqn = class,
        entry_class_fqn = entry_class,
        method = method,
        pre_call = pre_call,
    );
    HarnessSource {
        source,
        filename: "NyxHarness.java".to_owned(),
        command: vec![
            "java".to_owned(),
            "-cp".to_owned(),
            ".".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files: vec![],
        entry_subpath: Some(format!("{entry_class}.java")),
    }
}

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
    use crate::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
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
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
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
            .contains(&EntryKindTag::Function));
        assert!(JavaEmitter
            .entry_kinds_supported()
            .contains(&EntryKindTag::HttpRoute));
        assert!(JavaEmitter
            .entry_kinds_supported()
            .contains(&EntryKindTag::CliSubcommand));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = JavaEmitter.entry_kind_hint(EntryKindTag::LibraryApi);
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
    fn shape_detect_micronaut_route() {
        let src = "import io.micronaut.http.annotation.Controller;\nimport io.micronaut.http.annotation.Get;\n@Controller(\"/x\")\npublic class V { @Get(\"/y\") public String run(String p) { return p; } }";
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "V.java");
        assert_eq!(JavaShape::detect(&spec, src), JavaShape::MicronautRoute);
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
    fn micronaut_shape_emits_reflective_invocation() {
        let spec = make_spec_with(EntryKind::HttpRoute, "run", "Vuln.java");
        let src = generate_harness_java(&spec, JavaShape::MicronautRoute, "Vuln");
        assert!(src.contains("invokeReflective(Vuln.class, \"run\""));
    }

    #[test]
    fn spring_shape_emits_marker_when_with_spring_test() {
        let mut spec = make_spec_with(EntryKind::HttpRoute, "run", "Vuln.java");
        spec.java_toolchain.with_spring_test = true;
        let src = generate_harness_java(&spec, JavaShape::SpringController, "Vuln");
        assert!(src.contains("NYX_SPRING_TEST=1"));
        let mut off = make_spec_with(EntryKind::HttpRoute, "run", "Vuln.java");
        off.java_toolchain.with_spring_test = false;
        let src_off = generate_harness_java(&off, JavaShape::SpringController, "Vuln");
        assert!(!src_off.contains("NYX_SPRING_TEST=1"));
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

    // ── Servlet stub bundle (path (a) of Phase 31 budget gate) ──────────────

    fn stage_entry(dir: &std::path::Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("stage java entry source");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn emit_servlet_doget_carries_servlet_stub_bundle() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entry_file = stage_entry(
            tmp.path(),
            "Vuln.java",
            "import javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\npublic class Vuln {\n  public void doGet(HttpServletRequest r, HttpServletResponse w) {}\n}\n",
        );
        let mut spec = make_spec_with(EntryKind::HttpRoute, "doGet", &entry_file);
        spec.payload_slot = PayloadSlot::QueryParam("payload".into());
        let harness = emit(&spec).unwrap();
        let paths: Vec<&str> = harness.extra_files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            paths.contains(&"javax/servlet/http/HttpServletRequest.java"),
            "doGet bundle missing javax HttpServletRequest stub; got {paths:?}"
        );
        assert!(
            paths.contains(&"jakarta/servlet/http/HttpServletRequest.java"),
            "doGet bundle missing jakarta HttpServletRequest stub; got {paths:?}"
        );
        assert!(paths.contains(&"javax/servlet/annotation/WebServlet.java"));
        assert!(paths.contains(&"javax/servlet/ServletException.java"));
    }

    #[test]
    fn emit_servlet_dopost_carries_servlet_stub_bundle() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entry_file = stage_entry(
            tmp.path(),
            "Vuln.java",
            "import jakarta.servlet.http.HttpServletRequest;\nimport jakarta.servlet.http.HttpServletResponse;\npublic class Vuln {\n  public void doPost(HttpServletRequest r, HttpServletResponse w) {}\n}\n",
        );
        let mut spec = make_spec_with(EntryKind::HttpRoute, "doPost", &entry_file);
        spec.payload_slot = PayloadSlot::HttpBody;
        let harness = emit(&spec).unwrap();
        assert!(!harness.extra_files.is_empty(), "doPost bundle is empty");
        let paths: Vec<&str> = harness.extra_files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"javax/servlet/http/HttpServlet.java"));
        assert!(paths.contains(&"jakarta/servlet/http/HttpServlet.java"));
    }

    #[test]
    fn emit_static_method_carries_no_extra_files() {
        // Regression guard: non-servlet shapes must not pay the servlet
        // stub cost.  Adding stubs would balloon the workdir + compile
        // time for every Rust / Python / etc. harness too.
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(
            harness.extra_files.is_empty(),
            "non-servlet shape unexpectedly ships extra files: {:?}",
            harness.extra_files.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );
    }

    #[test]
    fn emit_static_main_carries_no_extra_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entry_file = stage_entry(
            tmp.path(),
            "Vuln.java",
            "public class Vuln { public static void main(String[] args) {} }\n",
        );
        let spec = make_spec_with(EntryKind::CliSubcommand, "main", &entry_file);
        let harness = emit(&spec).unwrap();
        assert!(harness.extra_files.is_empty());
    }

    #[test]
    fn emit_servlet_doget_bundles_owasp_stubs_when_source_imports_owasp() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entry_file = stage_entry(
            tmp.path(),
            "BenchmarkTest00001.java",
            "package org.owasp.benchmark.testcode;\nimport javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\nimport javax.servlet.http.HttpServlet;\nimport org.owasp.benchmark.helpers.Utils;\nimport org.owasp.esapi.ESAPI;\npublic class BenchmarkTest00001 extends HttpServlet {\n  public void doGet(HttpServletRequest r, HttpServletResponse w) {}\n}\n",
        );
        let spec = make_spec_with(EntryKind::HttpRoute, "doGet", &entry_file);
        let harness = emit(&spec).unwrap();
        let paths: Vec<&str> = harness.extra_files.iter().map(|(p, _)| p.as_str()).collect();
        // Servlet stubs are present (same as the non-OWASP servlet case).
        assert!(paths.contains(&"javax/servlet/http/HttpServletRequest.java"));
        // OWASP helpers + esapi + spring stubs are appended.
        assert!(paths.contains(&"org/owasp/benchmark/helpers/Utils.java"));
        assert!(paths.contains(&"org/owasp/esapi/ESAPI.java"));
        assert!(paths.contains(&"org/owasp/benchmark/helpers/DatabaseHelper.java"));
        assert!(paths.contains(&"org/springframework/jdbc/core/RowMapper.java"));
    }

    #[test]
    fn emit_servlet_doget_skips_owasp_stubs_when_source_is_plain() {
        // Servlet entry without OWASP / Spring imports must only carry
        // the servlet stub bundle, not the OWASP add-on.  Keeps workdir
        // small for the existing servlet_doget fixture path.
        let tmp = tempfile::TempDir::new().unwrap();
        let entry_file = stage_entry(
            tmp.path(),
            "Vuln.java",
            "import javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\npublic class Vuln {\n  public void doGet(HttpServletRequest r, HttpServletResponse w) {}\n}\n",
        );
        let spec = make_spec_with(EntryKind::HttpRoute, "doGet", &entry_file);
        let harness = emit(&spec).unwrap();
        let paths: Vec<&str> = harness.extra_files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.starts_with("org/owasp/")),
            "plain servlet entry unexpectedly bundles OWASP stubs: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.starts_with("org/springframework/")),
            "plain servlet entry unexpectedly bundles Spring stubs: {paths:?}"
        );
    }

    #[test]
    fn emit_static_method_with_owasp_imports_bundles_helpers() {
        // Non-servlet shapes still need the OWASP stub set when the
        // entry source pulls in helpers (e.g. a plain @Test fixture
        // calling `Utils.encodeForHTML`).
        let tmp = tempfile::TempDir::new().unwrap();
        let entry_file = stage_entry(
            tmp.path(),
            "Vuln.java",
            "import org.owasp.benchmark.helpers.Utils;\npublic class Vuln {\n  public static void run(String p) { Utils.encodeForHTML(p); }\n}\n",
        );
        let spec = make_spec_with(EntryKind::Function, "run", &entry_file);
        let harness = emit(&spec).unwrap();
        let paths: Vec<&str> = harness.extra_files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"org/owasp/benchmark/helpers/Utils.java"));
        // No servlet stubs for a non-servlet shape.
        assert!(!paths.iter().any(|p| p.starts_with("javax/servlet/")));
    }

    #[test]
    fn parse_package_name_handles_packaged_source() {
        assert_eq!(
            parse_package_name("package org.owasp.benchmark.testcode;\nclass X {}\n"),
            Some("org.owasp.benchmark.testcode".to_owned())
        );
        // Leading whitespace + extra spaces inside the line are tolerated.
        assert_eq!(
            parse_package_name("   package a.b.c ;\n"),
            Some("a.b.c".to_owned())
        );
        // Leading comments / blank lines must not cause an early miss.
        assert_eq!(
            parse_package_name("// header comment\n/* block */\npackage com.example;\n"),
            Some("com.example".to_owned())
        );
    }

    #[test]
    fn parse_package_name_returns_none_when_absent() {
        assert_eq!(parse_package_name(""), None);
        assert_eq!(parse_package_name("public class X {}\n"), None);
    }

    #[test]
    fn derive_entry_qualifier_uses_package_when_present() {
        let src = "package org.owasp.benchmark.testcode;\npublic class BenchmarkTest00001 {}\n";
        assert_eq!(
            derive_entry_qualifier(src, "BenchmarkTest00001"),
            "org.owasp.benchmark.testcode.BenchmarkTest00001"
        );
    }

    #[test]
    fn derive_entry_qualifier_falls_back_to_simple_name() {
        assert_eq!(derive_entry_qualifier("", "Vuln"), "Vuln");
        assert_eq!(
            derive_entry_qualifier("public class Vuln {}", "Vuln"),
            "Vuln"
        );
    }

    #[test]
    fn emit_static_method_with_packaged_source_uses_fqn_in_harness() {
        // Packaged entry sources must be addressed by FQN in the
        // generated NyxHarness, otherwise javac fails with
        // `cannot find symbol: class <simple_name>` because the
        // packaged .class lives under `org/owasp/.../<simple>.class`
        // and NyxHarness itself sits in the default package.
        let tmp = tempfile::TempDir::new().unwrap();
        let entry_file = stage_entry(
            tmp.path(),
            "Vuln.java",
            "package org.example;\npublic class Vuln { public static void run(String p) {} }\n",
        );
        let spec = make_spec_with(EntryKind::Function, "run", &entry_file);
        let harness = emit(&spec).unwrap();
        assert!(
            harness.source.contains("org.example.Vuln.run(payload)"),
            "harness must address packaged entry via FQN; got source:\n{}",
            harness.source
        );
    }

    #[test]
    fn emit_spring_controller_carries_no_servlet_stubs() {
        // Spring controllers do not import `javax.servlet.*`; shipping
        // the bundle would still compile fine but adds dead `.class`
        // files to the workdir.  Keep the bundle scoped to actual
        // servlet shapes.
        let tmp = tempfile::TempDir::new().unwrap();
        let entry_file = stage_entry(
            tmp.path(),
            "Vuln.java",
            "@RestController\npublic class Vuln {\n  @GetMapping(\"/x\") public String run(String p) { return p; }\n}\n",
        );
        let mut spec = make_spec_with(EntryKind::HttpRoute, "run", &entry_file);
        spec.payload_slot = PayloadSlot::Param(0);
        let harness = emit(&spec).unwrap();
        assert!(harness.extra_files.is_empty());
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
        let step = chain_step(Some(b"<prev>"), None);
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
            let spec = make_spec_with(kind.clone(), entry_name, path.to_str().unwrap());
            assert_eq!(detect_shape(&spec), *expected, "case {name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
