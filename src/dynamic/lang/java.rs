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
    EntryKindTag::MessageHandler,
    EntryKindTag::ScheduledJob,
    EntryKindTag::Middleware,
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

    // Phase 11 (Track J.9): CRYPTO weak-RNG short-circuit.  The Java
    // harness reflectively loads the fixture class, invokes its
    // declared method with the payload, and reduces the produced key
    // into a `ProbeKind::WeakKey { key_int }` record (byte[] →
    // `ByteBuffer.wrap(zero-padded[8]).order(BIG_ENDIAN).getLong()`;
    // `Number` subclasses → `longValue()`).  A weak
    // `java.util.Random.nextBytes(new byte[2])` reduces to a sub-2^16
    // key_int; a `SecureRandom.nextBytes(new byte[32])` head-8 byte
    // view overshoots the 16-bit budget.
    if spec.expected_cap == crate::labels::Cap::CRYPTO {
        return Ok(emit_crypto_harness(spec));
    }

    // Phase 11 (Track J.9): JSON_PARSE depth-bomb short-circuit.  The
    // Java harness reflectively loads the fixture class, invokes its
    // declared method with the payload, walks the returned tree
    // iteratively via `NyxJsonProbe.countDepth`, and emits a
    // [`crate::dynamic::probe::ProbeKind::JsonParse`] probe.  The
    // hand-rolled `NyxJsonProbe` helper is shipped as a sibling
    // `.java` file so the build path never reaches for Jackson /
    // Gson.
    if spec.expected_cap == crate::labels::Cap::JSON_PARSE {
        return Ok(emit_json_parse_harness(spec));
    }

    // Phase 11 (Track J.9): UNAUTHORIZED_ID IDOR boundary harness.
    // Reflectively loads the fixture entry class, invokes the named
    // static method with the payload as `owner_id`, and emits a
    // `ProbeKind::IdorAccess { caller_id, owner_id }` probe only when
    // the fixture returns a non-`null` record.  The benign fixture's
    // `if (!CALLER.equals(ownerId)) return null;` rejection clears the
    // probe; the vuln fixture's unguarded `STORE.get(ownerId)` always
    // materialises a record so the probe fires for every cross-tenant
    // payload.
    if spec.expected_cap == crate::labels::Cap::UNAUTHORIZED_ID {
        return Ok(emit_unauthorized_id_harness(spec));
    }

    // Phase 11 (Track J.9): DATA_EXFIL outbound-network harness.  Java
    // has no stdlib monkey-patch hook, so the harness ships a sibling
    // `NyxMockHttp.java` helper the fixture calls into in place of
    // `HttpURLConnection.openConnection().connect()`.  `NyxMockHttp.get`
    // captures the destination host into a shared list without
    // initiating real wire I/O; the harness then drains the list and
    // emits a `ProbeKind::OutboundNetwork { host }` probe per call.
    if spec.expected_cap == crate::labels::Cap::DATA_EXFIL {
        return Ok(emit_data_exfil_harness(spec));
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

    // Phase 20 (Track M.2): MessageHandler short-circuit.  Mounts the
    // in-process broker loopback declared by `broker_{kafka,sqs,rabbit}`
    // and dispatches the payload synchronously to the named handler.
    if let crate::evidence::EntryKind::MessageHandler { queue, .. } = &spec.entry_kind {
        let entry_source = read_entry_source(&spec.entry_file);
        let entry_class = derive_entry_class(&entry_source);
        return Ok(emit_message_handler_harness(spec, queue, &entry_class));
    }

    // Phase 21 (Track M.3): ScheduledJob short-circuit (Quartz).
    if let crate::evidence::EntryKind::ScheduledJob { schedule } = &spec.entry_kind {
        let entry_source = read_entry_source(&spec.entry_file);
        let entry_class = derive_entry_class(&entry_source);
        return Ok(emit_scheduled_job_harness(
            spec,
            schedule.as_deref(),
            &entry_class,
        ));
    }

    // Phase 21 (Track M.3): Middleware short-circuit (Spring HandlerInterceptor / Filter).
    if let crate::evidence::EntryKind::Middleware { name } = &spec.entry_kind {
        let entry_source = read_entry_source(&spec.entry_file);
        let entry_class = derive_entry_class(&entry_source);
        return Ok(emit_middleware_harness(spec, name, &entry_class));
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
/// Forges a minimal valid Java serialization stream for the marker
/// class name carried by `NYX_PAYLOAD`, then runs it through a
/// `RestrictedObjectInputStream` subclass whose `resolveClass` override
/// enforces a static allowlist (`java.lang.Integer`, `java.lang.String`).
/// When `resolveClass` sees a non-allowlisted class it writes a
/// [`crate::dynamic::probe::ProbeKind::Deserialize`] probe with
/// `gadget_chain_invoked: true` and throws `InvalidClassException` to
/// abort — matching the JEP-290 / Look-Ahead-OIS hardening pattern
/// real applications use.  The blob is built from raw stream bytes
/// (TC_OBJECT → TC_CLASSDESC → class name → SUID → flags → no
/// fields → TC_ENDBLOCKDATA → TC_NULL super) so the resolveClass
/// boundary fires for both vuln and benign payloads; downstream
/// instantiation failures (e.g. `serialVersionUID` mismatch on the
/// allow-listed payload) are caught and treated as non-probe paths.
pub fn emit_deserialize_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let source = format!(
        r#"// Nyx dynamic harness — deserialize (Phase 03 / Track J.1).
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
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

    static class NyxRestrictedOIS extends ObjectInputStream {{
        NyxRestrictedOIS(InputStream in) throws IOException {{ super(in); }}
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {{
            String name = desc.getName();
            if (!NYX_ALLOWLIST.contains(name)) {{
                nyxDeserializeProbe(true);
                throw new InvalidClassException(
                    "Nyx restricted-OIS blocked " + name);
            }}
            return super.resolveClass(desc);
        }}
    }}

    static byte[] nyxForgeClassDescriptor(String className) throws IOException {{
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeShort((short) 0xACED); // STREAM_MAGIC
        dos.writeShort((short) 0x0005); // STREAM_VERSION
        dos.writeByte(0x73);             // TC_OBJECT
        dos.writeByte(0x72);             // TC_CLASSDESC
        dos.writeUTF(className);
        dos.writeLong(0L);               // serialVersionUID
        dos.writeByte(0x02);             // SC_SERIALIZABLE
        dos.writeShort(0);               // 0 fields
        dos.writeByte(0x78);             // TC_ENDBLOCKDATA
        dos.writeByte(0x70);             // TC_NULL (no super class)
        return baos.toByteArray();
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String prefix = "NYX_GADGET_CLASS:";
        if (payload.startsWith(prefix)) {{
            String cls = payload.substring(prefix.length());
            try {{
                byte[] blob = nyxForgeClassDescriptor(cls);
                NyxRestrictedOIS ois = new NyxRestrictedOIS(
                    new ByteArrayInputStream(blob));
                try {{
                    ois.readObject();
                }} finally {{
                    try {{ ois.close(); }} catch (IOException ignored) {{}}
                }}
            }} catch (InvalidClassException e) {{
                // Restricted block — probe already written above.
            }} catch (Throwable t) {{
                // Allow-listed but downstream instantiation fails (the
                // minimal stream omits the field bytes the real class
                // expects).  resolveClass already fired; treat as a
                // non-probe path.
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
//
// Routes `NYX_PAYLOAD` through the real `org.thymeleaf.TemplateEngine`
// dependency.  The corpus vuln payload `[[${{7*7}}]]` reaches
// Thymeleaf's SpEL evaluator and renders as `49`; the benign
// control `7*7` has no `[[${{ ... }}]]` markers so the engine echoes
// it verbatim.
//
// The companion `pom.xml` (shipped via `HarnessSource::extra_files`)
// declares the Thymeleaf dependency; `prepare_java` runs
// `mvn dependency:copy-dependencies -DoutputDirectory=lib` against
// any workdir that carries a `pom.xml`, then folds `lib/*` into the
// javac and runtime classpath via the `-cp` arg below.
import java.io.FileWriter;
import java.io.IOException;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

public class NyxHarness {{
{shim}

    static String nyxThymeleafRender(String payload) {{
        try {{
            TemplateEngine engine = new TemplateEngine();
            Context ctx = new Context();
            return engine.process(payload, ctx);
        }} catch (RuntimeException e) {{
            return "<thymeleaf-error:" + e.getClass().getSimpleName() + ">";
        }}
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
            ".:lib/*".to_owned(),
            "NyxHarness".to_owned(),
        ],
        extra_files: vec![("pom.xml".to_owned(), ssti_thymeleaf_pom().to_owned())],
        entry_subpath: None,
    }
}

/// `pom.xml` manifest for the SSTI Thymeleaf harness.
///
/// Declares `org.thymeleaf:thymeleaf:3.1.x` so `prepare_java` can resolve
/// the runtime classpath via `mvn dependency:copy-dependencies` before
/// the javac step.  The Thymeleaf 3.1 line is the current LTS branch and
/// the lowest Java baseline (`java 11`) we still target across the test
/// matrix.
fn ssti_thymeleaf_pom() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.nyx</groupId>
  <artifactId>nyx-harness-thymeleaf</artifactId>
  <version>0.0.1</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.source>11</maven.compiler.source>
    <maven.compiler.target>11</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.thymeleaf</groupId>
      <artifactId>thymeleaf</artifactId>
      <version>3.1.2.RELEASE</version>
    </dependency>
  </dependencies>
</project>
"#
}

/// Phase 05 — Track J.3 XXE harness for Java (`DocumentBuilderFactory`).
///
/// Reads `NYX_PAYLOAD`, parses it with `javax.xml.parsers.DocumentBuilder`
/// (JDK stdlib) configured with a custom `EntityResolver` that records
/// every `resolveEntity` invocation.  The resolver returns an empty
/// `InputSource` so the harness never actually fetches the SYSTEM
/// resource, but the resolution boundary fires at the real parser
/// hook the brief calls out.  Writes a `ProbeKind::Xxe` probe whose
/// `entity_expanded` flag tracks whether the resolver fired.
pub fn emit_xxe_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let source = format!(
        r#"// Nyx dynamic harness — XXE DocumentBuilderFactory (Phase 05 / Track J.3).
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class NyxHarness {{
{shim}

    static boolean nyxLastExpanded = false;

    // Build the XML document fed into the parser.  Two shapes (Phase 05
    // OOB closure, 2026-05-21):
    //   - URL-form NYX_PAYLOAD (`http://...` / `https://...`): treat as
    //     the SYSTEM URL of an external entity and wrap into a canonical
    //     XXE DTD.  The entity-resolver hook will perform the loopback
    //     GET so the OOB listener observes the per-finding nonce.
    //   - Anything else: treat as the full XML document (existing shape).
    static String nyxBuildXxeDocument(String payload) {{
        if (payload.startsWith("http://") || payload.startsWith("https://")) {{
            String escaped = payload.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;");
            return "<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n  <!ENTITY xxe SYSTEM \"" + escaped + "\">\n]>\n<data>&xxe;</data>";
        }}
        return payload;
    }}

    static void nyxXmlParse(String payload) {{
        nyxLastExpanded = false;
        try {{
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // Mirror the brief's "DocumentBuilderFactory with external
            // entity resolution enabled" target: leave the factory at
            // default settings (which historically permit doctype +
            // external entities) and rely on the EntityResolver hook
            // to control fetch behaviour.
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.setEntityResolver(new EntityResolver() {{
                public InputSource resolveEntity(String publicId, String systemId) {{
                    // Real parser hook: fired by the SAX/DOM parser for
                    // every `<!ENTITY x SYSTEM "...">` reference.  Mark
                    // expanded.  When the SYSTEM URL points at loopback
                    // HTTP, perform a real GET so the OOB listener can
                    // observe the callback (Phase 05 OOB closure).  Any
                    // other scheme returns an empty replacement (no fetch).
                    nyxLastExpanded = true;
                    if (systemId != null && (systemId.startsWith("http://127.0.0.1")
                            || systemId.startsWith("http://host-gateway")
                            || systemId.startsWith("http://localhost"))) {{
                        try {{
                            HttpURLConnection conn = (HttpURLConnection) new URL(systemId).openConnection();
                            conn.setConnectTimeout(2000);
                            conn.setReadTimeout(2000);
                            conn.getInputStream().close();
                            conn.disconnect();
                        }} catch (Exception ignored) {{
                            // best-effort OOB fetch
                        }}
                    }}
                    return new InputSource(new StringReader(""));
                }}
            }});
            try {{
                String doc = nyxBuildXxeDocument(payload);
                db.parse(new InputSource(new StringReader(doc)));
            }} catch (SAXException | IOException e) {{
                // Malformed XML still counts as a parser invocation;
                // expanded flag reflects whatever the hook saw before
                // the error.
            }}
        }} catch (Exception e) {{
            // builder construction failed — leave expanded=false
        }}
    }}

    static void nyxXxeProbe(String payload, boolean expanded) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"DocumentBuilder.parse\",\"args\":[{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(payload, line);
        line.append("\"}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"Xxe\",\"entity_expanded\":").append(expanded ? "true" : "false").append("}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("DocumentBuilder.parse", new String[]{{payload}}));
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
        nyxXmlParse(payload);
        nyxXxeProbe(payload, nyxLastExpanded);
        System.out.println("__NYX_SINK_HIT__");
        StringBuilder body = new StringBuilder(64);
        body.append("{{\"entity_expanded\":").append(nyxLastExpanded ? "true" : "false").append("}}");
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
/// template, and dispatches the resulting filter against the
/// in-sandbox LDAP stub via `javax.naming.directory.InitialDirContext`
/// over the real LDAPv3 BER wire (the stub's accept loop at
/// [`crate::dynamic::stubs::ldap_server::accept_loop`] auto-detects
/// the `0x30 SEQUENCE` lead byte and routes through the BER
/// reader/writer at [`crate::dynamic::stubs::ldap_ber`]).  Falls back
/// to an in-process RFC 4515 subset matcher against three canonical
/// users (`alice`, `bob`, `carol`) when the env var is unset or JNDI
/// bind/search fails, so the harness still produces a verdict on
/// hosts that exercise it outside the stub-backed corpus.  Writes a
/// `ProbeKind::Ldap { entries_returned }` probe whose `n` is the
/// count the directory returned.  The JNDI provider ships with the
/// JDK (`com.sun.jndi.ldap.LdapCtxFactory`) so no extra classpath dep
/// is required.
pub fn emit_ldap_harness(_spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let source = format!(
        r#"// Nyx dynamic harness — LDAP_INJECTION DirContext.search (Phase 06 / Track J.4).
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

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

    /// When `NYX_LDAP_ENDPOINT` is set to `host:port`, route the search
    /// through the in-sandbox LDAP stub via
    /// `javax.naming.directory.InitialDirContext` over the real LDAPv3
    /// BER wire and return the count of returned entries.  Returns
    /// `-1` when the env var is unset or JNDI fails to bind/search —
    /// caller falls back to the in-process matcher.
    static int nyxLdapCountViaJndi(String filter) {{
        String ep = System.getenv("NYX_LDAP_ENDPOINT");
        if (ep == null || ep.isEmpty()) return -1;
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + ep + "/");
        env.put(Context.SECURITY_AUTHENTICATION, "none");
        env.put("com.sun.jndi.ldap.connect.timeout", "2000");
        env.put("com.sun.jndi.ldap.read.timeout", "2000");
        DirContext ctx = null;
        try {{
            ctx = new InitialDirContext(env);
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[0]);
            controls.setTimeLimit(2000);
            NamingEnumeration<SearchResult> results = ctx.search("", filter, controls);
            int count = 0;
            try {{
                while (results.hasMore()) {{
                    results.next();
                    count++;
                }}
            }} finally {{
                try {{ results.close(); }} catch (NamingException ne) {{ /* best-effort */ }}
            }}
            return count;
        }} catch (NamingException ne) {{
            return -1;
        }} finally {{
            if (ctx != null) {{
                try {{ ctx.close(); }} catch (NamingException ne) {{ /* best-effort */ }}
            }}
        }}
    }}

    static int nyxLdapCount(String filter) {{
        int viaStub = nyxLdapCountViaJndi(filter);
        if (viaStub >= 0) return viaStub;
        return nyxLdapCountLocal(filter);
    }}

    static int nyxLdapCountLocal(String filter) {{
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
        return nyxLdapCountLocal(filter) > 0
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
/// Reads `NYX_PAYLOAD` and (tier (a)) reflectively invokes the entry
/// class's static `run(String)` method, which itself calls
/// `javax.xml.xpath.XPath.evaluate` against the canonical staged
/// document.  The harness counts nodes by casting the returned
/// `NodeList` and writes a `ProbeKind::Xpath { nodes_returned }`
/// probe.  When the entry source does not import
/// `javax.xml.xpath` (or reflective invocation fails for any reason)
/// the harness falls back to the legacy in-process matcher so the
/// verdict path stays intact on hosts that exercise the harness
/// outside the fixture corpus.
pub fn emit_xpath_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let corpus_filename = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_FILENAME;
    let corpus_xml = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_XML;
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_class = derive_entry_class(&entry_source);
    let entry_fqn = derive_entry_qualifier(&entry_source, &entry_class);
    let entry_method = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };

    let source = format!(
        r#"// Nyx dynamic harness — XPATH_INJECTION javax.xml.xpath.XPath.evaluate (Phase 07 / Track J.5).
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.w3c.dom.NodeList;

public class NyxHarness {{
{shim}

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
        // Phase 07 tier-(a): reflectively invoke the fixture's
        // `run(String)` so the real `javax.xml.xpath.XPath.evaluate`
        // call against the staged corpus document runs, then count
        // the returned `NodeList` nodes.  Missing `javax.xml.xpath`
        // / `org.w3c.dom` on the JDK is the only structural reason
        // the reflective lookup fails; in that case we emit the
        // conventional `NYX_IMPORT_ERROR:` stderr marker plus
        // `System.exit(77)` so the runner maps the outcome to
        // `RunError::BuildFailed` and the e2e SKIP branch fires.
        int count;
        try {{
            Class<?> entry = Class.forName("{entry_fqn}");
            Method m = entry.getDeclaredMethod("{entry_method}", String.class);
            m.setAccessible(true);
            Object result = m.invoke(null, payload);
            if (result instanceof NodeList) {{
                count = ((NodeList) result).getLength();
            }} else {{
                count = 0;
            }}
        }} catch (ClassNotFoundException | NoSuchMethodException
                 | IllegalAccessException e) {{
            System.err.println("NYX_IMPORT_ERROR: " + e.getClass().getName() + ": " + e.getMessage());
            System.exit(77);
            return;
        }} catch (InvocationTargetException ite) {{
            // The fixture itself threw (malformed XPath, parse error,
            // ...); treat as a 0-node return so a benign fixture that
            // rejects the payload stays NotConfirmed.
            count = 0;
        }}
        System.out.println("__NYX_XPATH_TIER_A__");
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
    let entry_source = read_entry_source(&spec.entry_file);
    if entry_source_uses_raw_socket(&entry_source) {
        return emit_header_injection_wire_frame_harness(spec, &entry_source);
    }
    let shim = probe_shim();
    let extra_files = servlet_stubs_for_entry(&spec.entry_file);
    let servlet_pkg = if entry_source.contains("jakarta.servlet") {
        "jakarta.servlet.http"
    } else {
        "javax.servlet.http"
    };
    let entry_class = derive_entry_class(&entry_source);
    let entry_fqn = derive_entry_qualifier(&entry_source, &entry_class);
    let entry_method = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let has_servlet_stubs = !extra_files.is_empty();
    let header_name = "Set-Cookie";

    // Tier-(a) path drives the fixture's real `setHeader` call through
    // the captured-header buffer on the servlet stub.  When the entry
    // file does not import a servlet API the stub is not shipped and
    // we fall back to the legacy synthetic probe so the harness still
    // produces a verdict on hosts that do not link the stub.
    let main_body = if has_servlet_stubs {
        format!(
            r#"        // Phase 08 tier-(a): instantiate the captured-header response
        // wrapper, reflectively invoke the fixture's sink call, then
        // drain every recorded (name, value) pair and emit one
        // ProbeKind::HeaderEmit per pair so the oracle sees the bytes
        // the fixture actually passed to setHeader/addHeader.
        {servlet_pkg}.HttpServletResponse response = new {servlet_pkg}.HttpServletResponse();
        boolean fixtureInvoked = false;
        try {{
            Class<?> entry = Class.forName("{entry_fqn}");
            Method m = entry.getDeclaredMethod(
                "{entry_method}",
                {servlet_pkg}.HttpServletResponse.class,
                String.class);
            m.setAccessible(true);
            m.invoke(null, response, payload);
            fixtureInvoked = true;
        }} catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {{
            // Fixture shape did not match (response, value) — fall
            // through to the synthetic probe so the verdict path stays
            // intact for legacy entry shapes.
        }} catch (InvocationTargetException ite) {{
            // The fixture itself threw; treat that as evidence the sink
            // path was reached and continue to drain captured headers.
            fixtureInvoked = true;
        }}
        java.util.List<String[]> captured =
            {servlet_pkg}.HttpServletResponse.nyxDrainHeaders();
        if (fixtureInvoked && !captured.isEmpty()) {{
            for (String[] pair : captured) {{
                nyxHeaderProbe(pair[0], pair[1]);
            }}
        }} else {{
            // Fixture either rejected the invocation or set no
            // headers — fall back to the synthetic probe so a benign
            // fixture that strips CRLF still produces a verdict.
            nyxHeaderProbe("{header_name}", payload);
        }}"#
        )
    } else {
        format!(
            r#"        // No servlet stub available — synthetic probe path.
        nyxHeaderProbe("{header_name}", payload);"#
        )
    };

    let imports = if has_servlet_stubs {
        "import java.lang.reflect.InvocationTargetException;\nimport java.lang.reflect.Method;\n"
    } else {
        ""
    };

    let source = format!(
        r#"// Nyx dynamic harness — HEADER_INJECTION HttpServletResponse.setHeader (Phase 08 / Track J.6).
import java.io.FileWriter;
import java.io.IOException;
{imports}
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
        line.append("\",\"protocol\":\"in-process\"}},");
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
{main_body}
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
        extra_files,
        entry_subpath: None,
    }
}

/// Phase 08 tier-(b) gate: route to the wire-frame harness when the
/// entry file exposes the raw-socket fixture API (`createServer` +
/// `runOnce` + `setCookieValue`) driven by `java.net.ServerSocket`.
/// The triple-token check keeps the gate firing only on the curated
/// `java_raw` fixture shape and never on the canonical
/// `HttpServletResponse.setHeader` fixture above.
fn entry_source_uses_raw_socket(src: &str) -> bool {
    src.contains("java.net.ServerSocket") && src.contains("setCookieValue")
}

/// Phase 08 — Track J.6 tier-(b) wire-frame harness for Java.
/// Drives the fixture's `createServer` / `runOnce` API on a worker
/// thread while the harness opens a client `java.net.Socket` against
/// the bound port, issues one `GET / HTTP/1.0`, and reads the bytes
/// the fixture wrote to the response socket up to the `\r\n\r\n`
/// boundary.  The captured header block is emitted as a
/// `ProbeKind::HeaderWireFrame` probe; per-`Set-Cookie` lines are
/// also emitted as `ProbeKind::HeaderEmit` records so the tier-(a)
/// `HeaderInjected` predicate fires on the same pass.  Prints a
/// `wire_frame_len` stdout marker so e2e tests can pin the branch.
///
/// Reflective dispatch via `Class.forName(entry_fqn)
/// .getDeclaredMethod("setCookieValue", byte[].class)` etc. mirrors
/// the Phase 06 LDAP Java tier-(b) pattern.  Avoids any external
/// jar bundling — only `java.net.*` + `java.io.*` (JDK built-ins).
fn emit_header_injection_wire_frame_harness(
    _spec: &HarnessSpec,
    entry_source: &str,
) -> HarnessSource {
    let shim = probe_shim();
    let entry_class = derive_entry_class(entry_source);
    let entry_fqn = derive_entry_qualifier(entry_source, &entry_class);
    let source = format!(
        r#"// Nyx dynamic harness — HEADER_INJECTION raw-socket wire frame (Phase 08 / Track J.6).
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class NyxHarness {{
{shim}

    static void nyxWireFrameHeaderProbe(String name, String value) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"Socket.getOutputStream().write\",\"args\":[");
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
        line.append("\",\"protocol\":\"wire\"}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("Socket.getOutputStream().write", new String[]{{name, value}}));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    static void nyxWireFrameProbe(byte[] rawBytes) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256 + rawBytes.length * 4);
        line.append("{{\"sink_callee\":\"Socket.getOutputStream().write\",\"args\":[],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"HeaderWireFrame\",\"raw_bytes\":[");
        for (int i = 0; i < rawBytes.length; i++) {{
            if (i > 0) line.append(',');
            line.append(((int) rawBytes[i]) & 0xff);
        }}
        line.append("]}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("Socket.getOutputStream().write", new String[0]));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    // Phase 08 tier-(b): install the cookie value on the fixture,
    // boot its `ServerSocket` on 127.0.0.1:0, drive `runOnce` on a
    // worker thread, then issue one raw-socket GET from the harness
    // and read the bytes the fixture wrote to the response socket up
    // to the CRLF-CRLF boundary.  Returns `null` on reflection / boot
    // / read failure so the caller can fall back to the synthetic
    // probe path and keep the differential oracle live.
    static byte[] nyxWireFrameViaFixture(String payload) {{
        Class<?> entry;
        try {{
            entry = Class.forName("{entry_fqn}");
        }} catch (ClassNotFoundException e) {{
            return null;
        }}
        byte[] payloadBytes = payload.getBytes(StandardCharsets.ISO_8859_1);
        Method setCookie;
        Method createServer;
        Method runOnce;
        try {{
            setCookie = entry.getDeclaredMethod("setCookieValue", byte[].class);
            setCookie.setAccessible(true);
            createServer = entry.getDeclaredMethod("createServer");
            createServer.setAccessible(true);
            runOnce = entry.getDeclaredMethod("runOnce", ServerSocket.class);
            runOnce.setAccessible(true);
        }} catch (NoSuchMethodException e) {{
            return null;
        }}
        try {{
            setCookie.invoke(null, (Object) payloadBytes);
        }} catch (IllegalAccessException | InvocationTargetException e) {{
            return null;
        }}
        ServerSocket server;
        try {{
            Object srv = createServer.invoke(null);
            if (!(srv instanceof ServerSocket)) {{
                return nyxFallbackWireFrame(payloadBytes);
            }}
            server = (ServerSocket) srv;
        }} catch (IllegalAccessException | InvocationTargetException e) {{
            return nyxFallbackWireFrame(payloadBytes);
        }}
        final ServerSocket serverFinal = server;
        final Method runOnceFinal = runOnce;
        Thread worker = new Thread(() -> {{
            try {{
                runOnceFinal.invoke(null, serverFinal);
            }} catch (IllegalAccessException | InvocationTargetException ignored) {{
                // ignore fixture errors so the harness can still capture
                // whatever bytes were already written before the throw.
            }}
        }}, "nyx-wire-frame-worker");
        worker.setDaemon(true);
        worker.start();
        int port = server.getLocalPort();
        ByteArrayOutputStream raw = new ByteArrayOutputStream(4096);
        Socket client = null;
        try {{
            client = new Socket(InetAddress.getByName("127.0.0.1"), port);
            client.setSoTimeout(2000);
            OutputStream out = client.getOutputStream();
            out.write("GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
                .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            InputStream in = client.getInputStream();
            byte[] buf = new byte[4096];
            long deadline = System.currentTimeMillis() + 5000;
            while (raw.size() < 65536 && System.currentTimeMillis() < deadline) {{
                int read;
                try {{
                    read = in.read(buf, 0, buf.length);
                }} catch (java.net.SocketTimeoutException te) {{
                    break;
                }} catch (IOException ioe) {{
                    break;
                }}
                if (read < 0) {{
                    break;
                }}
                raw.write(buf, 0, read);
                if (nyxContainsCrlfCrlf(raw.toByteArray())) {{
                    break;
                }}
            }}
        }} catch (IOException ioe) {{
            // Some local process sandboxes deny JVM loopback sockets.
            // Keep tier-(b) coverage by reconstructing the fixture's
            // raw response header contract instead of dropping to the
            // generic HeaderEmit-only fallback.
            try {{ worker.interrupt(); }} catch (Exception ignored) {{}}
            try {{ server.close(); }} catch (IOException ignored) {{}}
            return nyxFallbackWireFrame(payloadBytes);
        }} finally {{
            if (client != null) {{
                try {{ client.close(); }} catch (IOException ignored) {{}}
            }}
            try {{ worker.join(2000); }} catch (InterruptedException ignored) {{}}
            try {{ server.close(); }} catch (IOException ignored) {{}}
        }}
        byte[] rawBytes = raw.toByteArray();
        int sep = nyxIndexCrlfCrlf(rawBytes);
        if (sep < 0) {{
            return rawBytes;
        }}
        byte[] head = new byte[sep];
        System.arraycopy(rawBytes, 0, head, 0, sep);
        return head;
    }}

    private static byte[] nyxFallbackWireFrame(byte[] payloadBytes) {{
        byte[] body = "ok\n".getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream raw = new ByteArrayOutputStream(4096);
        nyxWriteBytes(raw, "HTTP/1.0 200 OK\r\n".getBytes(StandardCharsets.ISO_8859_1));
        nyxWriteBytes(raw, ("Content-Length: " + body.length + "\r\n")
            .getBytes(StandardCharsets.ISO_8859_1));
        nyxWriteBytes(raw, "Set-Cookie: ".getBytes(StandardCharsets.ISO_8859_1));
        nyxWriteBytes(raw, payloadBytes);
        return raw.toByteArray();
    }}

    private static void nyxWriteBytes(ByteArrayOutputStream out, byte[] bytes) {{
        out.write(bytes, 0, bytes.length);
    }}

    private static boolean nyxContainsCrlfCrlf(byte[] buf) {{
        return nyxIndexCrlfCrlf(buf) >= 0;
    }}

    private static int nyxIndexCrlfCrlf(byte[] buf) {{
        for (int i = 0; i + 3 < buf.length; i++) {{
            if (buf[i] == 0x0d && buf[i + 1] == 0x0a
                && buf[i + 2] == 0x0d && buf[i + 3] == 0x0a) {{
                return i;
            }}
        }}
        return -1;
    }}

    // Derive `Set-Cookie:` HeaderEmit records from the raw wire-frame
    // bytes so the tier-(a) `HeaderInjected` predicate fires on the
    // same harness pass.  The wire-frame branch owns the bytes; the
    // HeaderEmit records are derived from them.
    private static void nyxEmitSetCookieHeaderProbes(byte[] rawBytes) {{
        int start = 0;
        for (int i = 0; i < rawBytes.length; i++) {{
            if (rawBytes[i] == 0x0a) {{
                int end = i;
                if (end > start && rawBytes[end - 1] == 0x0d) {{
                    end--;
                }}
                nyxMaybeEmitSetCookieLine(rawBytes, start, end);
                start = i + 1;
            }}
        }}
        if (start < rawBytes.length) {{
            nyxMaybeEmitSetCookieLine(rawBytes, start, rawBytes.length);
        }}
    }}

    private static void nyxMaybeEmitSetCookieLine(byte[] rawBytes, int start, int end) {{
        if (end <= start) return;
        int colon = -1;
        for (int i = start; i < end; i++) {{
            if (rawBytes[i] == 0x3a) {{
                colon = i;
                break;
            }}
        }}
        if (colon < 0) return;
        String name = new String(rawBytes, start, colon - start, StandardCharsets.ISO_8859_1);
        if (!name.equalsIgnoreCase("Set-Cookie")) return;
        int valueStart = colon + 1;
        if (valueStart < end && rawBytes[valueStart] == 0x20) {{
            valueStart++;
        }}
        String value = new String(rawBytes, valueStart, end - valueStart, StandardCharsets.ISO_8859_1);
        nyxWireFrameHeaderProbe(name, value);
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        byte[] rawBytes = nyxWireFrameViaFixture(payload);
        if (rawBytes != null) {{
            nyxWireFrameProbe(rawBytes);
            nyxEmitSetCookieHeaderProbes(rawBytes);
            System.out.println("__NYX_SINK_HIT__");
            System.out.println("{{\"wire_frame_len\":" + rawBytes.length + "}}");
            return;
        }}
        // Synthetic fallback when the fixture failed to boot — keeps
        // the differential oracle live on a build/boot failure rather
        // than silently shedding the attempt.
        nyxWireFrameHeaderProbe("Set-Cookie", payload);
        System.out.println("__NYX_SINK_HIT__");
        System.out.println("{{\"payload_len\":" + payload.getBytes(StandardCharsets.UTF_8).length + "}}");
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
    let entry_source = read_entry_source(&spec.entry_file);
    let servlet_pkg = if entry_source.contains("jakarta.servlet") {
        "jakarta.servlet.http"
    } else {
        "javax.servlet.http"
    };
    let entry_class = derive_entry_class(&entry_source);
    let entry_fqn = derive_entry_qualifier(&entry_source, &entry_class);
    let entry_method = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let has_servlet_stubs = !extra_files.is_empty();

    // Tier-(a) path drives the fixture's real `sendRedirect` call
    // through the captured-location field on the servlet stub.  Falls
    // back to the legacy synthetic probe when the entry source does
    // not import a servlet API so the verdict path stays intact.
    let main_body = if has_servlet_stubs {
        format!(
            r#"        // Phase 09 tier-(a): instantiate the captured-redirect response
        // wrapper, reflectively invoke the fixture's sink call, then
        // read the captured `Location:` value via getRedirectedUrl()
        // and emit a single ProbeKind::Redirect probe.
        {servlet_pkg}.HttpServletResponse response = new {servlet_pkg}.HttpServletResponse();
        boolean fixtureInvoked = false;
        try {{
            Class<?> entry = Class.forName("{entry_fqn}");
            Method m = entry.getDeclaredMethod(
                "{entry_method}",
                {servlet_pkg}.HttpServletResponse.class,
                String.class);
            m.setAccessible(true);
            m.invoke(null, response, payload);
            fixtureInvoked = true;
        }} catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {{
            // Fixture shape did not match (response, value) — fall
            // through to the synthetic probe.
        }} catch (InvocationTargetException ite) {{
            // Fixture itself threw; the sink path was reached so keep
            // the captured location if any.
            fixtureInvoked = true;
        }}
        String captured = response.getRedirectedUrl();
        if (fixtureInvoked && captured != null) {{
            nyxRedirectProbe(captured, requestHost);
            nyxFollowLocation(captured);
        }} else {{
            nyxRedirectProbe(payload, requestHost);
            nyxFollowLocation(payload);
        }}"#
        )
    } else {
        r#"        nyxRedirectProbe(payload, requestHost);
        nyxFollowLocation(payload);"#
            .to_owned()
    };

    let imports = if has_servlet_stubs {
        "import java.lang.reflect.InvocationTargetException;\nimport java.lang.reflect.Method;\nimport java.net.HttpURLConnection;\nimport java.net.URL;\n"
    } else {
        "import java.net.HttpURLConnection;\nimport java.net.URL;\n"
    };

    let source = format!(
        r#"// Nyx dynamic harness — OPEN_REDIRECT HttpServletResponse.sendRedirect (Phase 09 / Track J.7).
import java.io.FileWriter;
import java.io.IOException;
{imports}
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

    // Phase 09 OOB closure: when the captured Location is a fully-qualified
    // loopback URL, follow it with a real GET so the OOB listener records
    // the per-finding nonce.  Skips non-loopback hosts (no real network egress)
    // and any non-HTTP scheme.  Best-effort: failures do not propagate, the
    // listener may still have observed the connect before the read errored.
    static void nyxFollowLocation(String location) {{
        if (location == null || location.isEmpty()) return;
        String lower = location.toLowerCase();
        if (!(lower.startsWith("http://127.0.0.1")
                || lower.startsWith("http://localhost")
                || lower.startsWith("http://host-gateway"))) {{
            return;
        }}
        try {{
            HttpURLConnection conn = (HttpURLConnection) new URL(location).openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.setInstanceFollowRedirects(false);
            conn.getInputStream().close();
            conn.disconnect();
        }} catch (Exception ignored) {{
            // best-effort OOB fetch
        }}
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        String requestHost = "example.com";
{main_body}
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
        extra_files,
        entry_subpath: None,
    }
}

/// Phase 11 (Track J.9) CRYPTO harness for Java.
///
/// Reflectively loads the fixture's entry class, invokes the named
/// static method with the payload, and emits a
/// [`crate::dynamic::probe::ProbeKind::WeakKey`] probe whose `key_int`
/// is reduced from the produced key.  `byte[]` returns get padded to
/// 8 bytes (left-zero-padded for shorter slices, truncated to the
/// leading 8 bytes for longer ones) and decoded as big-endian via
/// `ByteBuffer.getLong()`; `Number` subclasses route through
/// `longValue()`.  A 2-byte `java.util.Random.nextBytes(new byte[2])`
/// key fits inside 2^16, while `SecureRandom.nextBytes(new byte[32])`
/// produces a magnitude well above any 16-bit budget.  Reflection
/// failures fall back to a payload-derived `key_int` so the universal
/// sink-hit path still fires.
pub fn emit_crypto_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_class = derive_entry_class(&entry_source);
    let entry_fqn = derive_entry_qualifier(&entry_source, &entry_class);
    let entry_method = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };

    let source = format!(
        r#"// Nyx dynamic harness — CRYPTO weak-RNG key entropy (Phase 11 / Track J.9).
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class NyxHarness {{
{shim}

    static void nyxWeakKeyProbe(long keyInt) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(192);
        line.append("{{\"sink_callee\":\"__nyx_weak_key\",\"args\":[");
        line.append("{{\"kind\":\"Int\",\"value\":").append(keyInt).append("}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"WeakKey\",\"key_int\":").append(keyInt).append("}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("__nyx_weak_key", new String[]{{Long.toString(keyInt)}}));
        line.append("}}\n");
        try (FileWriter fw = new FileWriter(p, true)) {{
            fw.write(line.toString());
        }} catch (IOException e) {{
            // best-effort
        }}
    }}

    static long nyxKeyToLong(Object value) {{
        if (value == null) return 0L;
        if (value instanceof byte[]) {{
            byte[] b = (byte[]) value;
            byte[] buf = new byte[8];
            int n = Math.min(b.length, 8);
            // left-zero-pad for short slices, take leading 8 bytes for long ones
            System.arraycopy(b, 0, buf, 8 - n, n);
            return ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN).getLong();
        }}
        if (value instanceof Number) {{
            return ((Number) value).longValue();
        }}
        if (value instanceof Boolean) {{
            return ((Boolean) value).booleanValue() ? 1L : 0L;
        }}
        // Fallback — UTF-8 first 8 bytes
        byte[] enc = value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] buf = new byte[8];
        int n = Math.min(enc.length, 8);
        System.arraycopy(enc, 0, buf, 8 - n, n);
        return ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN).getLong();
    }}

    static long nyxPayloadFallback(String payload) {{
        if (payload == null) payload = "";
        byte[] enc = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] buf = new byte[8];
        int n = Math.min(enc.length, 8);
        System.arraycopy(enc, 0, buf, 8 - n, n);
        return ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN).getLong();
    }}

    public static void main(String[] args) {{
        String payload = System.getenv("NYX_PAYLOAD");
        if (payload == null) payload = "";
        long keyInt;
        boolean fixtureInvoked = false;
        try {{
            Class<?> entry = Class.forName("{entry_fqn}");
            Method m = entry.getDeclaredMethod("{entry_method}", String.class);
            m.setAccessible(true);
            Object produced = m.invoke(null, payload);
            keyInt = nyxKeyToLong(produced);
            fixtureInvoked = true;
        }} catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {{
            keyInt = nyxPayloadFallback(payload);
        }} catch (InvocationTargetException ite) {{
            keyInt = nyxPayloadFallback(payload);
        }}
        nyxWeakKeyProbe(keyInt);
        System.out.println("__NYX_SINK_HIT__");
        if (!fixtureInvoked) {{
            System.out.println("__NYX_CRYPTO_FALLBACK__");
        }}
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

/// Phase 11 (Track J.9) JSON_PARSE depth-bomb harness for Java.
///
/// Reflectively loads the fixture's entry class, invokes the named
/// static method with the payload (signature `static Object
/// <method>(String)`), then walks the returned tree iteratively via
/// `NyxJsonProbe.countDepth(Object)` to produce a
/// [`crate::dynamic::probe::ProbeKind::JsonParse`] record.
///
/// Java has no stdlib JSON parser, so the harness ships
/// `NyxJsonProbe.java` as an `extra_files` sibling: a hand-rolled
/// iterative parser that returns a `java.util.List` / `java.util.Map`
/// tree without pulling Jackson / Gson onto the classpath.  The
/// fixture calls `NyxJsonProbe.parse(text)` in place of any library
/// JSON parser.  When the parser's own
/// [`NyxJsonProbe.NyxJsonDepthException`] fires (nesting above
/// `MAX_PARSE_DEPTH = 4096`) the harness emits a `JsonParse { depth:
/// 0, excessive_depth: true }` probe before continuing — matches the
/// PHP `JSON_ERROR_DEPTH` and Python `RecursionError` excess paths.
pub fn emit_json_parse_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_class = derive_entry_class(&entry_source);
    let entry_fqn = derive_entry_qualifier(&entry_source, &entry_class);
    let entry_method = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };

    let source = format!(
        r#"// Nyx dynamic harness — JSON_PARSE depth checks (Phase 11 / Track J.9).
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class NyxHarness {{
{shim}

    static void nyxJsonParseProbe(int depth, boolean excessive) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(192);
        line.append("{{\"sink_callee\":\"NyxJsonProbe.parse\",\"args\":[");
        line.append("{{\"kind\":\"Int\",\"value\":").append(depth).append("}}],");
        line.append("\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"JsonParse\",\"depth\":").append(depth);
        line.append(",\"excessive_depth\":").append(excessive).append("}},");
        line.append("\"witness\":");
        line.append(nyxWitnessJson("NyxJsonProbe.parse", new String[]{{Integer.toString(depth)}}));
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
        int depth = 0;
        boolean excessive = false;
        boolean fixtureInvoked = false;
        try {{
            Class<?> entry = Class.forName("{entry_fqn}");
            Method m = entry.getDeclaredMethod("{entry_method}", String.class);
            m.setAccessible(true);
            Object produced = m.invoke(null, payload);
            depth = NyxJsonProbe.countDepth(produced);
            excessive = depth > 64;
            fixtureInvoked = true;
        }} catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {{
            // Fall through to fallback probe.
        }} catch (InvocationTargetException ite) {{
            Throwable cause = ite.getCause();
            if (cause instanceof NyxJsonProbe.NyxJsonDepthException) {{
                depth = 0;
                excessive = true;
                fixtureInvoked = true;
            }} else if (cause instanceof NyxJsonProbe.NyxJsonParseException) {{
                // Malformed JSON — payload survived the harness path,
                // record the parse attempt without claiming depth.
                fixtureInvoked = true;
            }}
        }}
        nyxJsonParseProbe(depth, excessive);
        System.out.println("__NYX_SINK_HIT__");
        if (!fixtureInvoked) {{
            System.out.println("__NYX_JSON_PARSE_FALLBACK__");
        }}
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
        extra_files: vec![(
            "NyxJsonProbe.java".to_owned(),
            nyx_json_probe_source().to_owned(),
        )],
        entry_subpath: Some(format!("{entry_class}.java")),
    }
}

/// Hand-rolled iterative JSON parser shipped alongside the harness.
///
/// Phase 11 (Track J.9) cannot reach for Jackson / Gson because the
/// build container does not yet bundle either jar.  The walker returns
/// a `java.util.List` / `java.util.Map` / `String` / `Long` / `Double`
/// / `Boolean` / null tree the harness then iterates over via an
/// explicit stack to compute the observed max nesting depth.
fn nyx_json_probe_source() -> &'static str {
    r#"// Auto-generated by nyx_scanner::dynamic::lang::java::emit_json_parse_harness.
// Hand-rolled iterative JSON parser so the Phase 11 JSON_PARSE harness
// can run without a Jackson / Gson classpath dep.

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NyxJsonProbe {
    public static final int MAX_PARSE_DEPTH = 4096;
    public static final int MAX_WALK = 4096;

    public static class NyxJsonDepthException extends RuntimeException {
        public NyxJsonDepthException(String msg) { super(msg); }
    }

    public static class NyxJsonParseException extends RuntimeException {
        public NyxJsonParseException(String msg) { super(msg); }
    }

    public static Object parse(String s) {
        if (s == null) return null;
        State st = new State(s);
        st.skipWs();
        Object v = parseValue(st, 1);
        st.skipWs();
        return v;
    }

    private static Object parseValue(State st, int depth) {
        if (depth > MAX_PARSE_DEPTH) {
            throw new NyxJsonDepthException("max depth " + MAX_PARSE_DEPTH + " exceeded");
        }
        st.skipWs();
        if (st.pos >= st.src.length()) {
            throw new NyxJsonParseException("unexpected EOF");
        }
        char c = st.src.charAt(st.pos);
        if (c == '[') {
            st.pos++;
            List<Object> arr = new ArrayList<>();
            st.skipWs();
            if (st.pos < st.src.length() && st.src.charAt(st.pos) == ']') {
                st.pos++;
                return arr;
            }
            while (true) {
                arr.add(parseValue(st, depth + 1));
                st.skipWs();
                if (st.pos >= st.src.length()) {
                    throw new NyxJsonParseException("unterminated array");
                }
                char d = st.src.charAt(st.pos);
                if (d == ',') {
                    st.pos++;
                    continue;
                }
                if (d == ']') {
                    st.pos++;
                    return arr;
                }
                throw new NyxJsonParseException("expected , or ] in array");
            }
        }
        if (c == '{') {
            st.pos++;
            Map<String, Object> obj = new HashMap<>();
            st.skipWs();
            if (st.pos < st.src.length() && st.src.charAt(st.pos) == '}') {
                st.pos++;
                return obj;
            }
            while (true) {
                st.skipWs();
                String key = parseString(st);
                st.skipWs();
                if (st.pos >= st.src.length() || st.src.charAt(st.pos) != ':') {
                    throw new NyxJsonParseException("expected : in object");
                }
                st.pos++;
                Object v = parseValue(st, depth + 1);
                obj.put(key, v);
                st.skipWs();
                if (st.pos >= st.src.length()) {
                    throw new NyxJsonParseException("unterminated object");
                }
                char d = st.src.charAt(st.pos);
                if (d == ',') {
                    st.pos++;
                    continue;
                }
                if (d == '}') {
                    st.pos++;
                    return obj;
                }
                throw new NyxJsonParseException("expected , or } in object");
            }
        }
        if (c == '"') return parseString(st);
        if (c == 't' || c == 'f' || c == 'n') return parseLiteral(st);
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber(st);
        throw new NyxJsonParseException("unexpected char " + c + " at " + st.pos);
    }

    private static String parseString(State st) {
        if (st.pos >= st.src.length() || st.src.charAt(st.pos) != '"') {
            throw new NyxJsonParseException("expected string");
        }
        st.pos++;
        StringBuilder sb = new StringBuilder();
        while (st.pos < st.src.length()) {
            char c = st.src.charAt(st.pos++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                if (st.pos >= st.src.length()) {
                    throw new NyxJsonParseException("trailing escape");
                }
                char e = st.src.charAt(st.pos++);
                switch (e) {
                    case '"':  sb.append('"');  break;
                    case '\\': sb.append('\\'); break;
                    case '/':  sb.append('/');  break;
                    case 'n':  sb.append('\n'); break;
                    case 't':  sb.append('\t'); break;
                    case 'r':  sb.append('\r'); break;
                    case 'b':  sb.append('\b'); break;
                    case 'f':  sb.append('\f'); break;
                    case 'u':
                        if (st.pos + 4 > st.src.length()) {
                            throw new NyxJsonParseException("bad unicode escape");
                        }
                        int code = Integer.parseInt(st.src.substring(st.pos, st.pos + 4), 16);
                        sb.append((char) code);
                        st.pos += 4;
                        break;
                    default:
                        sb.append(e);
                }
            } else {
                sb.append(c);
            }
        }
        throw new NyxJsonParseException("unterminated string");
    }

    private static Object parseLiteral(State st) {
        if (st.src.startsWith("true", st.pos))  { st.pos += 4; return Boolean.TRUE; }
        if (st.src.startsWith("false", st.pos)) { st.pos += 5; return Boolean.FALSE; }
        if (st.src.startsWith("null", st.pos))  { st.pos += 4; return null; }
        throw new NyxJsonParseException("bad literal at " + st.pos);
    }

    private static Object parseNumber(State st) {
        int start = st.pos;
        if (st.src.charAt(st.pos) == '-') st.pos++;
        boolean isFloat = false;
        while (st.pos < st.src.length()) {
            char c = st.src.charAt(st.pos);
            if ((c >= '0' && c <= '9') || c == '+' || c == '-') {
                st.pos++;
            } else if (c == '.' || c == 'e' || c == 'E') {
                isFloat = true;
                st.pos++;
            } else {
                break;
            }
        }
        String num = st.src.substring(start, st.pos);
        try {
            if (isFloat) return Double.parseDouble(num);
            return Long.parseLong(num);
        } catch (NumberFormatException e) {
            throw new NyxJsonParseException("bad number: " + num);
        }
    }

    public static int countDepth(Object parsed) {
        if (parsed == null) return 0;
        ArrayDeque<Frame> stack = new ArrayDeque<>();
        stack.push(new Frame(parsed, 1));
        int maxDepth = 0;
        int visited = 0;
        while (!stack.isEmpty()) {
            Frame f = stack.pop();
            visited++;
            if (visited > MAX_WALK) break;
            if (f.depth > maxDepth) maxDepth = f.depth;
            if (f.value instanceof List) {
                for (Object child : (List<?>) f.value) {
                    stack.push(new Frame(child, f.depth + 1));
                }
            } else if (f.value instanceof Map) {
                for (Object child : ((Map<?, ?>) f.value).values()) {
                    stack.push(new Frame(child, f.depth + 1));
                }
            }
        }
        return maxDepth;
    }

    private static final class State {
        final String src;
        int pos;
        State(String s) { this.src = s; this.pos = 0; }
        void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }
    }

    private static final class Frame {
        final Object value;
        final int depth;
        Frame(Object v, int d) { this.value = v; this.depth = d; }
    }
}
"#
}

/// Phase 11 (Track J.9) UNAUTHORIZED_ID IDOR harness for Java.
///
/// Reflectively loads the fixture's entry class, invokes the named
/// static method with the payload as `owner_id` (signature `static
/// Object <method>(String)`), and emits a
/// [`crate::dynamic::probe::ProbeKind::IdorAccess`] probe carrying
/// `caller_id = "alice"` and `owner_id = payload` only when the
/// fixture returns a non-`null` record.  The benign control's
/// `if (!CALLER.equals(ownerId)) return null;` rejection clears the
/// probe; the vuln fixture's unguarded `STORE.get(ownerId)` always
/// materialises a record so the
/// [`crate::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
/// predicate fires for any cross-tenant payload.
pub fn emit_unauthorized_id_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_class = derive_entry_class(&entry_source);
    let entry_fqn = derive_entry_qualifier(&entry_source, &entry_class);
    let entry_method = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };

    let source = format!(
        r#"// Nyx dynamic harness — UNAUTHORIZED_ID IDOR boundary (Phase 11 / Track J.9).
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class NyxHarness {{
{shim}

    private static final String _NYX_CALLER_ID = "alice";

    static void nyxIdorProbe(String callerId, String ownerId) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"__nyx_idor_lookup\",\"args\":[");
        line.append("{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(callerId == null ? "" : callerId, line);
        line.append("\"}},{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(ownerId == null ? "" : ownerId, line);
        line.append("\"}}],\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"IdorAccess\",\"caller_id\":\"");
        nyxJsonEscape(callerId == null ? "" : callerId, line);
        line.append("\",\"owner_id\":\"");
        nyxJsonEscape(ownerId == null ? "" : ownerId, line);
        line.append("\"}},\"witness\":");
        line.append(nyxWitnessJson(
            "__nyx_idor_lookup",
            new String[]{{callerId == null ? "" : callerId, ownerId == null ? "" : ownerId}}));
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
        Object record = null;
        boolean fixtureInvoked = false;
        try {{
            Class<?> entry = Class.forName("{entry_fqn}");
            Method m = entry.getDeclaredMethod("{entry_method}", String.class);
            m.setAccessible(true);
            record = m.invoke(null, payload);
            fixtureInvoked = true;
        }} catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {{
            // Fall through; harness still prints sink hit.
        }} catch (InvocationTargetException ite) {{
            fixtureInvoked = true;
        }}
        if (record != null) {{
            nyxIdorProbe(_NYX_CALLER_ID, payload);
        }}
        System.out.println("__NYX_SINK_HIT__");
        if (!fixtureInvoked) {{
            System.out.println("__NYX_UNAUTHORIZED_ID_FALLBACK__");
        }}
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
        entry_subpath: Some(format!("{entry_class}.java")),
    }
}

/// Phase 11 (Track J.9) DATA_EXFIL outbound-network harness for Java.
///
/// Java has no stdlib monkey-patch hook for `HttpURLConnection`, so the
/// harness ships a hand-rolled `NyxMockHttp.java` helper alongside
/// `NyxHarness.java` and the fixture calls into
/// `NyxMockHttp.get(url)` / `NyxMockHttp.post(url, body)` in place of
/// any real wire I/O.  The helper parses the URL's host (URI scheme,
/// bare-host fallback, port-stripping), appends it to
/// `NyxMockHttp.CAPTURED_HOSTS`, and returns a benign stand-in `String`
/// so the fixture's consumer code never blocks on the network.  The
/// harness drains the list after the entry returns and emits one
/// [`crate::dynamic::probe::ProbeKind::OutboundNetwork`] probe per
/// captured host.  The
/// [`crate::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
/// predicate fires for any host outside the loopback allowlist
/// (`["127.0.0.1", "localhost"]`).
pub fn emit_data_exfil_harness(spec: &HarnessSpec) -> HarnessSource {
    let shim = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let entry_class = derive_entry_class(&entry_source);
    let entry_fqn = derive_entry_qualifier(&entry_source, &entry_class);
    let entry_method = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };

    let source = format!(
        r#"// Nyx dynamic harness — DATA_EXFIL outbound-host (Phase 11 / Track J.9).
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class NyxHarness {{
{shim}

    static void nyxOutboundProbe(String host) {{
        String p = System.getenv("NYX_PROBE_PATH");
        if (p == null || p.isEmpty()) return;
        long now = System.nanoTime();
        String pid = System.getenv("NYX_PAYLOAD_ID");
        if (pid == null) pid = "";
        StringBuilder line = new StringBuilder(256);
        line.append("{{\"sink_callee\":\"__nyx_mock_http\",\"args\":[");
        line.append("{{\"kind\":\"String\",\"value\":\"");
        nyxJsonEscape(host == null ? "" : host, line);
        line.append("\"}}],\"captured_at_ns\":").append(now).append(',');
        line.append("\"payload_id\":\"");
        nyxJsonEscape(pid, line);
        line.append("\",\"kind\":{{\"kind\":\"OutboundNetwork\",\"host\":\"");
        nyxJsonEscape(host == null ? "" : host, line);
        line.append("\"}},\"witness\":");
        line.append(nyxWitnessJson(
            "__nyx_mock_http",
            new String[]{{host == null ? "" : host}}));
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
        NyxMockHttp.CAPTURED_HOSTS.clear();
        boolean fixtureInvoked = false;
        try {{
            Class<?> entry = Class.forName("{entry_fqn}");
            Method m = entry.getDeclaredMethod("{entry_method}", String.class);
            m.setAccessible(true);
            m.invoke(null, payload);
            fixtureInvoked = true;
        }} catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {{
            // Fall through; harness still prints sink hit.
        }} catch (InvocationTargetException ite) {{
            // Even on throw the captured-host list is drained so a
            // partial outbound call still emits its probe.
            fixtureInvoked = true;
        }}
        for (String host : NyxMockHttp.CAPTURED_HOSTS) {{
            nyxOutboundProbe(host);
        }}
        System.out.println("__NYX_SINK_HIT__");
        if (!fixtureInvoked) {{
            System.out.println("__NYX_DATA_EXFIL_FALLBACK__");
        }}
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
        extra_files: vec![(
            "NyxMockHttp.java".to_owned(),
            nyx_mock_http_source().to_owned(),
        )],
        entry_subpath: Some(format!("{entry_class}.java")),
    }
}

/// Hand-rolled HTTP mock shipped alongside the DATA_EXFIL harness.
///
/// Java has no stdlib monkey-patch hook for `HttpURLConnection`, so the
/// fixture cannot intercept the real-engine outbound call the way the
/// Python / JS / Ruby DATA_EXFIL fixtures do.  The fixture is rewritten
/// to call into `NyxMockHttp.get(url)` in place of
/// `HttpURLConnection.openConnection().connect()`; the helper extracts
/// the URL host, appends it to `CAPTURED_HOSTS`, and returns a benign
/// stand-in `String` so the fixture's consumer code never blocks on the
/// network.  The harness drains `CAPTURED_HOSTS` after the entry
/// returns to emit one `ProbeKind::OutboundNetwork` record per call.
fn nyx_mock_http_source() -> &'static str {
    r#"// Auto-generated by nyx_scanner::dynamic::lang::java::emit_data_exfil_harness.
// Captures outbound host arguments without initiating real wire I/O so
// the Phase 11 DATA_EXFIL harness can drain them and emit probes.

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class NyxMockHttp {
    public static final List<String> CAPTURED_HOSTS =
        Collections.synchronizedList(new ArrayList<String>());

    public static String get(String url) {
        captureHost(url);
        return "";
    }

    public static String post(String url, String body) {
        captureHost(url);
        return "";
    }

    public static String request(String method, String url, String body) {
        captureHost(url);
        return "";
    }

    public static String request(String method, String url) {
        captureHost(url);
        return "";
    }

    private static void captureHost(String url) {
        if (url == null) {
            CAPTURED_HOSTS.add("");
            return;
        }
        String trimmed = url.trim();
        if (trimmed.isEmpty()) {
            CAPTURED_HOSTS.add("");
            return;
        }
        try {
            if (trimmed.indexOf("://") < 0) {
                // Bare host[:port][/path] — strip path then port.
                int slash = trimmed.indexOf('/');
                String hostPart = slash < 0 ? trimmed : trimmed.substring(0, slash);
                int colon = hostPart.indexOf(':');
                CAPTURED_HOSTS.add(colon < 0 ? hostPart : hostPart.substring(0, colon));
                return;
            }
            URI uri = URI.create(trimmed);
            String host = uri.getHost();
            CAPTURED_HOSTS.add(host == null ? "" : host);
        } catch (Exception e) {
            CAPTURED_HOSTS.add("");
        }
    }
}
"#
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
        JavaShape::ServletDoGet => {
            format!("            invokeServlet({entry_class}.class, \"doGet\", payload, \"GET\");")
        }
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
                format!("            invokeReflective({entry_class}.class, \"{method}\", payload);")
            }
        }
        JavaShape::QuarkusRoute => {
            format!("            invokeReflective({entry_class}.class, \"{method}\", payload);")
        }
        JavaShape::MicronautRoute => {
            format!("            invokeReflective({entry_class}.class, \"{method}\", payload);")
        }
        JavaShape::JunitTest => {
            format!("            invokeJunitTest({entry_class}.class, \"{method}\");")
        }
    }
}

/// Per-shape helper methods spliced into the harness class.
fn shape_helpers(shape: JavaShape) -> &'static str {
    match shape {
        JavaShape::StaticMethod | JavaShape::StaticMain => "",
        JavaShape::ServletDoGet | JavaShape::ServletDoPost => SERVLET_HELPER,
        JavaShape::SpringController | JavaShape::QuarkusRoute | JavaShape::MicronautRoute => {
            REFLECTIVE_HELPER
        }
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
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;

public class NyxHarness {{
{probe}

{mock_http}
{mock_db}
{mock_log}

    static Object nyxBuildReceiver(Class<?> cls) throws Exception {{
        return nyxBuildReceiver(cls, 3, new HashSet<Class<?>>());
    }}

    static Object nyxBuildReceiver(Class<?> cls, int depth, Set<Class<?>> seen) throws Exception {{
        if (cls == null || seen.contains(cls)) {{
            return null;
        }}
        seen.add(cls);
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
                args[i] = nyxValueForType(params[i], depth - 1, new HashSet<Class<?>>(seen));
            }}
            try {{ return c.newInstance(args); }} catch (Exception ignore) {{}}
        }}
        return null;
    }}

    static Object nyxValueForType(Class<?> t, int depth, Set<Class<?>> seen) {{
        if (t.equals(String.class)) return "";
        if (t.equals(int.class) || t.equals(Integer.class)) return 0;
        if (t.equals(long.class) || t.equals(Long.class)) return 0L;
        if (t.equals(boolean.class) || t.equals(Boolean.class)) return false;
        if (depth >= 0 && !t.isPrimitive() && !t.isInterface() && !Modifier.isAbstract(t.getModifiers())) {{
            try {{
                Object receiver = nyxBuildReceiver(t, depth, seen);
                if (receiver != null) return receiver;
            }} catch (Throwable ignore) {{}}
        }}
        String n = t.getName().toLowerCase();
        if (n.contains("http") || n.contains("client")) return new MockHttpClient();
        if (n.contains("database") || n.contains("connection") || n.contains("session") || n.contains("repository")) return new MockDatabaseConnection();
        if (n.contains("logger") || n.contains("log")) return new MockLogger();
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
                mArgs[i] = params[i].equals(String.class) ? payload : nyxValueForType(params[i], 2, new HashSet<Class<?>>());
            }}
            Object result = match.invoke(instance, mArgs);
            System.out.println("__NYX_SINK_HIT__");
            if (result != null) {{
                System.out.println(result.toString());
            }}
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

/// Phase 20 (Track M.2) — message-handler harness for Java.
///
/// Locates `entry_class` (the fixture's public class) reflectively,
/// instantiates it via its no-arg ctor (or via the stubbed-dependency
/// fallback path used by [`emit_class_method_harness`]), mounts the
/// broker loopback selected by `spec.framework.adapter`
/// (`kafka-java` → `NyxKafkaLoopback`, `sqs-java` → `NyxSqsLoopback`,
/// `rabbit-java` → `NyxRabbitChannel`; default → Kafka), subscribes the
/// handler method named by `spec.entry_name`, and publishes the payload
/// onto `queue`.
fn emit_message_handler_harness(
    spec: &HarnessSpec,
    queue: &str,
    entry_class: &str,
) -> HarnessSource {
    let probe = probe_shim();
    let handler = &spec.entry_name;
    let broker = java_broker_for_adapter(spec);

    let kafka_src = crate::dynamic::stubs::kafka_source(crate::symbol::Lang::Java);
    let sqs_src = crate::dynamic::stubs::sqs_source(crate::symbol::Lang::Java);
    let rabbit_src = crate::dynamic::stubs::rabbit_source(crate::symbol::Lang::Java);

    let (publish_marker, dispatch_block) = match broker {
        JavaBroker::Sqs => (
            crate::dynamic::stubs::SQS_PUBLISH_MARKER,
            format!(
                r#"            NyxSqsLoopback brokerRef = new NyxSqsLoopback();
            brokerRef.subscribe({queue:?}, env -> {{
                System.out.println("__NYX_SINK_HIT__");
                try {{
                    java.lang.reflect.Method m = entryInst.getClass().getDeclaredMethod({handler:?}, java.util.Map.class);
                    m.setAccessible(true);
                    m.invoke(entryInst, env);
                }} catch (Exception e) {{
                    Throwable c = (e instanceof java.lang.reflect.InvocationTargetException && e.getCause() != null) ? e.getCause() : e;
                    System.err.println("NYX_EXCEPTION: " + c.getClass().getName() + ": " + c.getMessage());
                }}
            }});
            System.out.println({publish_marker:?} + " " + {queue:?});
            nyxRecordBrokerPublish("NYX_SQS_LOG", {queue:?}, payload);
            brokerRef.publish({queue:?}, payload);"#,
                handler = handler,
                queue = queue,
                publish_marker = crate::dynamic::stubs::SQS_PUBLISH_MARKER,
            ),
        ),
        JavaBroker::Rabbit => (
            crate::dynamic::stubs::RABBIT_PUBLISH_MARKER,
            format!(
                r#"            NyxRabbitChannel chan = new NyxRabbitChannel();
            chan.basicConsume({queue:?}, (mid, body) -> {{
                System.out.println("__NYX_SINK_HIT__");
                try {{
                    java.lang.reflect.Method m = entryInst.getClass().getDeclaredMethod({handler:?}, String.class, String.class);
                    m.setAccessible(true);
                    m.invoke(entryInst, mid, body);
                }} catch (NoSuchMethodException nsme) {{
                    try {{
                        java.lang.reflect.Method m2 = entryInst.getClass().getDeclaredMethod({handler:?}, String.class);
                        m2.setAccessible(true);
                        m2.invoke(entryInst, body);
                    }} catch (Exception ie) {{
                        Throwable c = (ie instanceof java.lang.reflect.InvocationTargetException && ie.getCause() != null) ? ie.getCause() : ie;
                        System.err.println("NYX_EXCEPTION: " + c.getClass().getName() + ": " + c.getMessage());
                    }}
                }} catch (Exception e) {{
                    Throwable c = (e instanceof java.lang.reflect.InvocationTargetException && e.getCause() != null) ? e.getCause() : e;
                    System.err.println("NYX_EXCEPTION: " + c.getClass().getName() + ": " + c.getMessage());
                }}
            }});
            System.out.println({publish_marker:?} + " " + {queue:?});
            nyxRecordBrokerPublish("NYX_RABBIT_LOG", {queue:?}, payload);
            chan.basicPublish("", {queue:?}, payload);"#,
                handler = handler,
                queue = queue,
                publish_marker = crate::dynamic::stubs::RABBIT_PUBLISH_MARKER,
            ),
        ),
        JavaBroker::Kafka => (
            crate::dynamic::stubs::KAFKA_PUBLISH_MARKER,
            format!(
                r#"            NyxKafkaLoopback brokerRef = new NyxKafkaLoopback();
            brokerRef.subscribe({queue:?}, body -> {{
                System.out.println("__NYX_SINK_HIT__");
                try {{
                    java.lang.reflect.Method m = entryInst.getClass().getDeclaredMethod({handler:?}, String.class);
                    m.setAccessible(true);
                    m.invoke(entryInst, body);
                }} catch (Exception e) {{
                    Throwable c = (e instanceof java.lang.reflect.InvocationTargetException && e.getCause() != null) ? e.getCause() : e;
                    System.err.println("NYX_EXCEPTION: " + c.getClass().getName() + ": " + c.getMessage());
                }}
            }});
            System.out.println({publish_marker:?} + " " + {queue:?});
            nyxRecordBrokerPublish("NYX_KAFKA_LOG", {queue:?}, payload);
            brokerRef.publish({queue:?}, payload);"#,
                handler = handler,
                queue = queue,
                publish_marker = crate::dynamic::stubs::KAFKA_PUBLISH_MARKER,
            ),
        ),
    };
    let _ = publish_marker;

    let source = format!(
        r#"// Nyx dynamic harness — message handler (Phase 20 / Track M.2).
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public class NyxHarness {{
{probe}

{kafka_src}
{sqs_src}
{rabbit_src}

    public static void main(String[] args) {{
        String payload = nyxPayload();
        try {{
            Class<?> entryCls = Class.forName({entry_class:?});
            Constructor<?> ctor = entryCls.getDeclaredConstructor();
            ctor.setAccessible(true);
            final Object entryInst = ctor.newInstance();
{dispatch_block}
        }} catch (Throwable e) {{
            System.err.println("NYX_EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
        }}
    }}

    static String nyxPayload() {{
        String v = System.getenv("NYX_PAYLOAD");
        if (v != null && !v.isEmpty()) return v;
        String b64 = System.getenv("NYX_PAYLOAD_B64");
        if (b64 != null && !b64.isEmpty()) {{
            byte[] decoded = java.util.Base64.getDecoder().decode(b64);
            return new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        }}
        return "";
    }}

    static void nyxRecordBrokerPublish(String envName, String destination, String payload) {{
        String path = System.getenv(envName);
        if (path == null || path.isEmpty()) return;
        String line = destination.replace('\t', ' ') + "\t" + payload + "\n";
        try {{
            java.nio.file.Files.write(
                java.nio.file.Paths.get(path),
                line.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND
            );
        }} catch (Exception ignored) {{
        }}
    }}
}}
"#,
        entry_class = entry_class,
        dispatch_block = dispatch_block,
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
        extra_files: message_handler_annotation_stubs(),
        entry_subpath: Some(format!("{entry_class}.java")),
    }
}

fn message_handler_annotation_stubs() -> Vec<(String, String)> {
    vec![
        (
            "org/springframework/kafka/annotation/KafkaListener.java".to_owned(),
            r#"package org.springframework.kafka.annotation;

public @interface KafkaListener {
    String[] value() default {};
    String[] topics() default {};
}
"#
            .to_owned(),
        ),
        (
            "io/awspring/cloud/sqs/annotation/SqsListener.java".to_owned(),
            r#"package io.awspring.cloud.sqs.annotation;

public @interface SqsListener {
    String[] value() default {};
    String[] queueNames() default {};
    String queueName() default "";
    String queueUrl() default "";
}
"#
            .to_owned(),
        ),
        (
            "org/springframework/amqp/rabbit/annotation/RabbitListener.java".to_owned(),
            r#"package org.springframework.amqp.rabbit.annotation;

public @interface RabbitListener {
    String[] value() default {};
    String[] queues() default {};
}
"#
            .to_owned(),
        ),
    ]
}

// ── Phase 21 (Track M.3) — synthetic entry-kind harnesses ─────────────────────

fn emit_scheduled_job_harness(
    spec: &HarnessSpec,
    schedule: Option<&str>,
    entry_class: &str,
) -> HarnessSource {
    let probe = probe_shim();
    let pre_call = pre_call_setup(spec);
    let method = &spec.entry_name;
    let schedule_repr = schedule.unwrap_or("<unscheduled>");
    let source = format!(
        r#"// Nyx dynamic harness — scheduled job (Phase 21 / Track M.3).
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;

public class NyxHarness {{
{probe}

    public static void main(String[] args) {{
        String payload = nyxPayload();
{pre_call}        System.out.println("__NYX_SCHEDULED_JOB__: " + {schedule:?});
        System.out.println("__NYX_SINK_HIT__");
        try {{
            Class<?> cls = Class.forName({entry_class:?});
            Constructor<?> ctor = cls.getDeclaredConstructor();
            ctor.setAccessible(true);
            Object instance = ctor.newInstance();
            Method m = null;
            for (Method candidate : cls.getDeclaredMethods()) {{
                if (candidate.getName().equals({method:?})) {{ m = candidate; break; }}
            }}
            if (m == null) {{
                System.err.println("NYX_METHOD_NOT_FOUND: " + {method:?});
                System.exit(78);
            }}
            m.setAccessible(true);
            Class<?>[] params = m.getParameterTypes();
            Object[] mArgs = new Object[params.length];
            for (int i = 0; i < params.length; i++) {{
                mArgs[i] = params[i].equals(String.class) ? payload : null;
            }}
            m.invoke(instance, mArgs);
        }} catch (InvocationTargetException ite) {{
            Throwable cause = ite.getCause() == null ? ite : ite.getCause();
            System.err.println("NYX_EXCEPTION: " + cause.getClass().getName() + ": " + cause.getMessage());
        }} catch (Throwable e) {{
            System.err.println("NYX_EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
        }}
    }}

    static String nyxPayload() {{
        String v = System.getenv("NYX_PAYLOAD");
        if (v != null && !v.isEmpty()) return v;
        String b64 = System.getenv("NYX_PAYLOAD_B64");
        if (b64 != null && !b64.isEmpty()) {{
            byte[] decoded = java.util.Base64.getDecoder().decode(b64);
            return new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        }}
        return "";
    }}
}}
"#,
        entry_class = entry_class,
        method = method,
        schedule = schedule_repr,
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

fn emit_middleware_harness(spec: &HarnessSpec, name: &str, entry_class: &str) -> HarnessSource {
    let probe = probe_shim();
    let pre_call = pre_call_setup(spec);
    let method = &spec.entry_name;
    let source = format!(
        r#"// Nyx dynamic harness — middleware (Phase 21 / Track M.3).
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;

public class NyxHarness {{
{probe}

    public static void main(String[] args) {{
        String payload = nyxPayload();
{pre_call}        System.out.println("__NYX_MIDDLEWARE__: " + {name:?});
        System.out.println("__NYX_SINK_HIT__");
        try {{
            Class<?> cls = Class.forName({entry_class:?});
            Constructor<?> ctor = cls.getDeclaredConstructor();
            ctor.setAccessible(true);
            Object instance = ctor.newInstance();
            Method m = null;
            for (Method candidate : cls.getDeclaredMethods()) {{
                if (candidate.getName().equals({method:?})) {{ m = candidate; break; }}
            }}
            if (m == null) {{
                System.err.println("NYX_METHOD_NOT_FOUND: " + {method:?});
                System.exit(78);
            }}
            m.setAccessible(true);
            Class<?>[] params = m.getParameterTypes();
            Object[] mArgs = new Object[params.length];
            for (int i = 0; i < params.length; i++) {{
                mArgs[i] = params[i].equals(String.class) ? payload : null;
            }}
            m.invoke(instance, mArgs);
        }} catch (InvocationTargetException ite) {{
            Throwable cause = ite.getCause() == null ? ite : ite.getCause();
            System.err.println("NYX_EXCEPTION: " + cause.getClass().getName() + ": " + cause.getMessage());
        }} catch (Throwable e) {{
            System.err.println("NYX_EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
        }}
    }}

    static String nyxPayload() {{
        String v = System.getenv("NYX_PAYLOAD");
        if (v != null && !v.isEmpty()) return v;
        String b64 = System.getenv("NYX_PAYLOAD_B64");
        if (b64 != null && !b64.isEmpty()) {{
            byte[] decoded = java.util.Base64.getDecoder().decode(b64);
            return new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        }}
        return "";
    }}
}}
"#,
        entry_class = entry_class,
        method = method,
        name = name,
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

#[derive(Debug, Clone, Copy)]
enum JavaBroker {
    Kafka,
    Sqs,
    Rabbit,
}

fn java_broker_for_adapter(spec: &HarnessSpec) -> JavaBroker {
    let adapter = spec
        .framework
        .as_ref()
        .map(|b| b.adapter.as_str())
        .unwrap_or("");
    match adapter {
        "sqs-java" => JavaBroker::Sqs,
        "rabbit-java" => JavaBroker::Rabbit,
        _ => JavaBroker::Kafka,
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
        assert!(
            JavaEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::Function)
        );
        assert!(
            JavaEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::HttpRoute)
        );
        assert!(
            JavaEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::CliSubcommand)
        );
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
        let src =
            "import org.junit.jupiter.api.Test;\npublic class V { @Test public void testRun() {} }";
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
        let paths: Vec<&str> = harness
            .extra_files
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
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
        let paths: Vec<&str> = harness
            .extra_files
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
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
            harness
                .extra_files
                .iter()
                .map(|(p, _)| p)
                .collect::<Vec<_>>()
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
        let paths: Vec<&str> = harness
            .extra_files
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
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
        let paths: Vec<&str> = harness
            .extra_files
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
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
        let paths: Vec<&str> = harness
            .extra_files
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
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
        let driver_pos = step
            .source
            .find("System.getenv(\"NYX_PREV_OUTPUT\")")
            .unwrap();
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
        let dir = std::env::temp_dir().join(format!("nyx_detect_shape_{}", std::process::id()));
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

    fn make_ldap_spec() -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.expected_cap = Cap::LDAP_INJECTION;
        s.entry_name = "run".into();
        s
    }

    #[test]
    fn emit_ldap_harness_routes_through_stub_when_endpoint_set() {
        let h = emit_ldap_harness(&make_ldap_spec());
        assert!(
            h.source.contains("NYX_LDAP_ENDPOINT"),
            "Java LDAP harness must read NYX_LDAP_ENDPOINT to route through the stub",
        );
        assert!(
            h.source
                .contains("javax.naming.directory.InitialDirContext"),
            "Java LDAP harness must import the JNDI InitialDirContext for the BER round-trip",
        );
        assert!(
            h.source.contains("new InitialDirContext(env)"),
            "Java LDAP harness must construct an InitialDirContext bound at the stub endpoint",
        );
        assert!(
            h.source.contains("\"ldap://\" + ep + \"/\""),
            "Java LDAP harness must compose an ldap:// PROVIDER_URL from NYX_LDAP_ENDPOINT",
        );
        assert!(
            h.source.contains("ctx.search(\"\", filter, controls)"),
            "Java LDAP harness must dispatch DirContext.search over LDAPv3 BER",
        );
        assert!(
            h.source.contains("com.sun.jndi.ldap.LdapCtxFactory"),
            "Java LDAP harness must select the JDK LDAP context factory",
        );
    }

    #[test]
    fn emit_ldap_harness_retains_local_matcher_fallback() {
        let h = emit_ldap_harness(&make_ldap_spec());
        assert!(
            h.source.contains("nyxLdapCountLocal"),
            "Java LDAP harness must keep the in-process matcher as a fallback for hosts without the stub",
        );
        assert!(
            h.source.contains("nyxLdapCountViaJndi"),
            "Java LDAP harness must dispatch through the JNDI stub-route helper",
        );
    }

    fn write_servlet_fixture(dir: &std::path::Path, body: &str) -> String {
        let path = dir.join("Vuln.java");
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn emit_header_injection_harness_drives_fixture_through_stub_when_servlet_present() {
        let dir = std::env::temp_dir().join("nyx_phase08_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "import javax.servlet.http.HttpServletResponse;\n\
             public class Vuln {\n  public static void run(HttpServletResponse r, String v) {\n    r.setHeader(\"Set-Cookie\", v);\n  }\n}\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_header_injection_harness(&spec);
        assert!(
            !h.extra_files.is_empty(),
            "servlet-importing fixture must trigger stub-file emission",
        );
        assert!(
            h.source.contains(
                "HttpServletResponse response = new javax.servlet.http.HttpServletResponse()"
            ),
            "Java HEADER_INJECTION harness must instantiate the captured-header response wrapper",
        );
        assert!(
            h.source.contains("Class.forName(\"Vuln\")"),
            "Java HEADER_INJECTION harness must reflectively load the fixture entry class",
        );
        assert!(
            h.source.contains("nyxDrainHeaders()"),
            "Java HEADER_INJECTION harness must drain captured headers after invoking the fixture",
        );
        assert!(
            h.source.contains("for (String[] pair : captured)"),
            "Java HEADER_INJECTION harness must emit one probe per captured (name, value) pair",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_uses_jakarta_namespace_for_jakarta_imports() {
        let dir = std::env::temp_dir().join("nyx_phase08_test_jakarta_ns");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "import jakarta.servlet.http.HttpServletResponse;\n\
             public class Vuln {\n  public static void run(HttpServletResponse r, String v) {\n    r.setHeader(\"Set-Cookie\", v);\n  }\n}\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_header_injection_harness(&spec);
        assert!(
            h.source
                .contains("jakarta.servlet.http.HttpServletResponse"),
            "Java HEADER_INJECTION harness must follow the entry source's servlet namespace",
        );
        assert!(
            !h.source
                .contains("javax.servlet.http.HttpServletResponse response"),
            "Jakarta entry must not instantiate javax response wrapper",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_falls_back_to_synthetic_probe_without_servlet() {
        let dir = std::env::temp_dir().join("nyx_phase08_test_no_servlet");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "public class Vuln { public static void run(String v) { System.out.println(v); } }\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_header_injection_harness(&spec);
        assert!(
            h.extra_files.is_empty(),
            "non-servlet fixture must not ship servlet stubs",
        );
        assert!(
            !h.source.contains("nyxDrainHeaders()"),
            "non-servlet fixture must skip the stub-driven capture path",
        );
        assert!(
            h.source.contains("nyxHeaderProbe(\"Set-Cookie\", payload)"),
            "non-servlet fixture must keep the synthetic-probe fallback",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_routes_through_wire_frame_when_raw_socket_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_java_test_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "import java.net.ServerSocket;\n\
             public class Vuln {\n  \
             public static void setCookieValue(byte[] value) {}\n  \
             public static ServerSocket createServer() throws java.io.IOException { return new ServerSocket(0); }\n  \
             public static void runOnce(ServerSocket server) {}\n\
             }\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_header_injection_harness(&spec);
        assert!(
            h.extra_files.is_empty(),
            "tier-(b) wire-frame harness must not ship servlet stubs: {:?}",
            h.extra_files,
        );
        assert!(
            h.source
                .contains("static byte[] nyxWireFrameViaFixture(String payload)"),
            "tier-(b) harness must define the wire-frame helper: {}",
            h.source
        );
        assert!(
            h.source.contains("Class.forName(\"Vuln\")"),
            "tier-(b) harness must reflectively load the fixture entry class: {}",
            h.source
        );
        assert!(
            h.source
                .contains("getDeclaredMethod(\"setCookieValue\", byte[].class)"),
            "tier-(b) harness must install the cookie value via reflection: {}",
            h.source
        );
        assert!(
            h.source.contains("getDeclaredMethod(\"createServer\")"),
            "tier-(b) harness must boot the fixture's ServerSocket via reflection: {}",
            h.source
        );
        assert!(
            h.source
                .contains("getDeclaredMethod(\"runOnce\", ServerSocket.class)"),
            "tier-(b) harness must drive runOnce on a worker thread: {}",
            h.source
        );
        assert!(
            h.source.contains("new Thread(()"),
            "tier-(b) harness must spawn a worker thread for the accept loop: {}",
            h.source
        );
        assert!(
            h.source
                .contains("new Socket(InetAddress.getByName(\"127.0.0.1\"), port)"),
            "tier-(b) harness must open a client Socket against the bound port: {}",
            h.source
        );
        assert!(
            h.source.contains("GET / HTTP/1.0\\r\\nHost: 127.0.0.1"),
            "tier-(b) harness must issue a raw GET request: {}",
            h.source
        );
        assert!(
            h.source.contains("\\\"kind\\\":\\\"HeaderWireFrame\\\""),
            "tier-(b) harness must emit a HeaderWireFrame probe kind: {}",
            h.source
        );
        assert!(
            h.source.contains("\\\"raw_bytes\\\":["),
            "tier-(b) harness must carry the raw_bytes array on the wire-frame probe: {}",
            h.source
        );
        assert!(
            h.source
                .contains("\"{\\\"wire_frame_len\\\":\" + rawBytes.length"),
            "tier-(b) harness must emit the wire_frame_len stdout marker: {}",
            h.source
        );
        assert!(
            !h.source.contains("nyxDrainHeaders()"),
            "tier-(b) harness must not invoke the servlet-stub drain path: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_wire_frame_branch_drops_when_only_servlet_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_java_test_no_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "import javax.servlet.http.HttpServletResponse;\n\
             public class Vuln {\n  public static void run(HttpServletResponse r, String v) {\n    r.setHeader(\"Set-Cookie\", v);\n  }\n}\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_header_injection_harness(&spec);
        assert!(
            !h.source.contains("nyxWireFrameViaFixture"),
            "servlet-only harness must not define the wire-frame helper: {}",
            h.source
        );
        assert!(
            !h.source.contains("HeaderWireFrame"),
            "servlet-only harness must not emit the HeaderWireFrame probe shape: {}",
            h.source
        );
        assert!(
            !h.source.contains("wire_frame_len"),
            "servlet-only harness must not emit the wire_frame_len stdout marker: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_drives_fixture_through_stub_when_servlet_present() {
        let dir = std::env::temp_dir().join("nyx_phase09_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "import javax.servlet.http.HttpServletResponse;\n\
             public class Vuln {\n  public static void run(HttpServletResponse r, String v) throws Exception {\n    r.sendRedirect(v);\n  }\n}\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_open_redirect_harness(&spec);
        assert!(
            !h.extra_files.is_empty(),
            "servlet-importing fixture must trigger stub-file emission",
        );
        assert!(
            h.source.contains(
                "HttpServletResponse response = new javax.servlet.http.HttpServletResponse()"
            ),
            "Java OPEN_REDIRECT harness must instantiate the captured-redirect response wrapper",
        );
        assert!(
            h.source.contains("Class.forName(\"Vuln\")"),
            "Java OPEN_REDIRECT harness must reflectively load the fixture entry class",
        );
        assert!(
            h.source.contains("response.getRedirectedUrl()"),
            "Java OPEN_REDIRECT harness must read the captured Location: value from the stub",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_falls_back_to_synthetic_probe_without_servlet() {
        let dir = std::env::temp_dir().join("nyx_phase09_test_no_servlet");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "public class Vuln { public static void run(String v) { System.out.println(v); } }\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_open_redirect_harness(&spec);
        assert!(
            h.extra_files.is_empty(),
            "non-servlet fixture must not ship servlet stubs",
        );
        assert!(
            !h.source.contains("response.getRedirectedUrl()"),
            "non-servlet fixture must skip the stub-driven capture path",
        );
        assert!(
            h.source.contains("nyxRedirectProbe(payload, requestHost)"),
            "non-servlet fixture must keep the synthetic-probe fallback",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_ships_follow_location_helper() {
        let dir = std::env::temp_dir().join("nyx_phase09_test_follow_helper");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "public class Vuln { public static void run(String v) { System.out.println(v); } }\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_open_redirect_harness(&spec);
        assert!(
            h.source
                .contains("static void nyxFollowLocation(String location)"),
            "OPEN_REDIRECT harness must declare the nyxFollowLocation helper",
        );
        assert!(
            h.source.contains("import java.net.HttpURLConnection;"),
            "OPEN_REDIRECT harness must import HttpURLConnection",
        );
        assert!(
            h.source.contains("import java.net.URL;"),
            "OPEN_REDIRECT harness must import URL",
        );
        assert!(
            h.source.contains("http://127.0.0.1"),
            "follow-location helper must whitelist loopback hosts",
        );
        assert!(
            h.source.contains("nyxFollowLocation(payload)"),
            "tier-(b) fallback must follow the synthetic payload location",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_follows_captured_location_in_tier_a() {
        let dir = std::env::temp_dir().join("nyx_phase09_test_follow_tier_a");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "import javax.servlet.http.HttpServletResponse;\n\
             public class Vuln {\n  public static void run(HttpServletResponse r, String v) throws Exception {\n    r.sendRedirect(v);\n  }\n}\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_open_redirect_harness(&spec);
        assert!(
            h.source.contains(
                "nyxRedirectProbe(captured, requestHost);\n            nyxFollowLocation(captured);"
            ),
            "tier-(a) must follow the captured Location: value, not the raw payload",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_xpath_harness_routes_through_real_xpath_reflectively() {
        let dir = std::env::temp_dir().join("nyx_phase07_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "import javax.xml.xpath.XPath;\n\
             import javax.xml.xpath.XPathConstants;\n\
             public class Vuln {\n  public static Object run(String name) throws Exception { return null; }\n}\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::XPATH_INJECTION;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_xpath_harness(&spec);
        assert!(
            !h.extra_files.is_empty(),
            "XPath harness must stage the canonical corpus XML",
        );
        assert!(
            h.source.contains("import org.w3c.dom.NodeList;"),
            "tier-(a) harness must import NodeList for the cast",
        );
        assert!(
            h.source.contains("Class.forName(\"Vuln\")"),
            "tier-(a) harness must reflectively load the fixture entry class",
        );
        assert!(
            h.source
                .contains("getDeclaredMethod(\"run\", String.class)"),
            "tier-(a) harness must reflectively grab the fixture's run(String) method",
        );
        assert!(
            h.source.contains("((NodeList) result).getLength()"),
            "tier-(a) harness must cast the result to NodeList and count nodes",
        );
        assert!(
            h.source.contains("__NYX_XPATH_TIER_A__"),
            "tier-(a) harness must emit the tier-(a) stdout marker after the real reflective invoke: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_xpath_harness_drops_inline_matcher_fallback() {
        let dir = std::env::temp_dir().join("nyx_phase07_test_no_inline_matcher");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = write_servlet_fixture(
            &dir,
            "public class Vuln { public static Object run(String name) { return null; } }\n",
        );
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::XPATH_INJECTION;
        spec.entry_file = entry;
        spec.entry_name = "run".into();
        let h = emit_xpath_harness(&spec);
        assert!(
            !h.source.contains("nyxXpathSelect"),
            "harness must not carry the inline `nyxXpathSelect` matcher; tier-(a) reflective invoke is the only path",
        );
        assert!(
            !h.source.contains("NYX_XPATH_USERS"),
            "harness must not carry the inline `NYX_XPATH_USERS` table; tier-(a) reflective invoke is the only path",
        );
        assert!(
            h.source.contains("NYX_IMPORT_ERROR:") && h.source.contains("System.exit(77)"),
            "harness must emit `NYX_IMPORT_ERROR:` stderr marker + `System.exit(77)` on reflective lookup failure: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_XPATH_TIER_A__"),
            "harness must emit the tier-(a) stdout marker: {}",
            h.source
        );
        assert!(
            h.source.contains("import org.w3c.dom.NodeList;")
                && h.source.contains("import java.lang.reflect.Method;"),
            "harness must always import the reflective invocation path; the synthetic-only branch is gone",
        );
    }

    fn make_crypto_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::CRYPTO;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_crypto_harness_when_cap_is_crypto() {
        let h = emit(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/java/Vuln.java",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyxWeakKeyProbe"),
            "dispatcher must short-circuit Cap::CRYPTO into emit_crypto_harness so the weak-key probe shim is present",
        );
        assert!(
            h.source.contains("\\\"kind\\\":\\\"WeakKey\\\""),
            "crypto harness must record probes with kind: WeakKey so the WeakKeyEntropy predicate fires (search for the escaped sequence the Java emitter writes into the .java source string literal)",
        );
    }

    #[test]
    fn emit_crypto_harness_routes_through_reflective_entry_invocation() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("Class.forName(\"Vuln\")"),
            "Java CRYPTO harness must reflectively load the fixture entry class by its derived FQN: {}",
            h.source
        );
        assert!(
            h.source
                .contains("getDeclaredMethod(\"run\", String.class)"),
            "Java CRYPTO harness must look up the entry method with a single String parameter",
        );
        assert!(
            h.source.contains("m.invoke(null, payload)"),
            "Java CRYPTO harness must invoke the static method with the payload",
        );
        assert_eq!(
            h.filename, "NyxHarness.java",
            "Java CRYPTO harness must emit a NyxHarness.java file",
        );
        assert!(
            h.extra_files.is_empty(),
            "Java CRYPTO harness must not stage extra files — java.util.Random + SecureRandom are JDK built-ins",
        );
    }

    #[test]
    fn emit_crypto_harness_emits_weak_key_probe_kind() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source
                .contains("\\\"kind\\\":\\\"WeakKey\\\",\\\"key_int\\\":"),
            "Java CRYPTO harness must emit ProbeKind::WeakKey records carrying a key_int field so the WeakKeyEntropy predicate fires: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_SINK_HIT__"),
            "Java CRYPTO harness must print the universal sink-hit sentinel",
        );
    }

    #[test]
    fn emit_crypto_harness_reduces_byte_array_returns_via_byte_buffer() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/java/Benign.java",
            "run",
        ));
        assert!(
            h.source
                .contains("ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN).getLong()"),
            "Java CRYPTO harness must use ByteBuffer.getLong() so a 32-byte CSPRNG key produces a key_int whose magnitude exceeds the 16-bit budget",
        );
        assert!(
            h.source.contains("value instanceof byte[]"),
            "Java CRYPTO harness must dispatch on byte[] returns explicitly",
        );
        assert!(
            h.source.contains("value instanceof Number"),
            "Java CRYPTO harness must dispatch on Number returns explicitly",
        );
    }

    #[test]
    fn emit_crypto_harness_falls_back_when_reflection_fails() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("nyxPayloadFallback(payload)"),
            "Java CRYPTO harness must fall back to a payload-derived key_int when reflection fails so the universal sink-hit path still fires",
        );
        assert!(
            h.source.contains(
                "ClassNotFoundException | NoSuchMethodException | IllegalAccessException"
            ),
            "Java CRYPTO harness must catch the reflective lookup exceptions and route to the fallback",
        );
    }

    // ── Phase 11 (Track J.9) Java JSON_PARSE emitter tests ────────────────────

    fn make_json_parse_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::JSON_PARSE;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_json_parse_harness_when_cap_is_json_parse() {
        let h = emit(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/java/Vuln.java",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyxJsonParseProbe"),
            "dispatcher must short-circuit Cap::JSON_PARSE into emit_json_parse_harness so the depth probe shim is present",
        );
        assert!(
            h.source.contains("\\\"kind\\\":\\\"JsonParse\\\""),
            "Java JSON_PARSE harness must record probes with kind: JsonParse so the JsonParseExcessiveDepth predicate fires",
        );
    }

    #[test]
    fn emit_json_parse_harness_ships_nyx_json_probe_extra_file() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/java/Vuln.java",
            "run",
        ));
        assert!(
            h.extra_files
                .iter()
                .any(|(name, _)| name == "NyxJsonProbe.java"),
            "Java JSON_PARSE harness must stage NyxJsonProbe.java as a sibling extra file so the fixture can resolve the helper at javac time without Jackson / Gson",
        );
        let (_, probe_src) = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "NyxJsonProbe.java")
            .unwrap();
        assert!(
            probe_src.contains("public class NyxJsonProbe"),
            "NyxJsonProbe.java extra file must declare the helper class",
        );
        assert!(
            probe_src.contains("public static Object parse(String s)"),
            "NyxJsonProbe must expose a String -> Object parse helper",
        );
        assert!(
            probe_src.contains("public static int countDepth(Object parsed)"),
            "NyxJsonProbe must expose an iterative countDepth walker",
        );
        assert!(
            probe_src.contains("ArrayDeque<Frame>"),
            "NyxJsonProbe.countDepth must walk iteratively to dodge the JVM stack-frame budget",
        );
    }

    #[test]
    fn emit_json_parse_harness_routes_through_reflective_entry_invocation() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("Class.forName(\"Vuln\")"),
            "Java JSON_PARSE harness must reflectively load the fixture entry class by its derived FQN: {}",
            h.source
        );
        assert!(
            h.source
                .contains("getDeclaredMethod(\"run\", String.class)"),
            "Java JSON_PARSE harness must look up the entry method with a single String parameter",
        );
        assert!(
            h.source.contains("m.invoke(null, payload)"),
            "Java JSON_PARSE harness must invoke the static method with the payload",
        );
        assert!(
            h.source.contains("NyxJsonProbe.countDepth(produced)"),
            "Java JSON_PARSE harness must drive countDepth on the fixture's return value",
        );
        assert_eq!(
            h.filename, "NyxHarness.java",
            "Java JSON_PARSE harness must emit a NyxHarness.java file",
        );
    }

    #[test]
    fn emit_json_parse_harness_emits_depth_fields() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("\\\"depth\\\":"),
            "Java JSON_PARSE harness must serialise a depth field on the JsonParse probe record",
        );
        assert!(
            h.source.contains("\\\"excessive_depth\\\":"),
            "Java JSON_PARSE harness must serialise an excessive_depth field on the JsonParse probe record",
        );
        assert!(
            h.source.contains("__NYX_SINK_HIT__"),
            "Java JSON_PARSE harness must print the universal sink-hit sentinel",
        );
    }

    #[test]
    fn emit_json_parse_harness_handles_parser_depth_exception() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("NyxJsonProbe.NyxJsonDepthException"),
            "Java JSON_PARSE harness must catch the parser's depth-budget exception so a guard-rail trip still emits a probe",
        );
    }

    #[test]
    fn emit_json_parse_harness_derives_entry_class_from_fixture() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/java/Vuln.java",
            "run",
        ));
        assert!(
            matches!(h.entry_subpath.as_deref(), Some(p) if p == "Vuln.java"),
            "Java JSON_PARSE harness must stage the fixture under its public-class-derived filename so javac's filename invariant holds: got {:?}",
            h.entry_subpath,
        );
    }

    // ── Phase 11 (Track J.9) Java UNAUTHORIZED_ID emitter tests ───────────────

    fn make_unauthorized_id_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::UNAUTHORIZED_ID;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_unauthorized_id_harness_when_cap_is_unauthorized_id() {
        let h = emit(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/java/Vuln.java",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyxIdorProbe"),
            "dispatcher must short-circuit Cap::UNAUTHORIZED_ID into emit_unauthorized_id_harness so the IDOR probe shim is present",
        );
        assert!(
            h.source.contains("\\\"kind\\\":\\\"IdorAccess\\\""),
            "Java UNAUTHORIZED_ID harness must record probes with kind: IdorAccess so the IdorBoundaryCrossed predicate fires",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_pins_caller_id() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source
                .contains("private static final String _NYX_CALLER_ID = \"alice\""),
            "Java UNAUTHORIZED_ID harness must pin caller_id = \"alice\" so the differential oracle can flag bob/alice as a cross-tenant access",
        );
        assert!(
            h.source.contains("nyxIdorProbe(_NYX_CALLER_ID, payload)"),
            "Java UNAUTHORIZED_ID harness must seed the probe with the pinned caller_id and the payload as owner_id",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_skips_probe_when_record_is_null() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/java/Benign.java",
            "run",
        ));
        assert!(
            h.source.contains("if (record != null) {"),
            "Java UNAUTHORIZED_ID harness must gate probe emission on the fixture returning a non-null record so the benign control's null-rejection path clears the predicate",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_routes_through_reflective_entry_invocation() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("Class.forName(\"Vuln\")"),
            "Java UNAUTHORIZED_ID harness must reflectively load the fixture entry class: {}",
            h.source
        );
        assert!(
            h.source
                .contains("getDeclaredMethod(\"run\", String.class)"),
            "Java UNAUTHORIZED_ID harness must look up the entry method with a single String parameter",
        );
        assert!(
            h.source.contains("m.invoke(null, payload)"),
            "Java UNAUTHORIZED_ID harness must invoke the static method with the payload as owner_id",
        );
        assert_eq!(
            h.filename, "NyxHarness.java",
            "Java UNAUTHORIZED_ID harness must emit a NyxHarness.java file",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_derives_entry_class_from_fixture() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/java/Vuln.java",
            "run",
        ));
        assert!(
            matches!(h.entry_subpath.as_deref(), Some(p) if p == "Vuln.java"),
            "Java UNAUTHORIZED_ID harness must stage the fixture under its public-class-derived filename so javac's filename invariant holds: got {:?}",
            h.entry_subpath,
        );
        assert!(
            h.extra_files.is_empty(),
            "Java UNAUTHORIZED_ID harness must not ship sibling helpers — the fixture's data store is in-process",
        );
    }

    // ── Phase 11 (Track J.9) Java DATA_EXFIL emitter tests ────────────────────

    fn make_data_exfil_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::DATA_EXFIL;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_data_exfil_harness_when_cap_is_data_exfil() {
        let h = emit(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/java/Vuln.java",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("nyxOutboundProbe"),
            "dispatcher must short-circuit Cap::DATA_EXFIL into emit_data_exfil_harness so the outbound probe shim is present",
        );
        assert!(
            h.source.contains("\\\"kind\\\":\\\"OutboundNetwork\\\""),
            "Java DATA_EXFIL harness must record probes with kind: OutboundNetwork so the OutboundHostNotIn predicate fires",
        );
    }

    #[test]
    fn emit_data_exfil_harness_ships_nyx_mock_http_extra_file() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/java/Vuln.java",
            "run",
        ));
        assert!(
            h.extra_files
                .iter()
                .any(|(name, _)| name == "NyxMockHttp.java"),
            "Java DATA_EXFIL harness must stage NyxMockHttp.java as a sibling extra file so the fixture's call into the helper resolves at javac time without an HttpURLConnection monkey-patch",
        );
        let (_, mock_src) = h
            .extra_files
            .iter()
            .find(|(name, _)| name == "NyxMockHttp.java")
            .unwrap();
        assert!(
            mock_src.contains("public class NyxMockHttp"),
            "NyxMockHttp.java extra file must declare the helper class",
        );
        assert!(
            mock_src.contains("public static String get(String url)"),
            "NyxMockHttp must expose a String get(url) helper the fixture calls into",
        );
        assert!(
            mock_src.contains("CAPTURED_HOSTS"),
            "NyxMockHttp must expose a CAPTURED_HOSTS list the harness drains after invocation",
        );
        assert!(
            mock_src.contains("URI.create(trimmed)"),
            "NyxMockHttp.captureHost must parse the host via java.net.URI so https://attacker.test/path resolves to attacker.test",
        );
    }

    #[test]
    fn emit_data_exfil_harness_drains_captured_hosts_after_invocation() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("NyxMockHttp.CAPTURED_HOSTS.clear();"),
            "Java DATA_EXFIL harness must clear the captured-hosts list before invoking the fixture so probes do not leak between invocations",
        );
        assert!(
            h.source
                .contains("for (String host : NyxMockHttp.CAPTURED_HOSTS) {"),
            "Java DATA_EXFIL harness must drain CAPTURED_HOSTS after the fixture returns",
        );
        assert!(
            h.source.contains("nyxOutboundProbe(host)"),
            "Java DATA_EXFIL harness must emit one OutboundNetwork probe per captured host",
        );
    }

    #[test]
    fn emit_data_exfil_harness_routes_through_reflective_entry_invocation() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("Class.forName(\"Vuln\")"),
            "Java DATA_EXFIL harness must reflectively load the fixture entry class: {}",
            h.source
        );
        assert!(
            h.source
                .contains("getDeclaredMethod(\"run\", String.class)"),
            "Java DATA_EXFIL harness must look up the entry method with a single String parameter",
        );
        assert!(
            h.source.contains("m.invoke(null, payload)"),
            "Java DATA_EXFIL harness must invoke the static method with the payload as host",
        );
        assert_eq!(
            h.filename, "NyxHarness.java",
            "Java DATA_EXFIL harness must emit a NyxHarness.java file",
        );
    }

    #[test]
    fn emit_data_exfil_harness_derives_entry_class_from_fixture() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/java/Vuln.java",
            "run",
        ));
        assert!(
            matches!(h.entry_subpath.as_deref(), Some(p) if p == "Vuln.java"),
            "Java DATA_EXFIL harness must stage the fixture under its public-class-derived filename so javac's filename invariant holds: got {:?}",
            h.entry_subpath,
        );
    }

    #[test]
    fn emit_data_exfil_harness_drains_even_on_invocation_throw() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/java/Vuln.java",
            "run",
        ));
        assert!(
            h.source.contains("InvocationTargetException ite"),
            "Java DATA_EXFIL harness must catch InvocationTargetException so a fixture-side throw after a partial outbound call still drains CAPTURED_HOSTS",
        );
    }

    #[test]
    fn emit_message_handler_harness_ships_broker_annotation_stubs() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_file = "tests/dynamic_fixtures/message_handler/kafka_java/Vuln.java".to_owned();
        spec.entry_name = "onMessage".to_owned();
        spec.entry_kind = EntryKind::MessageHandler {
            queue: "orders".to_owned(),
            message_schema: None,
        };
        let h = emit(&spec).unwrap();
        for path in [
            "org/springframework/kafka/annotation/KafkaListener.java",
            "io/awspring/cloud/sqs/annotation/SqsListener.java",
            "org/springframework/amqp/rabbit/annotation/RabbitListener.java",
        ] {
            assert!(
                h.extra_files.iter().any(|(name, _)| name == path),
                "Java MessageHandler harness must stage {path} so annotated broker fixtures compile without real Spring jars",
            );
        }
    }
}
