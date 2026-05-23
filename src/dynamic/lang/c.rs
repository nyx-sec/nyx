//! C harness emitter.
//!
//! Phase 16 (Track B Rust + C/C++ vertical) replaces the stub body with
//! dispatch over [`CShape`] — the cross product of [`EntryKind`] and a
//! lightweight per-file shape detector that inspects the entry file for
//! `main(int argc, char *argv[])`, libFuzzer's `LLVMFuzzerTestOneInput`,
//! and free functions with `(const char*, size_t)` signatures.
//!
//! Each shape emits a single `main.c` that:
//! 1. Reads the payload from `NYX_PAYLOAD` / `NYX_PAYLOAD_B64` env vars.
//! 2. `#include`s `entry.c` (the user's vulnerable code) and dispatches
//!    via the per-shape adapter.
//!
//! Build step: `prepare_c()` in `build_sandbox.rs` runs
//! `cc -O0 -o nyx_harness main.c` in the workdir.
//!
//! File layout in workdir:
//! ```text
//! main.c          ← harness entry point (generated, includes entry.c)
//! entry.c         ← user entry source (copied from project)
//! Makefile        ← optional, generated for reference
//! ```
//!
//! Payload slot support:
//! - `PayloadSlot::Param(0)` — pass payload as the first parameter (string
//!   or `(buf, len)` pair depending on shape).
//! - `PayloadSlot::EnvVar(name)` — set env var before invoking entry.
//! - `PayloadSlot::Argv(n)` — `main(argc, argv)` shape: appended to argv.

use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for C.
pub struct CEmitter;

/// Entry kinds the C emitter understands after Phase 16.
///
/// `Function` covers free functions (libfuzzer-style + plain (const
/// char*, size_t)).  `CliSubcommand` covers `main(argc, argv)`.
/// `LibraryApi` covers libFuzzer `LLVMFuzzerTestOneInput`.
const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::CliSubcommand,
    EntryKindTag::LibraryApi,
    EntryKindTag::ClassMethod,
];

// ── Phase 16: shape detector ─────────────────────────────────────────────────

/// Concrete per-file shape resolved by reading the entry source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CShape {
    /// `int main(int argc, char *argv[])`.  Harness embeds payload into
    /// argv and calls `main(argc, argv)` directly.
    MainArgv,
    /// libFuzzer-style: `int LLVMFuzzerTestOneInput(const uint8_t *data,
    /// size_t size)`.  Harness invokes with `payload` bytes + length.
    LibfuzzerEntry,
    /// Free function with `(const char *, size_t)` or `(const char *)`
    /// signature.  Harness invokes directly.
    FreeFn,
}

impl CShape {
    /// Detect the shape from `(spec, source)`.
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let entry = spec.entry_name.as_str();
        let kind = spec.entry_kind.tag();

        let has_main_argv = (source.contains("int main(") || source.contains("int main ("))
            && (source.contains("argc")
                || source.contains("char *argv")
                || source.contains("char* argv")
                || source.contains("char **argv"));
        let has_libfuzzer =
            source.contains("LLVMFuzzerTestOneInput") || entry == "LLVMFuzzerTestOneInput";

        if has_libfuzzer {
            return Self::LibfuzzerEntry;
        }
        if entry == "main" || has_main_argv {
            return Self::MainArgv;
        }
        match kind {
            EntryKindTag::CliSubcommand => Self::MainArgv,
            EntryKindTag::LibraryApi => Self::LibfuzzerEntry,
            _ => Self::FreeFn,
        }
    }
}

/// Public wrapper: detect the shape for a finalised `HarnessSpec`, reading
/// the entry file from disk.
pub fn detect_shape(spec: &HarnessSpec) -> CShape {
    let src = read_entry_source(&spec.entry_file);
    CShape::detect(spec, &src)
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

/// Source of the `__nyx_probe` shim for the (future) C harness (Phase 06 —
/// Track C.1).  Variadic over `const char *` args; hand-rolled JSON keeps
/// the only dep on libc / stdio.
pub fn probe_shim() -> &'static str {
    // The body holds literal `"# key: value\n"` log-line formats for the
    // Phase 10 stub recorders, so the surrounding raw string uses
    // `r##"..."##` to keep `"#` substrings from terminating it early
    // (same trick the Rust / Java / Go / Ruby siblings use).
    r##"
/* ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ── */
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef __NYX_PAYLOAD_LIMIT
#define __NYX_PAYLOAD_LIMIT (16 * 1024)
#endif
#define __NYX_REDACTED "<redacted-by-nyx-policy>"

extern char **environ;

static const char *__nyx_deny[] = {
    "TOKEN","SECRET","PASSWORD","PASSWD","API_KEY","APIKEY","PRIVATE_KEY",
    "CREDENTIAL","SESSION","COOKIE","AUTH","BEARER","AWS_ACCESS","AWS_SESSION",
    "GH_TOKEN","GITHUB_TOKEN","NPM_TOKEN","PYPI_TOKEN","DOCKER_PASS",
    NULL,
};

static int __nyx_is_denied_upper(const char *k_upper) {
    for (int i = 0; __nyx_deny[i]; ++i) {
        if (strstr(k_upper, __nyx_deny[i])) return 1;
    }
    return 0;
}

static void __nyx_write_witness(FILE *f, const char *sink_callee, int nargs, const char **args) {
    fputs("{\"env_snapshot\":{", f);
    int first = 1;
    for (char **e = environ; *e; ++e) {
        const char *eq = strchr(*e, '=');
        if (!eq) continue;
        size_t klen = (size_t)(eq - *e);
        char *kup = (char *)malloc(klen + 1);
        if (!kup) continue;
        for (size_t i = 0; i < klen; ++i) {
            char c = (*e)[i];
            if (c >= 'a' && c <= 'z') c -= 32;
            kup[i] = c;
        }
        kup[klen] = '\0';
        int denied = __nyx_is_denied_upper(kup);
        if (!first) fputc(',', f);
        first = 0;
        fputc('"', f);
        fwrite(*e, 1, klen, f);
        fputs("\":\"", f);
        if (denied) {
            fputs(__NYX_REDACTED, f);
        } else {
            const char *v = eq + 1;
            for (; *v; ++v) {
                switch (*v) {
                    case '"': fputs("\\\"", f); break;
                    case '\\': fputs("\\\\", f); break;
                    case '\n': fputs("\\n", f); break;
                    case '\r': fputs("\\r", f); break;
                    case '\t': fputs("\\t", f); break;
                    default: fputc(*v, f);
                }
            }
        }
        fputc('"', f);
        free(kup);
    }
    fputs("},\"cwd\":\"", f);
    char cwdbuf[4096];
    if (getcwd(cwdbuf, sizeof(cwdbuf))) {
        fputs(cwdbuf, f);
    }
    fputs("\",\"payload_bytes\":[", f);
    const char *payload = getenv("NYX_PAYLOAD");
    if (payload) {
        size_t plen = strlen(payload);
        if (plen > __NYX_PAYLOAD_LIMIT) plen = __NYX_PAYLOAD_LIMIT;
        for (size_t i = 0; i < plen; ++i) {
            if (i > 0) fputc(',', f);
            fprintf(f, "%d", (unsigned char)payload[i]);
        }
    }
    fputs("],\"callee\":\"", f);
    fputs(sink_callee, f);
    fputs("\",\"args_repr\":[", f);
    for (int i = 0; i < nargs; ++i) {
        if (i > 0) fputc(',', f);
        fputc('"', f);
        if (args && args[i]) fputs(args[i], f);
        fputc('"', f);
    }
    fputs("]}", f);
}

static void __nyx_probe(const char *sink_callee, int nargs, ...) {
    const char *p = getenv("NYX_PROBE_PATH");
    if (!p || *p == '\0') return;
    FILE *f = fopen(p, "a");
    if (!f) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ULL +
                            (unsigned long long)ts.tv_nsec;
    const char *pid = getenv("NYX_PAYLOAD_ID");
    if (!pid) pid = "";
    fprintf(f, "{\"sink_callee\":\"%s\",\"args\":[", sink_callee);
    va_list ap;
    va_start(ap, nargs);
    const char *args_arr[32];
    int captured = nargs > 32 ? 32 : nargs;
    for (int i = 0; i < nargs; ++i) {
        const char *arg = va_arg(ap, const char *);
        if (!arg) arg = "";
        if (i < captured) args_arr[i] = arg;
        if (i > 0) fputc(',', f);
        fprintf(f, "{\"kind\":\"String\",\"value\":\"%s\"}", arg);
    }
    va_end(ap);
    fprintf(f, "],\"captured_at_ns\":%llu,\"payload_id\":\"%s\",", ns, pid);
    fputs("\"kind\":{\"kind\":\"Normal\"},\"witness\":", f);
    __nyx_write_witness(f, sink_callee, captured, args_arr);
    fputs("}\n", f);
    fclose(f);
}

/* Phase 08: sink-site signal handler.  __nyx_install_crash_guard sets a
 * sigaction(2) handler over SIGSEGV / SIGABRT / SIGBUS / SIGFPE / SIGILL
 * that writes a Crash probe with witness before restoring SIG_DFL and
 * re-raising the signal — the process still dies with the same exit
 * code, but the probe channel now carries the forensic record. */
static const char *__nyx_crash_sink_callee = "";

static void __nyx_crash_handler(int sig) {
    const char *p = getenv("NYX_PROBE_PATH");
    if (p && *p) {
        FILE *f = fopen(p, "a");
        if (f) {
            const char *name = "SIGABRT";
            switch (sig) {
                case SIGSEGV: name = "SIGSEGV"; break;
                case SIGABRT: name = "SIGABRT"; break;
                case SIGBUS:  name = "SIGBUS"; break;
                case SIGFPE:  name = "SIGFPE"; break;
                case SIGILL:  name = "SIGILL"; break;
            }
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ULL +
                                    (unsigned long long)ts.tv_nsec;
            const char *pid = getenv("NYX_PAYLOAD_ID");
            if (!pid) pid = "";
            fprintf(f,
                "{\"sink_callee\":\"%s\",\"args\":[],\"captured_at_ns\":%llu,"
                "\"payload_id\":\"%s\",\"kind\":{\"kind\":\"Crash\",\"signal\":\"%s\"},"
                "\"witness\":",
                __nyx_crash_sink_callee, ns, pid, name);
            __nyx_write_witness(f, __nyx_crash_sink_callee, 0, NULL);
            fputs("}\n", f);
            fclose(f);
        }
    }
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigaction(sig, &dfl, NULL);
    raise(sig);
}

static void __nyx_install_crash_guard(const char *sink_callee) {
    __nyx_crash_sink_callee = sink_callee;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = __nyx_crash_handler;
    sigemptyset(&sa.sa_mask);
    int sigs[] = { SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL };
    for (size_t i = 0; i < sizeof(sigs)/sizeof(sigs[0]); ++i) {
        sigaction(sigs[i], &sa, NULL);
    }
}

/* Phase 10 (Track D.3) stub recorder helpers.  When the verifier spawns a
 * SqlStub it publishes the queries-log path through NYX_SQL_LOG; a sink
 * call site that wants the host-side stub to see its query appends one
 * record-per-call.  Detail kv pairs use parallel arrays so the helper is
 * variadic in arity without depending on stdarg-with-typed args.  The
 * helper is a no-op when the env var is unset so the same source still
 * runs under harness modes that did not spawn a stub. */
static void __nyx_stub_sql_record(const char *query,
                                  const char **detail_keys,
                                  const char **detail_vals,
                                  int detail_count) {
    const char *p = getenv("NYX_SQL_LOG");
    if (!p || *p == '\0') return;
    FILE *f = fopen(p, "a");
    if (!f) return;
    for (int i = 0; i < detail_count; ++i) {
        if (detail_keys && detail_vals && detail_keys[i] && detail_vals[i]) {
            fprintf(f, "# %s: %s\n", detail_keys[i], detail_vals[i]);
        }
    }
    if (query) {
        size_t qlen = strlen(query);
        fputs(query, f);
        if (qlen == 0 || query[qlen - 1] != '\n') {
            fputc('\n', f);
        }
    }
    fclose(f);
}

/* Phase 10 (Track D.3) HTTP recording helper.  When the verifier spawns an
 * HttpStub it publishes the side-channel log path through NYX_HTTP_LOG; a
 * sink call site whose outbound request never reaches the on-the-wire
 * listener (DNS-mocked, network-isolated sandbox, pre-flight check) can
 * call this helper to surface the attempted call.  Format matches the SQL
 * helper so the host-side merger parses both streams identically. */
static void __nyx_stub_http_record(const char *method,
                                   const char *url,
                                   const char *body,
                                   const char **detail_keys,
                                   const char **detail_vals,
                                   int detail_count) {
    const char *p = getenv("NYX_HTTP_LOG");
    if (!p || *p == '\0') return;
    FILE *f = fopen(p, "a");
    if (!f) return;
    if (method) fprintf(f, "# method: %s\n", method);
    if (url)    fprintf(f, "# url: %s\n", url);
    if (body)   fprintf(f, "# body: %s\n", body);
    for (int i = 0; i < detail_count; ++i) {
        if (detail_keys && detail_vals && detail_keys[i] && detail_vals[i]) {
            fprintf(f, "# %s: %s\n", detail_keys[i], detail_vals[i]);
        }
    }
    if (method && url) {
        fprintf(f, "%s %s\n", method, url);
    }
    fclose(f);
}
"##
}

impl LangEmitter for CEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "c emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 16 / 19 / 20 / 21 shape dispatch (main / libFuzzer / free function + future class / msg / job adapters)"
        )
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        chain_step(prev_output, terminal)
    }
}

/// Phase 26 — C chain-step harness.
///
/// Splices the C probe shim ([`probe_shim`]) ahead of a minimal driver
/// that reads `NYX_PREV_OUTPUT` and forwards it on stdout.  When the
/// step is the chain's terminal step (`terminal == Some(_)`) the driver
/// also calls `__nyx_probe(callee, 1, prev)` and emits the
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] on stdout so the runner
/// flips `sink_hit` for the chain.
///
/// Shell-wraps `cc` + run so the compiled binary actually executes after
/// the build completes — `ChainStepHarness.command` models a single
/// process, so the build-then-run sequence must collapse to one `sh -c`.
fn chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let shim = probe_shim();
    let mut driver = String::from(
        "\nint main(void) {\n    const char *prev = getenv(\"NYX_PREV_OUTPUT\");\n    if (prev) fputs(prev, stdout);\n",
    );
    if let Some(t) = terminal {
        let callee = c_string_literal(&t.sink_callee);
        let sentinel = c_string_literal(ChainStepHarness::SINK_HIT_SENTINEL);
        driver.push_str(&format!(
            "    __nyx_probe({callee}, 1, prev ? prev : \"\");\n    puts({sentinel});\n    fflush(stdout);\n",
        ));
    }
    driver.push_str("    return 0;\n}\n");
    let source = format!("{shim}{driver}");
    ChainStepHarness {
        source,
        filename: "step.c".to_owned(),
        command: vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "cc step.c -o step && ./step".to_owned(),
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

/// Escape a string for safe C double-quoted literal embedding.
fn c_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Emit a C harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    // Phase 19 (Track M.1): ClassMethod short-circuit.  C has no class
    // system — the dispatcher treats `class` + `method` as a single
    // free function whose name is the entry symbol (often
    // `Class_method` by convention) and calls it with the payload.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method_harness(class, method));
    }

    let shape = detect_shape(spec);

    match (&spec.payload_slot, shape) {
        (PayloadSlot::Param(0) | PayloadSlot::EnvVar(_), _) => {}
        (PayloadSlot::Argv(_), CShape::MainArgv) => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    let main_c = generate_main_c(spec, shape);
    let makefile = generate_makefile();

    Ok(HarnessSource {
        source: main_c,
        filename: "main.c".into(),
        command: vec!["./nyx_harness".into()],
        extra_files: vec![("Makefile".into(), makefile)],
        entry_subpath: Some("entry.c".into()),
    })
}

/// Phase 19 (Track M.1) — class-method harness for C.
///
/// C has no classes; the dispatcher calls the conventional
/// `<class>_<method>(const char *payload, size_t len)` free function
/// the fixture declares.  When the fixture exposes a different
/// symbol shape the caller is expected to pre-rewrite the
/// `entry_name` field; this fallback keeps the build path uniform
/// for the Phase 19 acceptance harness even though the class /
/// method projection collapses to a free-function call in C.
fn emit_class_method_harness(class: &str, method: &str) -> HarnessSource {
    let shim = probe_shim();
    let symbol = format!("{class}_{method}");
    let body = format!(
        r#"/* Nyx dynamic harness — class method (Phase 19 / Track M.1). */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
{shim}
static char *nyx_payload(void);

#include "entry.c"

int main(int argc, char *argv[]) {{
    (void)argc; (void)argv;
    char *payload = nyx_payload();
    if (!payload) payload = (char*)"";
    __nyx_install_crash_guard("{symbol}");
    {symbol}(payload, strlen(payload));
    puts("__NYX_SINK_HIT__");
    return 0;
}}

static char *nyx_payload(void) {{
    const char *v = getenv("NYX_PAYLOAD");
    if (v && *v) {{
        return strdup(v);
    }}
    return strdup("");
}}
"#,
        symbol = symbol,
    );
    HarnessSource {
        source: body,
        filename: "main.c".into(),
        command: vec!["./nyx_harness".into()],
        extra_files: vec![("Makefile".into(), generate_makefile())],
        entry_subpath: Some("entry.c".into()),
    }
}

/// Generate the harness `main.c` for the resolved shape.
fn generate_main_c(spec: &HarnessSpec, shape: CShape) -> String {
    let invocation = invoke_for_shape(spec, shape);
    let (entry_open, entry_close) = entry_include_guards(spec);
    let shim = probe_shim();
    let crash_callee = entry_symbol_for_spec(spec);

    format!(
        r#"/* Nyx dynamic harness — auto-generated, do not edit (Phase 16 — CShape::{shape:?}). */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
{shim}
/* Forward declarations: the entry file is appended below via `#include`
 * so the harness can call user-defined functions without a separate
 * compilation unit. */
static char *nyx_payload(void);

{entry_open}#include "entry.c"
{entry_close}
int main(int argc, char *argv[]) {{
    (void)argc; (void)argv;
    char *payload = nyx_payload();
    if (!payload) payload = (char*)"";

    /* Phase 08 sink-site signal handler: install AFTER payload decode so a
     * crash inside `nyx_payload`/`nyx_b64_decode` (harness setup) writes no
     * Crash probe, routing the verifier to `Inconclusive(UnrelatedCrash)`.
     * A crash inside the entry call below DOES fire the handler and writes
     * a Crash probe to `NYX_PROBE_PATH`, lifting an `Oracle::SinkCrash`
     * payload to `Confirmed`. */
    __nyx_install_crash_guard("{crash_callee}");
{invocation}
    /* Intentionally no free(payload): payload is either a strdup/b64_decode
     * heap pointer or a string literal substituted above when allocation
     * failed.  free() on the literal is UB; the process exits immediately
     * so the kernel reclaims the heap copy. */
    return 0;
}}

/* Minimal base64 decoder (no external deps). */
static int nyx_b64_value(unsigned char c) {{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}}

static char *nyx_b64_decode(const char *in) {{
    size_t n = strlen(in);
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    size_t outi = 0;
    int buf = 0, bits = 0;
    for (size_t i = 0; i < n; ++i) {{
        if (in[i] == '\n' || in[i] == '\r' || in[i] == '=') continue;
        int v = nyx_b64_value((unsigned char)in[i]);
        if (v < 0) {{ free(out); return NULL; }}
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {{
            bits -= 8;
            out[outi++] = (char)((buf >> bits) & 0xFF);
        }}
    }}
    out[outi] = '\0';
    return out;
}}

static char *nyx_payload(void) {{
    const char *v = getenv("NYX_PAYLOAD");
    if (v && *v) {{
        return strdup(v);
    }}
    const char *b64 = getenv("NYX_PAYLOAD_B64");
    if (b64 && *b64) {{
        return nyx_b64_decode(b64);
    }}
    return strdup("");
}}
"#,
        shape = shape,
        invocation = invocation,
        entry_open = entry_open,
        entry_close = entry_close,
    )
}

/// Preprocessor wrapper around `#include "entry.c"` that renames the user's
/// `int main(...)` to `__nyx_entry_main(...)` when the spec's entry symbol IS
/// `main` (i.e. a real CLI under Track B).  Without this, the entry's `main`
/// collides with the harness's own `main` at link time.
///
/// Fixture authors who already expose a non-`main` entry name (e.g.
/// `nyx_entry_main` under `tests/dynamic_fixtures/c/main_argv/`) get
/// empty guards.
fn entry_include_guards(spec: &HarnessSpec) -> (&'static str, &'static str) {
    if spec.entry_name == "main" {
        ("#define main __nyx_entry_main\n", "#undef main\n")
    } else {
        ("", "")
    }
}

/// Effective C symbol used to invoke the entry from the harness `main`.
/// Mirrors the rename inserted by [`entry_include_guards`]: when the user's
/// entry function IS named `main` it is renamed to `__nyx_entry_main` via
/// the preprocessor wrap, so both the call site in [`invoke_for_shape`] and
/// the `__nyx_install_crash_guard` callee label use this helper.
fn entry_symbol_for_spec(spec: &HarnessSpec) -> &str {
    if spec.entry_name == "main" {
        "__nyx_entry_main"
    } else {
        spec.entry_name.as_str()
    }
}

fn invoke_for_shape(spec: &HarnessSpec, shape: CShape) -> String {
    let entry_fn: &str = entry_symbol_for_spec(spec);
    match shape {
        CShape::FreeFn => match &spec.payload_slot {
            PayloadSlot::EnvVar(name) => format!(
                "    setenv({name:?}, payload, 1);\n    {entry_fn}(payload, strlen(payload));\n",
            ),
            _ => format!("    {entry_fn}(payload, strlen(payload));\n"),
        },
        CShape::LibfuzzerEntry => {
            // libFuzzer: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.
            format!(
                "    {entry_fn}((const uint8_t *)payload, strlen(payload));\n",
                entry_fn = entry_fn,
            )
        }
        CShape::MainArgv => {
            // Heap-allocate `new_argv` so a future `PayloadSlot::Argv(n)` with
            // `n >= 6` cannot overrun a fixed stack array.  Slots: 1
            // ("nyx_harness") + pad + 1 (payload) + 1 (NULL terminator).
            //
            // When `spec.entry_name == "main"` the entry's `int main(...)` is
            // renamed to `__nyx_entry_main` via the preprocessor guards on
            // `#include "entry.c"`, and the call site below targets that
            // renamed symbol.  Fixtures that already expose a non-`main`
            // entry symbol are called by name unchanged.
            let pad = match &spec.payload_slot {
                PayloadSlot::Argv(n) => *n,
                _ => 0,
            };
            let slots = pad + 3;
            let mut buf = String::new();
            buf.push_str(&format!(
                "    char **new_argv = (char**)calloc({slots}, sizeof(char*));\n",
            ));
            buf.push_str("    if (!new_argv) return 1;\n");
            buf.push_str("    int new_argc = 0;\n");
            buf.push_str("    new_argv[new_argc++] = (char*)\"nyx_harness\";\n");
            for _ in 0..pad {
                buf.push_str("    new_argv[new_argc++] = (char*)\"\";\n");
            }
            buf.push_str("    new_argv[new_argc++] = payload;\n");
            buf.push_str("    new_argv[new_argc] = NULL;\n");
            buf.push_str(&format!("    {entry_fn}(new_argc, new_argv);\n"));
            buf.push_str("    free(new_argv);\n");
            buf
        }
    }
}

fn generate_makefile() -> String {
    r#"# Phase 16 — reference Makefile, not used by the runner (the build sandbox
# calls cc directly).  Kept so reproductions can re-build the harness by hand.
CC ?= cc
CFLAGS ?= -O0 -g
all: nyx_harness
nyx_harness: main.c entry.c
	$(CC) $(CFLAGS) -o nyx_harness main.c
clean:
	rm -f nyx_harness
"#
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "c00000000000001".into(),
            entry_file: "entry.c".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::C,
            toolchain_id: "gcc-stable".into(),
            payload_slot,
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: "entry.c".into(),
            sink_line: 10,
            spec_hash: "ctest0000000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!CEmitter.entry_kinds_supported().is_empty());
        assert!(
            CEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::Function)
        );
        assert!(
            CEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::CliSubcommand)
        );
        assert!(
            CEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::LibraryApi)
        );
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = CEmitter.entry_kind_hint(EntryKindTag::LibraryApi);
        assert!(hint.contains("LibraryApi"));
        assert!(hint.contains("Phase 16"));
    }

    #[test]
    fn shape_detect_main_argv() {
        let src = "int main(int argc, char *argv[]) { return 0; }";
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "main".into();
        assert_eq!(CShape::detect(&spec, src), CShape::MainArgv);
    }

    #[test]
    fn shape_detect_libfuzzer_entry() {
        let src = "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }";
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_kind = EntryKind::LibraryApi;
        spec.entry_name = "LLVMFuzzerTestOneInput".into();
        assert_eq!(CShape::detect(&spec, src), CShape::LibfuzzerEntry);
    }

    #[test]
    fn shape_detect_free_fn() {
        let src = "void run(const char *s, size_t n) { (void)s; (void)n; }";
        let spec = make_spec(PayloadSlot::Param(0));
        assert_eq!(CShape::detect(&spec, src), CShape::FreeFn);
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        assert_eq!(h.filename, "main.c");
        assert!(h.source.contains("#include \"entry.c\""));
        assert!(h.source.contains("run(payload, strlen(payload))"));
        assert_eq!(h.command, vec!["./nyx_harness"]);
        assert_eq!(h.entry_subpath, Some("entry.c".to_string()));
    }

    #[test]
    fn emit_main_argv_shape_routes_through_new_argv() {
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "nyx_entry_main".into();
        let h = emit(&spec).unwrap();
        assert!(h.source.contains("new_argv[new_argc++] = payload"));
        assert!(h.source.contains("nyx_entry_main(new_argc, new_argv)"));
    }

    #[test]
    fn emit_main_argv_uses_heap_allocation_sized_for_pad() {
        // Phase 16 follow-up: heap-allocate `new_argv` so deep `Argv(n)` slots
        // cannot overrun a fixed stack array.  Slots = pad + 3
        // (nyx_harness + pad + payload + NULL).
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "nyx_entry_main".into();
        let h = emit(&spec).unwrap();
        assert!(
            !h.source.contains("char *new_argv[8]"),
            "fixed-size stack array must be gone — Argv(n>=6) used to overrun",
        );
        assert!(
            h.source
                .contains("char **new_argv = (char**)calloc(3, sizeof(char*))")
        );
        assert!(h.source.contains("free(new_argv);"));

        let mut spec6 = make_spec(PayloadSlot::Argv(6));
        spec6.entry_kind = EntryKind::CliSubcommand;
        spec6.entry_name = "nyx_entry_main".into();
        let h6 = emit(&spec6).unwrap();
        assert!(
            h6.source
                .contains("char **new_argv = (char**)calloc(9, sizeof(char*))")
        );
        assert!(h6.source.contains("free(new_argv);"));
    }

    #[test]
    fn emit_main_argv_renames_main_when_entry_named_main() {
        // Real-world Track B CLI vuln: the spec.entry_name IS "main", and the
        // entry source defines `int main(int argc, char *argv[])`.  Without
        // preprocessor rename guards, the entry's `main` collides with the
        // harness's own `main` at link time.
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "main".into();
        let h = emit(&spec).unwrap();
        assert!(
            h.source.contains("#define main __nyx_entry_main"),
            "rename guard missing from emitted source",
        );
        assert!(
            h.source.contains("#undef main"),
            "undef guard missing — harness `int main(...)` definition follows the include",
        );
        assert!(
            h.source.contains("__nyx_entry_main(new_argc, new_argv)"),
            "harness call site must target the renamed symbol",
        );
        // The harness's own `main` must remain a real entry point.
        assert!(h.source.contains("int main(int argc, char *argv[])"));
        // Guards must NOT fire for fixture-style non-main entry names.
        let mut fixture_spec = make_spec(PayloadSlot::Argv(0));
        fixture_spec.entry_kind = EntryKind::CliSubcommand;
        fixture_spec.entry_name = "nyx_entry_main".into();
        let fh = emit(&fixture_spec).unwrap();
        assert!(!fh.source.contains("#define main"));
        assert!(!fh.source.contains("#undef main"));
        assert!(fh.source.contains("nyx_entry_main(new_argc, new_argv)"));
    }

    #[test]
    fn emit_splices_probe_shim_and_installs_crash_guard_for_free_fn() {
        // Phase 16 follow-up: the C emitter now splices probe_shim() into the
        // generated harness AND installs the sink-site signal handler around
        // the entry invocation.  This is the joint unblock for Phase 08
        // (a) / (b) — a SIGSEGV inside the entry writes a Crash probe to
        // `NYX_PROBE_PATH`; a SIGSEGV during `nyx_payload` setup (before the
        // install) writes nothing, routing to `Inconclusive(UnrelatedCrash)`.
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        // The shim text is identified by its banner comment.
        assert!(
            h.source.contains("__nyx_probe shim (Phase 06 — Track C.1"),
            "probe_shim banner missing from generated main.c — splicing regressed",
        );
        // The signal-handler installer is callable from the harness body.
        assert!(
            h.source.contains("static void __nyx_install_crash_guard("),
            "install_crash_guard definition missing from generated main.c",
        );
        // The install call references the entry symbol (here `run`, since
        // `make_spec` sets `entry_name = "run"`).
        assert!(
            h.source.contains("__nyx_install_crash_guard(\"run\");"),
            "install_crash_guard call site missing or wrong callee in main()",
        );
        // The install must come after `nyx_payload()` returns and before the
        // entry invocation — otherwise a crash inside payload decode would
        // be misattributed to the sink (would defeat Phase 08(b)).
        let install_pos = h
            .source
            .find("__nyx_install_crash_guard(\"run\");")
            .unwrap();
        let payload_pos = h.source.find("char *payload = nyx_payload();").unwrap();
        let invoke_pos = h.source.find("run(payload, strlen(payload));").unwrap();
        assert!(
            payload_pos < install_pos && install_pos < invoke_pos,
            "install_crash_guard ordering wrong: payload_pos={payload_pos} install_pos={install_pos} invoke_pos={invoke_pos}",
        );
    }

    #[test]
    fn probe_shim_publishes_stub_sql_and_http_recorders() {
        // Phase 10 (Track D.3): the C probe shim ships the manual-record
        // stub helpers so a C harness can surface attempted DB / outbound
        // calls to the host-side SqlStub / HttpStub through their
        // NYX_SQL_LOG / NYX_HTTP_LOG side channels.  Helpers must be
        // declared before `__nyx_install_crash_guard` so a sink-rewrite
        // pass can reference them from anywhere in the entry source.
        let shim = probe_shim();
        assert!(
            shim.contains("static void __nyx_stub_sql_record("),
            "C probe shim must define __nyx_stub_sql_record",
        );
        assert!(
            shim.contains("static void __nyx_stub_http_record("),
            "C probe shim must define __nyx_stub_http_record",
        );
        assert!(
            shim.contains("getenv(\"NYX_SQL_LOG\")"),
            "SQL recorder must read NYX_SQL_LOG so the SqlStub side channel picks it up",
        );
        assert!(
            shim.contains("getenv(\"NYX_HTTP_LOG\")"),
            "HTTP recorder must read NYX_HTTP_LOG so the HttpStub side channel picks it up",
        );
    }

    #[test]
    fn emit_install_crash_guard_targets_renamed_main_entry() {
        // Real-world Track B CLI vuln: spec.entry_name == "main" → the entry
        // is renamed to __nyx_entry_main by entry_include_guards, and the
        // install call must reference the renamed symbol so the Crash probe
        // attributes correctly.
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "main".into();
        let h = emit(&spec).unwrap();
        assert!(
            h.source
                .contains("__nyx_install_crash_guard(\"__nyx_entry_main\");"),
            "install_crash_guard must use the post-rename symbol when entry_name == 'main'",
        );
    }

    #[test]
    fn emit_libfuzzer_shape_passes_bytes() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_kind = EntryKind::LibraryApi;
        spec.entry_name = "LLVMFuzzerTestOneInput".into();
        let h = emit(&spec).unwrap();
        assert!(
            h.source
                .contains("LLVMFuzzerTestOneInput((const uint8_t *)payload, strlen(payload))")
        );
    }

    #[test]
    fn emit_makefile_in_extra_files() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        let mk = h
            .extra_files
            .iter()
            .find(|(n, _)| n == "Makefile")
            .expect("Makefile must be staged");
        assert!(mk.1.contains("nyx_harness: main.c entry.c"));
    }

    #[test]
    fn chain_step_splices_probe_shim_for_composite_reverify() {
        // Phase 26 follow-up: C chain_step now splices the probe shim
        // ahead of the driver so a chain step that terminates at a sink
        // can drive the `__nyx_probe` channel directly.  Asserts the
        // shim banner is present and lands before `int main`, that
        // `__nyx_install_crash_guard` is reachable from the spliced
        // source, that `prev_output` rides through `extra_env`, and
        // that the build-then-run command stays in one `sh -c` so the
        // sandbox sees a single process.
        let step = chain_step(Some(b"prev-output"), None);
        assert!(
            step.source.contains("__nyx_probe shim (Phase 06"),
            "probe_shim banner missing from chain step source",
        );
        assert!(
            step.source
                .contains("static void __nyx_install_crash_guard("),
            "install_crash_guard missing from chain step source",
        );
        let shim_pos = step
            .source
            .find("__nyx_probe shim (Phase 06")
            .expect("shim banner");
        let main_pos = step.source.find("int main(void)").expect("main fn");
        assert!(
            shim_pos < main_pos,
            "shim must be spliced before int main: shim={shim_pos} main={main_pos}",
        );
        assert_eq!(step.filename, "step.c");
        assert_eq!(
            step.command,
            vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "cc step.c -o step && ./step".to_owned(),
            ],
        );
        assert!(
            step.extra_env
                .iter()
                .any(|(k, v)| k == ChainStepHarness::PREV_OUTPUT_ENV && v == "prev-output"),
            "prev_output must be threaded through extra_env, got {:?}",
            step.extra_env,
        );
        assert!(
            step.extra_files.is_empty(),
            "C chain step needs no companion build manifest; `cc` is self-sufficient",
        );
    }
}
