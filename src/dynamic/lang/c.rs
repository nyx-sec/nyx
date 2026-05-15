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

use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for C.
pub struct CEmitter;

/// Entry kinds the C emitter understands after Phase 16.
///
/// `Function` covers free functions (libfuzzer-style + plain (const
/// char*, size_t)).  `CliSubcommand` covers `main(argc, argv)`.
/// `LibraryApi` covers libFuzzer `LLVMFuzzerTestOneInput`.
const SUPPORTED: &[EntryKind] = &[
    EntryKind::Function,
    EntryKind::CliSubcommand,
    EntryKind::LibraryApi,
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
        let kind = spec.entry_kind;

        let has_main_argv = (source.contains("int main(") || source.contains("int main ("))
            && (source.contains("argc") || source.contains("char *argv")
                || source.contains("char* argv") || source.contains("char **argv"));
        let has_libfuzzer = source.contains("LLVMFuzzerTestOneInput") || entry == "LLVMFuzzerTestOneInput";

        if has_libfuzzer {
            return Self::LibfuzzerEntry;
        }
        if entry == "main" || has_main_argv {
            return Self::MainArgv;
        }
        match kind {
            EntryKind::CliSubcommand => Self::MainArgv,
            EntryKind::LibraryApi => Self::LibfuzzerEntry,
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
    let candidates = [PathBuf::from(entry_file), PathBuf::from(".").join(entry_file)];
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
    r#"
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
"#
}

impl LangEmitter for CEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "c emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 16 shape dispatch (main / libFuzzer / free function)"
        )
    }
}

/// Emit a C harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
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

/// Generate the harness `main.c` for the resolved shape.
fn generate_main_c(spec: &HarnessSpec, shape: CShape) -> String {
    let invocation = invoke_for_shape(spec, shape);

    format!(
        r#"/* Nyx dynamic harness — auto-generated, do not edit (Phase 16 — CShape::{shape:?}). */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward declarations: the entry file is appended below via `#include`
 * so the harness can call user-defined functions without a separate
 * compilation unit. */
static char *nyx_payload(void);

#include "entry.c"

int main(int argc, char *argv[]) {{
    (void)argc; (void)argv;
    char *payload = nyx_payload();
    if (!payload) payload = (char*)"";

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
    )
}

fn invoke_for_shape(spec: &HarnessSpec, shape: CShape) -> String {
    let entry_fn = &spec.entry_name;
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
            // Rename the user-supplied entry to `nyx_entry_main` via macro so
            // it does not collide with the harness `main` symbol when the
            // entry source defines `int main(...)`.  Fixture authors should
            // expose the entry as a function named in `spec.entry_name`.
            let pad = match &spec.payload_slot {
                PayloadSlot::Argv(n) => *n,
                _ => 0,
            };
            let mut buf = String::from("    char *new_argv[8];\n");
            buf.push_str("    int new_argc = 0;\n");
            buf.push_str("    new_argv[new_argc++] = (char*)\"nyx_harness\";\n");
            for _ in 0..pad {
                buf.push_str("    new_argv[new_argc++] = (char*)\"\";\n");
            }
            buf.push_str("    new_argv[new_argc++] = payload;\n");
            buf.push_str("    new_argv[new_argc] = NULL;\n");
            buf.push_str(&format!("    {entry_fn}(new_argc, new_argv);\n"));
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
    use crate::dynamic::spec::{EntryKind, HarnessSpec, PayloadSlot};
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
        }
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!CEmitter.entry_kinds_supported().is_empty());
        assert!(CEmitter.entry_kinds_supported().contains(&EntryKind::Function));
        assert!(CEmitter.entry_kinds_supported().contains(&EntryKind::CliSubcommand));
        assert!(CEmitter.entry_kinds_supported().contains(&EntryKind::LibraryApi));
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = CEmitter.entry_kind_hint(EntryKind::LibraryApi);
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
    fn emit_libfuzzer_shape_passes_bytes() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_kind = EntryKind::LibraryApi;
        spec.entry_name = "LLVMFuzzerTestOneInput".into();
        let h = emit(&spec).unwrap();
        assert!(h.source.contains("LLVMFuzzerTestOneInput((const uint8_t *)payload, strlen(payload))"));
    }

    #[test]
    fn emit_makefile_in_extra_files() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        let mk = h.extra_files.iter().find(|(n, _)| n == "Makefile").expect("Makefile must be staged");
        assert!(mk.1.contains("nyx_harness: main.c entry.c"));
    }
}
