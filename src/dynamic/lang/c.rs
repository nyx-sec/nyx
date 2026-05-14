//! C harness emitter (stub).
//!
//! No harness source is generated yet — `emit` returns
//! [`UnsupportedReason::LangUnsupported`].  The module exists so that
//! [`crate::dynamic::lang::entry_kinds_supported`] can advertise the entry
//! kinds Track B will deliver (Phase 16: `main(argc, argv)`,
//! `LLVMFuzzerTestOneInput`, free functions with `(const char*, size_t)` or
//! `(int, char**)` shapes) and so the verifier can surface
//! `Inconclusive(EntryKindUnsupported { … })` instead of dropping C findings.

use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for C.
pub struct CEmitter;

/// Entry kinds the C emitter intends to support once Phase 16 lands.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

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
    fn emit(&self, _spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        Err(UnsupportedReason::LangUnsupported)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "c emitter is a stub; once Phase 16 (Track B Rust + C/C++ vertical) lands it will support {SUPPORTED:?} plus libFuzzer + main(argc, argv) shapes — attempted `EntryKind::{attempted}`"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!CEmitter.entry_kinds_supported().is_empty());
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = CEmitter.entry_kind_hint(EntryKind::LibraryApi);
        assert!(hint.contains("LibraryApi"));
        assert!(hint.contains("Phase 16"));
    }
}
