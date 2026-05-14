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
/* ── __nyx_probe shim (Phase 06 — Track C.1) ─────────────────────────────── */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    for (int i = 0; i < nargs; ++i) {
        const char *arg = va_arg(ap, const char *);
        if (!arg) arg = "";
        if (i > 0) fputc(',', f);
        fprintf(f, "{\"kind\":\"String\",\"value\":\"%s\"}", arg);
    }
    va_end(ap);
    fprintf(f, "],\"captured_at_ns\":%llu,\"payload_id\":\"%s\"}\n", ns, pid);
    fclose(f);
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
