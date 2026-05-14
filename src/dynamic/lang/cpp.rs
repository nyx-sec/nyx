//! C++ harness emitter (stub).
//!
//! No harness source is generated yet — `emit` returns
//! [`UnsupportedReason::LangUnsupported`].  The module exists so that
//! [`crate::dynamic::lang::entry_kinds_supported`] can advertise the entry
//! kinds Track B will deliver (Phase 16: `main(argc, argv)`,
//! `LLVMFuzzerTestOneInput`, free functions with `(const char*, size_t)`)
//! and so the verifier can surface `Inconclusive(EntryKindUnsupported { … })`
//! instead of dropping C++ findings.

use crate::dynamic::lang::{HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKind, HarnessSpec};
use crate::evidence::UnsupportedReason;

/// Zero-sized [`LangEmitter`] handle for C++.
pub struct CppEmitter;

/// Entry kinds the C++ emitter intends to support once Phase 16 lands.
const SUPPORTED: &[EntryKind] = &[EntryKind::Function];

/// Source of the `__nyx_probe` shim for the (future) C++ harness
/// (Phase 06 — Track C.1).  Uses `<fstream>` + variadic templates; the
/// JSON-emit format matches [`crate::dynamic::probe::SinkProbe`].
pub fn probe_shim() -> &'static str {
    r#"
/* ── __nyx_probe shim (Phase 06 — Track C.1) ─────────────────────────────── */
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

inline void __nyx_probe_one(std::ostringstream &out, const std::string &v) {
    out << "{\"kind\":\"String\",\"value\":\"";
    for (char c : v) {
        switch (c) {
            case '"':  out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:   out << c;
        }
    }
    out << "\"}";
}

template <typename... Args>
inline void __nyx_probe(const char *sink_callee, Args... args) {
    const char *p = std::getenv("NYX_PROBE_PATH");
    if (!p || *p == '\0') return;
    std::ostringstream out;
    out << "{\"sink_callee\":\"" << sink_callee << "\",\"args\":[";
    bool first = true;
    auto emit = [&](const std::string &s) {
        if (!first) out << ',';
        first = false;
        __nyx_probe_one(out, s);
    };
    (emit(std::string(args)), ...);
    const char *pid = std::getenv("NYX_PAYLOAD_ID");
    auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    out << "],\"captured_at_ns\":" << now << ",\"payload_id\":\""
        << (pid ? pid : "") << "\"}\n";
    std::ofstream f(p, std::ios::app);
    if (f.is_open()) f << out.str();
}
"#
}

impl LangEmitter for CppEmitter {
    fn emit(&self, _spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        Err(UnsupportedReason::LangUnsupported)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKind] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKind) -> String {
        format!(
            "cpp emitter is a stub; once Phase 16 (Track B Rust + C/C++ vertical) lands it will support {SUPPORTED:?} plus libFuzzer + main(argc, argv) shapes — attempted `EntryKind::{attempted}`"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!CppEmitter.entry_kinds_supported().is_empty());
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = CppEmitter.entry_kind_hint(EntryKind::CliSubcommand);
        assert!(hint.contains("CliSubcommand"));
        assert!(hint.contains("Phase 16"));
    }
}
