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
/* ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ── */
#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#ifndef __NYX_PAYLOAD_LIMIT
#define __NYX_PAYLOAD_LIMIT (16 * 1024)
#endif
#define __NYX_REDACTED "<redacted-by-nyx-policy>"

extern char **environ;

static const char *__nyx_deny_substrings_cpp[] = {
    "TOKEN","SECRET","PASSWORD","PASSWD","API_KEY","APIKEY","PRIVATE_KEY",
    "CREDENTIAL","SESSION","COOKIE","AUTH","BEARER","AWS_ACCESS","AWS_SESSION",
    "GH_TOKEN","GITHUB_TOKEN","NPM_TOKEN","PYPI_TOKEN","DOCKER_PASS",
};

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

inline void __nyx_esc(std::ostringstream &out, const std::string &v) {
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
}

inline std::string __nyx_witness_json(const char *sink_callee, const std::vector<std::string> &args_repr) {
    std::ostringstream out;
    out << "{\"env_snapshot\":{";
    bool first = true;
    for (char **e = environ; *e; ++e) {
        const char *eq = std::strchr(*e, '=');
        if (!eq) continue;
        std::string k(*e, static_cast<size_t>(eq - *e));
        std::string ku = k;
        std::transform(ku.begin(), ku.end(), ku.begin(), [](unsigned char c){ return (char)std::toupper(c); });
        bool denied = false;
        for (const char *needle : __nyx_deny_substrings_cpp) {
            if (ku.find(needle) != std::string::npos) { denied = true; break; }
        }
        if (!first) out << ',';
        first = false;
        out << '"'; __nyx_esc(out, k); out << "\":\"";
        if (denied) out << __NYX_REDACTED;
        else __nyx_esc(out, std::string(eq + 1));
        out << '"';
    }
    out << "},\"cwd\":\"";
    char cwdbuf[4096];
    if (::getcwd(cwdbuf, sizeof(cwdbuf))) __nyx_esc(out, std::string(cwdbuf));
    out << "\",\"payload_bytes\":[";
    const char *payload = std::getenv("NYX_PAYLOAD");
    if (payload) {
        size_t plen = std::strlen(payload);
        if (plen > __NYX_PAYLOAD_LIMIT) plen = __NYX_PAYLOAD_LIMIT;
        for (size_t i = 0; i < plen; ++i) {
            if (i > 0) out << ',';
            out << static_cast<int>(static_cast<unsigned char>(payload[i]));
        }
    }
    out << "],\"callee\":\""; __nyx_esc(out, std::string(sink_callee));
    out << "\",\"args_repr\":[";
    for (size_t i = 0; i < args_repr.size(); ++i) {
        if (i > 0) out << ',';
        out << '"'; __nyx_esc(out, args_repr[i]); out << '"';
    }
    out << "]}";
    return out.str();
}

template <typename... Args>
inline void __nyx_probe(const char *sink_callee, Args... args) {
    const char *p = std::getenv("NYX_PROBE_PATH");
    if (!p || *p == '\0') return;
    std::ostringstream out;
    out << "{\"sink_callee\":\"" << sink_callee << "\",\"args\":[";
    bool first = true;
    std::vector<std::string> repr;
    auto emit = [&](const std::string &s) {
        if (!first) out << ',';
        first = false;
        __nyx_probe_one(out, s);
        repr.push_back(s);
    };
    (emit(std::string(args)), ...);
    const char *pid = std::getenv("NYX_PAYLOAD_ID");
    auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    out << "],\"captured_at_ns\":" << now << ",\"payload_id\":\""
        << (pid ? pid : "") << "\",";
    out << "\"kind\":{\"kind\":\"Normal\"},\"witness\":"
        << __nyx_witness_json(sink_callee, repr) << "}\n";
    std::ofstream f(p, std::ios::app);
    if (f.is_open()) f << out.str();
}

/* Phase 08: sink-site sigaction handler.  Mirrors the C variant; the
 * captured `sink_callee` is held in a file-scope const char* so the
 * async-signal-unsafe write path can pull it without TLS. */
static const char *__nyx_crash_sink_callee = "";

inline void __nyx_crash_handler(int sig) {
    const char *p = std::getenv("NYX_PROBE_PATH");
    if (p && *p) {
        std::ofstream f(p, std::ios::app);
        if (f.is_open()) {
            const char *name = "SIGABRT";
            switch (sig) {
                case SIGSEGV: name = "SIGSEGV"; break;
                case SIGABRT: name = "SIGABRT"; break;
                case SIGBUS:  name = "SIGBUS"; break;
                case SIGFPE:  name = "SIGFPE"; break;
                case SIGILL:  name = "SIGILL"; break;
            }
            auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            const char *pid = std::getenv("NYX_PAYLOAD_ID");
            std::ostringstream out;
            out << "{\"sink_callee\":\"" << __nyx_crash_sink_callee
                << "\",\"args\":[],\"captured_at_ns\":" << now
                << ",\"payload_id\":\"" << (pid ? pid : "")
                << "\",\"kind\":{\"kind\":\"Crash\",\"signal\":\"" << name
                << "\"},\"witness\":"
                << __nyx_witness_json(__nyx_crash_sink_callee, {}) << "}\n";
            f << out.str();
        }
    }
    struct sigaction dfl;
    std::memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigaction(sig, &dfl, nullptr);
    raise(sig);
}

inline void __nyx_install_crash_guard(const char *sink_callee) {
    __nyx_crash_sink_callee = sink_callee;
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = __nyx_crash_handler;
    sigemptyset(&sa.sa_mask);
    for (int sig : { SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL }) {
        sigaction(sig, &sa, nullptr);
    }
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
