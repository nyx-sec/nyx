//! C++ harness emitter.
//!
//! Phase 16 (Track B Rust + C/C++ vertical) replaces the stub body with
//! dispatch over [`CppShape`] — `main(int argc, char *argv[])`, libFuzzer
//! `LLVMFuzzerTestOneInput`, and free functions with `(const char*,
//! size_t)` or `(const std::string&)` signatures.
//!
//! File layout in workdir:
//! ```text
//! main.cpp        ← harness entry point (generated, includes entry.cpp)
//! entry.cpp       ← user entry source (copied from project)
//! CMakeLists.txt  ← optional, generated for reference
//! ```
//!
//! Build step: `prepare_cpp()` in `build_sandbox.rs` runs
//! `g++ -O0 -std=c++17 -o nyx_harness main.cpp` in the workdir.

use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for C++.
pub struct CppEmitter;

/// Entry kinds the C++ emitter understands after Phase 16.
const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::CliSubcommand,
    EntryKindTag::LibraryApi,
    EntryKindTag::ClassMethod,
];

// ── Phase 16: shape detector ─────────────────────────────────────────────────

/// Concrete per-file shape resolved by reading the entry source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppShape {
    /// `int main(int argc, char *argv[])`.
    MainArgv,
    /// libFuzzer-style: `int LLVMFuzzerTestOneInput(const uint8_t *, size_t)`.
    LibfuzzerEntry,
    /// Free function with `(const char *, size_t)` or `(const std::string&)`
    /// signature.
    FreeFn,
}

impl CppShape {
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

pub fn detect_shape(spec: &HarnessSpec) -> CppShape {
    let src = read_entry_source(&spec.entry_file);
    CppShape::detect(spec, &src)
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

/// Source of the `__nyx_probe` shim for the (future) C++ harness
/// (Phase 06 — Track C.1).  Uses `<fstream>` + variadic templates; the
/// JSON-emit format matches [`crate::dynamic::probe::SinkProbe`].
pub fn probe_shim() -> &'static str {
    // The body holds literal `"# key: value\n"` log-line formats for the
    // Phase 10 stub recorders, so the surrounding raw string uses
    // `r##"..."##` to keep `"#` substrings from terminating it early
    // (same trick the Rust / Java / Go / Ruby siblings use).
    r##"
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

/* Phase 10 (Track D.3) stub recorder helpers.  See the C-side commentary
 * for the contract — these are the same helpers expressed in C++ idiom
 * (std::ofstream + std::initializer_list of {key, value} pairs).  Both
 * are no-ops when the relevant NYX_*_LOG env var is unset. */
inline void __nyx_stub_sql_record(
    const std::string &query,
    std::initializer_list<std::pair<std::string, std::string>> detail = {}) {
    const char *p = std::getenv("NYX_SQL_LOG");
    if (!p || *p == '\0') return;
    std::ofstream f(p, std::ios::app);
    if (!f.is_open()) return;
    for (const auto &kv : detail) {
        f << "# " << kv.first << ": " << kv.second << "\n";
    }
    f << query;
    if (query.empty() || query.back() != '\n') {
        f << "\n";
    }
}

inline void __nyx_stub_http_record(
    const std::string &method,
    const std::string &url,
    const std::string &body = std::string(),
    std::initializer_list<std::pair<std::string, std::string>> detail = {}) {
    const char *p = std::getenv("NYX_HTTP_LOG");
    if (!p || *p == '\0') return;
    std::ofstream f(p, std::ios::app);
    if (!f.is_open()) return;
    f << "# method: " << method << "\n";
    f << "# url: " << url << "\n";
    if (!body.empty()) {
        f << "# body: " << body << "\n";
    }
    for (const auto &kv : detail) {
        f << "# " << kv.first << ": " << kv.second << "\n";
    }
    f << method << " " << url << "\n";
}
"##
}

impl LangEmitter for CppEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "cpp emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 16 / 19 / 20 / 21 shape dispatch (main / libFuzzer / free function + future class / msg / job adapters)"
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

/// Phase 26 — C++ chain-step harness.
///
/// Splices the C++ probe shim ([`probe_shim`]) ahead of a minimal driver
/// that reads `NYX_PREV_OUTPUT` and forwards it on stdout.  When the
/// step is the chain's terminal step (`terminal == Some(_)`) the driver
/// also calls `__nyx_probe(callee, std::string(prev))` and emits the
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] so the runner flips
/// `sink_hit` for the chain.
///
/// Shell-wraps `c++` + run so the compiled binary actually executes
/// after the build completes (see C-side commentary for the rationale).
fn chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let shim = probe_shim();
    let mut driver = String::from(
        "\nint main() {\n    const char *prev = std::getenv(\"NYX_PREV_OUTPUT\");\n    if (prev) std::fputs(prev, stdout);\n",
    );
    if let Some(t) = terminal {
        let callee = cpp_string_literal(&t.sink_callee);
        let sentinel = cpp_string_literal(ChainStepHarness::SINK_HIT_SENTINEL);
        driver.push_str(&format!(
            "    __nyx_probe({callee}, std::string(prev ? prev : \"\"));\n    std::puts({sentinel});\n    std::fflush(stdout);\n",
        ));
    }
    driver.push_str("    return 0;\n}\n");
    let source = format!("{shim}{driver}");
    ChainStepHarness {
        source,
        filename: "step.cpp".to_owned(),
        command: vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "c++ step.cpp -o step && ./step".to_owned(),
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

/// Escape a string for safe C++ double-quoted literal embedding.
fn cpp_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Emit a C++ harness for `spec`.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    // Phase 19 (Track M.1): ClassMethod short-circuit.  The harness
    // constructs the receiver and invokes `method(payload)`.  When the
    // entry source exposes same-file constructor dependencies, build a
    // small recursive initializer instead of requiring a zero-arg ctor.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        let entry_src = read_entry_source(&spec.entry_file);
        return Ok(emit_class_method_harness(class, method, &entry_src));
    }

    let shape = detect_shape(spec);

    match (&spec.payload_slot, shape) {
        (PayloadSlot::Param(0) | PayloadSlot::EnvVar(_), _) => {}
        (PayloadSlot::Argv(_), CppShape::MainArgv) => {}
        _ => return Err(UnsupportedReason::PayloadSlotUnsupported),
    }

    let main_cpp = generate_main_cpp(spec, shape);
    let cmake = generate_cmake();

    Ok(HarnessSource {
        source: main_cpp,
        filename: "main.cpp".into(),
        command: vec!["./nyx_harness".into()],
        extra_files: vec![("CMakeLists.txt".into(), cmake)],
        entry_subpath: Some("entry.cpp".into()),
    })
}

/// Phase 19 (Track M.1) — class-method harness for C++.
///
/// Includes `entry.cpp`, constructs the class, and calls
/// `instance.<method>(payload)`.
fn emit_class_method_harness(class: &str, method: &str, entry_src: &str) -> HarnessSource {
    let shim = probe_shim();
    let receiver_expr = cpp_receiver_expr(entry_src, class, 3);
    let instance_decl = if receiver_expr.is_empty() {
        format!("{class} instance;")
    } else {
        format!("{class} instance{{{receiver_expr}}};")
    };
    let body = format!(
        r#"// Nyx dynamic harness — class method (Phase 19 / Track M.1).
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
{shim}
static std::string nyx_payload();

#include "entry.cpp"

int main(int argc, char *argv[]) {{
    (void)argc; (void)argv;
    std::string payload = nyx_payload();
    __nyx_install_crash_guard("{class}::{method}");
    {instance_decl}
    instance.{method}(payload);
    std::cout << "__NYX_SINK_HIT__" << std::endl;
    return 0;
}}

static std::string nyx_payload() {{
    if (const char *v = std::getenv("NYX_PAYLOAD")) {{
        if (*v) return std::string(v);
    }}
    return std::string();
}}
"#,
        class = class,
        method = method,
        instance_decl = instance_decl,
    );
    HarnessSource {
        source: body,
        filename: "main.cpp".into(),
        command: vec!["./nyx_harness".into()],
        extra_files: vec![("CMakeLists.txt".into(), generate_cmake())],
        entry_subpath: Some("entry.cpp".into()),
    }
}

fn cpp_receiver_expr(entry_src: &str, class: &str, depth: usize) -> String {
    if depth == 0 || cpp_has_default_constructor(entry_src, class) {
        return String::new();
    }
    let Some(params) = cpp_constructor_params(entry_src, class) else {
        return String::new();
    };
    if params.is_empty() {
        return String::new();
    }
    params
        .iter()
        .map(|param| cpp_value_for_param(entry_src, param, depth - 1))
        .collect::<Vec<_>>()
        .join(", ")
}

fn cpp_has_default_constructor(entry_src: &str, class: &str) -> bool {
    let pattern = format!("{class}()");
    entry_src.contains(&pattern) || entry_src.contains(&format!("{class} ()"))
}

fn cpp_constructor_params(entry_src: &str, class: &str) -> Option<Vec<String>> {
    let class_body = cpp_class_body(entry_src, class)?;
    let mut search_from = 0usize;
    while let Some(rel) = class_body[search_from..].find(class) {
        let idx = search_from + rel;
        let before = class_body[..idx].chars().rev().find(|c| !c.is_whitespace());
        if before.is_some_and(|c| c == '~') {
            search_from = idx + class.len();
            continue;
        }
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            && !cpp_constructor_prefix_allows_keyword(&class_body[..idx])
        {
            search_from = idx + class.len();
            continue;
        }
        let after = &class_body[idx + class.len()..];
        let after = after.trim_start();
        if !after.starts_with('(') {
            search_from = idx + class.len();
            continue;
        }
        let Some(sig) = balanced_parens(after) else {
            search_from = idx + class.len();
            continue;
        };
        let tail = after[sig.len()..].trim_start();
        if tail.starts_with(';') || tail.starts_with('{') || tail.starts_with(':') {
            let inner = &sig[1..sig.len() - 1];
            return Some(
                split_top_level_commas(inner)
                    .into_iter()
                    .filter_map(|part| {
                        let part = strip_cpp_default_value(part).trim();
                        if part.is_empty() || part == "void" {
                            None
                        } else {
                            Some(part.to_owned())
                        }
                    })
                    .collect(),
            );
        }
        search_from = idx + class.len();
    }
    None
}

fn cpp_constructor_prefix_allows_keyword(prefix: &str) -> bool {
    let mut chars = prefix.trim_end().chars().rev().peekable();
    let mut word_rev = String::new();
    while let Some(ch) = chars.peek().copied() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            word_rev.push(ch);
            chars.next();
        } else {
            break;
        }
    }
    let word = word_rev.chars().rev().collect::<String>();
    matches!(
        word.as_str(),
        "explicit" | "inline" | "constexpr" | "consteval"
    )
}

fn cpp_class_body<'a>(entry_src: &'a str, class: &str) -> Option<&'a str> {
    for keyword in ["class", "struct"] {
        let marker = format!("{keyword} {class}");
        let Some(idx) = entry_src.find(&marker) else {
            continue;
        };
        let after = &entry_src[idx + marker.len()..];
        let open = after.find('{')?;
        let block = balanced_block(&after[open..])?;
        return Some(&block[1..block.len() - 1]);
    }
    None
}

fn balanced_block(text: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&text[..=idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn balanced_parens(text: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&text[..=idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut angle_depth = 0isize;
    let mut paren_depth = 0isize;
    let mut brace_depth = 0isize;
    let mut start = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '<' => angle_depth += 1,
            '>' => angle_depth -= 1,
            '(' | '[' => paren_depth += 1,
            ')' | ']' => paren_depth -= 1,
            '{' => brace_depth += 1,
            '}' => brace_depth -= 1,
            ',' if angle_depth == 0 && paren_depth == 0 && brace_depth == 0 => {
                parts.push(&text[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

fn strip_cpp_default_value(param: &str) -> &str {
    let mut angle_depth = 0isize;
    let mut paren_depth = 0isize;
    for (idx, ch) in param.char_indices() {
        match ch {
            '<' => angle_depth += 1,
            '>' => angle_depth -= 1,
            '(' | '[' => paren_depth += 1,
            ')' | ']' => paren_depth -= 1,
            '=' if angle_depth == 0 && paren_depth == 0 => return &param[..idx],
            _ => {}
        }
    }
    param
}

fn cpp_value_for_param(entry_src: &str, param: &str, depth: usize) -> String {
    let ty = cpp_param_type(param);
    cpp_value_for_type(entry_src, &ty, depth)
}

fn cpp_param_type(param: &str) -> String {
    let mut tokens = param.split_whitespace().collect::<Vec<_>>();
    if tokens.len() > 1 {
        tokens.pop();
    }
    tokens
        .join(" ")
        .replace(" const", "")
        .replace("const ", "")
        .trim()
        .to_owned()
}

fn cpp_value_for_type(entry_src: &str, ty: &str, depth: usize) -> String {
    let clean = ty.trim();
    if clean.ends_with('*') {
        return "nullptr".to_owned();
    }
    let bare = clean
        .trim_end_matches('&')
        .trim()
        .trim_start_matches("std::")
        .split('<')
        .next()
        .unwrap_or(clean)
        .rsplit("::")
        .next()
        .unwrap_or(clean)
        .trim();
    match bare {
        "string" => "std::string()".to_owned(),
        "bool" => "false".to_owned(),
        "char" => "'\\0'".to_owned(),
        "float" | "double" => "0.0".to_owned(),
        "short" | "int" | "long" | "size_t" | "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t"
        | "int8_t" | "int16_t" | "int32_t" | "int64_t" => "0".to_owned(),
        _ if depth > 0 && cpp_class_body(entry_src, bare).is_some() => {
            let nested = cpp_receiver_expr(entry_src, bare, depth);
            if nested.is_empty() {
                format!("{bare}{{}}")
            } else {
                format!("{bare}{{{nested}}}")
            }
        }
        _ => format!("{bare}{{}}"),
    }
}

fn generate_main_cpp(spec: &HarnessSpec, shape: CppShape) -> String {
    let invocation = invoke_for_shape(spec, shape);
    let (entry_open, entry_close) = entry_include_guards(spec);
    let shim = probe_shim();
    let crash_callee = entry_symbol_for_spec(spec);

    format!(
        r#"// Nyx dynamic harness — auto-generated, do not edit (Phase 16 — CppShape::{shape:?}).
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
{shim}
static std::string nyx_payload();

{entry_open}#include "entry.cpp"
{entry_close}
int main(int argc, char *argv[]) {{
    (void)argc; (void)argv;
    std::string payload = nyx_payload();

    // Phase 08 sink-site signal handler: install AFTER payload decode so a
    // crash in nyx_payload / nyx_b64_decode (harness setup) writes no Crash
    // probe.  A crash inside the entry call below fires the handler and
    // writes a Crash probe to NYX_PROBE_PATH for `Oracle::SinkCrash`.
    __nyx_install_crash_guard("{crash_callee}");
{invocation}
    return 0;
}}

// Minimal base64 decoder (no external deps).
static int nyx_b64_value(unsigned char c) {{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}}

static std::string nyx_b64_decode(const std::string &in) {{
    std::string out;
    int buf = 0, bits = 0;
    for (char c : in) {{
        if (c == '\n' || c == '\r' || c == '=') continue;
        int v = nyx_b64_value(static_cast<unsigned char>(c));
        if (v < 0) return std::string();
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {{
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }}
    }}
    return out;
}}

static std::string nyx_payload() {{
    if (const char *v = std::getenv("NYX_PAYLOAD")) {{
        if (*v) return std::string(v);
    }}
    if (const char *b64 = std::getenv("NYX_PAYLOAD_B64")) {{
        if (*b64) return nyx_b64_decode(std::string(b64));
    }}
    return std::string();
}}
"#,
        shape = shape,
        invocation = invocation,
        entry_open = entry_open,
        entry_close = entry_close,
    )
}

/// Preprocessor guards that rename the entry source's `int main(...)` to
/// `__nyx_entry_main(...)` when the spec entry symbol IS `main`.  Mirrors
/// the C-side fix; without it the user's `main` collides with the harness's
/// own `main` at link time.
fn entry_include_guards(spec: &HarnessSpec) -> (&'static str, &'static str) {
    if spec.entry_name == "main" {
        ("#define main __nyx_entry_main\n", "#undef main\n")
    } else {
        ("", "")
    }
}

/// Effective C++ symbol used to invoke the entry from the harness `main`,
/// after [`entry_include_guards`] has rewritten an entry-side `main` to
/// `__nyx_entry_main`.
fn entry_symbol_for_spec(spec: &HarnessSpec) -> &str {
    if spec.entry_name == "main" {
        "__nyx_entry_main"
    } else {
        spec.entry_name.as_str()
    }
}

fn invoke_for_shape(spec: &HarnessSpec, shape: CppShape) -> String {
    let entry_fn: &str = entry_symbol_for_spec(spec);
    match shape {
        CppShape::FreeFn => match &spec.payload_slot {
            PayloadSlot::EnvVar(name) => format!(
                "    setenv({name:?}, payload.c_str(), 1);\n    {entry_fn}(payload.c_str(), payload.size());\n",
            ),
            _ => format!("    {entry_fn}(payload.c_str(), payload.size());\n"),
        },
        CppShape::LibfuzzerEntry => {
            format!(
                "    {entry_fn}(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());\n",
                entry_fn = entry_fn,
            )
        }
        CppShape::MainArgv => {
            let pad = match &spec.payload_slot {
                PayloadSlot::Argv(n) => *n,
                _ => 0,
            };
            let mut buf = String::from("    std::vector<char*> new_argv;\n");
            buf.push_str("    std::vector<std::string> argv_storage;\n");
            buf.push_str("    argv_storage.emplace_back(\"nyx_harness\");\n");
            for _ in 0..pad {
                buf.push_str("    argv_storage.emplace_back(\"\");\n");
            }
            buf.push_str("    argv_storage.push_back(payload);\n");
            buf.push_str("    for (auto &s : argv_storage) new_argv.push_back(s.data());\n");
            buf.push_str("    new_argv.push_back(nullptr);\n");
            buf.push_str(&format!(
                "    {entry_fn}(static_cast<int>(argv_storage.size()), new_argv.data());\n",
            ));
            buf
        }
    }
}

fn generate_cmake() -> String {
    r#"# Phase 16 — reference CMakeLists.txt, not used by the runner (the build
# sandbox calls g++ / clang++ directly).  Kept so reproductions can re-build
# the harness by hand via `cmake -B build && cmake --build build`.
cmake_minimum_required(VERSION 3.10)
project(nyx_harness CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_executable(nyx_harness main.cpp)
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
            finding_id: "cpp0000000000001".into(),
            entry_file: "entry.cpp".into(),
            entry_name: "run".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Cpp,
            toolchain_id: "g++-stable".into(),
            payload_slot,
            expected_cap: Cap::CODE_EXEC,
            constraint_hints: vec![],
            sink_file: "entry.cpp".into(),
            sink_line: 10,
            spec_hash: "cpptest00000001".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn entry_kinds_supported_is_non_empty() {
        assert!(!CppEmitter.entry_kinds_supported().is_empty());
        assert!(
            CppEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::Function)
        );
        assert!(
            CppEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::CliSubcommand)
        );
        assert!(
            CppEmitter
                .entry_kinds_supported()
                .contains(&EntryKindTag::LibraryApi)
        );
    }

    #[test]
    fn entry_kind_hint_names_attempted_and_phase() {
        let hint = CppEmitter.entry_kind_hint(EntryKindTag::CliSubcommand);
        assert!(hint.contains("CliSubcommand"));
        assert!(hint.contains("Phase 16"));
    }

    #[test]
    fn shape_detect_main_argv() {
        let src = "int main(int argc, char *argv[]) { return 0; }";
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "main".into();
        assert_eq!(CppShape::detect(&spec, src), CppShape::MainArgv);
    }

    #[test]
    fn shape_detect_libfuzzer() {
        let src =
            "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) { return 0; }";
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_kind = EntryKind::LibraryApi;
        spec.entry_name = "LLVMFuzzerTestOneInput".into();
        assert_eq!(CppShape::detect(&spec, src), CppShape::LibfuzzerEntry);
    }

    #[test]
    fn shape_detect_free_fn() {
        let src = "void run(const char *s, size_t n) { (void)s; (void)n; }";
        let spec = make_spec(PayloadSlot::Param(0));
        assert_eq!(CppShape::detect(&spec, src), CppShape::FreeFn);
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        assert_eq!(h.filename, "main.cpp");
        assert!(h.source.contains("#include \"entry.cpp\""));
        assert!(h.source.contains("run(payload.c_str(), payload.size())"));
        assert_eq!(h.command, vec!["./nyx_harness"]);
        assert_eq!(h.entry_subpath, Some("entry.cpp".to_string()));
    }

    #[test]
    fn emit_libfuzzer_shape_passes_bytes() {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_kind = EntryKind::LibraryApi;
        spec.entry_name = "LLVMFuzzerTestOneInput".into();
        let h = emit(&spec).unwrap();
        assert!(h.source.contains("LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(payload.data()), payload.size())"));
    }

    #[test]
    fn emit_main_argv_shape_builds_argv() {
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "nyx_entry_main".into();
        let h = emit(&spec).unwrap();
        assert!(h.source.contains("argv_storage.push_back(payload)"));
        assert!(
            h.source
                .contains("nyx_entry_main(static_cast<int>(argv_storage.size()), new_argv.data())")
        );
    }

    #[test]
    fn emit_main_argv_renames_main_when_entry_named_main() {
        // Real-world Track B CLI vuln: spec.entry_name IS "main".  Without
        // preprocessor rename guards, the entry's `int main(...)` collides
        // with the harness's own `main` at link time.
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "main".into();
        let h = emit(&spec).unwrap();
        assert!(
            h.source.contains("#define main __nyx_entry_main"),
            "rename guard missing",
        );
        assert!(h.source.contains("#undef main"), "undef guard missing");
        assert!(
            h.source.contains(
                "__nyx_entry_main(static_cast<int>(argv_storage.size()), new_argv.data())"
            ),
            "harness call site must target the renamed symbol",
        );
        assert!(h.source.contains("int main(int argc, char *argv[])"));
        // Guards must not fire for fixture-style non-main entry names.
        let mut fixture_spec = make_spec(PayloadSlot::Argv(0));
        fixture_spec.entry_kind = EntryKind::CliSubcommand;
        fixture_spec.entry_name = "nyx_entry_main".into();
        let fh = emit(&fixture_spec).unwrap();
        assert!(!fh.source.contains("#define main"));
        assert!(!fh.source.contains("#undef main"));
        assert!(
            fh.source
                .contains("nyx_entry_main(static_cast<int>(argv_storage.size()), new_argv.data())")
        );
    }

    #[test]
    fn emit_splices_probe_shim_and_installs_crash_guard_for_free_fn() {
        // Phase 16 follow-up: C++ emitter now splices probe_shim() and
        // installs the sink-site signal handler around the entry call.
        // Mirrors the C-side splicing tests.
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        assert!(
            h.source.contains("__nyx_probe shim (Phase 06 — Track C.1"),
            "probe_shim banner missing from generated main.cpp",
        );
        assert!(
            h.source.contains("inline void __nyx_install_crash_guard("),
            "install_crash_guard definition missing from generated main.cpp",
        );
        assert!(
            h.source.contains("__nyx_install_crash_guard(\"run\");"),
            "install_crash_guard call site missing or wrong callee",
        );
        let install_pos = h
            .source
            .find("__nyx_install_crash_guard(\"run\");")
            .unwrap();
        let payload_pos = h
            .source
            .find("std::string payload = nyx_payload();")
            .unwrap();
        let invoke_pos = h
            .source
            .find("run(payload.c_str(), payload.size());")
            .unwrap();
        assert!(
            payload_pos < install_pos && install_pos < invoke_pos,
            "install_crash_guard ordering wrong: payload_pos={payload_pos} install_pos={install_pos} invoke_pos={invoke_pos}",
        );
    }

    #[test]
    fn emit_install_crash_guard_targets_renamed_main_entry() {
        let mut spec = make_spec(PayloadSlot::Argv(0));
        spec.entry_kind = EntryKind::CliSubcommand;
        spec.entry_name = "main".into();
        let h = emit(&spec).unwrap();
        assert!(
            h.source
                .contains("__nyx_install_crash_guard(\"__nyx_entry_main\");"),
            "install_crash_guard must use post-rename symbol when entry_name == 'main'",
        );
    }

    #[test]
    fn probe_shim_publishes_stub_sql_and_http_recorders() {
        // Phase 10 (Track D.3): the C++ probe shim ships the manual-record
        // stub helpers so a C++ harness can surface attempted DB / outbound
        // calls to the host-side SqlStub / HttpStub through their
        // NYX_SQL_LOG / NYX_HTTP_LOG side channels.
        let shim = probe_shim();
        assert!(
            shim.contains("inline void __nyx_stub_sql_record("),
            "C++ probe shim must define __nyx_stub_sql_record",
        );
        assert!(
            shim.contains("inline void __nyx_stub_http_record("),
            "C++ probe shim must define __nyx_stub_http_record",
        );
        assert!(
            shim.contains("std::getenv(\"NYX_SQL_LOG\")"),
            "SQL recorder must read NYX_SQL_LOG so the SqlStub side channel picks it up",
        );
        assert!(
            shim.contains("std::getenv(\"NYX_HTTP_LOG\")"),
            "HTTP recorder must read NYX_HTTP_LOG so the HttpStub side channel picks it up",
        );
    }

    #[test]
    fn emit_cmake_in_extra_files() {
        let spec = make_spec(PayloadSlot::Param(0));
        let h = emit(&spec).unwrap();
        let mk = h
            .extra_files
            .iter()
            .find(|(n, _)| n == "CMakeLists.txt")
            .expect("CMakeLists.txt must be staged");
        assert!(mk.1.contains("add_executable(nyx_harness main.cpp)"));
    }

    #[test]
    fn chain_step_splices_probe_shim_for_composite_reverify() {
        // Phase 26 follow-up: C++ chain_step now splices the probe shim
        // ahead of the driver so a chain step that terminates at a sink
        // can drive the `__nyx_probe` channel directly.  Asserts the
        // shim banner is present and lands before `int main`, that
        // `__nyx_install_crash_guard` is reachable, prev_output rides
        // through `extra_env`, and build-then-run stays one `sh -c`.
        let step = chain_step(Some(b"prev-output"), None);
        assert!(
            step.source.contains("__nyx_probe shim (Phase 06"),
            "probe_shim banner missing from chain step source",
        );
        assert!(
            step.source
                .contains("inline void __nyx_install_crash_guard("),
            "install_crash_guard missing from chain step source",
        );
        let shim_pos = step
            .source
            .find("__nyx_probe shim (Phase 06")
            .expect("shim banner");
        let main_pos = step.source.find("int main()").expect("main fn");
        assert!(
            shim_pos < main_pos,
            "shim must be spliced before int main: shim={shim_pos} main={main_pos}",
        );
        assert_eq!(step.filename, "step.cpp");
        assert_eq!(
            step.command,
            vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "c++ step.cpp -o step && ./step".to_owned(),
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
            "C++ chain step needs no companion build manifest; `c++` is self-sufficient",
        );
    }
}
