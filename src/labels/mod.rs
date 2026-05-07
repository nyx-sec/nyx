//! Per-language source, sanitizer, and sink rule registries.
//!
//! The central type is [`DataLabel`], which pairs a [`Cap`] bitflag set with
//! a role (Source, Sanitizer, Sink). [`LabelRule`] maps AST text patterns to
//! labels. [`classify`] and [`classify_all`] look up a callee name against
//! the active language's rule table; [`classify_gated_sink`] handles
//! argument-role-aware sinks where one argument controls whether the call is
//! dangerous at all.
//!
//! Rules for each language live in per-language submodules (`rust`, `java`,
//! `go`, `python`, `php`, `ruby`, `javascript`, `typescript`, `c`, `cpp`).
//! The [`Cap`] bitflag type is defined here and shared with the taint engine.

mod c;
mod cpp;
mod go;
mod java;
mod javascript;
mod php;
mod python;
pub(crate) mod ruby;
mod rust;
mod typescript;

use bitflags::bitflags;
use once_cell::sync::Lazy;
use phf::Map;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;

/// A single rule: if the AST text equals (or ends with) one of the `matchers`,
/// the node gets `label`.
#[derive(Debug, Clone, Copy)]
pub struct LabelRule {
    pub matchers: &'static [&'static str],
    pub label: DataLabel,
    pub case_sensitive: bool,
}

/// Sentinel returned by [`classify_gated_sink`] for the dynamic/unknown-activation
/// branch: the gate fires conservatively and every positional argument must be
/// considered a potential tainted payload, not just the explicit `payload_args`.
/// Downstream code (`cfg.rs` node construction) detects this sentinel and
/// expands it to `(0..arity)` using the actual call arity.
///
/// The value `usize::MAX` is used because `args.get(usize::MAX)` is a guaranteed
/// miss for any real argument list, an accidental direct-lookup would be a no-op
/// rather than silently aliasing position 0.
pub const ALL_ARGS_PAYLOAD: &[usize] = &[usize::MAX];

/// How a gate decides to activate.
///
/// A gate's activation determines whether the callee is treated as a sink at
/// a given call site. `ValueMatch` inspects a literal/kwarg for dangerous
/// values; `Destination` fires unconditionally on taint reaching declared
/// destination-bearing positions or fields.
#[derive(Debug, Clone, Copy)]
pub enum GateActivation {
    /// Legacy literal-value activation.  The gate fires when the constant
    /// value at `arg_index` (or keyword arg, if `keyword_name`/`dangerous_kwargs`
    /// is set) matches `dangerous_values` / `dangerous_prefixes`, or when that
    /// value is dynamic/unknown (conservative).
    ///
    /// Used for argument-role-aware sinks like `setAttribute` (activation arg
    /// selects which attribute is being set) and `parseFromString` (activation
    /// arg selects the MIME type).
    ValueMatch,
    /// Destination-bearing flow activation.  The gate fires when taint reaches
    /// a declared destination location at the call site, no literal
    /// inspection, no prefix heuristic.
    ///
    /// For callees whose destination is a positional argument (e.g. `fetch`'s
    /// first arg, `axios.post`'s first arg), set `object_destination_fields`
    /// to `&[]`: the whole positional argument at each index in the gate's
    /// `payload_args` is treated as the destination.
    ///
    /// For callees that accept a config/options object whose fields designate
    /// the destination (`axios({url,baseURL,...})`, `http.request({host,path,port})`,
    /// `got({url,prefixUrl,...})`, `undici.request({origin,path,...})`), list
    /// the destination-bearing field names here.  When the positional arg is
    /// an object literal at call time, sink taint checks are restricted to
    /// identifiers found under those fields; non-destination fields (`body`,
    /// `data`, `json`, `headers`, ...) are silenced.
    ///
    /// When the positional arg is not an object literal (plain string / ident
    /// / expression), the whole arg is treated as the destination (same as
    /// the empty-field case).  This keeps `http.request(urlString, cb)` and
    /// `http.request({host,path}, cb)` both covered by a single gate.
    Destination {
        object_destination_fields: &'static [&'static str],
    },
}

/// Argument-sensitive sink activation.  Whether a call becomes a sink is
/// determined by the gate's [`GateActivation`] mode, literal-value matching
/// for traditional role-selector APIs, or destination-flow activation for
/// outbound HTTP clients and other APIs where a specific location in the
/// call carries the attacker-controlled destination.
///
/// `payload_args` specifies which argument positions carry the tainted payload.
/// When non-empty, only variables from those argument positions are checked for
/// taint at the sink.  When empty, all arguments are considered payloads
/// (backward-compatible default for `ValueMatch`).
#[derive(Debug, Clone, Copy)]
pub struct SinkGate {
    pub callee_matcher: &'static str,
    pub arg_index: usize,
    pub dangerous_values: &'static [&'static str],
    pub dangerous_prefixes: &'static [&'static str],
    pub label: DataLabel,
    pub case_sensitive: bool,
    pub payload_args: &'static [usize],
    /// Optional keyword argument name for languages that support keyword args
    /// (e.g. Python `shell=True` in `subprocess.Popen`).  When set, the
    /// activation value is extracted from the named keyword argument instead
    /// of the positional argument at `arg_index`.
    pub keyword_name: Option<&'static str>,
    /// Multi-keyword activation rules.  Each entry is `(kwarg_name, values)`
    /// where any listed value makes the call dangerous.  Gate semantics when
    /// non-empty:
    ///   * A listed kwarg with a matching literal value → activate.
    ///   * A listed kwarg present with a non-literal (dynamic) value →
    ///     activate conservatively.
    ///   * A listed kwarg present but with an explicitly safe literal → does
    ///     not by itself activate.
    ///   * No listed kwarg present → does not activate (matches the language
    ///     default, e.g. Python `shell=False` implicit for `subprocess.run`).
    ///
    /// When both `keyword_name` and `dangerous_kwargs` are set, `keyword_name`
    /// wins (back-compat for existing single-kwarg gates).  `&[]` is the
    /// default and disables this branch.
    pub dangerous_kwargs: &'static [(&'static str, &'static [&'static str])],
    /// Activation mode.  [`GateActivation::ValueMatch`] is the legacy default;
    /// [`GateActivation::Destination`] is used for destination-flow modeling
    /// (outbound HTTP clients etc.).
    pub activation: GateActivation,
}

bitflags! {
    /// Security capability bits for sources, sanitizers, and sinks.
    ///
    /// Each bit represents a security-relevant property. The meaning depends on
    /// which role the [`Cap`] value is attached to:
    ///
    /// - **Source**: which attack classes this tainted value can potentially
    ///   trigger. Sources usually carry [`Cap::all()`] so they match any sink.
    ///   [`ENV_VAR`](Cap::ENV_VAR) is an exception — it marks origin rather
    ///   than reach.
    /// - **Sanitizer**: which attack classes this function strips. A sanitizer
    ///   labelled with [`HTML_ESCAPE`](Cap::HTML_ESCAPE) clears the XSS-relevant
    ///   bits from tainted values that flow through it.
    /// - **Sink**: which capability bits must be present on the incoming tainted
    ///   value for a finding to fire. A SQL sink requires [`SQL_QUERY`](Cap::SQL_QUERY).
    ///
    /// In practice: a finding fires when a tainted value reaches a sink and
    /// `(value_caps & sink_caps) != 0`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Cap: u32 {
        /// Taint that originated from an environment variable read.
        /// Used as a source-origin marker for env-injection rules.
        const ENV_VAR              = 1 << 0;
        /// Sanitizer: the value has passed through HTML entity escaping.
        /// Strips XSS risk from values that reach HTML output sinks.
        const HTML_ESCAPE          = 1 << 1;
        /// Sanitizer: the value has been shell-argument escaped.
        /// Strips command-injection risk before shell sinks.
        const SHELL_ESCAPE         = 1 << 2;
        /// Sanitizer: the value has been percent-encoded for use in a URL.
        const URL_ENCODE           = 1 << 3;
        /// Sanitizer: the value was parsed through a structured JSON decoder
        /// (as opposed to `eval`-based or regex parsing).
        const JSON_PARSE           = 1 << 4;
        /// Sink: file system read or write operation (path traversal, arbitrary
        /// file read/write).
        const FILE_IO              = 1 << 5;
        /// Sink: format string injection (e.g. `printf`-family, `String.format`).
        const FMT_STRING           = 1 << 6;
        /// Sink: SQL query construction. Fires for string-concatenated queries
        /// and parameterized-query builders where the query text itself is tainted.
        const SQL_QUERY            = 1 << 7;
        /// Sink: unsafe object deserialization (Java `ObjectInputStream`,
        /// Python `pickle`, Ruby `Marshal`, PHP `unserialize`, etc.).
        const DESERIALIZE          = 1 << 8;
        /// Sink: server-side request forgery. Fires when attacker-controlled
        /// data reaches the destination URL of an outbound HTTP request.
        const SSRF                 = 1 << 9;
        /// Sink: code or command execution (shell injection, `eval`, `exec`,
        /// dynamic `require`/`import`, template injection).
        const CODE_EXEC            = 1 << 10;
        /// Sink: cryptographic operation with a tainted algorithm name or seed
        /// (weak-crypto / predictable-randomness patterns).
        const CRYPTO               = 1 << 11;
        /// Request-bound, caller-supplied identifier that has not yet been
        /// validated against an ownership/membership check.  Used as the
        /// carrier cap for folding `auth_analysis` into the SSA/taint
        /// engine.
        const UNAUTHORIZED_ID      = 1 << 12;
        /// Cross-boundary data-exfiltration: tainted sensitive data flowing
        /// into outbound request bodies, headers, or other payload-bearing
        /// fields of network egress APIs.  Distinct from `SSRF` (attacker
        /// control over the destination URL), `DATA_EXFIL` fires when the
        /// destination is fixed but attacker-influenced data leaves the
        /// process via the request payload.
        const DATA_EXFIL           = 1 << 13;
        /// Sink: LDAP search/query construction. Fires when attacker-controlled
        /// data reaches a directory-service filter or DN argument without
        /// LDAP-filter escaping.
        const LDAP_INJECTION       = 1 << 14;
        /// Sink: XPath expression construction. Fires when attacker-controlled
        /// data is concatenated into an XPath query rather than passed via
        /// XPath variable bindings.
        const XPATH_INJECTION      = 1 << 15;
        /// Sink: HTTP response header value (or any CRLF-sensitive output).
        /// Fires when attacker-controlled data lands in a `Set-Header` /
        /// header-add call without `\r\n` stripping (response splitting).
        const HEADER_INJECTION     = 1 << 16;
        /// Sink: redirect / `Location` header destination. Fires when an
        /// attacker-controlled URL reaches a redirect call without an
        /// allowlist or relative-URL check.
        const OPEN_REDIRECT        = 1 << 17;
        /// Sink: server-side template injection. Fires when the **template
        /// source string** itself is attacker-controlled (e.g.
        /// `Template(user_input).render()`), distinct from rendering a
        /// trusted template with tainted variables.
        const SSTI                 = 1 << 18;
        /// Sink: XML external entity resolution. Fires when attacker-controlled
        /// XML reaches a parser configured to resolve external entities (or
        /// missing the secure-processing feature).
        const XXE                  = 1 << 19;
        /// Sink: prototype pollution. Fires when an attacker-controlled key
        /// reaches an object property assignment that can mutate
        /// `Object.prototype` (`__proto__`, `constructor.prototype`, deep-merge
        /// helpers).
        const PROTOTYPE_POLLUTION  = 1 << 20;
    }
}

impl Default for Cap {
    fn default() -> Self {
        Cap::empty()
    }
}

impl serde::Serialize for Cap {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.bits())
    }
}

impl<'de> serde::Deserialize<'de> for Cap {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Accept any unsigned integer width (existing JSON written with the
        // u16 representation must continue to deserialise into the widened
        // u32 cap field). serde-json hands these through `deserialize_u64`;
        // the truncating cast preserves all currently-defined cap bits.
        let bits = u64::deserialize(d)?;
        Ok(Cap::from_bits_truncate(bits as u32))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    If,
    InfiniteLoop,
    While,
    For,
    CallFn,
    CallMethod,
    CallMacro,
    Break,
    Continue,
    Return,
    Block,
    SourceFile,
    Function,
    Assignment,
    CallWrapper,
    Try,
    Throw,
    /// Multi-way dispatch (switch/match): a discriminant evaluates and routes
    /// control to one of many case bodies. Cases with no terminating jump fall
    /// through to the next case (where the surface language allows). The CFG
    /// builder gives each case body the dispatch header as a predecessor so
    /// reachability does not depend on sibling-case execution order.
    Switch,
    Trivia,
    /// Simple sequential expression (e.g. cast/type-assertion), treated like
    /// any other sequential statement in the CFG but explicitly classified so
    /// code that inspects `Kind` can recognise it.
    Seq,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DataLabel {
    Source(Cap),
    Sanitizer(Cap),
    Sink(Cap),
}

/// Configuration for extracting parameter names from function AST nodes.
pub struct ParamConfig {
    /// Field name on the function node that holds the parameter list
    /// (e.g. "parameters", "formal_parameters").
    pub params_field: &'static str,
    /// Tree-sitter node kinds that represent individual parameters.
    pub param_node_kinds: &'static [&'static str],
    /// Node kinds representing self/this parameters (e.g. "self_parameter" in Rust).
    pub self_param_kinds: &'static [&'static str],
    /// Field names tried in order to extract the identifier from a parameter node.
    pub ident_fields: &'static [&'static str],
}

static DEFAULT_PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["parameter", "identifier"],
    self_param_kinds: &[],
    ident_fields: &["name", "pattern"],
};

/// Describes taint propagation from input arguments to output arguments
/// for known C/C++ functions (e.g., inet_pton copies network address from arg 1 to arg 2).
pub struct ArgPropagation {
    pub callee: &'static str,
    pub from_args: &'static [usize],
    pub to_args: &'static [usize],
}

/// Look up output-parameter positions for Source-labeled C/C++ functions.
/// Returns argument indices that receive taint alongside the return value.
pub fn output_param_source_positions(lang: &str, callee: &str) -> Option<&'static [usize]> {
    let registry: &[(&str, &[usize])] = match lang {
        "c" => c::OUTPUT_PARAM_SOURCES,
        "cpp" => cpp::OUTPUT_PARAM_SOURCES,
        _ => return None,
    };
    let normalized = callee
        .rsplit("::")
        .next()
        .unwrap_or(callee)
        .rsplit('.')
        .next()
        .unwrap_or(callee);
    registry
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(normalized))
        .map(|(_, positions)| *positions)
}

/// Look up arg-to-arg propagation rules for known C/C++ functions.
pub fn arg_propagation(lang: &str, callee: &str) -> Option<&'static ArgPropagation> {
    let registry: &[ArgPropagation] = match lang {
        "c" => c::ARG_PROPAGATIONS,
        "cpp" => cpp::ARG_PROPAGATIONS,
        _ => return None,
    };
    let normalized = callee
        .rsplit("::")
        .next()
        .unwrap_or(callee)
        .rsplit('.')
        .next()
        .unwrap_or(callee);
    registry
        .iter()
        .find(|p| p.callee.eq_ignore_ascii_case(normalized))
}

static REGISTRY: Lazy<HashMap<&'static str, &'static [LabelRule]>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("rust", rust::RULES);
    m.insert("rs", rust::RULES);

    m.insert("javascript", javascript::RULES);
    m.insert("js", javascript::RULES);

    m.insert("typescript", typescript::RULES);
    m.insert("ts", typescript::RULES);

    m.insert("python", python::RULES);
    m.insert("py", python::RULES);

    m.insert("go", go::RULES);

    m.insert("java", java::RULES);

    m.insert("c", c::RULES);

    m.insert("cpp", cpp::RULES);
    m.insert("c++", cpp::RULES);

    m.insert("php", php::RULES);

    m.insert("ruby", ruby::RULES);
    m.insert("rb", ruby::RULES);

    m
});

static GATED_REGISTRY: Lazy<HashMap<&'static str, &'static [SinkGate]>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("javascript", javascript::GATED_SINKS);
    m.insert("js", javascript::GATED_SINKS);
    m.insert("typescript", typescript::GATED_SINKS);
    m.insert("ts", typescript::GATED_SINKS);

    // Python prototype-pollution gates are opt-in: `dict.update(target,
    // src)` overlaps too broadly with non-pollution use of `update`
    // (Counter, namespaced state mutation) to ship as a default sink.
    // The `NYX_PYTHON_PROTO_POLLUTION` env var enables them; when set
    // the merged slice is leaked into a `'static` reference so the
    // registry's lifetime invariant holds.
    let python_gates: &'static [SinkGate] = if env_python_proto_pollution() {
        let mut combined: Vec<SinkGate> = python::GATED_SINKS.to_vec();
        combined.extend_from_slice(python::PROTO_POLLUTION_GATES);
        Box::leak(combined.into_boxed_slice())
    } else {
        python::GATED_SINKS
    };
    m.insert("python", python_gates);
    m.insert("py", python_gates);

    m.insert("go", go::GATED_SINKS);
    m.insert("php", php::GATED_SINKS);
    m.insert("c", c::GATED_SINKS);
    m.insert("cpp", cpp::GATED_SINKS);
    m.insert("c++", cpp::GATED_SINKS);
    m.insert("ruby", ruby::GATED_SINKS);
    m.insert("rb", ruby::GATED_SINKS);
    m.insert("java", java::GATED_SINKS);
    m.insert("rust", rust::GATED_SINKS);
    m.insert("rs", rust::GATED_SINKS);
    m
});

/// Feature flag for the Python prototype-pollution gates.  Disabled by
/// default; set `NYX_PYTHON_PROTO_POLLUTION=1` (or `true`) to enable
/// `dict.update` / `__dict__.update` proto-pollution detection.
fn env_python_proto_pollution() -> bool {
    matches!(
        std::env::var("NYX_PYTHON_PROTO_POLLUTION").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

/// Per-language exclusion patterns: callee text that must never be classified.
static EXCLUDES: Lazy<HashMap<&'static str, &'static [&'static str]>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("javascript", javascript::EXCLUDES);
    m.insert("js", javascript::EXCLUDES);
    m.insert("typescript", typescript::EXCLUDES);
    m.insert("ts", typescript::EXCLUDES);
    m
});

/// Check whether `text` matches a per-language exclusion pattern.
pub(crate) fn is_excluded(lang: &str, trimmed: &[u8]) -> bool {
    let excludes = match EXCLUDES.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        EXCLUDES.get(key.as_str())
    }) {
        Some(e) => *e,
        None => return false,
    };
    for &pat in excludes {
        if match_suffix_cs(trimmed, pat.as_bytes(), false) {
            return true;
        }
    }
    false
}

type FastMap = &'static Map<&'static str, Kind>;

pub(crate) static CLASSIFIERS: Lazy<HashMap<&'static str, FastMap>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("rust", &rust::KINDS);
    m.insert("rs", &rust::KINDS);

    m.insert("javascript", &javascript::KINDS);
    m.insert("js", &javascript::KINDS);

    m.insert("typescript", &typescript::KINDS);
    m.insert("ts", &typescript::KINDS);

    m.insert("python", &python::KINDS);
    m.insert("py", &python::KINDS);

    m.insert("go", &go::KINDS);

    m.insert("java", &java::KINDS);

    m.insert("c", &c::KINDS);

    m.insert("cpp", &cpp::KINDS);
    m.insert("c++", &cpp::KINDS);

    m.insert("php", &php::KINDS);

    m.insert("ruby", &ruby::KINDS);
    m.insert("rb", &ruby::KINDS);

    m
});

static PARAM_CONFIGS: Lazy<HashMap<&'static str, &'static ParamConfig>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("rust", &rust::PARAM_CONFIG);
    m.insert("rs", &rust::PARAM_CONFIG);

    m.insert("javascript", &javascript::PARAM_CONFIG);
    m.insert("js", &javascript::PARAM_CONFIG);

    m.insert("typescript", &typescript::PARAM_CONFIG);
    m.insert("ts", &typescript::PARAM_CONFIG);

    m.insert("python", &python::PARAM_CONFIG);
    m.insert("py", &python::PARAM_CONFIG);

    m.insert("go", &go::PARAM_CONFIG);

    m.insert("java", &java::PARAM_CONFIG);

    m.insert("c", &c::PARAM_CONFIG);

    m.insert("cpp", &cpp::PARAM_CONFIG);
    m.insert("c++", &cpp::PARAM_CONFIG);

    m.insert("php", &php::PARAM_CONFIG);

    m.insert("ruby", &ruby::PARAM_CONFIG);
    m.insert("rb", &ruby::PARAM_CONFIG);

    m
});

/// Return the parameter extraction config for the given language, with a sensible default.
pub fn param_config(lang: &str) -> &'static ParamConfig {
    PARAM_CONFIGS
        .get(lang)
        .copied()
        .unwrap_or(&DEFAULT_PARAM_CONFIG)
}

/// Lowercase names whose use as a JS/TS function parameter strongly suggests
/// the binding carries attacker-controlled input (handler dispatch functions,
/// controller methods, command wrappers).  When the taint engine enters a
/// function whose formal parameter matches one of these names and no caller
/// taint has been supplied, it auto-seeds the parameter as a `UserInput`
/// source so sinks downstream of the parameter still fire.
const JS_TS_HANDLER_PARAM_NAMES: &[&str] = &["userinput", "userid", "payload", "cmd", "input"];

/// Check whether a JS/TS formal parameter name strongly implies user input.
///
/// Matches the curated exact-name list (case-insensitive) *and* any identifier
/// that begins with a `user` prefix followed by an uppercase letter (camelCase)
/// or underscore (snake_case).  The prefix rule captures common handler
/// parameter names such as `userCmd`, `userPath`, `userData`, and `user_input`
/// without broadening into generic words that just contain "user".
pub fn is_js_ts_handler_param_name(name: &str) -> bool {
    if name.is_empty() || !name.is_ascii() {
        return false;
    }
    if JS_TS_HANDLER_PARAM_NAMES
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
    {
        return true;
    }
    // camelCase / snake_case `user*` prefix: requires at least one
    // distinguishing character after the prefix so `user` alone does not match.
    let bytes = name.as_bytes();
    if bytes.len() >= 5
        && bytes[..4].eq_ignore_ascii_case(b"user")
        && (bytes[4].is_ascii_uppercase() || bytes[4] == b'_')
    {
        return true;
    }
    false
}

#[inline(always)]
pub fn lookup(lang: &str, raw: &str) -> Kind {
    CLASSIFIERS
        .get(lang)
        .and_then(|m| m.get(raw).copied())
        .unwrap_or(Kind::Other)
}

/// The kind of taint source, used to refine finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Direct user input (request params, argv, stdin, form data)
    UserInput,
    /// HTTP cookie value (carries session / auth material)
    Cookie,
    /// HTTP request header (may carry auth tokens, user-agent fingerprints)
    Header,
    /// Environment variables and configuration
    EnvironmentConfig,
    /// File system reads
    FileSystem,
    /// Database query results
    Database,
    /// Caught exception, may carry user-controlled data
    CaughtException,
    /// Could not determine, treat conservatively
    Unknown,
}

/// Sensitivity classification of a taint source.  Drives detector classes
/// like `DATA_EXFIL` that only fire when the source carries information
/// the operator did not intend to leak.  Plain user input echoed back into
/// an outbound request is not data exfiltration, the user already controls
/// it, surfacing it as a leak is noise.
///
/// The threshold for `DATA_EXFIL` is `>= Sensitive`, plain user input is
/// suppressed.  Projects that legitimately classify a request body as
/// sensitive (e.g. an API gateway forwarding pre-authenticated user tokens
/// out of a request body) can override via custom rules in `nyx.conf`,
/// either by re-classifying the source or by adding a Sanitizer rule for
/// `Cap::DATA_EXFIL` on the legitimate forwarding path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Sensitivity {
    /// Attacker-controlled but not secret in itself, request bodies, query
    /// strings, form fields, argv.  Echoing this to an outbound request is
    /// not data exfiltration.
    Plain,
    /// Carries operator state the user should not see leak out, cookies,
    /// auth headers, env, file system reads, database rows.
    Sensitive,
    /// Reserved for future explicit secret classifications (API keys,
    /// credential stores, key material).  No source currently produces
    /// this, but the threshold check in `effective_sink_caps` already
    /// handles it monotonically.
    Secret,
}

impl SourceKind {
    /// Return the sensitivity tier this source kind belongs to.  Drives the
    /// `Cap::DATA_EXFIL` cap-suppression decision in `ast.rs`.
    pub fn sensitivity(self) -> Sensitivity {
        match self {
            // Plain user-controlled input, the user already has the data,
            // surfacing it back to them via an outbound request is not a
            // disclosure.
            SourceKind::UserInput => Sensitivity::Plain,
            // Operator-bound state, leaking these via an outbound request
            // is a real cross-boundary disclosure.
            SourceKind::Cookie
            | SourceKind::Header
            | SourceKind::EnvironmentConfig
            | SourceKind::FileSystem
            | SourceKind::Database => Sensitivity::Sensitive,
            // Caught exceptions can carry stack traces, db errors, internal
            // paths, treat them as sensitive by default.
            SourceKind::CaughtException => Sensitivity::Sensitive,
            // Conservative default for unclassified sources, surface
            // findings rather than silently drop them.
            SourceKind::Unknown => Sensitivity::Sensitive,
        }
    }
}

/// Infer the source kind from capabilities and callee name.
pub fn infer_source_kind(caps: Cap, callee: &str) -> SourceKind {
    let cl = callee.to_ascii_lowercase();

    // Cookie / Header are checked *before* the generic user-input bucket
    // because they imply higher sensitivity (auth material, session ids).
    // The generic UserInput substrings (`request`, `header`, `cookie`)
    // would otherwise swallow these.
    //
    // Session stores carry auth material (CSRF tokens, signed user ids) of
    // the same sensitivity tier as raw cookies, so route them through the
    // `Cookie` arm.  The substring is checked AFTER excluding the
    // capitalised `Session` constructor (covered by the `request` /
    // `requests` checks below not firing for `Session` builders).
    if cl.contains("cookie") || cl.contains("session") {
        return SourceKind::Cookie;
    }
    if cl.contains("header") {
        return SourceKind::Header;
    }

    // User input patterns
    if cl.contains("argv")
        || cl.contains("stdin")
        || cl.contains("request")
        || cl.contains("form")
        || cl.contains("query")
        || cl.contains("params")
        || cl.contains("param")
        || cl.contains("input")
        || cl.contains("body")
        || cl.contains("location")
        || cl.contains("document.url")
        || cl.contains("document.referrer")
        // PHP superglobals: the AST text preserves the `$` (member-text
        // extraction reads the `variable_name` node verbatim) so we match
        // both `$_POST` and the `_POST` form some collectors emit.
        // `$_REQUEST` already matches via the `request` substring above;
        // `$_COOKIE` / `$_SESSION` route through the Cookie tier earlier in
        // the function.  `$_SERVER` is operator-state-bearing (auth headers
        // etc.) so it stays Sensitive by falling through to the Unknown
        // bucket.
        || cl == "$_get"
        || cl == "$_post"
        || cl == "$_files"
        || cl == "_get"
        || cl == "_post"
        || cl == "_files"
    {
        return SourceKind::UserInput;
    }

    // Environment / config patterns
    if cl.contains("env")
        || cl.contains("getenv")
        || cl.contains("environ")
        || cl.contains("config")
    {
        return SourceKind::EnvironmentConfig;
    }

    // File system patterns
    if cl.contains("read") || cl.contains("fopen") || cl.contains("open") {
        // Distinguish from db reads, file reads typically have FILE_IO cap
        if caps.contains(Cap::FILE_IO) {
            return SourceKind::FileSystem;
        }
    }

    // Database patterns
    if cl.contains("fetchone")
        || cl.contains("fetchall")
        || cl.contains("fetch_row")
        || cl.contains("query")
        || cl.contains("execute")
    {
        // Queries that read back from db
        return SourceKind::Database;
    }

    SourceKind::Unknown
}

/// Map a source kind to its appropriate severity level.
pub fn severity_for_source_kind(kind: SourceKind) -> crate::patterns::Severity {
    match kind {
        SourceKind::UserInput => crate::patterns::Severity::High,
        SourceKind::Cookie => crate::patterns::Severity::High,
        SourceKind::Header => crate::patterns::Severity::High,
        SourceKind::EnvironmentConfig => crate::patterns::Severity::High,
        SourceKind::FileSystem => crate::patterns::Severity::Medium,
        SourceKind::Database => crate::patterns::Severity::Medium,
        SourceKind::CaughtException => crate::patterns::Severity::Medium,
        SourceKind::Unknown => crate::patterns::Severity::High,
    }
}

/// A runtime (config-derived) label rule with owned matchers.
#[derive(Debug, Clone)]
pub struct RuntimeLabelRule {
    pub matchers: Vec<String>,
    pub label: DataLabel,
    pub case_sensitive: bool,
}

/// Parse a capability name string into a `Cap` bitflag.
///
/// Prefer `CapName` enum for config values; this remains for ad-hoc string parsing.
#[allow(dead_code)]
pub fn parse_cap(s: &str) -> Option<Cap> {
    match s.to_ascii_lowercase().as_str() {
        "env_var" => Some(Cap::ENV_VAR),
        "html_escape" => Some(Cap::HTML_ESCAPE),
        "shell_escape" => Some(Cap::SHELL_ESCAPE),
        "url_encode" => Some(Cap::URL_ENCODE),
        "json_parse" => Some(Cap::JSON_PARSE),
        "file_io" => Some(Cap::FILE_IO),
        "fmt_string" => Some(Cap::FMT_STRING),
        "sql_query" => Some(Cap::SQL_QUERY),
        "deserialize" => Some(Cap::DESERIALIZE),
        "ssrf" => Some(Cap::SSRF),
        "code_exec" => Some(Cap::CODE_EXEC),
        "crypto" => Some(Cap::CRYPTO),
        "unauthorized_id" => Some(Cap::UNAUTHORIZED_ID),
        "data_exfil" | "data_exfiltration" => Some(Cap::DATA_EXFIL),
        "ldap_injection" | "ldapi" => Some(Cap::LDAP_INJECTION),
        "xpath_injection" | "xpathi" => Some(Cap::XPATH_INJECTION),
        "header_injection" | "crlf" | "response_splitting" => Some(Cap::HEADER_INJECTION),
        "open_redirect" | "redirect" => Some(Cap::OPEN_REDIRECT),
        "ssti" | "template_injection" => Some(Cap::SSTI),
        "xxe" => Some(Cap::XXE),
        "prototype_pollution" | "proto_pollution" => Some(Cap::PROTOTYPE_POLLUTION),
        "all" => Some(Cap::all()),
        _ => None,
    }
}

/// Pre-built analysis rules for a specific language, derived from config.
/// Built once per file and threaded through the pipeline.
#[derive(Debug, Clone, Default)]
pub struct LangAnalysisRules {
    pub extra_labels: Vec<RuntimeLabelRule>,
    pub terminators: Vec<String>,
    pub event_handlers: Vec<String>,
    pub frameworks: Vec<crate::utils::project::DetectedFramework>,
}

/// Build `LangAnalysisRules` from a `Config` for a given language slug.
pub fn build_lang_rules(
    config: &crate::utils::config::Config,
    lang_slug: &str,
) -> LangAnalysisRules {
    let mut extra_labels: Vec<RuntimeLabelRule> = Vec::new();
    let mut terminators = Vec::new();
    let mut event_handlers = Vec::new();

    if let Some(lang_cfg) = config.analysis.languages.get(lang_slug) {
        extra_labels.extend(lang_cfg.rules.iter().map(|r| {
            use crate::utils::config::RuleKind;
            let cap = r.cap.to_cap();
            let label = match r.kind {
                RuleKind::Source => DataLabel::Source(cap),
                RuleKind::Sanitizer => DataLabel::Sanitizer(cap),
                RuleKind::Sink => DataLabel::Sink(cap),
            };
            RuntimeLabelRule {
                matchers: r.matchers.clone(),
                label,
                case_sensitive: r.case_sensitive,
            }
        }));
        terminators = lang_cfg.terminators.clone();
        event_handlers = lang_cfg.event_handlers.clone();
    }

    // Append framework-conditional rules when frameworks are detected.
    let frameworks = if let Some(ref fw_ctx) = config.framework_ctx {
        extra_labels.extend(framework_rules_for_lang(lang_slug, fw_ctx));
        fw_ctx.frameworks.clone()
    } else {
        Vec::new()
    };

    // fold `auth_analysis` into the taint engine by injecting
    // `Cap::UNAUTHORIZED_ID` sink/sanitizer rules.  Gated by config; default
    // OFF so the standalone `auth_analysis` subsystem remains authoritative.
    if config.scanner.enable_auth_as_taint {
        extra_labels.extend(phase_c_auth_rules_for_lang(lang_slug));
    }

    LangAnalysisRules {
        extra_labels,
        terminators,
        event_handlers,
        frameworks,
    }
}

/// Return the auth-as-taint rules for a given language (Rust-only).
fn phase_c_auth_rules_for_lang(lang_slug: &str) -> Vec<RuntimeLabelRule> {
    match lang_slug {
        "rust" | "rs" => rust::phase_c_auth_rules(),
        _ => Vec::new(),
    }
}

/// Look up a *receiver-side* validator for the given callee name.
///
/// Returns `Some(cap)` when the callee is registered as a method-call
/// validator that strips `cap` from its receiver (and other call
/// equivalents) on success.  Distinct from the `Sanitizer` label,
/// which clears caps from the *return value*.  Used by the Call
/// transfer to model idioms like `path.relative_to(base)` whose
/// observable effect on data flow is "the receiver is validated"
/// rather than "the return value is sanitised".
pub fn lookup_receiver_validator(lang: &str, callee: &str) -> Option<Cap> {
    let table: &[(&str, Cap)] = match lang {
        "python" | "py" => python::RECEIVER_VALIDATORS,
        _ => return None,
    };
    let head = callee.split(['(', '<']).next().unwrap_or(callee);
    let trimmed = head.trim().as_bytes();
    let normalized = normalize_chained_call(callee);
    let norm = normalized.as_bytes();
    for (name, cap) in table {
        let m = name.as_bytes();
        if match_suffix_cs(trimmed, m, false) || match_suffix_cs(norm, m, false) {
            return Some(*cap);
        }
    }
    None
}

/// Public re-export used by `ParsedFile::from_source` to
/// augment per-file rule sets when imports reveal frameworks that the
/// manifest-level detector missed.
pub fn framework_rules_for_lang_pub(
    lang_slug: &str,
    ctx: &crate::utils::project::FrameworkContext,
) -> Vec<RuntimeLabelRule> {
    framework_rules_for_lang(lang_slug, ctx)
}

/// Return framework-conditional label rules for a given language.
fn framework_rules_for_lang(
    lang_slug: &str,
    ctx: &crate::utils::project::FrameworkContext,
) -> Vec<RuntimeLabelRule> {
    match lang_slug {
        "go" => go::framework_rules(ctx),
        "ruby" | "rb" => ruby::framework_rules(ctx),
        "java" => java::framework_rules(ctx),
        "php" => php::framework_rules(ctx),
        "python" | "py" => python::framework_rules(ctx),
        "rust" | "rs" => rust::framework_rules(ctx),
        "javascript" | "js" => javascript::framework_rules(ctx),
        "typescript" | "ts" => typescript::framework_rules(ctx),
        _ => Vec::new(),
    }
}

/// Suffix check with configurable case sensitivity.
#[inline]
fn ends_with_cs(haystack: &[u8], needle: &[u8], case_sensitive: bool) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let start = haystack.len() - needle.len();
    if case_sensitive {
        haystack[start..] == *needle
    } else {
        haystack[start..]
            .iter()
            .zip(needle)
            .all(|(h, n)| h.eq_ignore_ascii_case(n))
    }
}

/// Prefix check with configurable case sensitivity.  The `=` exact-match
/// sigil is meaningless for prefix matchers (which by definition match many
/// suffixes); it is stripped if present so a malformed matcher like
/// `=foo_` still behaves predictably.
#[inline]
fn starts_with_cs(haystack: &[u8], needle: &[u8], case_sensitive: bool) -> bool {
    let (needle, _) = unpack_matcher(needle);
    if needle.len() > haystack.len() {
        return false;
    }
    if case_sensitive {
        haystack[..needle.len()] == *needle
    } else {
        haystack[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(h, n)| h.eq_ignore_ascii_case(n))
    }
}

/// Word-boundary suffix match with configurable case sensitivity.
#[inline]
fn match_suffix_cs(text: &[u8], matcher: &[u8], case_sensitive: bool) -> bool {
    let (m, exact_only) = unpack_matcher(matcher);
    if ends_with_cs(text, m, case_sensitive) {
        let start = text.len() - m.len();
        if exact_only {
            // `=foo` matchers fire only when `text` IS `foo` (no `Mod.foo`,
            // `Class::foo`, or any preceding namespace).  Lets a label rule
            // distinguish bare `Kernel#open` from `File.open`, the former
            // shells out on `|cmd`, the latter never does (CVE-2020-8130).
            start == 0
        } else {
            start == 0 || matches!(text[start - 1], b'.' | b':')
        }
    } else {
        false
    }
}

/// Strip an optional `=` "exact-match" sigil from the start of a matcher.
/// Matchers prefixed with `=` (e.g. `"=open"`) only fire when the candidate
/// text equals the matcher exactly, the boundary-`.`-or-`:` allowance is
/// suppressed.  Used to distinguish bare-callee Ruby/Python builtins from
/// methods of the same name on a typed receiver.
#[inline]
fn unpack_matcher(matcher: &[u8]) -> (&[u8], bool) {
    if matcher.first() == Some(&b'=') {
        (&matcher[1..], true)
    } else {
        (matcher, false)
    }
}

/// Try to classify a piece of syntax text.
/// `lang` is the canonicalised language key ("rust", "javascript", ...).
///
/// If `extra` runtime rules are provided, they are checked **first** (config
/// takes priority over built-in rules).
///
/// **Two-pass matching** -- exact / suffix matches are checked across *all*
/// rules before any prefix (`foo_`) match is attempted.  This prevents a
/// greedy prefix like `sanitize_` from shadowing a more specific exact
/// match like `sanitize_shell`.
pub fn classify(lang: &str, text: &str, extra: Option<&[RuntimeLabelRule]>) -> Option<DataLabel> {
    let head = text.split(['(', '<']).next().unwrap_or("");
    let trimmed = head.trim().as_bytes();

    // Early out: exclude known-benign framework patterns.
    if is_excluded(lang, trimmed) {
        return None;
    }

    // For chained calls like `r.URL.Query().Get`, also strip internal
    // `().` segments to produce a normalized form like `r.URL.Query.Get`.
    let full_normalized = normalize_chained_call(text);
    let full_norm_bytes = full_normalized.as_bytes();

    // ── Check runtime (config) rules first, they take priority ──────
    if let Some(extras) = extra {
        // Pass 1: exact / suffix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') {
                    continue;
                }
                if match_suffix_cs(trimmed, m, rule.case_sensitive)
                    || match_suffix_cs(full_norm_bytes, m, rule.case_sensitive)
                {
                    return Some(rule.label);
                }
            }
        }
        // Pass 2: prefix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_')
                    && (starts_with_cs(trimmed, m, rule.case_sensitive)
                        || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
                {
                    return Some(rule.label);
                }
            }
        }
    }

    // ── Built-in static rules ────────────────────────────────────────
    let rules = REGISTRY.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        REGISTRY.get(key.as_str())
    })?;

    // Pass 1: exact / suffix matches (high confidence)
    for rule in *rules {
        for raw in rule.matchers {
            let m = raw.as_bytes();
            if m.last() == Some(&b'_') {
                continue;
            }
            if match_suffix_cs(trimmed, m, rule.case_sensitive)
                || match_suffix_cs(full_norm_bytes, m, rule.case_sensitive)
            {
                return Some(rule.label);
            }
        }
    }

    // Pass 2: prefix matches (catch-all, lower priority)
    for rule in *rules {
        for raw in rule.matchers {
            let m = raw.as_bytes();
            if m.last() == Some(&b'_')
                && (starts_with_cs(trimmed, m, rule.case_sensitive)
                    || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
            {
                return Some(rule.label);
            }
        }
    }

    None
}

/// Classify a piece of syntax text, returning **all** matching labels.
///
/// Same two-pass (exact/suffix then prefix) structure as [`classify()`], but
/// collects every match instead of returning on first hit.  Deduplicates
/// exact `(variant, caps)` pairs.
pub fn classify_all(
    lang: &str,
    text: &str,
    extra: Option<&[RuntimeLabelRule]>,
) -> SmallVec<[DataLabel; 2]> {
    let head = text.split(['(', '<']).next().unwrap_or("");
    let trimmed = head.trim().as_bytes();

    // Early out: exclude known-benign framework patterns.
    if is_excluded(lang, trimmed) {
        return SmallVec::new();
    }

    let full_normalized = normalize_chained_call(text);
    let full_norm_bytes = full_normalized.as_bytes();

    let mut out: SmallVec<[DataLabel; 2]> = SmallVec::new();

    // Helper: push if not already present (dedup by variant+caps equality).
    #[inline]
    fn push_dedup(out: &mut SmallVec<[DataLabel; 2]>, label: DataLabel) {
        if !out.contains(&label) {
            out.push(label);
        }
    }

    // ── Check runtime (config) rules first, they take priority ──────
    if let Some(extras) = extra {
        // Pass 1: exact / suffix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') {
                    continue;
                }
                if match_suffix_cs(trimmed, m, rule.case_sensitive)
                    || match_suffix_cs(full_norm_bytes, m, rule.case_sensitive)
                {
                    push_dedup(&mut out, rule.label);
                }
            }
        }
        // Pass 2: prefix
        for rule in extras {
            for raw in &rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_')
                    && (starts_with_cs(trimmed, m, rule.case_sensitive)
                        || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
                {
                    push_dedup(&mut out, rule.label);
                }
            }
        }
    }

    // ── Built-in static rules ────────────────────────────────────────
    let rules = REGISTRY.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        REGISTRY.get(key.as_str())
    });

    if let Some(rules) = rules {
        // Pass 1: exact / suffix matches (high confidence)
        for rule in *rules {
            for raw in rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') {
                    continue;
                }
                if match_suffix_cs(trimmed, m, rule.case_sensitive)
                    || match_suffix_cs(full_norm_bytes, m, rule.case_sensitive)
                {
                    push_dedup(&mut out, rule.label);
                }
            }
        }

        // Pass 2: prefix matches (catch-all, lower priority)
        for rule in *rules {
            for raw in rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_')
                    && (starts_with_cs(trimmed, m, rule.case_sensitive)
                        || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
                {
                    push_dedup(&mut out, rule.label);
                }
            }
        }
    }

    out
}

/// Result of a gated-sink classification.
///
/// `label` is the sink capability the callee contributes at this site.
/// `payload_args` identifies positional args that carry the tainted payload
/// (or [`ALL_ARGS_PAYLOAD`] for dynamic-activation conservative fallback).
/// `object_destination_fields`, when non-empty, restricts sink-taint checks
/// to identifiers found under those field names within an object-literal
/// positional argument, used by destination-aware outbound-HTTP gates so
/// `fetch({url, body})` fires only when taint reaches `url`, not `body`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateMatch {
    pub label: DataLabel,
    pub payload_args: &'static [usize],
    pub object_destination_fields: &'static [&'static str],
}

/// Classify a call against gated sink rules.
///
/// Returns every gate whose callee matches AND whose activation conditions
/// fire.  An empty result means the callee did not match any gated rule, or
/// every match was provably safe.  Multiple matches are possible when the
/// same callee carries gates for different sink classes, e.g. `fetch` is
/// both an SSRF gate (URL flow) and a `DATA_EXFIL` gate (body / headers /
/// json flow); each gate carries its own [`GateMatch`] so downstream code
/// can attribute findings per-cap.
///
/// `const_arg_at` extracts positional argument values.
/// `const_keyword_arg` extracts keyword argument values (for languages like Python).
pub fn classify_gated_sink(
    lang: &str,
    callee_text: &str,
    const_arg_at: impl Fn(usize) -> Option<String>,
    const_keyword_arg: impl Fn(&str) -> Option<String>,
    kwarg_present: impl Fn(&str) -> bool,
) -> SmallVec<[GateMatch; 2]> {
    let mut out: SmallVec<[GateMatch; 2]> = SmallVec::new();
    let gates = match GATED_REGISTRY.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        GATED_REGISTRY.get(key.as_str())
    }) {
        Some(g) => g,
        None => return out,
    };

    // Match against the original callee text AND a chain-normalised form
    // that strips `()` between dots so a chained construction like
    // `httpx.AsyncClient().post` matches a gate matcher of
    // `httpx.AsyncClient.post`.  Mirrors the normalisation applied by
    // `classify` for flat label rules.
    let callee_bytes = callee_text.as_bytes();
    let normalized = normalize_chained_call(callee_text);
    let normalized_bytes = normalized.as_bytes();

    for gate in *gates {
        let matcher = gate.callee_matcher.as_bytes();
        if !match_suffix_cs(callee_bytes, matcher, gate.case_sensitive)
            && !match_suffix_cs(normalized_bytes, matcher, gate.case_sensitive)
        {
            continue;
        }

        // Destination-flow activation: always fires.  Downstream filters sink
        // taint checks to `payload_args` (and, for object-literal args, further
        // to `object_destination_fields`).
        if let GateActivation::Destination {
            object_destination_fields,
        } = gate.activation
        {
            out.push(GateMatch {
                label: gate.label,
                payload_args: gate.payload_args,
                object_destination_fields,
            });
            continue;
        }

        // ── ValueMatch activation (legacy) ───────────────────────────────

        // Multi-kwarg gate path.  Takes precedence over positional / single-kwarg
        // inspection when populated.  Semantics are presence-aware: an absent
        // kwarg is treated as the language default (safe) and does not alone
        // activate the gate.
        if !gate.dangerous_kwargs.is_empty() && gate.keyword_name.is_none() {
            let mut any_dangerous = false;
            let mut any_dynamic_present = false;
            for (name, values) in gate.dangerous_kwargs {
                if !kwarg_present(name) {
                    continue; // absent → takes language default (safe)
                }
                match const_keyword_arg(name) {
                    Some(v) => {
                        let lower = v.to_ascii_lowercase();
                        if values.iter().any(|dv| lower == dv.to_ascii_lowercase()) {
                            any_dangerous = true;
                            break;
                        }
                        // Present with a safe literal, continue checking other kwargs.
                    }
                    None => {
                        any_dynamic_present = true;
                    }
                }
            }
            if any_dangerous {
                out.push(GateMatch {
                    label: gate.label,
                    payload_args: gate.payload_args,
                    object_destination_fields: &[],
                });
                continue;
            }
            if any_dynamic_present {
                // Dynamic kwarg value, we can't prove safe. Conservatively
                // flag every positional arg so the activation pathway isn't
                // silently narrowed to the gate's declared `payload_args`.
                out.push(GateMatch {
                    label: gate.label,
                    payload_args: ALL_ARGS_PAYLOAD,
                    object_destination_fields: &[],
                });
                continue;
            }
            continue; // all listed kwargs absent or safe-literal → suppress
        }

        // Single-kwarg / positional gate path (original semantics).
        let activation_value = if let Some(kw) = gate.keyword_name {
            const_keyword_arg(kw)
        } else {
            const_arg_at(gate.arg_index)
        };

        match activation_value {
            Some(value) => {
                let lower = value.to_ascii_lowercase();
                let is_dangerous = gate
                    .dangerous_values
                    .iter()
                    .any(|v| lower == v.to_ascii_lowercase())
                    || gate
                        .dangerous_prefixes
                        .iter()
                        .any(|p| lower.starts_with(&p.to_ascii_lowercase()));
                if is_dangerous {
                    out.push(GateMatch {
                        label: gate.label,
                        payload_args: gate.payload_args,
                        object_destination_fields: &[],
                    });
                }
                // safe constant → suppress (no push)
            }
            // Unknown / dynamic activation arg: the gate fires conservatively,
            // but we can't prove that only the declared `payload_args` carry
            // risk, a tainted activation arg (e.g. `setAttribute(userAttr, …)`
            // where `userAttr` is user-controlled) is itself a vulnerability
            // path. Return ALL_ARGS_PAYLOAD so downstream sink scanning
            // considers every positional argument.
            None => {
                out.push(GateMatch {
                    label: gate.label,
                    payload_args: ALL_ARGS_PAYLOAD,
                    object_destination_fields: &[],
                });
            }
        }
    }
    out
}

/// Public wrapper for `normalize_chained_call` so callers outside the module
/// can share the same normalization used by the label classifier.
pub fn normalize_chained_call_for_classify(text: &str) -> String {
    normalize_chained_call(text)
}

/// Return the bare method-name segment of a callee text. Returns the
/// input unchanged for bare callees. When you have an `SsaOp::Call`,
/// prefer reading `callee` directly and walking `receiver` through
/// `FieldProj` ops, this helper is the textual fallback for callsites
/// that only see a `&str`.
pub fn bare_method_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

/// Normalize a chained method call: strip `()` between `.` segments.
/// e.g. `r.URL.Query().Get` → `r.URL.Query.Get`
/// e.g. `r.URL.Query().Get("host")` → `r.URL.Query.Get`
fn normalize_chained_call(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                // Skip from `(` to matching `)`, but only if followed by `.`
                // This handles `Query().Get` → `Query.Get`
                let mut depth = 1u32;
                let mut j = i + 1;
                while j < bytes.len() && depth > 0 {
                    if bytes[j] == b'(' {
                        depth += 1;
                    } else if bytes[j] == b')' {
                        depth -= 1;
                    }
                    j += 1;
                }
                // If we're at end or next char is `.`, skip the parens
                if j >= bytes.len() || bytes[j] == b'.' {
                    i = j;
                } else {
                    // Keep the paren content (unusual case)
                    result.push('(');
                    i += 1;
                }
            }
            b'<' => break, // Stop at generic args
            _ => {
                result.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    result
}

// ── Rule enumeration ─────────────────────────────────────────────────────────

/// All canonical language slugs (no aliases).
const CANONICAL_LANGS: &[&str] = &[
    "javascript",
    "typescript",
    "python",
    "go",
    "java",
    "c",
    "cpp",
    "php",
    "ruby",
    "rust",
];

/// Map alias slugs to canonical language name.
pub fn canonical_lang(slug: &str) -> &str {
    // Check exact matches first (fast path, no allocation)
    match slug {
        "javascript" | "js" => "javascript",
        "typescript" | "ts" => "typescript",
        "python" | "py" => "python",
        "go" => "go",
        "java" => "java",
        "c" => "c",
        "cpp" | "c++" => "cpp",
        "php" => "php",
        "ruby" | "rb" => "ruby",
        "rust" | "rs" => "rust",
        // For unknown slugs, return as-is (the caller's borrow keeps it alive)
        _ => slug,
    }
}

/// Human-readable name for a Cap bitflag value.
pub fn cap_to_name(cap: Cap) -> &'static str {
    if cap == Cap::all() {
        return "all";
    }
    match cap {
        Cap::ENV_VAR => "env_var",
        Cap::HTML_ESCAPE => "html_escape",
        Cap::SHELL_ESCAPE => "shell_escape",
        Cap::URL_ENCODE => "url_encode",
        Cap::JSON_PARSE => "json_parse",
        Cap::FILE_IO => "file_io",
        Cap::FMT_STRING => "fmt_string",
        Cap::SQL_QUERY => "sql_query",
        Cap::DESERIALIZE => "deserialize",
        Cap::SSRF => "ssrf",
        Cap::CODE_EXEC => "code_exec",
        Cap::CRYPTO => "crypto",
        Cap::UNAUTHORIZED_ID => "unauthorized_id",
        Cap::DATA_EXFIL => "data_exfil",
        Cap::LDAP_INJECTION => "ldap_injection",
        Cap::XPATH_INJECTION => "xpath_injection",
        Cap::HEADER_INJECTION => "header_injection",
        Cap::OPEN_REDIRECT => "open_redirect",
        Cap::SSTI => "ssti",
        Cap::XXE => "xxe",
        Cap::PROTOTYPE_POLLUTION => "prototype_pollution",
        _ => "unknown",
    }
}

// ── Cap rule registry ────────────────────────────────────────────────────
//
// Static, single-source-of-truth metadata table keyed by [`Cap`].  Every
// vulnerability class with its own canonical rule id appears here; the
// per-language `RULES` arrays only carry the language-specific match shapes.
// Sink-cap fields on a finding (or `Cap::DATA_EXFIL` carried alongside) feed
// `cap_rule_meta()` to pick the rule id surfaced to SARIF, the dashboard,
// and `enumerate_builtin_rules()` for `nyx rules list`.

/// Static metadata for one cap-defined vulnerability class.
#[derive(Debug, Clone, Copy)]
pub struct CapRuleMeta {
    pub cap: Cap,
    /// Canonical rule id surfaced by finding emission (no source-suffix).
    pub rule_id: &'static str,
    /// Display title for `nyx rules list` and dashboard.
    pub title: &'static str,
    pub severity: crate::patterns::Severity,
    /// OWASP 2021 code (e.g. `"A03"`).
    pub owasp_code: &'static str,
    /// OWASP 2021 long label (e.g. `"Injection"`).
    pub owasp_label: &'static str,
    pub description: &'static str,
    /// `false` only for caps gated behind a config flag (e.g.
    /// `Cap::UNAUTHORIZED_ID`, which still defers to the standalone
    /// `auth_analysis` subsystem unless `enable_auth_as_taint` is on).
    pub default_enabled: bool,
    /// Whether the diag-id emission path in `ast.rs` actually surfaces
    /// findings under [`Self::rule_id`].  When `false`, sink findings
    /// for this cap currently surface under the legacy
    /// `taint-unsanitised-flow` id (the per-language family-token
    /// dispatch in [`crate::server::owasp::owasp_bucket_for`] still
    /// buckets them correctly).  Dashboards and `nyx rules list` consume
    /// this flag to decide whether to surface the synthetic class entry
    /// alongside live findings or hide it as forward-declared.
    ///
    /// Migrating a cap from `false` → `true` requires adding it to the
    /// cap-specific routing list in `ast.rs::diag_for_finding`; tests
    /// that pin the legacy `taint-unsanitised-flow` rule id for that
    /// cap must be updated to the cap-specific id.
    pub emission_active: bool,
}

/// Registry of cap-class metadata.  Keyed in cap-bit order so additions
/// stay clustered with their bitflag declarations.
pub static CAP_RULE_REGISTRY: &[CapRuleMeta] = &[
    CapRuleMeta {
        cap: Cap::FILE_IO,
        rule_id: "taint-path-traversal",
        title: "Path Traversal / Arbitrary File Access",
        severity: crate::patterns::Severity::High,
        owasp_code: "A01",
        owasp_label: "Broken Access Control",
        description:
            "Attacker-controlled data flows into a filesystem path without canonicalisation \
             or root-confinement, allowing reads or writes outside the intended directory.",
        default_enabled: true,
        emission_active: false,
    },
    CapRuleMeta {
        cap: Cap::FMT_STRING,
        rule_id: "taint-format-string",
        title: "Format String Injection",
        severity: crate::patterns::Severity::High,
        owasp_code: "A03",
        owasp_label: "Injection",
        description:
            "Attacker-controlled data is used as a format string argument (printf-family, \
             String.format) and can leak memory or crash the process.",
        default_enabled: true,
        emission_active: false,
    },
    CapRuleMeta {
        cap: Cap::SQL_QUERY,
        rule_id: "taint-sql-injection",
        title: "SQL Injection",
        severity: crate::patterns::Severity::High,
        owasp_code: "A03",
        owasp_label: "Injection",
        description:
            "Attacker-controlled data is concatenated into a SQL query string instead of \
             being bound through a parameterised statement.",
        default_enabled: true,
        emission_active: false,
    },
    CapRuleMeta {
        cap: Cap::DESERIALIZE,
        rule_id: "taint-deserialization",
        title: "Unsafe Deserialization",
        severity: crate::patterns::Severity::High,
        owasp_code: "A08",
        owasp_label: "Software and Data Integrity Failures",
        description:
            "Attacker-controlled bytes are fed to an unsafe object deserialiser \
             (pickle, ObjectInputStream, Marshal, unserialize) enabling arbitrary code \
             execution via crafted payloads.",
        default_enabled: true,
        emission_active: false,
    },
    CapRuleMeta {
        cap: Cap::SSRF,
        rule_id: "taint-ssrf",
        title: "Server-Side Request Forgery",
        severity: crate::patterns::Severity::High,
        owasp_code: "A10",
        owasp_label: "Server-Side Request Forgery",
        description:
            "Attacker-controlled URL reaches the destination of an outbound HTTP request \
             without an allowlist or scheme/host restriction.",
        default_enabled: true,
        emission_active: false,
    },
    CapRuleMeta {
        cap: Cap::CODE_EXEC,
        rule_id: "taint-code-execution",
        title: "Code / Command Execution",
        severity: crate::patterns::Severity::High,
        owasp_code: "A03",
        owasp_label: "Injection",
        description:
            "Attacker-controlled data reaches an `eval`/`exec`/shell sink, dynamic \
             require/import, or other arbitrary-code construct.",
        default_enabled: true,
        emission_active: false,
    },
    CapRuleMeta {
        cap: Cap::CRYPTO,
        rule_id: "taint-crypto-misuse",
        title: "Tainted Cryptographic Parameter",
        severity: crate::patterns::Severity::Medium,
        owasp_code: "A02",
        owasp_label: "Cryptographic Failures",
        description:
            "Attacker-controlled data drives the algorithm name, key, or seed of a \
             cryptographic primitive (weak-crypto / predictable-randomness).",
        default_enabled: true,
        emission_active: false,
    },
    CapRuleMeta {
        cap: Cap::UNAUTHORIZED_ID,
        rule_id: "rs.auth.missing_ownership_check.taint",
        title: "Missing Ownership Check (taint variant)",
        severity: crate::patterns::Severity::High,
        owasp_code: "A01",
        owasp_label: "Broken Access Control",
        description:
            "Request-bound identifier reaches a privileged sink without an intervening \
             ownership/membership check.  Companion to the standalone `auth_analysis` \
             rule; gated by `scanner.enable_auth_as_taint`.",
        default_enabled: false,
        emission_active: true,
    },
    CapRuleMeta {
        cap: Cap::DATA_EXFIL,
        rule_id: "taint-data-exfiltration",
        title: "Sensitive Data Exfiltration",
        severity: crate::patterns::Severity::High,
        owasp_code: "A04",
        owasp_label: "Insecure Design",
        description:
            "Sensitive data (cookies, headers, env, db rows, files) flows into the body, \
             headers, or other payload field of an outbound network request to a fixed \
             destination.",
        default_enabled: true,
        emission_active: true,
    },
    // ── New cap classes (Phase 01) ────────────────────────────────────────
    CapRuleMeta {
        cap: Cap::LDAP_INJECTION,
        rule_id: "taint-ldap-injection",
        title: "LDAP Injection",
        severity: crate::patterns::Severity::High,
        owasp_code: "A03",
        owasp_label: "Injection",
        description:
            "Attacker-controlled data is concatenated into an LDAP filter or DN without \
             RFC 4515 escaping, letting the attacker rewrite the directory query.",
        default_enabled: true,
        emission_active: true,
    },
    CapRuleMeta {
        cap: Cap::XPATH_INJECTION,
        rule_id: "taint-xpath-injection",
        title: "XPath Injection",
        severity: crate::patterns::Severity::High,
        owasp_code: "A03",
        owasp_label: "Injection",
        description:
            "Attacker-controlled data is concatenated into an XPath expression instead of \
             passed through XPath variable bindings, letting the attacker rewrite the \
             query.",
        default_enabled: true,
        emission_active: true,
    },
    CapRuleMeta {
        cap: Cap::HEADER_INJECTION,
        rule_id: "taint-header-injection",
        title: "HTTP Header / Response Splitting",
        severity: crate::patterns::Severity::High,
        owasp_code: "A03",
        owasp_label: "Injection",
        description:
            "Attacker-controlled data lands in an HTTP response header without `\\r\\n` \
             stripping, enabling response splitting and cache-poisoning attacks.",
        default_enabled: true,
        emission_active: true,
    },
    CapRuleMeta {
        cap: Cap::OPEN_REDIRECT,
        rule_id: "taint-open-redirect",
        title: "Open Redirect",
        severity: crate::patterns::Severity::Medium,
        owasp_code: "A01",
        owasp_label: "Broken Access Control",
        description:
            "Attacker-controlled URL drives a redirect / `Location` header without an \
             allowlist or relative-URL check, enabling phishing pivots.",
        default_enabled: true,
        emission_active: true,
    },
    CapRuleMeta {
        cap: Cap::SSTI,
        rule_id: "taint-template-injection",
        title: "Server-Side Template Injection",
        severity: crate::patterns::Severity::High,
        owasp_code: "A03",
        owasp_label: "Injection",
        description:
            "Attacker controls the template *source string* (not just template variables) \
             passed to a server-side renderer (Jinja2, Twig, Handlebars, ERB), enabling \
             arbitrary expression evaluation.",
        default_enabled: true,
        emission_active: true,
    },
    CapRuleMeta {
        cap: Cap::XXE,
        rule_id: "taint-xxe",
        title: "XML External Entity Resolution",
        severity: crate::patterns::Severity::High,
        owasp_code: "A05",
        owasp_label: "Security Misconfiguration",
        description:
            "Attacker-controlled XML reaches a parser configured to resolve external \
             entities (or missing the secure-processing feature), enabling SSRF, file \
             read, and DoS.",
        default_enabled: true,
        emission_active: true,
    },
    CapRuleMeta {
        cap: Cap::PROTOTYPE_POLLUTION,
        rule_id: "taint-prototype-pollution",
        title: "Prototype Pollution",
        severity: crate::patterns::Severity::High,
        owasp_code: "A05",
        owasp_label: "Security Misconfiguration",
        description:
            "Attacker-controlled key reaches an object property assignment that can mutate \
             `Object.prototype` (deep-merge / `__proto__` / dynamic subscript).",
        default_enabled: true,
        emission_active: true,
    },
];

/// Resolve a cap to its canonical rule metadata.  Returns `None` for caps
/// without a rule-emission role (origin / sanitizer markers like
/// [`Cap::ENV_VAR`], [`Cap::HTML_ESCAPE`]).
pub fn cap_rule_meta(cap: Cap) -> Option<&'static CapRuleMeta> {
    CAP_RULE_REGISTRY.iter().find(|m| m.cap == cap)
}

/// Resolve any subset of `effective_caps` to a single rule id.  When
/// multiple bits are set, picks the first registry entry that intersects
/// (registry order is bit-position).  Returns `None` when no bit in the
/// set has a registered rule id.
pub fn rule_id_for_caps(effective_caps: Cap) -> Option<&'static str> {
    CAP_RULE_REGISTRY
        .iter()
        .find(|m| effective_caps.contains(m.cap))
        .map(|m| m.rule_id)
}

/// Generate a stable rule ID from language, kind, and matchers.
pub fn rule_id(lang: &str, kind: &str, matchers: &[&str]) -> String {
    let mut sorted: Vec<&str> = matchers.to_vec();
    sorted.sort_unstable();
    let joined = sorted.join("\0");
    let hash = blake3::hash(joined.as_bytes());
    let hex = hash.to_hex();
    format!("{}.{}.{}", lang, kind, &hex[..8])
}

/// Metadata-enriched view of a label rule (built-in or custom).
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub title: String,
    pub language: String,
    pub kind: String,
    pub cap: String,
    pub cap_bits: u32,
    pub matchers: Vec<String>,
    pub case_sensitive: bool,
    pub is_custom: bool,
    pub is_gated: bool,
    /// Cap-class registry entry (one per `Cap` with a canonical rule id),
    /// distinct from per-language sink/source/sanitizer match rules.  The
    /// dashboard groups these separately so the rules surface does not mix
    /// "the LDAP injection class exists" with "Java's `DirContext.search`
    /// is a sink for that class".
    pub is_class: bool,
    /// For class entries (`is_class == true`), whether the diag-id
    /// emission path in `ast.rs` actually surfaces findings under
    /// [`Self::id`].  When `false`, the class is registered but live
    /// findings still emerge under the legacy `taint-unsanitised-flow`
    /// rule id; dashboards can use this flag to suppress the synthetic
    /// entry until the cap is migrated to its specific rule id.
    /// Always `true` for non-class label rules.
    pub emission_active: bool,
    pub enabled: bool,
}

/// Enumerate all built-in rules across all languages.
pub fn enumerate_builtin_rules() -> Vec<RuleInfo> {
    let mut out = Vec::new();

    // Cap-class entries (one per registered vulnerability class). Kind
    // `class` so dashboards can distinguish them from per-language
    // sink/source/sanitizer entries.
    for meta in CAP_RULE_REGISTRY {
        out.push(RuleInfo {
            id: meta.rule_id.to_string(),
            title: meta.title.to_string(),
            language: "all".to_string(),
            kind: "class".to_string(),
            cap: cap_to_name(meta.cap).to_string(),
            cap_bits: meta.cap.bits(),
            matchers: Vec::new(),
            case_sensitive: false,
            is_custom: false,
            is_gated: false,
            is_class: true,
            emission_active: meta.emission_active,
            enabled: meta.default_enabled,
        });
    }

    for &lang in CANONICAL_LANGS {
        if let Some(rules) = REGISTRY.get(lang) {
            for rule in *rules {
                let (kind_str, cap) = match rule.label {
                    DataLabel::Source(c) => ("source", c),
                    DataLabel::Sanitizer(c) => ("sanitizer", c),
                    DataLabel::Sink(c) => ("sink", c),
                };
                let matchers_strs: Vec<&str> = rule.matchers.to_vec();
                let id = rule_id(lang, kind_str, &matchers_strs);
                let first = rule.matchers.first().copied().unwrap_or("?");
                let title = format!("{} ({})", first, kind_str);
                out.push(RuleInfo {
                    id,
                    title,
                    language: lang.to_string(),
                    kind: kind_str.to_string(),
                    cap: cap_to_name(cap).to_string(),
                    cap_bits: cap.bits(),
                    matchers: rule.matchers.iter().map(|s| s.to_string()).collect(),
                    case_sensitive: rule.case_sensitive,
                    is_custom: false,
                    is_gated: false,
                    is_class: false,
                    emission_active: true,
                    enabled: true,
                });
            }
        }

        // Include gated sink entries
        if let Some(gates) = GATED_REGISTRY.get(lang) {
            for gate in *gates {
                let cap = match gate.label {
                    DataLabel::Source(c) | DataLabel::Sanitizer(c) | DataLabel::Sink(c) => c,
                };
                let kind_str = "sink";
                let matchers_strs = &[gate.callee_matcher];
                let id = rule_id(lang, &format!("gated_{}", kind_str), matchers_strs);
                let title = format!("{} (gated {})", gate.callee_matcher, kind_str);
                out.push(RuleInfo {
                    id,
                    title,
                    language: lang.to_string(),
                    kind: kind_str.to_string(),
                    cap: cap_to_name(cap).to_string(),
                    cap_bits: cap.bits(),
                    matchers: vec![gate.callee_matcher.to_string()],
                    case_sensitive: gate.case_sensitive,
                    is_custom: false,
                    is_gated: true,
                    is_class: false,
                    emission_active: true,
                    enabled: true,
                });
            }
        }
    }

    out
}

/// Generate a custom rule ID with `custom.` prefix.
pub fn custom_rule_id(lang: &str, kind: &str, matchers: &[String]) -> String {
    let refs: Vec<&str> = matchers.iter().map(|s| s.as_str()).collect();
    format!("custom.{}", rule_id(lang, kind, &refs))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the current set of caps whose `rule_id` is reachable via the
    /// diag-id routing in `ast.rs::diag_for_finding`.  When migrating a
    /// legacy cap (e.g. SQL_QUERY → `taint-sql-injection`), update both
    /// `ast.rs` (add the cap to the cap-specific routing list) and the
    /// `emission_active: true` flag in `CAP_RULE_REGISTRY`, then update
    /// this assertion.  The split exists because legacy taint findings
    /// historically all surfaced under the generic `taint-unsanitised-flow`
    /// rule id; phase-01 introduced cap-specific routing for new classes
    /// only.
    #[test]
    fn cap_rule_registry_emission_active_set_is_pinned() {
        let active: Vec<Cap> = CAP_RULE_REGISTRY
            .iter()
            .filter(|m| m.emission_active)
            .map(|m| m.cap)
            .collect();
        let expected = [
            Cap::UNAUTHORIZED_ID,
            Cap::DATA_EXFIL,
            Cap::LDAP_INJECTION,
            Cap::XPATH_INJECTION,
            Cap::HEADER_INJECTION,
            Cap::OPEN_REDIRECT,
            Cap::SSTI,
            Cap::XXE,
            Cap::PROTOTYPE_POLLUTION,
        ];
        for c in expected {
            assert!(
                active.contains(&c),
                "cap {:?} expected to be emission_active in CAP_RULE_REGISTRY",
                c
            );
        }
        let inactive: Vec<Cap> = CAP_RULE_REGISTRY
            .iter()
            .filter(|m| !m.emission_active)
            .map(|m| m.cap)
            .collect();
        let expected_inactive = [
            Cap::FILE_IO,
            Cap::FMT_STRING,
            Cap::SQL_QUERY,
            Cap::DESERIALIZE,
            Cap::SSRF,
            Cap::CODE_EXEC,
            Cap::CRYPTO,
        ];
        for c in expected_inactive {
            assert!(
                inactive.contains(&c),
                "cap {:?} expected to be emission_inactive in CAP_RULE_REGISTRY (legacy \
                 finding still emits as taint-unsanitised-flow)",
                c
            );
        }
    }

    #[test]
    fn receiver_validator_python_relative_to() {
        // Bare method name fires.
        assert_eq!(
            lookup_receiver_validator("python", "relative_to"),
            Some(Cap::FILE_IO)
        );
        // Dotted-method-call form (chained receiver).
        assert_eq!(
            lookup_receiver_validator("python", "filepath.relative_to"),
            Some(Cap::FILE_IO)
        );
        // Other languages without a registry entry return None.
        assert_eq!(lookup_receiver_validator("rust", "relative_to"), None);
        assert_eq!(lookup_receiver_validator("javascript", "relative_to"), None);
        // Unrelated callees return None.
        assert_eq!(lookup_receiver_validator("python", "resolve"), None);
        assert_eq!(lookup_receiver_validator("python", "joinpath"), None);
    }

    #[test]
    fn bare_method_name_strips_chain() {
        // No-dot input → returned as-is.
        assert_eq!(bare_method_name("foo"), "foo");
        // 1-dot → trailing segment.
        assert_eq!(bare_method_name("obj.method"), "method");
        // Multi-dot → trailing segment.
        assert_eq!(bare_method_name("a.b.c.method"), "method");
        // Trailing dot → empty trailing segment.
        assert_eq!(bare_method_name("foo."), "");
        // Empty input.
        assert_eq!(bare_method_name(""), "");
        // SSA-decomposed chains pass through untouched.
        assert_eq!(bare_method_name("Lock"), "Lock");
    }

    #[test]
    fn handler_param_names_exact_and_prefix() {
        // Exact names still match.
        assert!(is_js_ts_handler_param_name("cmd"));
        assert!(is_js_ts_handler_param_name("input"));
        assert!(is_js_ts_handler_param_name("userId"));
        assert!(is_js_ts_handler_param_name("USERID"));
        // camelCase `user*` prefix.
        assert!(is_js_ts_handler_param_name("userCmd"));
        assert!(is_js_ts_handler_param_name("userData"));
        assert!(is_js_ts_handler_param_name("userPath"));
        // snake_case prefix.
        assert!(is_js_ts_handler_param_name("user_cmd"));
        // Bare `user` does not match (no distinguishing suffix).
        assert!(!is_js_ts_handler_param_name("user"));
        assert!(!is_js_ts_handler_param_name("userx"));
        // Other names unaffected.
        assert!(!is_js_ts_handler_param_name("url"));
        assert!(!is_js_ts_handler_param_name("value"));
    }

    #[test]
    fn classify_none_extra_unchanged() {
        // Built-in rule: innerHTML → Sink(HTML_ESCAPE)
        let result = classify("javascript", "innerHTML", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::HTML_ESCAPE)));

        // Non-existent should still be None
        let result = classify("javascript", "myCustomFunc", None);
        assert_eq!(result, None);
    }

    #[test]
    fn classify_extra_rules_take_priority() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["escapeHtml".into()],
            label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
            case_sensitive: false,
        }];

        let result = classify("javascript", "escapeHtml", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE)));

        // Built-in rules still work
        let result = classify("javascript", "innerHTML", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sink(Cap::HTML_ESCAPE)));
    }

    #[test]
    fn classify_extra_overrides_builtin() {
        // Override innerHTML to be a sanitizer (contrived but tests priority)
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["innerHTML".into()],
            label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
            case_sensitive: false,
        }];

        let result = classify("javascript", "innerHTML", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE)));
    }

    #[test]
    fn classify_location_href_is_sink() {
        let result = classify("javascript", "location.href", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::URL_ENCODE)));
    }

    #[test]
    fn classify_bare_href_is_none() {
        // Bare "href" should NOT be a sink, only "location.href" and variants
        let result = classify("javascript", "href", None);
        assert_eq!(result, None);
    }

    #[test]
    fn classify_case_insensitive_is_default() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["myCustomSink".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        }];
        // Default case_sensitive=false: case-insensitive match
        let result = classify("javascript", "MYCUSTOMSINK", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sink(Cap::HTML_ESCAPE)));
    }

    #[test]
    fn classify_case_sensitive_exact_match() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["MyExactSink".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: true,
        }];
        // Exact case matches
        let result = classify("javascript", "MyExactSink", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sink(Cap::HTML_ESCAPE)));
        // Wrong case does NOT match
        let result = classify("javascript", "myexactsink", Some(&extras));
        assert_eq!(result, None);
    }

    #[test]
    fn classify_case_sensitive_prefix() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["Sanitize_".into()],
            label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
            case_sensitive: true,
        }];
        // Correct case prefix matches
        let result = classify("javascript", "Sanitize_input", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE)));
        // Wrong case does NOT match
        let result = classify("javascript", "sanitize_input", Some(&extras));
        assert_eq!(result, None);
    }

    // CVE Hunt Session 2 (Go CVE-2024-31450 Owncast path traversal):
    // mutating filesystem helpers (`os.Remove`, `os.WriteFile`,
    // `os.RemoveAll`, `ioutil.WriteFile`) sink path-traversal flows that
    // the prior Go ruleset only saw on the read side (`os.Open`,
    // `os.ReadFile`).
    #[test]
    fn classify_go_os_remove_is_file_io_sink() {
        let result = classify("go", "os.Remove", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::FILE_IO)));
    }

    #[test]
    fn classify_go_os_write_file_is_file_io_sink() {
        let result = classify("go", "os.WriteFile", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::FILE_IO)));
    }

    #[test]
    fn classify_go_os_remove_all_is_file_io_sink() {
        let result = classify("go", "os.RemoveAll", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::FILE_IO)));
    }

    // CVE Hunt Session 6 (Go CVE-2026-41422 daptin SQL injection): goqu's
    // raw SQL literal builders `goqu.L(s)` / `goqu.Lit(s)` insert `s`
    // verbatim into the generated query.  Modeled by name as SQL_QUERY
    // sinks; the safe siblings `goqu.I` (identifier), `goqu.C`, `goqu.T`,
    // `goqu.V`, `goqu.SUM`, `goqu.COUNT`, etc. are typed and stay
    // unlabeled.
    #[test]
    fn classify_go_goqu_l_is_sql_query_sink() {
        let result = classify("go", "goqu.L", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::SQL_QUERY)));
    }

    #[test]
    fn classify_go_goqu_lit_is_sql_query_sink() {
        let result = classify("go", "goqu.Lit", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::SQL_QUERY)));
    }

    #[test]
    fn classify_go_goqu_i_is_not_sink() {
        let result = classify("go", "goqu.I", None);
        assert_eq!(result, None);
    }

    // CVE Hunt Session 2 (Go CVE-2023-3188 Owncast SSRF):
    // `http.DefaultClient.Get/Post/Head/Do/PostForm` is the idiomatic Go
    // SSRF sink shape (`http.DefaultClient` is the package-level shared
    // `*http.Client`).  These callees migrated from a flat `Sink(SSRF)`
    // rule to destination-aware gated sinks so that DATA_EXFIL gates can
    // coexist on the same callee (e.g. `http.DefaultClient.Post(url, _,
    // body)` carries SSRF on arg 0 and DATA_EXFIL on arg 2).  The
    // assertions below check the gate registration rather than the flat
    // classifier output.
    #[test]
    fn classify_go_http_default_client_get_is_ssrf_gate() {
        let no_kw = |_: &str| None;
        let no_kw_present = |_: &str| false;
        let result = classify_gated_sink(
            "go",
            "http.DefaultClient.Get",
            |_| None,
            no_kw,
            no_kw_present,
        );
        assert!(
            result.iter().any(|m| m.label == DataLabel::Sink(Cap::SSRF)),
            "expected SSRF gate match, got {result:?}"
        );
    }

    #[test]
    fn classify_go_http_default_client_post_is_ssrf_and_data_exfil_gate() {
        let no_kw = |_: &str| None;
        let no_kw_present = |_: &str| false;
        let result = classify_gated_sink(
            "go",
            "http.DefaultClient.Post",
            |_| None,
            no_kw,
            no_kw_present,
        );
        assert!(
            result.iter().any(|m| m.label == DataLabel::Sink(Cap::SSRF)),
            "expected SSRF gate match, got {result:?}"
        );
        assert!(
            result
                .iter()
                .any(|m| m.label == DataLabel::Sink(Cap::DATA_EXFIL)),
            "expected DATA_EXFIL gate match, got {result:?}"
        );
    }

    #[test]
    fn classify_go_http_default_client_do_is_data_exfil_gate() {
        let no_kw = |_: &str| None;
        let no_kw_present = |_: &str| false;
        let result = classify_gated_sink(
            "go",
            "http.DefaultClient.Do",
            |_| None,
            no_kw,
            no_kw_present,
        );
        assert!(
            result
                .iter()
                .any(|m| m.label == DataLabel::Sink(Cap::DATA_EXFIL)),
            "expected DATA_EXFIL gate match, got {result:?}"
        );
    }

    #[test]
    fn classify_go_user_client_get_is_not_ssrf_sink() {
        // `client.Get` on a user-named *http.Client variable should NOT
        // match, the Go SSRF set is restricted to the stdlib package
        // helper `http.DefaultClient`. Type-aware resolution would be the
        // path to a broader rule, not a bare-name match.
        let result = classify("go", "client.Get", None);
        assert_eq!(result, None);
    }

    // CVE Hunt Session 3 (Ruby CVE-2020-8130 rake `Kernel#open` CMDI):
    // bare `open(path)` interprets a leading `|` as a shell pipe.  The
    // `=` exact-match sigil distinguishes the dangerous bare-callee form
    // from `File.open` / `IO.open` / `URI.open`, each of which has its
    // own non-piping semantics.  Without the sigil, the suffix-with-
    // boundary matcher would over-fire on every `X.open` call.
    #[test]
    fn classify_ruby_bare_open_is_shell_escape_sink() {
        let result = classify("ruby", "open", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::SHELL_ESCAPE)));
    }

    #[test]
    fn classify_ruby_file_open_is_not_shell_escape_sink() {
        // The exact-match sigil on `=open` must NOT fire on `File.open`.
        // `File.open` is a separate FILE_IO sink (existing rule); the
        // CMDI rule must not double-classify it.
        let result = classify_all("ruby", "File.open", None);
        // FILE_IO from the existing `File.open` matcher is allowed.
        assert!(result.contains(&DataLabel::Sink(Cap::FILE_IO)));
        // SHELL_ESCAPE from the new bare-`open` matcher must NOT appear.
        assert!(!result.contains(&DataLabel::Sink(Cap::SHELL_ESCAPE)));
    }

    #[test]
    fn classify_ruby_io_open_is_not_shell_escape_sink() {
        // `IO.open` takes a file descriptor, never pipes.  The bare-
        // open CMDI rule must leave it alone.
        let result = classify("ruby", "IO.open", None);
        assert_ne!(result, Some(DataLabel::Sink(Cap::SHELL_ESCAPE)));
    }

    #[test]
    fn classify_ruby_uri_open_remains_ssrf_sink() {
        // `URI.open` is the existing SSRF sink.  Adding `=open` as a
        // CMDI rule must not break or shadow it.
        let result = classify("ruby", "URI.open", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::SSRF)));
    }

    #[test]
    fn classify_ruby_openuri_open_uri_is_ssrf_sink() {
        // OpenURI.open_uri is the canonical low-level URI fetcher that
        // URI.open delegates to. CarrierWave / Paperclip / similar gems
        // route SSRF-vulnerable downloads through it directly.
        // CVE-2021-21288 (CarrierWave) regression guard.
        let result = classify("ruby", "OpenURI.open_uri", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::SSRF)));
    }

    #[test]
    fn unpack_matcher_strips_exact_sigil() {
        let (m, exact) = unpack_matcher(b"=open");
        assert_eq!(m, b"open");
        assert!(exact);

        let (m, exact) = unpack_matcher(b"open");
        assert_eq!(m, b"open");
        assert!(!exact);
    }

    #[test]
    fn classify_case_sensitive_suffix_boundary() {
        let extras = vec![RuntimeLabelRule {
            matchers: vec!["RunQuery".into()],
            label: DataLabel::Sink(Cap::SQL_QUERY),
            case_sensitive: true,
        }];
        // Correct case with dot boundary
        let result = classify("javascript", "db.RunQuery", Some(&extras));
        assert_eq!(result, Some(DataLabel::Sink(Cap::SQL_QUERY)));
        // Wrong case does NOT match
        let result = classify("javascript", "db.runquery", Some(&extras));
        assert_eq!(result, None);
    }

    #[test]
    fn classify_cpp_sto_family_is_sanitizer() {
        // full `std::sto*` family (including 64-bit and `long
        // double` variants) clears every taint cap that flows through it,
        // matching the existing `std::stoi`/`std::stol` rule.
        for callee in [
            "std::stoi",
            "std::stol",
            "std::stoll",
            "std::stoul",
            "std::stoull",
            "std::stof",
            "std::stod",
            "std::stold",
        ] {
            assert_eq!(
                classify("cpp", callee, None),
                Some(DataLabel::Sanitizer(Cap::all())),
                "{callee} should be a Cap::all() sanitizer",
            );
        }
    }

    #[test]
    fn parse_cap_works() {
        assert_eq!(parse_cap("html_escape"), Some(Cap::HTML_ESCAPE));
        assert_eq!(parse_cap("shell_escape"), Some(Cap::SHELL_ESCAPE));
        assert_eq!(parse_cap("url_encode"), Some(Cap::URL_ENCODE));
        assert_eq!(parse_cap("json_parse"), Some(Cap::JSON_PARSE));
        assert_eq!(parse_cap("env_var"), Some(Cap::ENV_VAR));
        assert_eq!(parse_cap("file_io"), Some(Cap::FILE_IO));
        assert_eq!(parse_cap("all"), Some(Cap::all()));
        assert_eq!(parse_cap("ALL"), Some(Cap::all()));
        assert_eq!(parse_cap("sql_query"), Some(Cap::SQL_QUERY));
        assert_eq!(parse_cap("deserialize"), Some(Cap::DESERIALIZE));
        assert_eq!(parse_cap("ssrf"), Some(Cap::SSRF));
        assert_eq!(parse_cap("code_exec"), Some(Cap::CODE_EXEC));
        assert_eq!(parse_cap("crypto"), Some(Cap::CRYPTO));
        assert_eq!(parse_cap("invalid"), None);
    }

    /// No-op keyword arg extractor for tests (JS/TS have no keyword gates).
    fn no_kw(_: &str) -> Option<String> {
        None
    }

    /// No-op kwarg presence check for tests that don't exercise the multi-kwarg path.
    fn no_kw_present(_: &str) -> bool {
        false
    }

    /// Find the first matching gate whose label sink-caps overlap `caps`.
    /// Lets tests target a specific gate when a callee carries multiple
    /// (e.g. `fetch` is both an SSRF and a `DATA_EXFIL` gate).
    fn find_match_with_caps(matches: &[GateMatch], caps: Cap) -> Option<GateMatch> {
        matches
            .iter()
            .find(|m| matches!(m.label, DataLabel::Sink(c) if c.intersects(caps)))
            .copied()
    }

    #[test]
    fn gated_sink_dangerous_exact() {
        let result = classify_gated_sink(
            "javascript",
            "setAttribute",
            |_| Some("href".to_string()),
            no_kw,
            no_kw_present,
        );
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::HTML_ESCAPE),
                payload_args: [1usize].as_slice(),
                object_destination_fields: &[],
            }]
        );
    }

    #[test]
    fn gated_sink_dangerous_prefix() {
        let result = classify_gated_sink(
            "javascript",
            "setAttribute",
            |_| Some("onclick".to_string()),
            no_kw,
            no_kw_present,
        );
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::HTML_ESCAPE),
                payload_args: [1usize].as_slice(),
                object_destination_fields: &[],
            }]
        );
    }

    #[test]
    fn gated_sink_safe_suppressed() {
        let result = classify_gated_sink(
            "javascript",
            "setAttribute",
            |_| Some("class".to_string()),
            no_kw,
            no_kw_present,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn gated_sink_dynamic_conservative() {
        // Dynamic activation (e.g. `setAttribute(attrVar, val)`) returns the
        // ALL_ARGS_PAYLOAD sentinel so callers expand payload tracking to
        // every positional arg, the activation arg itself is a vulnerability
        // path when attacker-controlled.
        let result =
            classify_gated_sink("javascript", "setAttribute", |_| None, no_kw, no_kw_present);
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::HTML_ESCAPE),
                payload_args: ALL_ARGS_PAYLOAD,
                object_destination_fields: &[],
            }]
        );
    }

    #[test]
    fn gated_sink_no_match() {
        let result = classify_gated_sink(
            "rust",
            "setAttribute",
            |_| Some("href".to_string()),
            no_kw,
            no_kw_present,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn gated_sink_returns_payload_args() {
        // setAttribute: payload is arg 1
        let result = classify_gated_sink(
            "javascript",
            "setAttribute",
            |_| Some("href".to_string()),
            no_kw,
            no_kw_present,
        );
        assert_eq!(result[0].payload_args, &[1]);

        // parseFromString: payload is arg 0
        let result = classify_gated_sink(
            "javascript",
            "parseFromString",
            |idx| {
                if idx == 1 {
                    Some("text/html".to_string())
                } else {
                    None
                }
            },
            no_kw,
            no_kw_present,
        );
        assert_eq!(result[0].payload_args, &[0]);
    }

    #[test]
    fn gated_sink_parse_from_string_safe_mime() {
        let result = classify_gated_sink(
            "javascript",
            "parseFromString",
            |idx| {
                if idx == 1 {
                    Some("text/xml".to_string())
                } else {
                    None
                }
            },
            no_kw,
            no_kw_present,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn gated_sink_python_popen_shell_true() {
        let result = classify_gated_sink(
            "python",
            "Popen",
            |_| None,
            |kw| {
                if kw == "shell" {
                    Some("True".to_string())
                } else {
                    None
                }
            },
            |kw| kw == "shell",
        );
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::SHELL_ESCAPE),
                payload_args: [0usize].as_slice(),
                object_destination_fields: &[],
            }]
        );
    }

    #[test]
    fn gated_sink_python_popen_shell_false() {
        let result = classify_gated_sink(
            "python",
            "Popen",
            |_| None,
            |kw| {
                if kw == "shell" {
                    Some("False".to_string())
                } else {
                    None
                }
            },
            |kw| kw == "shell",
        );
        assert!(result.is_empty());
    }

    #[test]
    fn gated_sink_python_popen_no_shell_conservative() {
        // `Popen(cmd)` uses the single-kwarg / positional gate path: no `shell`
        // literal available → unknown activation → ALL_ARGS_PAYLOAD sentinel.
        let result = classify_gated_sink("python", "Popen", |_| None, |_| None, no_kw_present);
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::SHELL_ESCAPE),
                payload_args: ALL_ARGS_PAYLOAD,
                object_destination_fields: &[],
            }]
        );
    }

    // ── New multi-kwarg gate path (dangerous_kwargs) tests ─────────────────

    /// `subprocess.run(cmd, shell=True)` → activates via multi-kwarg gate.
    #[test]
    fn gated_sink_subprocess_run_shell_true() {
        let result = classify_gated_sink(
            "python",
            "subprocess.run",
            |_| None,
            |kw| {
                if kw == "shell" {
                    Some("True".to_string())
                } else {
                    None
                }
            },
            |kw| kw == "shell",
        );
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::SHELL_ESCAPE),
                payload_args: [0usize].as_slice(),
                object_destination_fields: &[],
            }]
        );
    }

    /// `subprocess.run(cmd, shell=False)` → explicit safe literal suppresses the gate.
    #[test]
    fn gated_sink_subprocess_run_shell_false() {
        let result = classify_gated_sink(
            "python",
            "subprocess.run",
            |_| None,
            |kw| {
                if kw == "shell" {
                    Some("False".to_string())
                } else {
                    None
                }
            },
            |kw| kw == "shell",
        );
        assert!(result.is_empty());
    }

    /// `subprocess.run(cmd)` → no shell kwarg → presence-aware gate suppresses.
    /// This is the behavioural difference from the legacy `Popen` gate path.
    #[test]
    fn gated_sink_subprocess_run_shell_absent_suppresses() {
        let result = classify_gated_sink(
            "python",
            "subprocess.run",
            |_| None,
            |_| None,
            no_kw_present,
        );
        assert!(result.is_empty());
    }

    /// `subprocess.run(cmd, shell=flag)` → shell kwarg present but dynamic →
    /// conservative activate. Multi-kwarg dynamic-present branch also returns
    /// ALL_ARGS_PAYLOAD so the activation pathway is not narrowed.
    #[test]
    fn gated_sink_subprocess_run_shell_dynamic_conservative() {
        let result = classify_gated_sink(
            "python",
            "subprocess.run",
            |_| None,
            |_| None, // dynamic: no literal available
            |kw| kw == "shell",
        );
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::SHELL_ESCAPE),
                payload_args: ALL_ARGS_PAYLOAD,
                object_destination_fields: &[],
            }]
        );
    }

    /// Destination-flow gate always fires; returns `object_destination_fields`
    /// verbatim for the caller to apply object-literal field filtering.
    #[test]
    fn gated_sink_destination_positional_always_fires() {
        // `fetch(url)`, arg 0 is the URL (positional destination) OR an
        // object with a `url` field. The gate fires unconditionally, with
        // `url` declared as the object-literal destination-field for the
        // `fetch({url, body})` shape.
        let result = classify_gated_sink(
            "javascript",
            "fetch",
            |_| None, // no literal, Destination mode doesn't inspect it
            no_kw,
            no_kw_present,
        );
        let m = find_match_with_caps(&result, Cap::SSRF).expect("fetch SSRF gate should fire");
        assert_eq!(m.label, DataLabel::Sink(Cap::SSRF));
        assert_eq!(m.payload_args, &[0]);
        assert_eq!(m.object_destination_fields, &["url"]);
    }

    /// Destination gate with `object_destination_fields` surfaces them for
    /// the CFG caller to drive object-literal field filtering.
    #[test]
    fn gated_sink_destination_object_fields_surfaced() {
        // `http.request(opts, cb)`, opts is an object with destination fields.
        let result =
            classify_gated_sink("javascript", "http.request", |_| None, no_kw, no_kw_present);
        let m = result
            .first()
            .copied()
            .expect("http.request gate should fire");
        assert_eq!(m.label, DataLabel::Sink(Cap::SSRF));
        assert_eq!(m.payload_args, &[0]);
        assert!(
            m.object_destination_fields
                .iter()
                .any(|&f| f == "host" || f == "hostname"),
            "expected host/hostname in destination fields, got {:?}",
            m.object_destination_fields,
        );
    }

    /// `fetch` carries both SSRF (URL flow) and `DATA_EXFIL` (body / headers /
    /// json flow) gates. Both must fire from a single classify call so the
    /// downstream CFG can build per-cap filters.
    #[test]
    fn gated_sink_fetch_emits_ssrf_and_data_exfil() {
        let result = classify_gated_sink("javascript", "fetch", |_| None, no_kw, no_kw_present);
        let ssrf = find_match_with_caps(&result, Cap::SSRF).expect("SSRF gate fires");
        assert_eq!(ssrf.label, DataLabel::Sink(Cap::SSRF));
        assert_eq!(ssrf.payload_args, &[0]);
        assert_eq!(ssrf.object_destination_fields, &["url"]);

        let exfil = find_match_with_caps(&result, Cap::DATA_EXFIL).expect("DATA_EXFIL gate fires");
        assert_eq!(exfil.label, DataLabel::Sink(Cap::DATA_EXFIL));
        assert_eq!(exfil.payload_args, &[1]);
        assert!(
            exfil.object_destination_fields.contains(&"body"),
            "expected body in DATA_EXFIL destination fields, got {:?}",
            exfil.object_destination_fields,
        );
    }

    #[test]
    fn classify_all_single_label() {
        let result = classify_all("javascript", "innerHTML", None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], DataLabel::Sink(Cap::HTML_ESCAPE));
    }

    #[test]
    fn classify_all_dual_label_php() {
        let result = classify_all("php", "file_get_contents", None);
        assert!(result.len() >= 2, "expected dual label, got {:?}", result);
        assert!(
            result.contains(&DataLabel::Source(Cap::all())),
            "expected Source(all), got {:?}",
            result
        );
        assert!(
            result.contains(&DataLabel::Sink(Cap::SSRF)),
            "expected Sink(SSRF), got {:?}",
            result
        );
    }

    #[test]
    fn classify_all_dual_label_java() {
        let result = classify_all("java", "readObject", None);
        assert!(result.len() >= 2, "expected dual label, got {:?}", result);
        assert!(
            result.contains(&DataLabel::Source(Cap::all())),
            "expected Source(all), got {:?}",
            result
        );
        assert!(
            result.contains(&DataLabel::Sink(Cap::DESERIALIZE)),
            "expected Sink(DESERIALIZE), got {:?}",
            result
        );
    }

    #[test]
    fn classify_go_echo_sinks_with_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Echo],
            inspected_langs: std::collections::HashSet::new(),
        };
        let rules = go::framework_rules(&ctx);
        let extras = rules.to_vec();

        assert_eq!(
            classify("go", "c.String", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("go", "c.HTML", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("go", "c.JSON", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );

        // Without Echo framework, these should not match
        let empty = go::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("go", "c.String", Some(&empty)), None);
    }

    #[test]
    fn classify_javascript_koa_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Koa],
            inspected_langs: std::collections::HashSet::new(),
        };
        let extras = javascript::framework_rules(&ctx);

        assert_eq!(
            classify("javascript", "ctx.query", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("javascript", "ctx.cookies.get", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("javascript", "ctx.body", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("javascript", "ctx.redirect", Some(&extras)),
            Some(DataLabel::Sink(Cap::SSRF)),
        );

        let empty = javascript::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("javascript", "ctx.query", Some(&empty)), None);
    }

    #[test]
    fn classify_typescript_fastify_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Fastify],
            inspected_langs: std::collections::HashSet::new(),
        };
        let extras = typescript::framework_rules(&ctx);

        assert_eq!(
            classify("typescript", "request.query", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("typescript", "reply.send", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("typescript", "reply.redirect", Some(&extras)),
            Some(DataLabel::Sink(Cap::SSRF)),
        );

        let empty = typescript::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("typescript", "request.query", Some(&empty)), None);
    }

    #[test]
    fn classify_ruby_sinatra_template_sinks() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Sinatra],
            inspected_langs: std::collections::HashSet::new(),
        };
        let rules = ruby::framework_rules(&ctx);
        let extras = rules.to_vec();

        assert_eq!(
            classify("ruby", "erb", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("ruby", "haml", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );

        // Without Sinatra, erb should not match
        let empty = ruby::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("ruby", "erb", Some(&empty)), None);
    }

    #[test]
    fn classify_rust_axum_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Axum],
            inspected_langs: std::collections::HashSet::new(),
        };
        let extras = rust::framework_rules(&ctx);

        assert_eq!(
            classify("rust", "Path<String>", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "HeaderMap.get(\"x-user\")", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "Html(name)", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("rust", "Redirect::to(next)", Some(&extras)),
            Some(DataLabel::Sink(Cap::OPEN_REDIRECT)),
        );

        let empty = rust::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("rust", "Html(name)", Some(&empty)), None);
    }

    #[test]
    fn classify_rust_actix_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::ActixWeb],
            inspected_langs: std::collections::HashSet::new(),
        };
        let extras = rust::framework_rules(&ctx);

        assert_eq!(
            classify("rust", "web::Json<String>", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "HttpRequest.match_info()", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "HttpResponse.body(payload)", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
    }

    #[test]
    fn classify_rust_rocket_runtime_rules() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Rocket],
            inspected_langs: std::collections::HashSet::new(),
        };
        let extras = rust::framework_rules(&ctx);

        assert_eq!(
            classify("rust", "CookieJar.get_private(\"sid\")", Some(&extras)),
            Some(DataLabel::Source(Cap::all())),
        );
        assert_eq!(
            classify("rust", "content::RawHtml(name)", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("rust", "Redirect::to(next)", Some(&extras)),
            Some(DataLabel::Sink(Cap::OPEN_REDIRECT)),
        );
    }
}
