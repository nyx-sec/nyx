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
pub(crate) mod javascript;
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

/// Activation gate carried by a [`GatedLabelRule`]. Phase 05 introduces the
/// import-derived gate so JS/TS bare-name `fs/promises` sinks (`readFile`,
/// `writeFile`, ...) only fire when the call resolves to that module — a
/// flat bare-name match would over-fire on user-defined `readFile` helpers.
#[derive(Debug, Clone, Copy)]
pub enum LabelGate {
    /// Fires only when the call's leading identifier is locally bound by an
    /// import / `require` whose `source_module` equals one of the listed
    /// specifiers. The synthetic prefix `FileSystemPromisesNs.` produced by
    /// receiver-type qualification also satisfies the gate (see Phase 05's
    /// `TypeKind::FileSystemPromisesNs`).
    ImportedFromModule(&'static [&'static str]),
    /// Fires when *any* local-name in the file's import view resolves to one
    /// of the listed specifiers, regardless of which identifier leads the
    /// call. Used for Phase 07 ORM bare-name method sinks (Knex's `whereRaw`
    /// / `orderByRaw` / `havingRaw`) where the receiver is a query-builder
    /// instance whose binding name is arbitrary (`db`, `qb`, `users`, ...)
    /// and the import witness is the package itself.
    FileImportsModule(&'static [&'static str]),
    /// Fires when the file's import view binds at least one of `local_names`
    /// to one of `modules`. Tighter than [`Self::FileImportsModule`]: type-only
    /// or peripheral named-import shapes (e.g. `import { Knex } from 'knex'`
    /// for type-only use of `Knex.QueryBuilder`) do not satisfy the gate
    /// unless the conventional value-binding name (`knex`, lowercase) is also
    /// present. Used for Phase 07 deferred-item 10's tightening of the Knex
    /// `whereRaw` / `orderByRaw` / `havingRaw` gate.
    FileImportsModuleAsLocalName {
        modules: &'static [&'static str],
        local_names: &'static [&'static str],
    },
}

/// A label rule that only fires when its [`LabelGate`] is satisfied at the
/// call site. The matcher / label / case-sensitivity semantics mirror
/// [`LabelRule`]; the gate is checked by [`classify_all_ctx`] using the
/// caller-supplied [`ClassificationContext`].
#[derive(Debug, Clone, Copy)]
pub struct GatedLabelRule {
    pub matchers: &'static [&'static str],
    pub label: DataLabel,
    pub case_sensitive: bool,
    pub gate: LabelGate,
    /// Positional args that carry the payload when `label` is a `Sink`.
    /// Same meaning as [`SinkGate::payload_args`]: the CFG post-pass copies
    /// these onto the call node's `sink_payload_args`, so taint on the
    /// receiver or on an options / callback argument does not reach the
    /// sink.  `&[]` leaves every argument a payload.
    pub payload_args: &'static [usize],
}

/// A [`GatedLabelRule`] hit: the label it contributes and the payload
/// positions it restricts a `Sink` to (`&[]` for every argument).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatedLabelMatch {
    pub label: DataLabel,
    pub payload_args: &'static [usize],
    /// The rule matched only the head of a chained callee
    /// (`execSync(cmd).toString` matching `execSync`), so `payload_args`
    /// index the head call's arguments, not the outer call's.
    pub chain_head: bool,
}

/// Per-file context consulted by [`classify_all_ctx`] when evaluating
/// gated rules. Threaded from the CFG layer's gated post-pass; `None`
/// elsewhere keeps existing classification paths intact.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClassificationContext<'a> {
    /// Local-name → source-module view of the file's imports. The map is
    /// computed at CFG build time (see `cfg::imports::extract_local_import_view`)
    /// so the gate fires before the project-wide resolver runs.
    pub local_imports: Option<&'a std::collections::HashMap<String, String>>,
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
    /// Strict literal-value activation.  The gate fires only when the
    /// activation arg is a literal that matches `dangerous_values` /
    /// `dangerous_prefixes`.  Unknown/dynamic activation arg suppresses
    /// (no conservative ALL_ARGS_PAYLOAD push).
    ///
    /// Used for ambiguously-named matchers where the dangerous shape is
    /// only identifiable by an explicit literal flag — e.g. bare `extend`
    /// where the deep-merge form is `extend(true, target, src)` but
    /// Backbone's `Model.extend({proto})` shares the suffix.  Conservative
    /// fallback would over-fire on the class-extension form.
    LiteralOnly,
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

impl SinkGate {
    /// A gate that always fires and restricts the sink to the listed
    /// positional args.  The common shape for an API whose receiver,
    /// options object or callback is never the injected value
    /// (`res.send(body)`, `vm.runInNewContext(code, sandbox)`): the gate's
    /// `payload_args` propagate onto a matching flat sink, so the receiver
    /// and the trailing arguments are not taint-checked.
    pub const fn payload_positions(
        callee_matcher: &'static str,
        label: DataLabel,
        case_sensitive: bool,
        payload_args: &'static [usize],
    ) -> Self {
        SinkGate {
            callee_matcher,
            arg_index: 0,
            dangerous_values: &[],
            dangerous_prefixes: &[],
            label,
            case_sensitive,
            payload_args,
            keyword_name: None,
            dangerous_kwargs: &[],
            activation: GateActivation::Destination {
                object_destination_fields: &[],
            },
        }
    }
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
    /// Async-await unary forward.  An `await x` expression evaluates `x` and
    /// resolves to the same value/taint, modelled as a 1:1 copy.  Lowered to
    /// SSA as `SsaOp::Assign(operand)` so taint, origins, and abstract value
    /// pass through unchanged.
    AwaitForward,
    /// JSX attribute (`<Tag name={value} />`).  Dispatched in the CFG so the
    /// builder can recognise React-specific shapes such as
    /// `dangerouslySetInnerHTML={{ __html: x }}` and synthesise a sink call.
    /// The attribute name is read from the AST at CFG-build time, not carried
    /// in this enum (which must remain `Copy` for `phf_map` storage).
    JsxAttr,
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

/// Look up output-parameter positions for Source-labeled functions (C/C++
/// input buffers, Go request binders).  Returns argument indices that
/// receive the source taint.
pub fn output_param_source_positions(lang: &str, callee: &str) -> Option<&'static [usize]> {
    let registry: &[(&str, &[usize])] = match lang {
        "c" => c::OUTPUT_PARAM_SOURCES,
        "cpp" => cpp::OUTPUT_PARAM_SOURCES,
        "go" => go::OUTPUT_PARAM_SOURCES,
        "rust" | "rs" => rust::OUTPUT_PARAM_SOURCES,
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
    let find = |name: &str| {
        registry
            .iter()
            .find(|p| p.callee.eq_ignore_ascii_case(name))
    };
    find(normalized).or_else(|| {
        // Arity-suffixed wrapper macros (`SNPRINTF2(dst, n, fmt, a, b)`) keep
        // the argument layout of the function they wrap.  Tree-sitter does no
        // preprocessing, so the macro name is all that is visible; only
        // all-caps names qualify, which keeps `memcpy2` style functions out.
        let base = normalized.trim_end_matches(|c: char| c.is_ascii_digit());
        let all_caps = !base.is_empty()
            && base != normalized
            && base.bytes().all(|b| b.is_ascii_uppercase() || b == b'_');
        if all_caps { find(base) } else { None }
    })
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

/// One flat matcher of a [`LabelRule`], flattened out of the per-rule
/// `matchers` slice so the dispatch index can address it by a single index.
struct MatcherEntry {
    /// Raw matcher bytes, including any leading `=` exact-match sigil
    /// (`match_suffix_cs`/`starts_with_cs` re-strip the sigil themselves).
    matcher: &'static [u8],
    label: DataLabel,
    case_sensitive: bool,
}

/// Per-language last-byte dispatch index for the flat (non-gated)
/// `classify` / `classify_all` matching path.
///
/// The original inner loops walked **every** matcher of **every** rule for
/// **every** classified node — `O(matchers)` per node (Go ≈ 150 matchers,
/// JS ≈ 200+), and `classify_all` runs once per CFG call node. A suffix/exact
/// match (`match_suffix_cs`) can only succeed when the candidate text's final
/// byte equals the matcher's final byte (case-insensitively) — every other
/// matcher is rejected on the very first byte compared. This index buckets the
/// suffix/exact matchers by their lowercased last byte, so a lookup visits only
/// the handful sharing the text's last byte: `O(bucket)` per node, an
/// asymptotic reduction of the per-node classify cost.
///
/// The bucket is a **pre-filter that never drops a true match**: a matcher
/// absent from the looked-up bucket has a different last byte and would have
/// been rejected by `ends_with_cs` anyway, so the labels produced (and their
/// order — bucket lists preserve the original registry iteration order, and the
/// full `match_suffix_cs` boundary/case check still runs on every candidate)
/// are byte-identical to the linear scan. `prefix` matchers (`foo_`) are a
/// small minority (Go has zero) and stay a linear list.
struct LabelIndex {
    /// Suffix/exact matchers (matcher does not end in `_`), in registry order.
    suffix: Vec<MatcherEntry>,
    /// `suffix_by_last[b]` = ascending indices into `suffix` of matchers whose
    /// lowercased last byte is `b`. Length 256.
    suffix_by_last: Vec<Vec<u32>>,
    /// Suffix matchers whose stripped form is empty (a bare `=` sigil) — cannot
    /// be keyed by a last byte, so they are consulted on every lookup to remain
    /// bit-identical. Empty for all real rule sets.
    suffix_always: Vec<u32>,
    /// Prefix matchers (matcher ends in `_`), in registry order.
    prefix: Vec<MatcherEntry>,
}

impl LabelIndex {
    fn build(rules: &'static [LabelRule]) -> LabelIndex {
        let mut suffix: Vec<MatcherEntry> = Vec::new();
        let mut suffix_by_last: Vec<Vec<u32>> = (0..256).map(|_| Vec::new()).collect();
        let mut suffix_always: Vec<u32> = Vec::new();
        let mut prefix: Vec<MatcherEntry> = Vec::new();
        for rule in rules {
            for raw in rule.matchers {
                let m = raw.as_bytes();
                let entry = MatcherEntry {
                    matcher: m,
                    label: rule.label,
                    case_sensitive: rule.case_sensitive,
                };
                if m.last() == Some(&b'_') {
                    // Prefix matcher (`foo_`) — Pass 2, kept as a linear list.
                    prefix.push(entry);
                } else {
                    let idx = suffix.len() as u32;
                    let (stripped, _) = unpack_matcher(m);
                    match stripped.last() {
                        Some(&lb) => suffix_by_last[lb.to_ascii_lowercase() as usize].push(idx),
                        None => suffix_always.push(idx),
                    }
                    suffix.push(entry);
                }
            }
        }
        LabelIndex {
            suffix,
            suffix_by_last,
            suffix_always,
            prefix,
        }
    }

    /// Visit the suffix-match candidates for a text pair whose lowercased last
    /// bytes are `tlb` / `nlb`, in ascending registry order, calling `f` on
    /// each. `f` returns `true` to stop early (first-match callers). The ≤3
    /// index lists (`tlb` bucket, distinct `nlb` bucket, `suffix_always`) are
    /// individually ascending and mutually disjoint — each suffix matcher lives
    /// in exactly one — so a k-way merge yields every candidate exactly once in
    /// registry order.
    #[inline]
    fn for_each_suffix_candidate<F: FnMut(&MatcherEntry) -> bool>(
        &self,
        tlb: Option<u8>,
        nlb: Option<u8>,
        bucketed: bool,
        mut f: F,
    ) {
        if !bucketed {
            // A/B escape hatch (`NYX_DISABLE_LABEL_INDEX=1`): the pre-index
            // linear scan — `suffix` is exactly the flat, registry-ordered list
            // of every suffix matcher, so iterating it whole reproduces the old
            // inner loop.
            for e in &self.suffix {
                if f(e) {
                    return;
                }
            }
            return;
        }
        let mut lists: SmallVec<[&[u32]; 3]> = SmallVec::new();
        if let Some(b) = tlb {
            let l = &self.suffix_by_last[b as usize];
            if !l.is_empty() {
                lists.push(l);
            }
        }
        if let Some(b) = nlb {
            if Some(b) != tlb {
                let l = &self.suffix_by_last[b as usize];
                if !l.is_empty() {
                    lists.push(l);
                }
            }
        }
        if !self.suffix_always.is_empty() {
            lists.push(&self.suffix_always);
        }
        let n = lists.len();
        // Fast path: a single candidate list is already ascending.
        if n == 1 {
            for &i in lists[0] {
                if f(&self.suffix[i as usize]) {
                    return;
                }
            }
            return;
        }
        let mut heads = [0usize; 3];
        loop {
            let mut best: Option<(usize, u32)> = None;
            for (i, list) in lists.iter().enumerate() {
                if heads[i] < list.len() {
                    let v = list[heads[i]];
                    match best {
                        Some((_, bv)) if bv <= v => {}
                        _ => best = Some((i, v)),
                    }
                }
            }
            let Some((li, v)) = best else { break };
            heads[li] += 1;
            if f(&self.suffix[v as usize]) {
                return;
            }
        }
    }
}

/// Last-byte dispatch index over [`REGISTRY`], built once at first use. Keyed
/// identically (every language alias) so `LABEL_INDEX.get(lang)` matches
/// `REGISTRY.get(lang)`.
static LABEL_INDEX: Lazy<HashMap<&'static str, LabelIndex>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for (k, rules) in REGISTRY.iter() {
        m.insert(*k, LabelIndex::build(rules));
    }
    m
});

/// A/B escape hatch: `NYX_DISABLE_LABEL_INDEX=1` forces the pre-index linear
/// matcher scan (for single-binary before/after benchmarking and as a safety
/// valve). Enabled path (default) uses the last-byte dispatch buckets.
fn label_index_bucketed() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    !*DISABLED.get_or_init(|| std::env::var("NYX_DISABLE_LABEL_INDEX").is_ok())
}

/// Resolve a language's [`LabelIndex`], retrying with the lowercased key (mirror
/// of the `REGISTRY.get(...).or_else(lowercase)` fallback the old path used).
#[inline]
fn label_index_for(lang: &str) -> Option<&'static LabelIndex> {
    LABEL_INDEX.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        LABEL_INDEX.get(key.as_str())
    })
}

/// One language's gated sinks with a last-byte index over their callee
/// matchers, the dispatch [`LabelIndex`] uses for flat rules: a gate matches a
/// text only when the text ends with its matcher, so only gates whose matcher
/// ends in the text's (lowercased) last byte can match it.
struct GateSet {
    gates: &'static [SinkGate],
    /// `by_last[b]` = ascending indices into `gates` of the matchers whose
    /// lowercased last byte is `b`.
    by_last: Vec<Vec<u16>>,
    /// Matchers with no last byte (a bare `=` sigil); none in practice.
    always: Vec<u16>,
}

impl GateSet {
    fn new(gates: &'static [SinkGate]) -> &'static GateSet {
        let mut by_last: Vec<Vec<u16>> = vec![Vec::new(); 256];
        let mut always = Vec::new();
        for (i, gate) in gates.iter().enumerate() {
            let (m, _) = unpack_matcher(gate.callee_matcher.as_bytes());
            match m.last() {
                Some(&b) => by_last[b.to_ascii_lowercase() as usize].push(i as u16),
                None => always.push(i as u16),
            }
        }
        Box::leak(Box::new(GateSet {
            gates,
            by_last,
            always,
        }))
    }

    /// Indices, ascending, of the gates that can match a text whose last byte
    /// is `text_last` or whose normalised form's last byte is `norm_last`.
    fn candidates(&self, text_last: Option<u8>, norm_last: Option<u8>) -> SmallVec<[u16; 8]> {
        let text_last = text_last.map(|b| b.to_ascii_lowercase());
        let norm_last = norm_last.map(|b| b.to_ascii_lowercase());
        let mut out: SmallVec<[u16; 8]> = SmallVec::new();
        if let Some(b) = text_last {
            out.extend_from_slice(&self.by_last[b as usize]);
        }
        if let Some(b) = norm_last.filter(|&b| Some(b) != text_last) {
            out.extend_from_slice(&self.by_last[b as usize]);
        }
        out.extend_from_slice(&self.always);
        out.sort_unstable();
        out.dedup();
        out
    }
}

static GATED_REGISTRY: Lazy<HashMap<&'static str, &'static GateSet>> = Lazy::new(|| {
    let mut m = HashMap::new();
    let mut add = |names: &[&'static str], gates: &'static [SinkGate]| {
        let set = GateSet::new(gates);
        for name in names {
            m.insert(*name, set);
        }
    };
    add(&["javascript", "js"], javascript::GATED_SINKS);
    add(&["typescript", "ts"], typescript::GATED_SINKS);

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
    add(&["python", "py"], python_gates);
    add(&["go"], go::GATED_SINKS);
    add(&["php"], php::GATED_SINKS);
    add(&["c"], c::GATED_SINKS);
    add(&["cpp", "c++"], cpp::GATED_SINKS);
    add(&["ruby", "rb"], ruby::GATED_SINKS);
    add(&["java"], java::GATED_SINKS);
    add(&["rust", "rs"], rust::GATED_SINKS);
    m
});

/// Per-language registry of [`GatedLabelRule`] entries. Phase 05 wires
/// JS/TS only (the `fs/promises` FILE_IO matcher set); other languages
/// fall back to an empty slice.
static GATED_LABEL_REGISTRY: Lazy<HashMap<&'static str, &'static [GatedLabelRule]>> =
    Lazy::new(|| {
        let mut m = HashMap::new();
        m.insert("javascript", javascript::GATED_LABEL_RULES);
        m.insert("js", javascript::GATED_LABEL_RULES);
        m.insert("typescript", typescript::GATED_LABEL_RULES);
        m.insert("ts", typescript::GATED_LABEL_RULES);
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
    m.insert("java", java::EXCLUDES);
    m
});

/// Check whether `text` matches a per-language exclusion pattern.
pub(crate) fn is_excluded(lang: &str, trimmed: &[u8]) -> bool {
    // Direct match for the canonical lowercase keys (no hashing); the map
    // lookup stays as the fallback for any other spelling.
    let excludes = match lang {
        "rust" | "rs" | "go" | "python" | "py" | "c" | "cpp" | "php" | "ruby" | "rb" => {
            return false;
        }
        "javascript" | "js" => javascript::EXCLUDES,
        "typescript" | "ts" => typescript::EXCLUDES,
        "java" => java::EXCLUDES,
        _ => match EXCLUDES.get(lang).or_else(|| {
            let key = lang.to_ascii_lowercase();
            EXCLUDES.get(key.as_str())
        }) {
            Some(e) => *e,
            None => return false,
        },
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
/// function with no known caller whose formal parameter matches one of these
/// names, it auto-seeds the parameter as a `UserInput` source so sinks
/// downstream of the parameter still fire.
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
    bytes.len() >= 5
        && bytes[..4].eq_ignore_ascii_case(b"user")
        && (bytes[4].is_ascii_uppercase() || bytes[4] == b'_')
}

/// Bare bindings denoting an Express/Koa request sub-object when the handler
/// param is destructured (`({ query }, res) => …`). Kept out of
/// [`is_js_ts_handler_param_name`] so a plain param named `query`/`body` is
/// never seeded; the SSA seeder additionally requires a sibling response param.
const JS_TS_REQUEST_FIELD_NAMES: &[&str] =
    &["query", "body", "params", "headers", "cookies", "cookie"];

/// True when `name` is a bare destructured request-field binding. Only
/// meaningful behind the destructured-handler-param gate in the SSA seeder.
pub fn is_express_request_field_name(name: &str) -> bool {
    JS_TS_REQUEST_FIELD_NAMES
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

/// True for the conventional Express/Koa/Fastify response-object parameter
/// (`res`/`response`/`reply`) — the structural signal that a function is a
/// route handler, so a sibling destructured `{ query }` is a real source.
pub fn is_handler_response_param_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "res" | "response" | "reply"
    )
}

#[inline(always)]
pub fn lookup(lang: &str, raw: &str) -> Kind {
    CLASSIFIERS
        .get(lang)
        .and_then(|m| m.get(raw).copied())
        .unwrap_or(Kind::Other)
}

/// Promise-callback methods (`p.then(cb)`, `p.catch(cb)`, `p.finally(cb)`).
///
/// These are not sinks. The taint engine consumes this predicate to recognise
/// the receiver as a Promise whose resolved value will be fed to the callback's
/// first parameter.  See phase 03 of `plan.md` for the recall-gap rationale.
///
/// JS/TS only.  `callee_leaf` is expected to be the post-`callee_leaf_name`
/// short form (e.g. `"then"`, not `"p.then"`).
pub fn is_promise_callback_method(lang: &str, callee_leaf: &str) -> bool {
    if !matches!(lang, "javascript" | "js" | "typescript" | "ts" | "tsx") {
        return false;
    }
    matches!(callee_leaf, "then" | "catch" | "finally")
}

/// Static `Promise.*` combinator a call resolves to, or `None`.
///
/// Combinators wrap arguments into a single Promise:
///   * `Promise.resolve(x)` — identity for `x`.
///   * `Promise.all([a, b])` — array whose elements have per-arg taint.
///   * `Promise.allSettled([...])` — same shape as `all`, conservative union.
///   * `Promise.race([...])` — first-to-settle, conservative union.
///
/// `callee` is the full callee text (e.g. `"Promise.all"`) since the leaf
/// segment alone (`"all"`) is too generic to match safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromiseCombinatorKind {
    Resolve,
    All,
    AllSettled,
    Race,
}

/// Lang-agnostic recognition of any promise combinator callee text. Used by
/// SSA lowering, which doesn't carry a `lang` argument.
pub fn is_any_promise_combinator(callee: &str) -> Option<PromiseCombinatorKind> {
    match callee {
        "Promise.resolve" => Some(PromiseCombinatorKind::Resolve),
        "Promise.all" => Some(PromiseCombinatorKind::All),
        "Promise.allSettled" => Some(PromiseCombinatorKind::AllSettled),
        "Promise.race" => Some(PromiseCombinatorKind::Race),
        "asyncio.gather" | "asyncio.wait" => Some(PromiseCombinatorKind::All),
        "tokio::join" | "tokio::try_join" | "futures::join" | "futures::try_join" => {
            Some(PromiseCombinatorKind::All)
        }
        _ => None,
    }
}

pub fn is_promise_combinator(lang: &str, callee: &str) -> Option<PromiseCombinatorKind> {
    match lang {
        "javascript" | "js" | "typescript" | "ts" | "tsx" => match callee {
            "Promise.resolve" => Some(PromiseCombinatorKind::Resolve),
            "Promise.all" => Some(PromiseCombinatorKind::All),
            "Promise.allSettled" => Some(PromiseCombinatorKind::AllSettled),
            "Promise.race" => Some(PromiseCombinatorKind::Race),
            _ => None,
        },
        // Python: `asyncio.gather(...)` / `asyncio.wait(...)` resolve to a
        // tuple/list whose elements carry the union of argument taints.
        // `asyncio.wait` returns `(done, pending)` sets but the same
        // conservative scalar-union approximation applies, downstream
        // destructuring already taints all bindings.
        "python" | "py" => match callee {
            "asyncio.gather" | "asyncio.wait" => Some(PromiseCombinatorKind::All),
            _ => None,
        },
        // Rust: `tokio::join!` / `futures::join!` (and their `try_*`
        // variants) evaluate every future concurrently and bind the
        // tuple of resolved values.  `cfg::push_node` rewrites the
        // macro_invocation's `arg_uses` so each future's tainted inputs
        // surface as a positional arg; this combinator entry then unions
        // them onto the tuple value.
        "rust" | "rs" => match callee {
            "tokio::join" | "tokio::try_join" | "futures::join" | "futures::try_join" => {
                Some(PromiseCombinatorKind::All)
            }
            _ => None,
        },
        _ => None,
    }
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

impl Cap {
    /// Capabilities a caught exception value can carry.
    ///
    /// An exception's message and stack text can embed attacker input, so
    /// output, log, header, template and command-style reflection stay live.
    /// Sinks that need an attacker-chosen key, URL, path, query or code
    /// (prototype pollution, open redirect, SSRF, file paths, SQL, code
    /// execution, deserialisation, XXE) have no attacker model for an
    /// exception object, and are masked out.
    pub const CAUGHT_EXCEPTION: Cap = Cap::all()
        .difference(Cap::PROTOTYPE_POLLUTION)
        .difference(Cap::OPEN_REDIRECT)
        .difference(Cap::SSRF)
        .difference(Cap::FILE_IO)
        .difference(Cap::SQL_QUERY)
        .difference(Cap::CODE_EXEC)
        .difference(Cap::DESERIALIZE)
        .difference(Cap::XXE);
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
    // Go `*http.Request` header accessors (`r.Referer()`, `r.UserAgent()`)
    // read a header without naming it.
    if cl.contains("header") || cl.contains("referer") || cl.contains("useragent") {
        return SourceKind::Header;
    }

    // User input patterns
    if cl.contains("argv")
        // Go request binders (`c.ShouldBindJSON(&in)`) and path wildcards
        // (`r.PathValue("id")`).
        || cl.contains("bind")
        || cl.contains("pathvalue")
        // Servlet `req.getReader()` reads the body.  Without this the "read"
        // substring below files it under FileSystem.
        || cl.ends_with("getreader")
        || cl.contains("stdin")
        || cl.contains("fgets")
        || cl.contains("scanf")
        || cl.contains("gets")
        || cl.contains("recv")
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

/// Allocation-free ASCII-case-insensitive prefix check on `&str` inputs.
/// Used by the gated-sink dispatch hot path where the previous
/// `value.to_ascii_lowercase().starts_with(&p.to_ascii_lowercase())` pair
/// allocated two `String` values per check.
#[inline]
fn starts_with_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    h.len() >= n.len() && h[..n.len()].eq_ignore_ascii_case(n)
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

/// `~_path` name-suffix matcher: fires on a bare callee (no receiver or
/// namespace) whose name ends with `tail` (`things_path`), with no word
/// boundary and a non-empty stem.  It keys on its last byte in the index like
/// every other suffix matcher.  Only a bare call (`things_path(..)`) is a
/// route helper: a callee with a receiver (`obj.relative_path`,
/// `Mod::unescape_path`) is an ordinary method that can return attacker data.
#[cold]
fn match_name_suffix(text: &[u8], tail: &[u8], case_sensitive: bool) -> bool {
    text.len() > tail.len()
        && ends_with_cs(text, tail, case_sensitive)
        && !text.contains(&b'.')
        && !text.contains(&b':')
}

/// Word-boundary suffix match with configurable case sensitivity.
// Always inline: this runs once per candidate matcher of every
// classification, and an out-of-line call here cost ~15% of the Go sweep
// bench on x86 once the sigil handling grew the body.
#[inline(always)]
fn match_suffix_cs(text: &[u8], matcher: &[u8], case_sensitive: bool) -> bool {
    // One first-byte branch decodes both sigils: this is the innermost loop
    // of every classification.  `=name` is exact-only; `~_path` is a
    // name-suffix matcher (see [`match_name_suffix`]).
    let (m, exact_only) = match matcher.first() {
        Some(b'=') => (&matcher[1..], true),
        Some(b'~') => return match_name_suffix(text, &matcher[1..], case_sensitive),
        _ => (matcher, false),
    };
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

#[inline]
fn is_python_lang(lang: &str) -> bool {
    lang == "python" || lang == "py"
}

/// Python: the module-qualified spelling of `text` when its leading name is
/// bound by `from M import n [as a]` or `import M as a` in the file being
/// analysed (`from subprocess import check_output` makes `check_output(..)`
/// into `subprocess.check_output`). `None` when the leading name is not an
/// import binding or no file view is published.
///
/// Label rules are keyed on the qualified callee. The qualified spelling is
/// classified in addition to the written one, so the written one keeps every
/// label it had and an import can only add labels, never take them away.
pub(crate) fn python_import_qualified(text: &str) -> Option<String> {
    let end = text.find(['.', '(', '[', ' ']).unwrap_or(text.len());
    let path = crate::ssa::type_facts::file_import_path(&text[..end])?;
    Some(format!("{path}{}", &text[end..]))
}

// ── Declared-type receiver aliases ──────────────────────────────────────────
//
// Some receivers are only recognisable by their declared type: a Go
// handler may name its `*http.Request` `r`, `req`, `httpReq` or anything
// else, its `http.ResponseWriter` `w` or `rw`, its `*http.Client` anything,
// and the flat suffix matchers cannot see the type.  While the CFG
// builder walks a function body it pushes one frame per function scope,
// mapping each formal parameter name to a canonical receiver prefix (or to
// `None` when the formal has an unrecognised type, so an inner closure's
// formal shadows an outer one of the same name).  `classify` /
// `classify_all` then also classify the text with its root identifier
// replaced by that prefix, so `req.Header.Get` additionally matches the
// `Request.Header.Get` rule.  The stack is empty outside CFG construction,
// which makes every other caller a no-op.
/// One function scope's formals: `(name, canonical receiver prefix)`.
pub(crate) type ReceiverAliasFrame = Vec<(String, Option<&'static str>)>;

thread_local! {
    static RECEIVER_ALIASES: std::cell::RefCell<Vec<ReceiverAliasFrame>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Pops the receiver-alias frame pushed by `push_receiver_aliases` when
/// dropped, so an early return or unwind inside the body walk cannot leak a
/// frame into the next function.
pub(crate) struct ReceiverAliasScope {
    pushed: bool,
}

impl Drop for ReceiverAliasScope {
    fn drop(&mut self) {
        if self.pushed {
            RECEIVER_ALIASES.with(|s| {
                s.borrow_mut().pop();
            });
        }
    }
}

/// Enter a function scope whose formals are `frame` (`(name, prefix)`
/// pairs).  A frame without any typed formal is only pushed when an outer
/// scope is active, where it is still needed for shadowing.
pub(crate) fn push_receiver_aliases(frame: ReceiverAliasFrame) -> ReceiverAliasScope {
    RECEIVER_ALIASES.with(|s| {
        let mut s = s.borrow_mut();
        let has_alias = frame.iter().any(|(_, p)| p.is_some());
        if frame.is_empty() || (!has_alias && s.is_empty()) {
            return ReceiverAliasScope { pushed: false };
        }
        s.push(frame);
        ReceiverAliasScope { pushed: true }
    })
}

/// Drop every receiver-alias frame.  Called at the start and end of each
/// file's CFG build so state never crosses files on a worker thread.
pub(crate) fn clear_receiver_aliases() {
    RECEIVER_ALIASES.with(|s| s.borrow_mut().clear());
}

/// Receiver prefix of the innermost formal named `name`, when it has one
/// (`w` declared `http.ResponseWriter` → `HttpResponse`).  `None` outside
/// CFG construction, for a name no frame binds, and for an untyped formal.
pub(crate) fn receiver_alias_prefix(name: &str) -> Option<&'static str> {
    RECEIVER_ALIASES.with(|s| {
        s.borrow()
            .iter()
            .rev()
            .find_map(|frame| frame.iter().find(|(n, _)| n == name))
            .and_then(|(_, prefix)| *prefix)
    })
}

/// Rewrite the root identifier of a member-access text (`req.Header.Get`)
/// to the canonical prefix of the innermost formal that binds it
/// (`Request.Header.Get`).  Returns `None` when no frame is active, the text
/// has no `.` member access after a plain identifier root, or the binding
/// formal has no recognised type.
fn aliased_receiver_text(text: &str) -> Option<String> {
    RECEIVER_ALIASES.with(|s| {
        let s = s.borrow();
        if s.is_empty() {
            return None;
        }
        let dot = text.find('.')?;
        let root = &text[..dot];
        if root.is_empty() || !root.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return None;
        }
        // `root.field.rest`: a formal's field with a declared receiver type
        // (`ctx.Req.URL.Path` where `Req` is an `*http.Request` field).
        let field_end = text[dot + 1..].find('.').map(|i| dot + 1 + i);
        for frame in s.iter().rev() {
            if let Some(end) = field_end
                && let Some((_, Some(prefix))) = frame.iter().find(|(name, _)| name == &text[..end])
            {
                return Some(format!("{prefix}{}", &text[end..]));
            }
            if let Some((_, prefix)) = frame.iter().find(|(name, _)| name == root) {
                return prefix
                    .filter(|p| *p != root)
                    .map(|p| format!("{p}{}", &text[dot..]));
            }
        }
        None
    })
}

/// Canonical receiver prefix for a Go formal parameter type
/// (`*http.Request` → `Request`, `*gin.Context` → `GinContext`).  Shared by
/// the CFG builder (label classification) and the auth extractor
/// (request-typed parameter evidence).
pub fn go_request_receiver_prefix(type_text: &str) -> Option<&'static str> {
    go::request_receiver_prefix(type_text)
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
///
/// When the text's root identifier is a formal with a declared request type
/// (see `push_receiver_aliases`), the aliased text is tried when the
/// literal text matches nothing.
pub fn classify(lang: &str, text: &str, extra: Option<&[RuntimeLabelRule]>) -> Option<DataLabel> {
    let direct = classify_aliased(lang, text, extra);
    if direct.is_some() || !is_python_lang(lang) {
        return direct;
    }
    let qualified = python_import_qualified(text)?;
    classify_aliased(lang, &qualified, extra)
}

/// [`classify_text`], retried on the receiver-aliased text when the literal
/// text matches nothing.
fn classify_aliased(
    lang: &str,
    text: &str,
    extra: Option<&[RuntimeLabelRule]>,
) -> Option<DataLabel> {
    classify_text(lang, text, extra)
        .filter(|label| {
            !(lang == "go"
                && matches!(label, DataLabel::Sink(c) if c.contains(Cap::HTML_ESCAPE))
                && go::name_rule_sink_contradicts_declared_type(text, receiver_alias_prefix))
        })
        .or_else(|| {
            aliased_receiver_text(text).and_then(|aliased| classify_text(lang, &aliased, extra))
        })
}

fn classify_text(lang: &str, text: &str, extra: Option<&[RuntimeLabelRule]>) -> Option<DataLabel> {
    let view = CalleeView::of(lang, text);
    classify_view(lang, &view, extra).or(view.polymorphic_decode.then_some(POLYMORPHIC_DECODE))
}

fn classify_view(
    lang: &str,
    view: &CalleeView<'_>,
    extra: Option<&[RuntimeLabelRule]>,
) -> Option<DataLabel> {
    let text = &*view.text;
    let head = view.head();
    let trimmed = head.trim().as_bytes();

    // Early out: exclude known-benign framework patterns.
    if is_excluded(lang, trimmed) {
        return None;
    }

    // For chained calls like `r.URL.Query().Get`, also strip internal
    // `().` segments to produce a normalized form like `r.URL.Query.Get`.
    // `normalize_chained_call` returns `Cow::Borrowed` when no rewrite is
    // needed, so the alloc is paid only on inputs that actually require
    // it.
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
    let index = label_index_for(lang)?;
    let tlb = trimmed.last().map(u8::to_ascii_lowercase);
    let nlb = full_norm_bytes.last().map(u8::to_ascii_lowercase);

    // Pass 1: exact / suffix matches (high confidence). Only matchers whose
    // last byte matches `text`'s last byte can suffix-match, so the last-byte
    // buckets visit just those candidates in registry order.
    let mut hit: Option<DataLabel> = None;
    index.for_each_suffix_candidate(tlb, nlb, label_index_bucketed(), |e| {
        if match_suffix_cs(trimmed, e.matcher, e.case_sensitive)
            || match_suffix_cs(full_norm_bytes, e.matcher, e.case_sensitive)
        {
            hit = Some(e.label);
            true
        } else {
            false
        }
    });
    if hit.is_some() {
        return hit;
    }

    // Pass 2: prefix matches (catch-all, lower priority)
    for e in &index.prefix {
        if starts_with_cs(trimmed, e.matcher, e.case_sensitive)
            || starts_with_cs(full_norm_bytes, e.matcher, e.case_sensitive)
        {
            return Some(e.label);
        }
    }

    None
}

/// Classify a piece of syntax text, returning **all** matching labels.
///
/// Same two-pass (exact/suffix then prefix) structure as [`classify()`], but
/// collects every match instead of returning on first hit.  Deduplicates
/// exact `(variant, caps)` pairs.  Labels of the receiver-aliased text (see
/// `push_receiver_aliases`) are unioned in.
pub fn classify_all(
    lang: &str,
    text: &str,
    extra: Option<&[RuntimeLabelRule]>,
) -> SmallVec<[DataLabel; 2]> {
    let mut out = classify_all_aliased(lang, text, extra);
    if is_python_lang(lang)
        && let Some(qualified) = python_import_qualified(text)
    {
        for label in classify_all_aliased(lang, &qualified, extra) {
            if !out.contains(&label) {
                out.push(label);
            }
        }
    }
    out
}

/// [`classify_all_text`] plus the labels of the receiver-aliased text.
fn classify_all_aliased(
    lang: &str,
    text: &str,
    extra: Option<&[RuntimeLabelRule]>,
) -> SmallVec<[DataLabel; 2]> {
    let mut out = classify_all_text(lang, text, extra);
    if lang == "go"
        && out
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::HTML_ESCAPE)))
        && go::name_rule_sink_contradicts_declared_type(text, receiver_alias_prefix)
    {
        out.retain(|l| !matches!(l, DataLabel::Sink(c) if c.contains(Cap::HTML_ESCAPE)));
    }
    if let Some(aliased) = aliased_receiver_text(text) {
        for label in classify_all_text(lang, &aliased, extra) {
            if !out.contains(&label) {
                out.push(label);
            }
        }
    }
    out
}

fn classify_all_text(
    lang: &str,
    text: &str,
    extra: Option<&[RuntimeLabelRule]>,
) -> SmallVec<[DataLabel; 2]> {
    let view = CalleeView::of(lang, text);
    let mut out = classify_all_view(lang, &view, extra);
    if view.polymorphic_decode && !out.contains(&POLYMORPHIC_DECODE) {
        out.push(POLYMORPHIC_DECODE);
    }
    out
}

fn classify_all_view(
    lang: &str,
    view: &CalleeView<'_>,
    extra: Option<&[RuntimeLabelRule]>,
) -> SmallVec<[DataLabel; 2]> {
    let text = &*view.text;
    let head = view.head();
    let trimmed = head.trim().as_bytes();

    // Early out: exclude known-benign framework patterns.
    if is_excluded(lang, trimmed) {
        return SmallVec::new();
    }

    // `normalize_chained_call` returns `Cow::Borrowed` when no rewrite
    // is needed, so the alloc is paid only on inputs that actually
    // require it. The hot classify path runs on every CFG node.
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
    if let Some(index) = label_index_for(lang) {
        let tlb = trimmed.last().map(u8::to_ascii_lowercase);
        let nlb = full_norm_bytes.last().map(u8::to_ascii_lowercase);

        // Pass 1: exact / suffix matches (high confidence)
        index.for_each_suffix_candidate(tlb, nlb, label_index_bucketed(), |e| {
            if match_suffix_cs(trimmed, e.matcher, e.case_sensitive)
                || match_suffix_cs(full_norm_bytes, e.matcher, e.case_sensitive)
            {
                push_dedup(&mut out, e.label);
            }
            false
        });

        // Pass 2: prefix matches (catch-all, lower priority)
        for e in &index.prefix {
            if starts_with_cs(trimmed, e.matcher, e.case_sensitive)
                || starts_with_cs(full_norm_bytes, e.matcher, e.case_sensitive)
            {
                push_dedup(&mut out, e.label);
            }
        }
    }

    out
}

/// Classify a call with an optional [`ClassificationContext`] enabling
/// gated rule evaluation.
///
/// This is a strict superset of [`classify_all`]: the same flat-rule
/// matching runs first, then any per-language [`GatedLabelRule`] is
/// evaluated against `ctx`. A `None` context (or a context with no
/// `local_imports`) leaves only the synthetic receiver-type prefix
/// (e.g. `FileSystemPromisesNs.`) able to satisfy the gate.
pub fn classify_all_ctx(
    lang: &str,
    text: &str,
    extra: Option<&[RuntimeLabelRule]>,
    ctx: Option<&ClassificationContext<'_>>,
) -> SmallVec<[DataLabel; 2]> {
    let mut out = classify_all(lang, text, extra);
    classify_gated_into(lang, text, ctx, &mut out);
    out
}

/// Run only the gated-rule pass — skip the flat [`classify_all`] scan.
///
/// Use when the caller has already classified `text` with the flat rules
/// during initial CFG construction and only needs the gate-conditioned
/// labels (which require a per-file [`ClassificationContext`] not
/// available at the original classification site).
pub fn classify_gated_only(
    lang: &str,
    text: &str,
    ctx: Option<&ClassificationContext<'_>>,
) -> SmallVec<[DataLabel; 2]> {
    let mut out = SmallVec::new();
    classify_gated_into(lang, text, ctx, &mut out);
    out
}

fn classify_gated_into(
    lang: &str,
    text: &str,
    ctx: Option<&ClassificationContext<'_>>,
    out: &mut SmallVec<[DataLabel; 2]>,
) {
    for m in classify_gated_matches(lang, text, ctx) {
        if !out.contains(&m.label) {
            out.push(m.label);
        }
    }
}

/// Gated-rule pass that also reports each hit's payload positions, so a
/// caller that attaches the label can restrict the sink to the same args
/// a flat-rule [`SinkGate`] would (see [`GatedLabelRule::payload_args`]).
/// Hits are deduped by label; the first rule to contribute a label wins.
pub fn classify_gated_matches(
    lang: &str,
    text: &str,
    ctx: Option<&ClassificationContext<'_>>,
) -> SmallVec<[GatedLabelMatch; 2]> {
    let mut out: SmallVec<[GatedLabelMatch; 2]> = SmallVec::new();
    let gated = match GATED_LABEL_REGISTRY.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        GATED_LABEL_REGISTRY.get(key.as_str())
    }) {
        Some(g) => *g,
        None => return out,
    };
    if gated.is_empty() {
        return out;
    }

    let view = CalleeView::of(lang, text);
    let text = &*view.text;
    let head = view.head();
    let trimmed = head.trim().as_bytes();
    if is_excluded(lang, trimmed) {
        return out;
    }
    let full_normalized = normalize_chained_call(text);
    let full_norm_bytes = full_normalized.as_bytes();

    #[inline]
    fn push_dedup(
        out: &mut SmallVec<[GatedLabelMatch; 2]>,
        rule: &GatedLabelRule,
        chain_head: bool,
    ) {
        if !out.iter().any(|m| m.label == rule.label) {
            out.push(GatedLabelMatch {
                label: rule.label,
                payload_args: rule.payload_args,
                chain_head,
            });
        }
    }
    // `text` is a chain (`a(..).b`) whose head is what `trimmed` holds.
    let chained = text.contains('(');

    // Pass 1: exact / suffix.
    for rule in gated {
        for raw in rule.matchers {
            let m = raw.as_bytes();
            if m.last() == Some(&b'_') {
                continue;
            }
            let on_chain = match_suffix_cs(full_norm_bytes, m, rule.case_sensitive);
            let on_head = match_suffix_cs(trimmed, m, rule.case_sensitive);
            if (on_head || on_chain) && gate_satisfied(&rule.gate, head, ctx) {
                push_dedup(&mut out, rule, chained && !on_chain);
            }
        }
    }
    // Pass 2: prefix.
    for rule in gated {
        for raw in rule.matchers {
            let m = raw.as_bytes();
            if m.last() == Some(&b'_')
                && (starts_with_cs(trimmed, m, rule.case_sensitive)
                    || starts_with_cs(full_norm_bytes, m, rule.case_sensitive))
                && gate_satisfied(&rule.gate, head, ctx)
            {
                push_dedup(&mut out, rule, false);
            }
        }
    }
    out
}

/// Restricted payload-arg positions for known type-qualified sink callees.
///
/// Phase 07's ORM raw-SQL receiver methods (`TypeOrmRepo.query`,
/// `TypeOrmManager.query`, `MikroOrmEm.execute`, etc.) take the SQL
/// template at arg 0 and bind / parameter arrays at arg 1+. The flat
/// label rule alone cannot encode this and would FP on
/// `repo.query("SELECT $1", [tainted])`. When the type-qualified
/// resolver synthesises one of these callees, this lookup returns the
/// payload positions to which sink-taint checks must be restricted.
///
/// Sequelize.literal(sql) is single-arg, so `&[0]` is also correct
/// (no precision loss vs the unconditional flat rule).
pub fn type_qualified_sink_payload_args(qualified_callee: &str) -> Option<&'static [usize]> {
    match qualified_callee {
        "Sequelize.literal"
        | "TypeOrmRepo.query"
        | "TypeOrmRepo.createQueryBuilder"
        | "TypeOrmManager.query"
        | "TypeOrmManager.createQueryBuilder"
        | "MikroOrmEm.execute"
        // `ProcessBuilder.command(argList)` — arg 0 is the command list;
        // any later positional args are not part of the v1 shape.  Restrict
        // sink-taint scanning to arg 0 so receiver / unrelated args don't fire.
        | "ProcessBuilder.command" => Some(&[0]),
        _ => None,
    }
}

/// Receiver-type prefixes that count as a witness for a given module
/// specifier on a [`LabelGate::ImportedFromModule`] gate.
///
/// When SSA receiver-type qualification synthesises a callee like
/// `FileSystemPromisesNs.readFile(...)`, the leading identifier becomes
/// the type prefix rather than an imported binding. Each gate module
/// can declare which type prefixes legitimise the gate firing without
/// a textual import witness. Returning an empty slice means the gate
/// must fall back to the `local_imports` map alone.
fn receiver_type_prefixes_for_module(module: &str) -> &'static [&'static str] {
    if module.eq_ignore_ascii_case("node:fs/promises") || module.eq_ignore_ascii_case("fs/promises")
    {
        &["FileSystemPromisesNs"]
    } else {
        &[]
    }
}

/// Evaluate a [`LabelGate`] against the call's leading identifier and the
/// caller-supplied context. Receiver-type qualification can satisfy
/// [`LabelGate::ImportedFromModule`] via
/// [`receiver_type_prefixes_for_module`].
fn gate_satisfied(
    gate: &LabelGate,
    callee_head: &str,
    ctx: Option<&ClassificationContext<'_>>,
) -> bool {
    match gate {
        LabelGate::ImportedFromModule(modules) => {
            let leading = leading_identifier(callee_head);
            for m in modules.iter() {
                for prefix in receiver_type_prefixes_for_module(m) {
                    if leading == *prefix {
                        return true;
                    }
                }
            }
            let Some(ctx) = ctx else {
                return false;
            };
            let Some(map) = ctx.local_imports else {
                return false;
            };
            let Some(source_module) = map.get(leading) else {
                return false;
            };
            modules
                .iter()
                .any(|m| source_module.eq_ignore_ascii_case(m))
        }
        LabelGate::FileImportsModule(modules) => {
            let Some(ctx) = ctx else {
                return false;
            };
            let Some(map) = ctx.local_imports else {
                return false;
            };
            map.values().any(|source_module| {
                modules
                    .iter()
                    .any(|m| source_module.eq_ignore_ascii_case(m))
            })
        }
        LabelGate::FileImportsModuleAsLocalName {
            modules,
            local_names,
        } => {
            let Some(ctx) = ctx else {
                return false;
            };
            let Some(map) = ctx.local_imports else {
                return false;
            };
            local_names.iter().any(|name| {
                map.get(*name).is_some_and(|source_module| {
                    modules
                        .iter()
                        .any(|m| source_module.eq_ignore_ascii_case(m))
                })
            })
        }
    }
}

/// Leading identifier of a call expression's text — the segment up to the
/// first `.`, `:`, `(`, or `<`. Used to drive ImportTable lookups.
fn leading_identifier(callee_head: &str) -> &str {
    let bytes = callee_head.as_bytes();
    let mut end = 0;
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'.' | b':' | b'(' | b'<' | b' ' | b'[' => {
                end = i;
                return &callee_head[..end];
            }
            _ => {}
        }
        end = i + 1;
    }
    &callee_head[..end]
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
    // Backward-compatible entry point: assume every positional activation arg is
    // *present* (`|_| true`), which reproduces the historical
    // conservative-fire-on-unknown behaviour for callers that only know the
    // callee name (name-based cap lookups, chained-gate guards).  Callers that
    // hold the actual call node should use
    // [`classify_gated_sink_with_presence`] so a *missing* activation arg
    // suppresses rather than fires.
    classify_gated_sink_with_presence(
        lang,
        callee_text,
        const_arg_at,
        const_keyword_arg,
        kwarg_present,
        |_| true,
    )
}

/// Like [`classify_gated_sink`], but takes an `arg_present` predicate so a
/// positional `ValueMatch` gate whose activation argument is **absent** (never
/// passed at the call site) suppresses instead of firing conservatively.  A
/// *present-but-dynamic* activation arg (`arg_present` true, `const_arg_at`
/// `None`) still fires conservatively, because an attacker-controlled flag /
/// attribute is itself a vulnerability path.  Motivated by CVE-2025-48882
/// (PHPOffice/Math): the fix drops the `LIBXML_DTDLOAD` options arg entirely
/// (`$dom->loadXML($content)`), which is XXE-safe under the libxml >= 2.9
/// default; the missing options arg must not keep the gate firing.
pub fn classify_gated_sink_with_presence(
    lang: &str,
    callee_text: &str,
    const_arg_at: impl Fn(usize) -> Option<String>,
    const_keyword_arg: impl Fn(&str) -> Option<String>,
    kwarg_present: impl Fn(&str) -> bool,
    arg_present: impl Fn(usize) -> bool,
) -> SmallVec<[GateMatch; 2]> {
    let mut out = gated_sink_matches(
        lang,
        callee_text,
        &const_arg_at,
        &const_keyword_arg,
        &kwarg_present,
        &arg_present,
    );
    // `from subprocess import run` calls `run(cmd, shell=True)`: gate it as
    // `subprocess.run` too.
    if is_python_lang(lang)
        && let Some(qualified) = python_import_qualified(callee_text)
    {
        for m in gated_sink_matches(
            lang,
            &qualified,
            &const_arg_at,
            &const_keyword_arg,
            &kwarg_present,
            &arg_present,
        ) {
            if !out.contains(&m) {
                out.push(m);
            }
        }
    }
    out
}

fn gated_sink_matches(
    lang: &str,
    callee_text: &str,
    const_arg_at: &impl Fn(usize) -> Option<String>,
    const_keyword_arg: &impl Fn(&str) -> Option<String>,
    kwarg_present: &impl Fn(&str) -> bool,
    arg_present: &impl Fn(usize) -> bool,
) -> SmallVec<[GateMatch; 2]> {
    let out = classify_gated_sink_text(
        lang,
        callee_text,
        &const_arg_at,
        &const_keyword_arg,
        &kwarg_present,
        &arg_present,
    );
    if !out.is_empty() {
        return out;
    }
    // A receiver formal with a declared type (`c *http.Client`) also matches
    // the gates keyed on its canonical prefix (`HttpClient.Get`).
    match aliased_receiver_text(callee_text) {
        Some(aliased) => classify_gated_sink_text(
            lang,
            &aliased,
            &const_arg_at,
            &const_keyword_arg,
            &kwarg_present,
            &arg_present,
        ),
        None => out,
    }
}

fn classify_gated_sink_text(
    lang: &str,
    callee_text: &str,
    const_arg_at: &impl Fn(usize) -> Option<String>,
    const_keyword_arg: &impl Fn(&str) -> Option<String>,
    kwarg_present: &impl Fn(&str) -> bool,
    arg_present: &impl Fn(usize) -> bool,
) -> SmallVec<[GateMatch; 2]> {
    let mut out: SmallVec<[GateMatch; 2]> = SmallVec::new();
    let gate_set = match GATED_REGISTRY.get(lang).or_else(|| {
        let key = lang.to_ascii_lowercase();
        GATED_REGISTRY.get(key.as_str())
    }) {
        Some(g) => *g,
        None => return out,
    };

    // Match against the original callee text AND a chain-normalised form
    // that strips `()` between dots so a chained construction like
    // `httpx.AsyncClient().post` matches a gate matcher of
    // `httpx.AsyncClient.post`.  Mirrors the normalisation applied by
    // `classify` for flat label rules.
    let callee_view = CalleeView::of(lang, callee_text);
    let callee_text = &*callee_view.text;
    let callee_bytes = callee_text.as_bytes();
    let normalized = normalize_chained_call(callee_text);
    let normalized_bytes = normalized.as_bytes();

    for gi in gate_set.candidates(
        callee_bytes.last().copied(),
        normalized_bytes.last().copied(),
    ) {
        let gate = &gate_set.gates[gi as usize];
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
                        if values.iter().any(|dv| v.eq_ignore_ascii_case(dv)) {
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
                let is_dangerous = gate
                    .dangerous_values
                    .iter()
                    .any(|v| value.eq_ignore_ascii_case(v))
                    || gate
                        .dangerous_prefixes
                        .iter()
                        .any(|p| starts_with_ignore_ascii_case(&value, p));
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
            //
            // `LiteralOnly` opts out of this conservative branch: the gate
            // requires positive literal evidence to fire, so unknown
            // activation suppresses entirely (avoids false positives on
            // ambiguously-named suffix matchers like bare `extend`).
            None => {
                if matches!(gate.activation, GateActivation::LiteralOnly) {
                    continue;
                }
                // Positional gate whose activation arg is ABSENT (never passed
                // at the call site): the guarded flag / attribute cannot hold a
                // dangerous value, so the call takes the language default and
                // the gate must not fire.  Only a PRESENT-but-dynamic activation
                // arg reaches the conservative push below.  Keyword-selected
                // gates keep their prior semantics (handled by the multi-kwarg
                // presence path above / single-kwarg lookup).  Motivated by
                // CVE-2025-48882: `loadXML($content)` (no `$options`) is XXE-safe.
                if gate.keyword_name.is_none() && !arg_present(gate.arg_index) {
                    continue;
                }
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

/// Drop Rust generic-argument groups (`::<..>`) from a callee text.
///
/// `sqlx::query_as::<_, User>(&q)` is the same call as `sqlx::query_as(&q)` for
/// classification, but the head split at `<` leaves `sqlx::query_as::`, whose
/// trailing `::` defeats every suffix matcher.  A following path segment stays,
/// so `Foo::<T>::new` becomes `Foo::new`.  An unterminated group truncates the
/// text, which matches what the `<` split did before.  Borrows when the text
/// has no `::<`.
fn strip_turbofish(text: &str) -> std::borrow::Cow<'_, str> {
    let Some(first) = text.find("::<") else {
        return std::borrow::Cow::Borrowed(text);
    };
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0usize;
    let mut at = first;
    loop {
        out.push_str(&text[copied..at]);
        // A turbofish on a method (`res.json::<T>()`, `row.get::<_, T>(0)`)
        // selects a return type; the callee is still the plain method and its
        // text must keep truncating at the `<`, as before.  `Response::json<T>`
        // is a decoder, not the actix response builder `.json(value)` that a
        // bare `json` sink rule models.  Only path calls such as
        // `sqlx::query_as::<_, User>` are normalised.
        if segment_is_method(&text[..at]) {
            out.push_str(&text[at..]);
            return std::borrow::Cow::Owned(out);
        }
        let mut depth = 1u32;
        let mut j = at + 3;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                b'<' => depth += 1,
                // `->` inside a `fn(..) -> T` argument is not a closer.
                b'>' if bytes[j - 1] != b'-' => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        if depth > 0 {
            return std::borrow::Cow::Owned(out);
        }
        copied = j;
        match text[copied..].find("::<") {
            Some(off) => at = copied + off,
            None => {
                out.push_str(&text[copied..]);
                return std::borrow::Cow::Owned(out);
            }
        }
    }
}

/// `toml::from_str::<Box<dyn Plugin>>` selects the concrete type from the
/// document (typetag style), unlike the same call into a concrete struct, so
/// it is a deserialisation sink while the typed-config form is not.
/// `stripped` is `text` with its turbofish removed.
fn is_polymorphic_decode(text: &str, stripped: &str) -> bool {
    let head = stripped.split('(').next().unwrap_or("").trim();
    if !is_polymorphic_decode_head(head) {
        return false;
    }
    let Some(at) = text.find("::<") else {
        return false;
    };
    let generic = &text[at..];
    let generic = generic.split('(').next().unwrap_or(generic);
    rust_decode_target_is_dyn(generic)
}

/// Whether `head` (a callee path with no turbofish or arguments) is a
/// `toml` / `ron` decode whose target type picks the concrete type.
pub(crate) fn is_polymorphic_decode_head(head: &str) -> bool {
    matches!(
        head,
        "toml::from_str" | "toml::from_slice" | "ron::from_str" | "ron::from_bytes"
    ) || head.ends_with("::toml::from_str")
        || head.ends_with("::ron::from_str")
}

/// Whether the value a decode produces is a trait object, given the type
/// text of an annotation or turbofish (`Box<dyn P>`, `Result<Box<dyn P>, E>`,
/// `::<Box<dyn P>>`).  `Result` and `Option` are unwrapped to their first
/// generic argument, so a `dyn` in the error type (`Box<dyn Error>`) does not
/// count.
pub(crate) fn rust_decode_target_is_dyn(type_text: &str) -> bool {
    let mut t = type_text.trim();
    t = t.strip_prefix("::").unwrap_or(t).trim_start();
    // A turbofish group: keep only the text up to its closing `>`.
    let mut ty = t;
    if let Some(inner) = t.strip_prefix('<') {
        ty = inner;
    }
    loop {
        let ty_trim = ty.trim_start();
        let Some(lt) = ty_trim.find('<') else {
            return rust_target_is_dyn(ty_trim);
        };
        let head = ty_trim[..lt].trim();
        let name = head.rsplit("::").next().unwrap_or(head).trim();
        if name != "Result" && name != "Option" {
            return rust_target_is_dyn(ty_trim);
        }
        // First generic argument, up to a top-level comma or the closing `>`.
        let rest = &ty_trim[lt + 1..];
        let mut depth = 0i32;
        let mut end = rest.len();
        for (i, c) in rest.char_indices() {
            match c {
                '<' | '(' | '[' => depth += 1,
                '>' | ')' | ']' => {
                    if depth == 0 {
                        end = i;
                        break;
                    }
                    depth -= 1;
                }
                ',' if depth == 0 => {
                    end = i;
                    break;
                }
                _ => {}
            }
        }
        ty = &rest[..end];
    }
}

/// Whether a Rust type text names a trait object (`Box<dyn Plugin>`), as a
/// whole `dyn` word.
pub(crate) fn rust_target_is_dyn(type_text: &str) -> bool {
    type_text
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == "dyn")
}

/// The label of a polymorphic decode ([`is_polymorphic_decode`]).
pub(crate) const POLYMORPHIC_DECODE: DataLabel = DataLabel::Sink(Cap::DESERIALIZE);

/// Whether the path segment ending `before` is reached through a `.`, i.e. is
/// a method call rather than a `::` path segment.
fn segment_is_method(before: &str) -> bool {
    let seg_start = before
        .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
        .map_or(0, |i| i + 1);
    before[..seg_start].ends_with('.')
}

/// Byte offset of the first `(` or `<` in `text`, where the callee head ends.
#[inline]
fn head_end(text: &str) -> usize {
    text.bytes()
        .position(|b| b == b'(' || b == b'<')
        .unwrap_or(text.len())
}

/// A callee text as the classifier reads it: the text with Rust generic
/// groups removed ([`strip_turbofish`]), where its head ends, and whether it
/// is a polymorphic decode.
///
/// Every classification builds one, and almost no callee has a generic group,
/// so the head scan the classifier needs anyway decides it: the text is
/// rewritten only when that head ends at a `<`.  A path turbofish can only
/// follow the callee path (a `::<` after a `(` is inside an argument, which no
/// suffix matcher reads, or on a method, which keeps its text).
struct CalleeView<'a> {
    text: std::borrow::Cow<'a, str>,
    head_end: usize,
    polymorphic_decode: bool,
}

impl<'a> CalleeView<'a> {
    #[inline]
    fn of(lang: &str, text: &'a str) -> Self {
        let end = head_end(text);
        if text.as_bytes().get(end) == Some(&b'<') && (lang == "rust" || lang == "rs") {
            let stripped = strip_turbofish(text);
            let polymorphic_decode = is_polymorphic_decode(text, &stripped);
            let head_end = head_end(&stripped);
            return CalleeView {
                text: stripped,
                head_end,
                polymorphic_decode,
            };
        }
        CalleeView {
            text: std::borrow::Cow::Borrowed(text),
            head_end: end,
            polymorphic_decode: false,
        }
    }

    #[inline]
    fn head(&self) -> &str {
        &self.text[..self.head_end]
    }
}

/// Public wrapper for `normalize_chained_call` so callers outside the module
/// can share the same normalization used by the label classifier.
pub fn normalize_chained_call_for_classify(text: &str) -> String {
    normalize_chained_call(text).into_owned()
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
///
/// Returns a borrow when no transformation is required (no `()` between
/// `.` segments and no leading `<`), avoiding the heap allocation. Only
/// pays for a `String` when the input actually needs rewriting; the hot
/// classify path runs on every CFG node so the borrow case dominates.
///
/// The rewrite starts at the first offset where a left-to-right scan has
/// to act: a `(` whose matching `)` ends the text or is followed by `.` (or
/// that never closes), or a `<`.  One pass with a stack of open parens
/// finds it, so callee texts that carry whole callback bodies
/// (`wrap(function(){...}).then`) cost O(len) rather than O(len * nesting).
fn normalize_chained_call(text: &str) -> std::borrow::Cow<'_, str> {
    let bytes = text.as_bytes();
    let mut open: SmallVec<[usize; 8]> = SmallVec::new();
    let mut first_collapse = usize::MAX;
    let mut first_angle = usize::MAX;
    for (k, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => open.push(k),
            b')' => {
                if let Some(i) = open.pop()
                    && (k + 1 >= bytes.len() || chain_dot_at(bytes, k + 1).is_some())
                {
                    first_collapse = first_collapse.min(i);
                }
            }
            b'<' if first_angle == usize::MAX => {
                first_angle = k;
                // Nothing past this `<` can matter unless an open `(` before
                // it may still close into a collapsing group.
                if open.is_empty() {
                    break;
                }
            }
            _ => {}
        }
    }
    // A `(` that never closes collapses like one closing at end of text.
    if let Some(&i) = open.first() {
        first_collapse = first_collapse.min(i);
    }
    if first_collapse < first_angle {
        std::borrow::Cow::Owned(normalize_chained_call_owned(text, first_collapse))
    } else if first_angle != usize::MAX {
        std::borrow::Cow::Borrowed(&text[..first_angle])
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

/// Offset of the `.` that continues a call chain at `at`, allowing the
/// whitespace a formatter leaves when it breaks a chain before `.method`.
#[inline]
fn chain_dot_at(bytes: &[u8], at: usize) -> Option<usize> {
    let mut k = at;
    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
        k += 1;
    }
    (k < bytes.len() && bytes[k] == b'.').then_some(k)
}

/// Every `(` at or after `from` with the offset just past its matching `)`
/// (`bytes.len()` when it never closes).  Returns the `(` offsets in
/// ascending order and the parallel group ends, so a lookup is a binary
/// search and memory is per paren, not per byte.
fn paren_group_ends(bytes: &[u8], from: usize) -> (Vec<usize>, Vec<usize>) {
    let mut opens: Vec<usize> = Vec::new();
    let mut ends: Vec<usize> = Vec::new();
    let mut stack: SmallVec<[usize; 8]> = SmallVec::new();
    for (k, &b) in bytes.iter().enumerate().skip(from) {
        match b {
            b'(' => {
                stack.push(opens.len());
                opens.push(k);
                ends.push(bytes.len());
            }
            b')' => {
                if let Some(o) = stack.pop() {
                    ends[o] = k + 1;
                }
            }
            _ => {}
        }
    }
    (opens, ends)
}

/// Slow path for `normalize_chained_call`: runs only when the input
/// actually contains a `(...)` group followed by `.` (the case that
/// requires removing characters). `prefix_end` is the byte offset of the
/// first transformation point so the prefix can be copied wholesale.
///
/// `(`, `)`, `<`, and `.` are all ASCII, so byte-level scanning is safe
/// for control characters. Non-ASCII identifier bytes are copied as
/// contiguous slices to keep multi-byte UTF-8 sequences intact.
fn normalize_chained_call_owned(text: &str, prefix_end: usize) -> String {
    let bytes = text.as_bytes();
    let (paren_opens, paren_ends) = paren_group_ends(bytes, prefix_end);
    let mut result = String::with_capacity(text.len());
    result.push_str(&text[..prefix_end]);
    let mut i = prefix_end;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                let j = paren_opens
                    .binary_search(&i)
                    .map_or(bytes.len(), |o| paren_ends[o]);
                if j >= bytes.len() {
                    i = j;
                } else if let Some(dot) = chain_dot_at(bytes, j) {
                    i = dot;
                } else {
                    result.push('(');
                    i += 1;
                }
            }
            b'<' => break,
            _ => {
                let start = i;
                while i < bytes.len() && !matches!(bytes[i], b'(' | b'<') {
                    i += 1;
                }
                result.push_str(&text[start..i]);
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
        description: "Attacker-controlled data flows into a filesystem path without canonicalisation \
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
        description: "Attacker-controlled data is used as a format string argument (printf-family, \
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
        description: "Attacker-controlled data is concatenated into a SQL query string instead of \
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
        description: "Attacker-controlled bytes are fed to an unsafe object deserialiser \
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
        description: "Attacker-controlled URL reaches the destination of an outbound HTTP request \
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
        description: "Attacker-controlled data reaches an `eval`/`exec`/shell sink, dynamic \
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
        description: "Attacker-controlled data drives the algorithm name, key, or seed of a \
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
        description: "Request-bound identifier reaches a privileged sink without an intervening \
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
        description: "Sensitive data (cookies, headers, env, db rows, files) flows into the body, \
             headers, or other payload field of an outbound network request to a fixed \
             destination.",
        default_enabled: true,
        emission_active: true,
    },
    // ── Cap-specific rule ids ────────────────────────────────────────────
    CapRuleMeta {
        cap: Cap::LDAP_INJECTION,
        rule_id: "taint-ldap-injection",
        title: "LDAP Injection",
        severity: crate::patterns::Severity::High,
        owasp_code: "A03",
        owasp_label: "Injection",
        description: "Attacker-controlled data is concatenated into an LDAP filter or DN without \
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
        description: "Attacker-controlled data is concatenated into an XPath expression instead of \
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
        description: "Attacker-controlled data lands in an HTTP response header without `\\r\\n` \
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
        description: "Attacker-controlled URL drives a redirect / `Location` header without an \
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
        description: "Attacker controls the template *source string* (not just template variables) \
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
        description: "Attacker-controlled XML reaches a parser configured to resolve external \
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
        description: "Attacker-controlled key reaches an object property assignment that can mutate \
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
        if let Some(gate_set) = GATED_REGISTRY.get(lang) {
            for gate in gate_set.gates {
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

/// Final path component of a program name, lower-cased, without a `.exe`
/// suffix: `/bin/Bash` and `C:\\Windows\\cmd.EXE` become `bash` and `cmd`.
fn program_leaf(name: &str) -> String {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = leaf.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

fn is_shell_program(leaf: &str) -> bool {
    matches!(
        leaf,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "ash"
            | "fish"
            | "csh"
            | "tcsh"
            | "cmd"
            | "powershell"
            | "pwsh"
    )
}

fn is_interpreter_program(leaf: &str) -> bool {
    [
        "python", "pypy", "ruby", "perl", "php", "lua", "node", "deno", "bun",
    ]
    .iter()
    .any(|p| leaf.starts_with(p))
}

fn is_wrapper_program(leaf: &str) -> bool {
    matches!(
        leaf,
        "env"
            | "sudo"
            | "doas"
            | "nice"
            | "nohup"
            | "timeout"
            | "stdbuf"
            | "setsid"
            | "xargs"
            | "busybox"
            | "command"
            | "exec"
            | "time"
            | "ionice"
            | "chroot"
            | "su"
            | "runuser"
    )
}

/// True when running `name` can evaluate a string or script it is handed as
/// code: a shell, a language interpreter, or a wrapper that runs another
/// program (`env`, `sudo`, `timeout`).  Used to decide that an argv-form
/// `system` / `Popen` is not shell-free: the program is chosen literally, but
/// its arguments are still run as code.
pub fn is_command_runner_program(name: &str) -> bool {
    let leaf = program_leaf(name);
    is_shell_program(&leaf) || is_interpreter_program(&leaf) || is_wrapper_program(&leaf)
}

/// True when `name` is a wrapper such as `env` or `sudo` that runs the
/// program named by one of its later arguments.
pub fn is_wrapper_command(name: &str) -> bool {
    is_wrapper_program(&program_leaf(name))
}

/// True when `flag` makes the shell or interpreter `program` run the next
/// argument as code: `-c` and clustered forms such as `-lc` for POSIX shells,
/// `/c` and `/k` for cmd, `-Command` for PowerShell, and the eval switch of
/// the common interpreters (`python -c`, `ruby -e`, `perl -e`, `node -e`,
/// `php -r`).
pub fn is_code_flag(program: &str, flag: &str) -> bool {
    let leaf = program_leaf(program);
    let lower = flag.to_ascii_lowercase();
    if leaf == "cmd" {
        return matches!(lower.as_str(), "/c" | "/k");
    }
    if leaf == "powershell" || leaf == "pwsh" {
        return matches!(
            lower.as_str(),
            "-c" | "-command" | "-encodedcommand" | "-ec" | "-e"
        );
    }
    let cluster = |chars: &str| {
        flag.len() > 1
            && flag.starts_with('-')
            && !flag.starts_with("--")
            && flag[1..].chars().all(|c| c.is_ascii_alphabetic())
            && flag[1..].chars().any(|c| chars.contains(c))
    };
    if is_shell_program(&leaf) {
        return cluster("c");
    }
    if leaf.starts_with("python") || leaf.starts_with("pypy") {
        return cluster("c");
    }
    if leaf.starts_with("ruby") || leaf.starts_with("perl") || leaf == "lua" {
        return cluster("eE");
    }
    if leaf.starts_with("php") {
        return cluster("r");
    }
    if matches!(leaf.as_str(), "node" | "deno" | "bun") {
        return cluster("ep") || matches!(flag, "--eval" | "--print");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference (pre-index) linear built-in `classify`: walks every matcher of
    /// every rule in registry order, exactly as the old inner loops did. Pins
    /// the `LabelIndex` dispatch against the naive scan.
    fn ref_classify(lang: &str, text: &str) -> Option<DataLabel> {
        let view = CalleeView::of(lang, text);
        let text = &*view.text;
        let head = view.head();
        let trimmed = head.trim().as_bytes();
        if is_excluded(lang, trimmed) {
            return None;
        }
        let full = normalize_chained_call(text);
        let fb = full.as_bytes();
        let rules = REGISTRY.get(lang).or_else(|| {
            let k = lang.to_ascii_lowercase();
            REGISTRY.get(k.as_str())
        })?;
        for rule in *rules {
            for raw in rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_') {
                    continue;
                }
                if match_suffix_cs(trimmed, m, rule.case_sensitive)
                    || match_suffix_cs(fb, m, rule.case_sensitive)
                {
                    return Some(rule.label);
                }
            }
        }
        for rule in *rules {
            for raw in rule.matchers {
                let m = raw.as_bytes();
                if m.last() == Some(&b'_')
                    && (starts_with_cs(trimmed, m, rule.case_sensitive)
                        || starts_with_cs(fb, m, rule.case_sensitive))
                {
                    return Some(rule.label);
                }
            }
        }
        None
    }

    /// Reference (pre-index) linear built-in `classify_all`.
    fn ref_classify_all(lang: &str, text: &str) -> SmallVec<[DataLabel; 2]> {
        let view = CalleeView::of(lang, text);
        let text = &*view.text;
        let head = view.head();
        let trimmed = head.trim().as_bytes();
        let mut out: SmallVec<[DataLabel; 2]> = SmallVec::new();
        if is_excluded(lang, trimmed) {
            return out;
        }
        let full = normalize_chained_call(text);
        let fb = full.as_bytes();
        let push = |out: &mut SmallVec<[DataLabel; 2]>, l: DataLabel| {
            if !out.contains(&l) {
                out.push(l);
            }
        };
        if let Some(rules) = REGISTRY.get(lang).or_else(|| {
            let k = lang.to_ascii_lowercase();
            REGISTRY.get(k.as_str())
        }) {
            for rule in *rules {
                for raw in rule.matchers {
                    let m = raw.as_bytes();
                    if m.last() == Some(&b'_') {
                        continue;
                    }
                    if match_suffix_cs(trimmed, m, rule.case_sensitive)
                        || match_suffix_cs(fb, m, rule.case_sensitive)
                    {
                        push(&mut out, rule.label);
                    }
                }
            }
            for rule in *rules {
                for raw in rule.matchers {
                    let m = raw.as_bytes();
                    if m.last() == Some(&b'_')
                        && (starts_with_cs(trimmed, m, rule.case_sensitive)
                            || starts_with_cs(fb, m, rule.case_sensitive))
                    {
                        push(&mut out, rule.label);
                    }
                }
            }
        }
        out
    }

    /// The last-byte dispatch index must be byte-identical to the linear scan
    /// for both `classify` (first match) and `classify_all` (ordered multi),
    /// across every matcher of every language plus boundary/case/miss shapes.
    #[test]
    fn label_index_matches_linear_scan_over_full_registry() {
        let langs = [
            "rust",
            "rs",
            "javascript",
            "js",
            "typescript",
            "ts",
            "python",
            "py",
            "go",
            "java",
            "c",
            "cpp",
            "c++",
            "php",
            "ruby",
            "rb",
        ];
        // Extra freeform probes that stress misses, empty, boundaries, chains.
        let extra_texts = [
            "",
            "x",
            "a.b.c",
            "randomFunctionName",
            "foo.bar.Baz",
            "r.URL.Query().Get",
            "obj.method(arg)",
            "Some::Path::to::thing",
            "OPEN",
            "Execute",
            "sqlx::query_as::<_, User>(&q).fetch_all",
            "Foo::<T>::new",
        ];
        for lang in langs {
            let rules = match REGISTRY.get(lang) {
                Some(r) => *r,
                None => continue,
            };
            let mut texts: Vec<String> = extra_texts.iter().map(|s| s.to_string()).collect();
            for rule in rules {
                for raw in rule.matchers {
                    let stripped = raw.strip_prefix('=').unwrap_or(raw);
                    // Exercise each matcher as a hit and in boundary/case forms.
                    texts.push(stripped.to_string());
                    texts.push(format!("obj.{stripped}"));
                    texts.push(format!("Mod::{stripped}"));
                    texts.push(format!("x{stripped}")); // no boundary — exact-only/`.`
                    texts.push(stripped.to_ascii_uppercase());
                    texts.push(format!("{stripped}(a, b)"));
                }
            }
            for text in &texts {
                assert_eq!(
                    classify(lang, text, None),
                    ref_classify(lang, text),
                    "classify mismatch lang={lang} text={text:?}"
                );
                assert_eq!(
                    classify_all(lang, text, None).into_vec(),
                    ref_classify_all(lang, text).into_vec(),
                    "classify_all mismatch lang={lang} text={text:?}"
                );
            }
        }
    }

    /// Pin the current set of caps whose `rule_id` is reachable via the
    /// diag-id routing in `ast.rs::diag_for_finding`.  When migrating a
    /// legacy cap (e.g. SQL_QUERY → `taint-sql-injection`), update both
    /// `ast.rs` (add the cap to the cap-specific routing list) and the
    /// `emission_active: true` flag in `CAP_RULE_REGISTRY`, then update
    /// this assertion.  The split exists because legacy taint findings
    /// historically all surfaced under the generic `taint-unsanitised-flow`
    /// rule id; the seven cap-specific routes (LDAP / XPath / header /
    /// open redirect / SSTI / XXE / prototype pollution) plus
    /// `unauthorized_id` and `data_exfil` are the only ones wired through.
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
    fn normalize_chained_call_borrows_when_no_change() {
        // No parens, no `<` → no rewrite, borrow returned.
        let r = normalize_chained_call("plain");
        assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
        assert_eq!(r.as_ref(), "plain");

        // `(` mid-token but not at end of any `.` chain → still owned
        // because the function's policy collapses any `(` followed by
        // EOL or `.`. Use a callee with a non-collapsing shape: bare
        // dotted text.
        let r = normalize_chained_call("a.b.c");
        assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
        assert_eq!(r.as_ref(), "a.b.c");

        // Truncate at `<` (generics) is a borrow with shorter slice.
        let r = normalize_chained_call("Vec<T>");
        assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
        assert_eq!(r.as_ref(), "Vec");
    }

    #[test]
    fn normalize_chained_call_collapses_paren_dot_chain() {
        let r = normalize_chained_call("r.URL.Query().Get");
        assert_eq!(r.as_ref(), "r.URL.Query.Get");

        let r = normalize_chained_call("a.b().c().d");
        assert_eq!(r.as_ref(), "a.b.c.d");

        // Last paren-call before EOL is also collapsed (j >= bytes.len()).
        let r = normalize_chained_call("a.b()");
        assert_eq!(r.as_ref(), "a.b");
    }

    /// The quadratic scan `normalize_chained_call` used before it learned
    /// to match parens in one pass.  Kept as the reference the linear
    /// version must agree with byte for byte.
    fn normalize_chained_call_reference(text: &str) -> String {
        fn group_end(bytes: &[u8], i: usize) -> usize {
            let mut depth = 1u32;
            let mut j = i + 1;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            j
        }
        let bytes = text.as_bytes();
        let mut i = 0;
        let mut prefix_end = None;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => {
                    let j = group_end(bytes, i);
                    if j >= bytes.len() || bytes[j] == b'.' {
                        prefix_end = Some(i);
                        break;
                    }
                    i += 1;
                }
                b'<' => return text[..i].to_string(),
                _ => i += 1,
            }
        }
        let Some(prefix_end) = prefix_end else {
            return text.to_string();
        };
        let mut result = String::from(&text[..prefix_end]);
        let mut i = prefix_end;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => {
                    let j = group_end(bytes, i);
                    if j >= bytes.len() || bytes[j] == b'.' {
                        i = j;
                    } else {
                        result.push('(');
                        i += 1;
                    }
                }
                b'<' => break,
                _ => {
                    let start = i;
                    while i < bytes.len() && !matches!(bytes[i], b'(' | b'<') {
                        i += 1;
                    }
                    result.push_str(&text[start..i]);
                }
            }
        }
        result
    }

    #[test]
    fn normalize_chained_call_matches_reference_scan() {
        // Hand-picked shapes: nested groups, unmatched and stray parens,
        // `<` inside and after groups, callback bodies in the chain.
        let cases = [
            "",
            "a",
            "(",
            ")",
            "()",
            "(.",
            ").(",
            "f(x)",
            "f(x).g",
            "f(g(x)).h(y)",
            "f(g(x).h)(y)",
            "f(a(b(c)))z",
            "f(a(b(c)).d)z",
            "f((x)",
            "f(x))).g",
            "a.b(c<d>).e",
            "a<b>(c).d",
            "a(b<c).d",
            "a(b(c<d).e)f",
            "items.filter(function(x){ return g(x).h; }).map",
            "wrap(function(){ a(b(c)).d(); }).then",
            "Vec::<u8>::new().len",
            "s.parse::<u32>().unwrap",
            "x.y().🦀_id(z).w",
        ];
        for c in cases {
            assert_eq!(
                normalize_chained_call(c).as_ref(),
                normalize_chained_call_reference(c),
                "input {c:?}"
            );
        }
        // Every string up to length 6 over a small alphabet that exercises
        // all the bytes the scan reacts to.
        let alphabet = ['(', ')', '.', '<', 'a'];
        for len in 0..=6u32 {
            for code in 0..alphabet.len().pow(len) {
                let s: String = (0..len)
                    .map(|d| alphabet[(code / alphabet.len().pow(d)) % alphabet.len()])
                    .collect();
                assert_eq!(
                    normalize_chained_call(&s).as_ref(),
                    normalize_chained_call_reference(&s),
                    "input {s:?}"
                );
            }
        }
    }

    #[test]
    fn normalize_chained_call_preserves_utf8_after_collapse() {
        // Greek lowercase letters are 2-byte UTF-8 sequences.  The slow
        // path must not split them when copying tail bytes after a
        // collapsed `(...)` group.
        let r = normalize_chained_call("obj.func().αβγ");
        assert_eq!(r.as_ref(), "obj.func.αβγ");

        // CJK ideographs are 3-byte sequences.  Same invariant.
        let r = normalize_chained_call("a.b().名前");
        assert_eq!(r.as_ref(), "a.b.名前");

        // Emoji (4-byte sequence) inside an identifier.  Engines never
        // see this in practice but the byte loop must not corrupt it.
        let r = normalize_chained_call("x.y().🦀_id");
        assert_eq!(r.as_ref(), "x.y.🦀_id");
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

    // CVE-2024-37896 (gin-vue-admin ORDER BY injection):
    // GORM query-builder methods take a raw SQL fragment at arg 0.  The
    // terminal / assigned form (`db = db.Order(x)`) resolves by suffix on a
    // `db`-named receiver; the `GormDb.<verb>` variant covers `gorm.Open`-typed
    // receivers with other names.  Each is also a payload-arg-0 gate so the
    // parameterised `db.Where("col = ?", val)` form stays silent.
    #[test]
    fn classify_go_gorm_order_is_sql_query_sink() {
        assert_eq!(
            classify("go", "db.Order", None),
            Some(DataLabel::Sink(Cap::SQL_QUERY))
        );
    }

    #[test]
    fn classify_go_gorm_where_and_group_are_sql_query_sinks() {
        assert_eq!(
            classify("go", "db.Where", None),
            Some(DataLabel::Sink(Cap::SQL_QUERY))
        );
        assert_eq!(
            classify("go", "db.Group", None),
            Some(DataLabel::Sink(Cap::SQL_QUERY))
        );
    }

    #[test]
    fn classify_go_gorm_typed_order_is_sql_query_sink() {
        assert_eq!(
            classify("go", "GormDb.Order", None),
            Some(DataLabel::Sink(Cap::SQL_QUERY))
        );
    }

    #[test]
    fn classify_go_gorm_where_gate_targets_payload_arg_zero() {
        let no_kw = |_: &str| None;
        let no_kw_present = |_: &str| false;
        let result = classify_gated_sink("go", "db.Where", |_| None, no_kw, no_kw_present);
        let m = result
            .iter()
            .find(|m| m.label == DataLabel::Sink(Cap::SQL_QUERY))
            .expect("expected SQL_QUERY gate for db.Where");
        // SQL string at arg 0; bind values at arg 1+ travel the parameterised
        // path and must not be scanned for taint.
        assert_eq!(m.payload_args, &[0]);
    }

    #[test]
    fn classify_go_non_gorm_db_method_is_not_sink() {
        // A non-GORM builder method must not become a SQL sink just because the
        // receiver ends in `db`.
        assert_eq!(classify("go", "db.Limit", None), None);
        assert_eq!(classify("go", "db.Offset", None), None);
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
        // `client.Get` on a user-named *http.Client variable does not match
        // by name.  A client is reached through its declared type instead:
        // the `HttpClient.*` gates (see `go_typed_client_gates_split_url_and_body`).
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
    fn classify_javascript_set_value_is_proto_pollution_gate() {
        let no_kw = |_: &str| None;
        let no_kw_present = |_: &str| false;
        let result = classify_gated_sink("javascript", "setValue", |_| None, no_kw, no_kw_present);
        assert!(
            result
                .iter()
                .any(|m| m.label == DataLabel::Sink(Cap::PROTOTYPE_POLLUTION)),
            "expected PROTOTYPE_POLLUTION gate match for bare `setValue`, got {result:?}"
        );
    }

    #[test]
    fn classify_javascript_dot_prop_set_is_proto_pollution_gate() {
        let no_kw = |_: &str| None;
        let no_kw_present = |_: &str| false;
        let result =
            classify_gated_sink("javascript", "dotProp.set", |_| None, no_kw, no_kw_present);
        assert!(
            result
                .iter()
                .any(|m| m.label == DataLabel::Sink(Cap::PROTOTYPE_POLLUTION)),
            "expected PROTOTYPE_POLLUTION gate match for `dotProp.set`, got {result:?}"
        );
    }

    #[test]
    fn classify_ruby_bare_open_is_shell_escape_sink() {
        let result = classify("ruby", "open", None);
        assert_eq!(result, Some(DataLabel::Sink(Cap::SHELL_ESCAPE)));
    }

    #[test]
    fn classify_ruby_bare_system_exec_are_shell_escape_sinks() {
        // The receiver-less Kernel#system / Kernel#exec primitives keep the
        // SHELL_ESCAPE classification via the `=system` / `=exec` exact-match
        // matchers (CVE-2026-42087 regression guard).
        assert_eq!(
            classify("ruby", "system", None),
            Some(DataLabel::Sink(Cap::SHELL_ESCAPE))
        );
        assert_eq!(
            classify("ruby", "exec", None),
            Some(DataLabel::Sink(Cap::SHELL_ESCAPE))
        );
    }

    #[test]
    fn classify_ruby_receiver_exec_is_not_shell_escape_sink() {
        // `conn.exec(sql)` on a typed receiver must NOT pick up the bare
        // Kernel#exec SHELL_ESCAPE label — the `=exec` exact-match sigil only
        // fires on the receiver-less form so the type-qualified
        // `DatabaseConnection.exec` SQL sink can take over.  Core of the
        // CVE-2026-42087 cmdi-misclassification fix.
        let result = classify_all("ruby", "conn.exec", None);
        assert!(!result.contains(&DataLabel::Sink(Cap::SHELL_ESCAPE)));
    }

    #[test]
    fn classify_ruby_database_connection_exec_is_sql_sink() {
        // Type-qualified raw `pg` driver sink: the resolver rewrites a
        // DatabaseConnection-typed `conn.exec(sql)` to `DatabaseConnection.exec`.
        assert_eq!(
            classify("ruby", "DatabaseConnection.exec", None),
            Some(DataLabel::Sink(Cap::SQL_QUERY))
        );
        assert_eq!(
            classify("ruby", "DatabaseConnection.exec_query", None),
            Some(DataLabel::Sink(Cap::SQL_QUERY))
        );
    }

    #[test]
    fn classify_ruby_database_connection_exec_params_is_not_sink() {
        // The parameterised `exec_params` / `exec_prepared` forms use libpq
        // `$1` placeholders and are the documented safe API — they must not be
        // SQL sinks (CVE-2026-42087 patched form).
        let result = classify_all("ruby", "DatabaseConnection.exec_params", None);
        assert!(!result.contains(&DataLabel::Sink(Cap::SQL_QUERY)));
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
    fn classify_java_apache_httpclient_request_constructors_are_ssrf_sinks() {
        // CVE-2024-39954 (Apache EventMesh): the target URL is bound on the
        // request object at construction, so `new HttpGet(url)` /
        // `new HttpOptions(url)` and the rest of the Apache HttpClient request
        // family are the SSRF interception point.  Constructor calls classify
        // with the bare type name as the callee (KINDS maps
        // `object_creation_expression` to `Kind::CallFn`).
        for ctor in [
            "HttpGet",
            "HttpPost",
            "HttpPut",
            "HttpDelete",
            "HttpHead",
            "HttpOptions",
            "HttpTrace",
            "HttpPatch",
        ] {
            let result = classify_all("java", ctor, None);
            assert!(
                result.contains(&DataLabel::Sink(Cap::SSRF)),
                "expected `{ctor}` to be an SSRF sink, got {result:?}"
            );
        }
    }

    #[test]
    fn classify_java_apache_httpclient_constructors_are_case_sensitive() {
        // The bare request-type matchers are case-sensitive so a lowercase
        // method/var named `httpget` does not widen into an SSRF sink.
        let result = classify_all("java", "httpget", None);
        assert!(
            !result.contains(&DataLabel::Sink(Cap::SSRF)),
            "lowercase `httpget` must not match the SSRF constructor rule, got {result:?}"
        );
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
    fn gated_sink_absent_positional_activation_arg_suppresses() {
        // CVE-2025-48882 (PHPOffice/Math): the fix drops the `LIBXML_DTDLOAD`
        // options arg (`$dom->loadXML($content)`), which is XXE-safe under the
        // libxml >= 2.9 default.  With the options activation arg ABSENT
        // (const_arg None AND arg_present false) the ValueMatch XXE gate must
        // NOT fire, rather than firing conservatively on the dynamic-unknown
        // path.
        let result = classify_gated_sink_with_presence(
            "php",
            "dom.loadXML",
            |_| None, // options arg has no resolvable constant value...
            no_kw,
            no_kw_present,
            |_| false, // ...because it is absent entirely
        );
        assert!(
            result.is_empty(),
            "absent options arg must suppress the XXE gate: {result:?}"
        );

        // Sibling gates on the same shape: bare `simplexml_load_string($xml)`.
        let simplexml = classify_gated_sink_with_presence(
            "php",
            "simplexml_load_string",
            |_| None,
            no_kw,
            no_kw_present,
            |_| false,
        );
        assert!(simplexml.is_empty(), "{simplexml:?}");
    }

    #[test]
    fn gated_sink_present_dynamic_activation_still_fires() {
        // `$dom->loadXML($content, $runtimeFlags)`: the options arg is PRESENT
        // but dynamic.  An attacker-controlled flags value could enable entity
        // expansion, so the gate still fires conservatively (ALL_ARGS_PAYLOAD).
        let result = classify_gated_sink_with_presence(
            "php",
            "dom.loadXML",
            |_| None,
            no_kw,
            no_kw_present,
            |idx| idx <= 1, // arg 1 (options) IS present
        );
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::XXE),
                payload_args: ALL_ARGS_PAYLOAD,
                object_destination_fields: &[],
            }]
        );
    }

    #[test]
    fn gated_sink_present_dangerous_positional_fires_restricted() {
        // `$dom->loadXML($content, LIBXML_DTDLOAD)`: dangerous flag present →
        // fire, payload restricted to arg 0 (the XML string).
        let result = classify_gated_sink_with_presence(
            "php",
            "dom.loadXML",
            |idx| (idx == 1).then(|| "LIBXML_DTDLOAD".to_string()),
            no_kw,
            no_kw_present,
            |idx| idx <= 1,
        );
        assert_eq!(
            result.as_slice(),
            &[GateMatch {
                label: DataLabel::Sink(Cap::XXE),
                payload_args: [0usize].as_slice(),
                object_destination_fields: &[],
            }]
        );
    }

    #[test]
    fn gated_sink_wrapper_assumes_activation_arg_present() {
        // The 3-arg `classify_gated_sink` wrapper preserves the historical
        // conservative-fire-on-unknown behaviour (arg_present = always true) for
        // name-only callers, so it still fires on an unresolved activation arg.
        let result = classify_gated_sink("php", "dom.loadXML", |_| None, no_kw, no_kw_present);
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].payload_args, ALL_ARGS_PAYLOAD);
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
    fn code_flag_covers_clusters_wrappers_and_interpreters() {
        assert!(is_code_flag("bash", "-c"));
        assert!(is_code_flag("/bin/sh", "-lc"));
        assert!(is_code_flag("zsh", "-ic"));
        assert!(!is_code_flag("bash", "-x"));
        assert!(!is_code_flag("bash", "--norc"));
        assert!(is_code_flag("cmd.exe", "/C"));
        assert!(is_code_flag("python3.11", "-c"));
        assert!(is_code_flag("ruby", "-e"));
        assert!(is_code_flag("node", "--eval"));
        assert!(!is_code_flag("git", "-c"));
        assert!(is_command_runner_program("C:\\Windows\\System32\\CMD.EXE"));
        assert!(is_command_runner_program("env"));
        assert!(is_wrapper_command("/usr/bin/sudo"));
        assert!(!is_command_runner_program("git"));
        assert!(!is_command_runner_program("ls"));
    }

    #[test]
    fn gated_sink_python_popen_no_shell_suppresses() {
        // `Popen(cmd)` without a `shell` keyword is argv form, the same as
        // `subprocess.Popen` and `subprocess.run`: no shell starts, so the gate
        // does not fire.  The inline shell array `Popen(["sh", "-c", x])` is
        // recognised from the call's arguments instead.
        let result = classify_gated_sink("python", "Popen", |_| None, |_| None, no_kw_present);
        assert!(result.is_empty());
    }

    #[test]
    fn gated_sink_python_popen_shell_dynamic_conservative() {
        // `shell=flag` is present but not a literal: cannot be proven safe.
        let result = classify_gated_sink("python", "Popen", |_| None, |_| None, |kw| kw == "shell");
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
    fn starts_with_ignore_ascii_case_matches_canonical_shapes() {
        assert!(starts_with_ignore_ascii_case(
            "FILE://etc/passwd",
            "file://"
        ));
        assert!(starts_with_ignore_ascii_case(
            "file://etc/passwd",
            "FILE://"
        ));
        assert!(starts_with_ignore_ascii_case("http://", "http://"));
        assert!(starts_with_ignore_ascii_case("http://", ""));
        assert!(!starts_with_ignore_ascii_case("http", "https"));
        assert!(!starts_with_ignore_ascii_case("", "x"));
        // Multibyte UTF-8: the helper is intentionally ASCII-only; non-ASCII
        // bytes compare byte-for-byte (no Unicode case folding).
        assert!(starts_with_ignore_ascii_case("café", "café"));
        assert!(!starts_with_ignore_ascii_case("café", "CAFÉ"));
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

        // `c.HTML` / `c.HTMLBlob` write raw HTML.
        assert_eq!(
            classify("go", "c.HTML", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        assert_eq!(
            classify("go", "c.HTMLBlob", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        // `c.String` is text/plain and `c.JSON` is HTML-escaped JSON.
        assert_eq!(classify("go", "c.String", Some(&extras)), None);
        assert_eq!(classify("go", "c.JSON", Some(&extras)), None);

        // Without Echo framework, these should not match
        let empty = go::framework_rules(&FrameworkContext::default());
        assert_eq!(classify("go", "c.HTML", Some(&empty)), None);
    }

    #[test]
    fn classify_go_gin_responses_are_not_html_sinks() {
        use crate::utils::project::{DetectedFramework, FrameworkContext};

        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Gin],
            inspected_langs: std::collections::HashSet::new(),
        };
        let extras = go::framework_rules(&ctx);
        // `c.String` is text/plain; `c.HTML(code, name, obj)` executes a
        // named html/template, which escapes `obj`.
        assert_eq!(classify("go", "c.String", Some(&extras)), None);
        assert_eq!(classify("go", "c.HTML", Some(&extras)), None);
        assert_eq!(
            classify("go", "c.Query", Some(&extras)),
            Some(DataLabel::Source(Cap::all()))
        );
    }

    #[test]
    fn classify_go_response_writers_and_json_marshal() {
        for writer in [
            "fmt.Fprintf",
            "fmt.Fprint",
            "fmt.Fprintln",
            "io.WriteString",
        ] {
            assert_eq!(
                classify("go", writer, None),
                Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
                "{writer}"
            );
        }
        assert_eq!(
            classify("go", "HttpResponse.Write", None),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE))
        );
        // Bare `w.Write` has no label: only a typed receiver resolves.
        assert_eq!(classify("go", "w.Write", None), None);
        assert_eq!(
            classify("go", "json.Marshal", None),
            Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE))
        );
        assert_eq!(classify("go", "json.Unmarshal", None), None);
    }

    #[test]
    fn classify_go_router_params_are_sources() {
        for src in ["mux.Vars", "chi.URLParam", "chi.URLParamFromCtx"] {
            assert_eq!(
                classify("go", src, None),
                Some(DataLabel::Source(Cap::all())),
                "{src}"
            );
        }
    }

    #[test]
    fn classify_go_command_context_and_serve_file_gates() {
        let gate = |callee: &str| {
            classify_gated_sink("go", callee, |_| None, |_| None, |_| false)
                .into_iter()
                .map(|g| (g.label, g.payload_args.to_vec()))
                .collect::<Vec<_>>()
        };
        // The context at arg 0 is not part of the command.
        let cmd = gate("exec.CommandContext");
        assert_eq!(cmd.len(), 1);
        assert_eq!(cmd[0].0, DataLabel::Sink(Cap::SHELL_ESCAPE));
        assert!(!cmd[0].1.contains(&0));
        assert!(cmd[0].1.contains(&1) && cmd[0].1.contains(&2));
        assert_eq!(
            gate("http.ServeFile"),
            vec![(DataLabel::Sink(Cap::FILE_IO), vec![2])]
        );
    }

    #[test]
    fn go_typed_client_gates_split_url_and_body() {
        let gates = |callee: &str| {
            let mut out: Vec<(DataLabel, Vec<usize>)> =
                classify_gated_sink("go", callee, |_| None, |_| None, |_| false)
                    .into_iter()
                    .map(|g| (g.label, g.payload_args.to_vec()))
                    .collect();
            out.sort_by_key(|(_, p)| p.clone());
            out
        };
        assert_eq!(
            gates("HttpClient.Post"),
            vec![
                (DataLabel::Sink(Cap::SSRF), vec![0]),
                (DataLabel::Sink(Cap::DATA_EXFIL), vec![2]),
            ]
        );
        assert_eq!(
            gates("HttpClient.Do"),
            vec![(DataLabel::Sink(Cap::DATA_EXFIL), vec![0])]
        );
        // Case-sensitive: a lowercase `.get` on an untyped receiver never
        // matches, and the bare user-named receiver has no gate.
        assert!(gates("httpclient.get").is_empty());
        assert!(gates("client.Get").is_empty());
    }

    #[test]
    fn go_typed_formals_alias_to_type_qualified_rules() {
        clear_receiver_aliases();
        {
            let _frame = push_receiver_aliases(vec![
                ("w".to_string(), Some("HttpResponse")),
                ("c".to_string(), Some("HttpClient")),
            ]);
            assert_eq!(
                classify("go", "w.Write", None),
                Some(DataLabel::Sink(Cap::HTML_ESCAPE))
            );
            let ssrf = classify_gated_sink("go", "c.Get", |_| None, |_| None, |_| false);
            assert_eq!(ssrf.len(), 1);
            assert_eq!(ssrf[0].label, DataLabel::Sink(Cap::SSRF));
            assert_eq!(ssrf[0].payload_args, &[0]);
            assert_eq!(receiver_alias_prefix("w"), Some("HttpResponse"));
            assert_eq!(receiver_alias_prefix("other"), None);
        }
        assert_eq!(classify("go", "w.Write", None), None);
        assert!(classify_gated_sink("go", "c.Get", |_| None, |_| None, |_| false).is_empty());
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
            classify("javascript", "ctx.response.body", Some(&extras)),
            Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
        );
        // A redirect navigates the browser (open redirect, not SSRF); header
        // setters are CRLF-injection sinks, not XSS sinks.
        assert_eq!(
            classify("javascript", "ctx.redirect", Some(&extras)),
            Some(DataLabel::Sink(Cap::OPEN_REDIRECT)),
        );
        assert_eq!(
            classify("javascript", "ctx.set", Some(&extras)),
            Some(DataLabel::Sink(Cap::HEADER_INJECTION)),
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
            Some(DataLabel::Sink(Cap::OPEN_REDIRECT)),
        );
        assert_eq!(
            classify("typescript", "reply.header", Some(&extras)),
            Some(DataLabel::Sink(Cap::HEADER_INJECTION)),
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
    fn sink_caps_of(labels: &[DataLabel]) -> Cap {
        labels.iter().fold(Cap::empty(), |acc, l| match l {
            DataLabel::Sink(c) => acc | *c,
            _ => acc,
        })
    }

    #[test]
    fn python_redirect_is_open_redirect_not_ssrf() {
        let caps = sink_caps_of(&classify_all("python", "redirect", None));
        assert!(caps.contains(Cap::OPEN_REDIRECT));
        assert!(!caps.contains(Cap::SSRF));
    }

    #[test]
    fn python_exec_is_a_sink_only_as_the_builtin() {
        let sink = |text: &str| {
            classify_all("python", text, None).contains(&DataLabel::Sink(Cap::CODE_EXEC))
        };
        assert!(sink("exec"));
        assert!(sink("builtins.exec"));
        // ORM and UI methods named `exec`.
        assert!(!sink("session.exec"));
        assert!(!sink("self.session.exec"));
        assert!(!sink("QDialog.exec"));
        // `eval` stays a suffix match: `df.eval` and `redis.eval` evaluate their argument.
        assert!(sink("eval"));
        assert!(sink("df.eval"));
    }

    #[test]
    fn python_getoutput_helpers_are_shell_sinks() {
        for callee in ["subprocess.getoutput", "subprocess.getstatusoutput"] {
            assert!(
                classify_all("python", callee, None).contains(&DataLabel::Sink(Cap::SHELL_ESCAPE)),
                "{callee}"
            );
        }
    }

    #[test]
    fn python_request_param_accessors_are_sources() {
        for text in [
            "request.query_params",
            "request.path_params",
            "request.view_args",
            "self.request.query_params",
        ] {
            assert_eq!(
                classify("python", text, None),
                Some(DataLabel::Source(Cap::all())),
                "{text}"
            );
        }
    }

    #[test]
    fn python_render_calls_sanitize_html_but_template_source_does_not() {
        let html = DataLabel::Sanitizer(Cap::HTML_ESCAPE);
        assert!(classify_all("python", "render_template", None).contains(&html));
        assert!(classify_all("python", "flask.render_template", None).contains(&html));
        assert!(classify_all("python", "render_to_string", None).contains(&html));
        let ssti = classify_all("python", "render_template_string", None);
        assert!(!ssti.contains(&html));
        assert!(ssti.contains(&DataLabel::Sink(Cap::CODE_EXEC)));
    }

    /// Publishes `imports` as the active Python import view while `f` runs.
    fn with_python_imports<R>(imports: &[(&str, &str)], f: impl FnOnce() -> R) -> R {
        let map: std::collections::HashMap<String, String> = imports
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        crate::ssa::type_facts::with_file_imports(Some(&map), f)
    }

    #[test]
    fn python_from_import_names_classify_as_their_qualified_callee() {
        // Without the view the bare names match nothing.
        assert!(classify_all("python", "check_output", None).is_empty());
        assert!(classify_all("python", "escape", None).is_empty());
        with_python_imports(
            &[
                ("check_output", "subprocess.check_output"),
                ("escape", "html.escape"),
                ("quote", "shlex.quote"),
                ("co", "subprocess.check_output"),
                ("sp", "subprocess"),
            ],
            || {
                let sink = |t: &str| sink_caps_of(&classify_all("python", t, None));
                assert!(sink("check_output").contains(Cap::SHELL_ESCAPE));
                // Aliased binding and aliased module.
                assert!(sink("co").contains(Cap::SHELL_ESCAPE));
                assert!(sink("sp.check_output").contains(Cap::SHELL_ESCAPE));
                assert!(
                    classify_all("python", "escape", None)
                        .contains(&DataLabel::Sanitizer(Cap::HTML_ESCAPE))
                );
                assert!(
                    classify_all("python", "quote", None)
                        .contains(&DataLabel::Sanitizer(Cap::SHELL_ESCAPE))
                );
                // The written spelling keeps every label it had.
                assert!(sink("subprocess.check_output").contains(Cap::SHELL_ESCAPE));
                // Names that are not import bindings are unaffected.
                assert!(classify_all("python", "helper", None).is_empty());
                // `classify` agrees with `classify_all`.
                assert_eq!(
                    classify("python", "check_output", None),
                    Some(DataLabel::Sink(Cap::SHELL_ESCAPE))
                );
            },
        );
    }

    #[test]
    fn python_import_view_does_not_leak_into_other_languages() {
        with_python_imports(&[("check_output", "subprocess.check_output")], || {
            assert!(classify_all("ruby", "check_output", None).is_empty());
            assert!(classify_all("javascript", "check_output", None).is_empty());
        });
    }

    #[test]
    fn python_from_import_names_pick_up_gated_sinks() {
        let gated = |text: &str, shell: &'static str| {
            classify_gated_sink(
                "python",
                text,
                |_| None,
                move |kw| (kw == "shell").then(|| shell.to_string()),
                |kw| kw == "shell",
            )
        };
        assert!(gated("run", "True").is_empty());
        with_python_imports(&[("run", "subprocess.run")], || {
            assert!(!gated("run", "True").is_empty());
            assert!(gated("run", "False").is_empty());
        });
    }

    #[test]
    fn go_request_receiver_alias_scopes_classification() {
        clear_receiver_aliases();
        assert_eq!(classify("go", "req.Header.Get", None), None);
        {
            let _outer = push_receiver_aliases(vec![
                ("w".to_string(), None),
                (
                    "req".to_string(),
                    go_request_receiver_prefix("*http.Request"),
                ),
            ]);
            assert_eq!(
                classify("go", "req.Header.Get", None),
                Some(DataLabel::Source(Cap::all()))
            );
            assert!(
                classify_all("go", "req.URL.Query().Get", None)
                    .contains(&DataLabel::Source(Cap::all()))
            );
            // Bare identifiers and non-identifier roots are never aliased.
            assert_eq!(aliased_receiver_text("req"), None);
            assert_eq!(aliased_receiver_text("x := req.Body"), None);
            {
                // An inner closure formal of another type shadows `req`.
                let _inner = push_receiver_aliases(vec![("req".to_string(), None)]);
                assert_eq!(classify("go", "req.Header.Get", None), None);
            }
            assert_eq!(
                aliased_receiver_text("req.Body").as_deref(),
                Some("Request.Body")
            );
        }
        assert_eq!(classify("go", "req.Header.Get", None), None);
        // A frame without typed formals is not pushed onto an empty stack.
        let untyped = push_receiver_aliases(vec![("req".to_string(), None)]);
        assert!(!untyped.pushed);
    }

    #[test]
    fn go_struct_field_alias_classifies_through_the_formal() {
        clear_receiver_aliases();
        let _frame = push_receiver_aliases(vec![
            (
                "ctx.Req".to_string(),
                go_request_receiver_prefix("*http.Request"),
            ),
            ("ctx".to_string(), None),
        ]);
        assert_eq!(
            aliased_receiver_text("ctx.Req.URL.Path").as_deref(),
            Some("Request.URL.Path")
        );
        assert!(
            classify_all("go", "ctx.Req.URL.Query().Get", None)
                .contains(&DataLabel::Source(Cap::all()))
        );
        // Another field of the struct, and the struct itself, are not aliased.
        assert_eq!(aliased_receiver_text("ctx.Other.URL.Path"), None);
        assert_eq!(aliased_receiver_text("ctx.Req"), None);
        {
            // An inner formal named `ctx` of another type shadows the field.
            let _inner = push_receiver_aliases(vec![("ctx".to_string(), None)]);
            assert_eq!(aliased_receiver_text("ctx.Req.URL.Path"), None);
        }
    }

    #[test]
    fn go_request_receiver_prefix_maps_declared_types() {
        assert_eq!(go_request_receiver_prefix("*http.Request"), Some("Request"));
        assert_eq!(go_request_receiver_prefix("http.Request"), Some("Request"));
        assert_eq!(
            go_request_receiver_prefix("* gin.Context"),
            Some("GinContext")
        );
        assert_eq!(
            go_request_receiver_prefix("echo.Context"),
            Some("EchoContext")
        );
        assert_eq!(go_request_receiver_prefix("context.Context"), None);
        assert_eq!(go_request_receiver_prefix("*http.Response"), None);
    }

    #[test]
    fn go_binders_are_output_param_sources() {
        assert_eq!(
            output_param_source_positions("go", "c.ShouldBindJSON"),
            Some(&[0usize][..])
        );
        assert_eq!(
            output_param_source_positions("go", "ctx.BindQuery"),
            Some(&[0usize][..])
        );
        assert_eq!(output_param_source_positions("go", "c.Query"), None);
    }

    #[test]
    fn normalize_chained_call_collapses_groups_across_a_line_break() {
        assert_eq!(
            normalize_chained_call("db.query_row(&sql, [], |r| r.get(0))\n        .unwrap()"),
            "db.query_row.unwrap"
        );
        assert_eq!(
            normalize_chained_call("a.b(x)\n    .c(y)\n    .d"),
            "a.b.c.d"
        );
        // A group not followed by a chain dot keeps its text.
        assert_eq!(normalize_chained_call("f(x) + g"), "f(x) + g");
    }

    #[test]
    fn strip_turbofish_removes_generic_groups() {
        use std::borrow::Cow;
        let s = |t: &str| strip_turbofish(t).into_owned();
        assert_eq!(s("a::b::<T>(x)"), "a::b(x)");
        assert_eq!(s("Foo::<T>::new"), "Foo::new");
        assert_eq!(s("f::<Vec<u8>>"), "f");
        assert_eq!(s("f::<fn() -> u8>(x)"), "f(x)");
        assert_eq!(
            s("sqlx::query_as::<_, User>(&q).fetch_all"),
            "sqlx::query_as(&q).fetch_all"
        );
        assert_eq!(s("a::<X>::b::<Y>(z)"), "a::b(z)");
        // Unterminated group truncates, like the old `<` split.
        assert_eq!(s("a::b::<Vec<u8"), "a::b");
        assert!(matches!(strip_turbofish("a::b(x)"), Cow::Borrowed(_)));
        assert!(matches!(
            CalleeView::of("go", "a::<b>(x)").text,
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            CalleeView::of("rust", "a::b(x::<T>())").text,
            Cow::Borrowed(_)
        ));
        let v = CalleeView::of("rust", "sqlx::query_as::<_, User>(&q)");
        assert_eq!(v.head(), "sqlx::query_as");
    }

    #[test]
    fn rust_turbofish_calls_classify_like_the_plain_call() {
        let has_sink = |text: &str, cap: Cap| {
            classify_all("rust", text, None)
                .iter()
                .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(cap)))
        };
        assert!(has_sink(
            "sqlx::query_as::<_, User>(&q).fetch_all",
            Cap::SQL_QUERY
        ));
        assert!(has_sink("sqlx::query_scalar::<_, i64>", Cap::SQL_QUERY));
        assert!(has_sink("serde_yaml::from_str::<Value>", Cap::DESERIALIZE));
        assert!(has_sink("bincode::deserialize::<Cfg>", Cap::DESERIALIZE));
        assert!(has_sink("std::fs::read_to_string::<&str>", Cap::FILE_IO));
        // Generic calls that are not labelled stay unlabelled.
        assert!(classify_all("rust", "Vec::<u8>::new", None).is_empty());
        assert!(classify_all("rust", "x.collect::<Vec<_>>", None).is_empty());
        assert!(classify_all("rust", "s.parse::<u32>", None).is_empty());
        // A method turbofish keeps truncating at the `<`: `res.json::<T>()`
        // decodes a client response and is not a response-builder sink.
        assert_eq!(strip_turbofish("res.json::<T>(x)"), "res.json::<T>(x)");
        assert_eq!(strip_turbofish("a::b.c::<T>(x)"), "a::b.c::<T>(x)");
        // The gated lookup sees the plain callee too.
        let gates = classify_gated_sink(
            "rust",
            "std::fs::write::<&str>",
            |_| None,
            |_| None,
            |_| false,
        );
        assert!(!gates.is_empty());
    }

    /// The gate index visits every gate a linear scan would match, for every
    /// language: each matcher, its qualified and upper-cased spellings, and a
    /// chained form that only the normalised text matches.
    #[test]
    fn gate_index_finds_every_matching_gate() {
        for (lang, set) in GATED_REGISTRY.iter() {
            let mut texts: Vec<String> = Vec::new();
            for gate in set.gates {
                let (m, _) = unpack_matcher(gate.callee_matcher.as_bytes());
                let m = std::str::from_utf8(m).unwrap();
                texts.push(m.to_string());
                texts.push(format!("x.{m}"));
                texts.push(m.to_ascii_uppercase());
                texts.push(format!("a().{m}()"));
            }
            texts.push("some_random_function".into());
            for text in &texts {
                let norm = normalize_chained_call(text);
                let linear: Vec<usize> = set
                    .gates
                    .iter()
                    .enumerate()
                    .filter(|(_, g)| {
                        let m = g.callee_matcher.as_bytes();
                        match_suffix_cs(text.as_bytes(), m, g.case_sensitive)
                            || match_suffix_cs(norm.as_bytes(), m, g.case_sensitive)
                    })
                    .map(|(i, _)| i)
                    .collect();
                let indexed: Vec<usize> = set
                    .candidates(
                        text.as_bytes().last().copied(),
                        norm.as_bytes().last().copied(),
                    )
                    .into_iter()
                    .map(usize::from)
                    .filter(|&i| {
                        let g = &set.gates[i];
                        let m = g.callee_matcher.as_bytes();
                        match_suffix_cs(text.as_bytes(), m, g.case_sensitive)
                            || match_suffix_cs(norm.as_bytes(), m, g.case_sensitive)
                    })
                    .collect();
                assert_eq!(linear, indexed, "{lang} {text}");
            }
        }
    }
}
