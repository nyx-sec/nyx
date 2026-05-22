//! Structured sink-probe channel (Phase 06 — Track C.1).
//!
//! Replaces the brittle stdout-substring matching path with a per-run JSON-line
//! channel.  Each harness defines a `__nyx_probe` shim (see the per-language
//! emitter in [`crate::dynamic::lang`]) that writes one [`SinkProbe`] record
//! to the channel when the instrumented sink fires.  After each sandbox run
//! the runner calls [`ProbeChannel::drain`] and the oracle (see
//! [`crate::dynamic::oracle::oracle_fired`]) evaluates a payload's
//! [`crate::dynamic::oracle::ProbePredicate`] set against the captured args.
//!
//! # Phase 08 extensions (Track C.4 + C.5)
//!
//! - [`ProbeKind`] discriminates a normal sink observation from a crash
//!   intercepted by a sink-site signal handler.  The handler stamps
//!   `ProbeKind::Crash { signal }` onto the probe before re-raising so the
//!   oracle can distinguish "the sink crashed under my payload"
//!   (Confirmed) from "some unrelated setup code crashed"
//!   (Inconclusive(UnrelatedCrash)).
//! - [`ProbeWitness`] carries bounded forensic data — scrubbed env, cwd,
//!   payload-bytes prefix, callee, args repr — so downstream repro and
//!   chain composition need only the probe file, not a live sandbox.  All
//!   bounding goes through [`crate::dynamic::policy`].
//!
//! # Channel medium
//!
//! Currently file-based: one JSON record per line at
//! `<workdir>/__nyx_probes.jsonl`.  The path is exposed to the harness via
//! the `NYX_PROBE_PATH` env var (see [`PROBE_PATH_ENV`]).  Named-pipe (FIFO)
//! transport is deferred; the file variant works on every platform the
//! sandbox supports and matches the drain-after-run lifecycle the runner
//! actually uses — there are no streaming consumers.
//!
//! Records are appended, so a single payload can fire the shim multiple
//! times (e.g. inside a retry loop) and the oracle sees every observation.
//! The runner truncates the file via [`ProbeChannel::clear`] before each
//! payload to keep verdicts independent.

use crate::dynamic::oracle::Signal;
use crate::dynamic::policy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Default filename for the file-backed probe channel inside a harness
/// workdir.  The harness shim and the runner both build their paths off
/// this constant so they cannot drift apart.
pub const PROBE_FILENAME: &str = "__nyx_probes.jsonl";

/// Env-var name that carries the absolute path of the probe channel into
/// the harness process.  Read by the per-language `__nyx_probe` shim.
pub const PROBE_PATH_ENV: &str = "NYX_PROBE_PATH";

/// Identifier of the payload that triggered the probe.  Currently the
/// static [`crate::dynamic::corpus::CuratedPayload::label`] string; future
/// fuzzer-generated payloads will use the corpus hash.
pub type PayloadId = String;

/// A single captured argument observed at the sink call site.
///
/// The harness shim chooses the variant based on the argument's runtime
/// type so the oracle can apply byte-level predicates without losing
/// information to lossy string conversion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value")]
pub enum ProbeArg {
    /// UTF-8 string argument.
    String(String),
    /// Raw byte buffer (e.g. `bytes` in Python, `Buffer` in Node).
    Bytes(Vec<u8>),
    /// Signed 64-bit integer.
    Int(i64),
}

impl ProbeArg {
    /// String view, when the arg is textual.  Returns `None` for `Int` and
    /// non-UTF-8 `Bytes`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ProbeArg::String(s) => Some(s.as_str()),
            ProbeArg::Bytes(b) => std::str::from_utf8(b).ok(),
            ProbeArg::Int(_) => None,
        }
    }

    /// Byte view, when the arg is byte-shaped.  Returns `None` for `Int`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ProbeArg::String(s) => Some(s.as_bytes()),
            ProbeArg::Bytes(b) => Some(b),
            ProbeArg::Int(_) => None,
        }
    }

    /// Integer view, when the arg is `Int`.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            ProbeArg::Int(i) => Some(*i),
            _ => None,
        }
    }
}

/// Transport layer that recorded a [`ProbeKind::HeaderEmit`] observation.
///
/// Today every per-language harness shim monkey-patches the framework's
/// response object (`flask.Response.headers.__setitem__`, the Java
/// servlet stub's `setHeader`, the Node `nyxResponse.setHeader` mock,
/// etc.) so the bytes are captured *before* the host runtime's CRLF
/// validator could reject them.  Those probes carry
/// [`HeaderEmitProtocol::InProcess`].
///
/// A future tier-(b) harness booting a real Tomcat / werkzeug /
/// `http.createServer` on loopback would tap the bytes the underlying
/// server actually wrote to the response socket and record them as
/// [`HeaderEmitProtocol::Wire`].  The variant exists now so an oracle
/// tightening landing later (e.g. a sibling
/// `ProbePredicate::HeaderSmuggledInWire` that scans wire-frame bytes
/// for two distinct `name:` lines) does not need to re-shape the
/// probe schema.
///
/// Probe records emitted before this field existed deserialise as
/// [`HeaderEmitProtocol::InProcess`] via `#[serde(default)]` on the
/// containing [`ProbeKind::HeaderEmit`] field.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderEmitProtocol {
    /// Bytes captured by an in-process monkey-patch on the framework's
    /// header setter, before the host runtime's CRLF validator ran.
    #[default]
    InProcess,
    /// Bytes captured at the wire layer — the literal response frame
    /// the underlying real server wrote to the response socket.
    Wire,
}

/// Discriminator on a [`SinkProbe`] (Phase 08 — Track C.4).
///
/// Distinguishes a probe written from the normal sink-instrumentation
/// path from one written by a sink-site signal handler when the sink
/// invocation crashed under the active payload.  The oracle's
/// [`crate::dynamic::oracle::Oracle::SinkCrash`] variant ignores anything
/// other than `Crash { signal }`, so a process-level abort outside the
/// sink no longer satisfies the oracle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
#[derive(Default)]
pub enum ProbeKind {
    /// Standard sink observation: arguments were captured before the sink
    /// returned normally (or raised a non-crash exception).
    #[default]
    Normal,
    /// Sink invocation was interrupted by a fatal signal that the
    /// sink-site handler intercepted.  The captured `signal` is the one
    /// the handler observed; the handler re-raises after writing the
    /// probe so the runner's outcome still records the process death.
    Crash {
        /// Signal that interrupted the sink call.
        signal: Signal,
    },
    /// Phase 03 (Track J.1) deserialization-sink observation.  Stamped
    /// by the per-language harness shim when the instrumented
    /// deserialiser (`ObjectInputStream.resolveClass`,
    /// `pickle.Unpickler.find_class`, `unserialize` `__wakeup`,
    /// `Marshal.load` const lookup) is asked to materialise a class
    /// outside the harness's allowlist.  `gadget_chain_invoked` is
    /// `true` when the disallowed class was actually constructed (i.e.
    /// the gadget chain ran) and `false` when the shim caught it at
    /// the resolution boundary before any sink effect.
    Deserialize {
        /// `true` iff the disallowed gadget class was instantiated /
        /// executed before the shim aborted the chain.
        gadget_chain_invoked: bool,
    },
    /// Phase 05 (Track J.3) XXE-sink observation.  Stamped by the
    /// per-language XML harness shim when the instrumented parser
    /// (`DocumentBuilder.parse`, `lxml.etree.XMLParser`,
    /// `simplexml_load_string` under `libxml_disable_entity_loader(false)`,
    /// `encoding/xml.Decoder` with `Strict: false`, Ruby `REXML` /
    /// `Nokogiri::XML`) consumes a payload carrying a `<!ENTITY …>`
    /// declaration that the parser then expands inside the document
    /// body.  `entity_expanded` is `true` when the entity body was
    /// substituted into the parsed tree (the differential rule's
    /// proof that XXE expansion actually fired) and `false` when the
    /// parser refused the doctype / external resolution (the benign
    /// `disallow-doctype-decl` control).
    Xxe {
        /// `true` iff the parser substituted the entity body into the
        /// parsed XML output.
        entity_expanded: bool,
    },
    /// Phase 06 (Track J.4) LDAP-sink observation.  Stamped by the
    /// per-language LDAP harness shim when the instrumented client
    /// (`LdapTemplate.search`, `ldap.search_s`, `ldap_search`) issues a
    /// filter against the in-sandbox
    /// [`ldap_server`](crate::dynamic::stubs::ldap_server) stub.  The
    /// shim records the number of directory entries the stub returned
    /// for the supplied filter — the differential oracle's
    /// [`crate::dynamic::oracle::ProbePredicate::QueryResultCountGreaterThan`]
    /// fires when `entries_returned > n`, catching a malicious filter
    /// (e.g. `*)(uid=*`) that matched more than the originally-intended
    /// user.  Benign filter-quoted controls produce
    /// `entries_returned == 1`.
    Ldap {
        /// Count of directory entries the stub LDAP server returned
        /// for the payload's filter.
        entries_returned: u32,
    },
    /// Phase 07 (Track J.5) XPath-sink observation.  Stamped by the
    /// per-language XPath harness shim when the instrumented evaluator
    /// (`javax.xml.xpath.XPath.evaluate`, `lxml.etree.xpath`,
    /// `DOMXPath::query`, the npm `xpath` package's `select`) issues
    /// an XPath expression against the canonical XML document staged
    /// in the workdir (`xpath_corpus.xml`).  The shim records the
    /// number of nodes the evaluator returned — the differential
    /// oracle's
    /// [`crate::dynamic::oracle::ProbePredicate::QueryResultCountGreaterThan`]
    /// fires when `nodes_returned > n`, catching a malicious
    /// expression (e.g. `' or '1'='1`) that selected every node.
    /// Benign quoted controls produce `nodes_returned == 1`.
    Xpath {
        /// Count of XML nodes the staged document returned for the
        /// payload's XPath expression.
        nodes_returned: u32,
    },
    /// Phase 08 (Track J.6) HTTP-response-header-write observation.
    /// Stamped by the per-language harness shim's instrumented header
    /// setter (`HttpServletResponse.setHeader`,
    /// `flask.Response.headers.__setitem__`, `header(...)`,
    /// `Rack::Response#set_header`, `res.setHeader`, `w.Header().Set`,
    /// `HeaderMap::insert`).  The shim records exactly one probe per
    /// `setHeader(name, value)` call carrying the raw bytes the host
    /// process emitted — the
    /// [`crate::dynamic::oracle::ProbePredicate::HeaderInjected`]
    /// predicate scans `value` for an embedded `\r\n` byte pair, which
    /// is the signal that the attacker payload split one header into
    /// two on the wire.
    HeaderEmit {
        /// Header name the host attempted to set (e.g. `"Set-Cookie"`,
        /// `"Location"`).  Echoed verbatim so the predicate can pin
        /// per-header expectations without name normalisation.
        name: String,
        /// Raw header value the host attempted to set.  A vulnerable
        /// host concatenates attacker bytes into this string without
        /// CRLF stripping; a benign host URL-encodes them (`%0d%0a`).
        value: String,
        /// Transport layer at which the bytes were captured.  Today's
        /// per-language harness shims monkey-patch the framework's
        /// response object before any CRLF validator runs and so
        /// produce [`HeaderEmitProtocol::InProcess`].  A future
        /// tier-(b) harness booting a real Tomcat / werkzeug /
        /// `http.createServer` on loopback would record the bytes the
        /// underlying server actually wrote to the response socket as
        /// [`HeaderEmitProtocol::Wire`].  Pre-existing on-disk probe
        /// records that pre-date this field deserialise as
        /// [`HeaderEmitProtocol::InProcess`] via `#[serde(default)]`
        /// so an oracle tightening landing later does not need to
        /// re-shape the probe schema.
        #[serde(default)]
        protocol: HeaderEmitProtocol,
    },
    /// Phase 08 (Track J.6) wire-frame header-injection observation.
    ///
    /// Stamped by a tier-(b) harness that boots a real Tomcat /
    /// werkzeug / `http.createServer` / `axum::serve` on a loopback
    /// port and taps the literal bytes the server wrote to the
    /// response socket.  Unlike [`ProbeKind::HeaderEmit`], which
    /// captures one logical `(name, value)` pair before the host
    /// runtime's CRLF validator runs, this kind records the entire
    /// raw response-header block so the oracle can scan for two
    /// distinct `name:` lines — the proof that a CRLF-bearing
    /// attacker value actually smuggled a second header through to
    /// the wire rather than being stripped on the way out.
    ///
    /// `raw_bytes` carries the bytes up to (but not including) the
    /// CRLF-CRLF that separates headers from the response body.  No
    /// per-shim path produces this variant today; the schema lands
    /// now so the tier-(b) shims can write the variant without a
    /// follow-up oracle-side re-shape, matching the
    /// [`HeaderEmitProtocol::Wire`] discriminator pattern.
    HeaderWireFrame {
        /// Raw header-block bytes the underlying real server wrote
        /// to the response socket, terminated by the CRLF-CRLF
        /// boundary preceding the response body.  Pre-CRLF-CRLF
        /// only; the body is not captured.
        raw_bytes: Vec<u8>,
    },
    /// Phase 09 (Track J.7) HTTP-redirect observation.  Stamped by
    /// the per-language harness shim's instrumented redirect entry
    /// point (`HttpServletResponse.sendRedirect`, `flask.redirect`,
    /// `Response::redirect`, `res.redirect`, `c.Redirect`,
    /// `Redirect::to`).  The shim records the raw `Location:` value
    /// the host attempted to bind plus the original request host so
    /// the [`crate::dynamic::oracle::ProbePredicate::RedirectHostNotIn`]
    /// predicate can decide whether the redirect target falls outside
    /// the configured allowlist.  A vulnerable host concatenates the
    /// attacker-controlled URL straight into the redirect; a benign
    /// host either validates the host against an allowlist or scopes
    /// the redirect to a same-origin path.
    Redirect {
        /// Raw `Location:` value the host attempted to set.  May be a
        /// fully-qualified URL (`https://attacker.test/`), a
        /// schemeless reference (`//attacker.test/`), or a relative
        /// path (`/dashboard`).
        location: String,
        /// Origin host the harness modelled the request as arriving
        /// at.  Used by the predicate to recognise schemeless or
        /// same-origin redirects as benign even when the bare value
        /// would otherwise resolve off-origin.
        request_host: String,
    },
    /// Phase 10 (Track J.8) prototype-pollution observation.  Stamped
    /// by the Node.js harness shim's canary-trap accessor installed on
    /// `Object.prototype.__nyx_canary` (a `Proxy`-style setter trap):
    /// when a deep-merge / `Object.assign` / `JSON.parse`-then-assign
    /// sink walks an attacker-controlled `__proto__` key into
    /// `Object.prototype`, the setter records the polluted value via
    /// this probe kind.  The
    /// [`crate::dynamic::oracle::ProbePredicate::PrototypeCanaryTouched`]
    /// predicate fires when any such probe lands on the channel.  A
    /// benign payload whose object literal has no `__proto__` key, or
    /// whose target is constructed via `Object.create(null)`, leaves
    /// the prototype chain untouched and emits no
    /// `PrototypePollution` probe.
    PrototypePollution {
        /// Property name the host attempted to set on
        /// `Object.prototype` — always `"__nyx_canary"` for Phase 10
        /// but parametrised so future per-sink canaries reuse the
        /// kind without proliferating variants.
        property: String,
        /// Stringified value the host attempted to bind.  Echoed
        /// verbatim so repro tooling can pin the exact payload bytes
        /// that traversed the chain.
        value: String,
    },
    /// Phase 11 (Track J.9) weak-key entropy observation.  Stamped by
    /// the per-language CRYPTO harness shim when the instrumented
    /// key-generation path produces a key whose effective entropy
    /// fits inside the search space the oracle pins.  `key_int` is
    /// the integer-decoded view of the produced key bytes (truncated
    /// to a `u64`); the
    /// [`crate::dynamic::oracle::ProbePredicate::WeakKeyEntropy`]
    /// predicate fires when `key_int < 2^max_bits`.
    WeakKey {
        /// Truncated integer view of the produced key bytes.  Big
        /// keys (e.g. an honest 2048-bit RSA modulus) hash down via
        /// `from_be_bytes` so a benign control with a strong key
        /// trivially exceeds any plausible `max_bits` budget.
        key_int: u64,
    },
    /// Phase 11 (Track J.9) IDOR / authorization-bypass observation.
    /// Stamped by the per-language UNAUTHORIZED_ID harness shim when
    /// the instrumented mock data store materialises a record whose
    /// `owner_id` differs from the harness's `caller_id`.  The
    /// [`crate::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
    /// predicate fires whenever `caller_id != owner_id`.
    IdorAccess {
        /// Authenticated principal the harness modelled the request
        /// as arriving from.  Compared case-sensitively against
        /// `owner_id`.
        caller_id: String,
        /// Owner of the record the host produced for the caller.
        owner_id: String,
    },
    /// Phase 11 (Track J.9) DATA_EXFIL outbound-network observation.
    /// Stamped by the per-language harness shim's mock HTTP client
    /// when the instrumented egress entry point (`http.post`,
    /// `requests.post`, `HttpURLConnection`, `Net::HTTP`, `fetch`,
    /// `http.NewRequest`, `reqwest::Client`) attempts to route the
    /// captured request body to a non-loopback host.  The
    /// [`crate::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
    /// predicate fires when the captured host falls outside the
    /// configured allowlist (typically `127.0.0.1` / `localhost`).
    OutboundNetwork {
        /// Host the harness's mock HTTP client recorded.  Compared
        /// case-insensitively against the allowlist entries.
        host: String,
    },
}

/// Bounded forensic snapshot captured alongside a [`SinkProbe`]
/// (Phase 08 — Track C.5).
///
/// Every byte that lands in a witness is policed by
/// [`crate::dynamic::policy`]: env keys are scrubbed against
/// [`crate::dynamic::policy::DENY_KEY_SUBSTRINGS`] and payload bytes are
/// truncated at [`crate::dynamic::policy::PAYLOAD_CAPTURE_LIMIT_BYTES`].
/// All fields are `#[serde(default, skip_serializing_if = "...")]` so
/// host-side host-emitted probes (which don't carry a witness) and
/// per-language shim-emitted probes (which do) round-trip through the
/// same JSON schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeWitness {
    /// Scrubbed snapshot of the harness process environment at probe
    /// time.  Keys matching a deny substring carry
    /// [`crate::dynamic::policy::REDACTED_VALUE`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_snapshot: BTreeMap<String, String>,
    /// Current working directory of the harness when the probe fired.
    /// Empty when the language shim could not determine it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    /// Head-truncated payload bytes routed into the sink, capped at
    /// [`crate::dynamic::policy::PAYLOAD_CAPTURE_LIMIT_BYTES`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload_bytes: Vec<u8>,
    /// Same callee name as [`SinkProbe::sink_callee`]; retained on the
    /// witness so repro tooling can consume the witness in isolation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub callee: String,
    /// Per-arg human-readable repr, parallel to [`SinkProbe::args`].
    /// `String` for textual / numeric args; `"<bytes:N>"` for binary
    /// payloads the shim chose not to inline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args_repr: Vec<String>,
}

impl ProbeWitness {
    /// An empty witness — every field at its `Default` value.  Used by
    /// tests and the host-side [`ProbeChannel::write`] path that does
    /// not snapshot any forensic state.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct a bounded witness from raw inputs.  Goes through
    /// [`crate::dynamic::policy::scrub_env`],
    /// [`crate::dynamic::policy::truncate_payload_bytes`], and
    /// [`crate::dynamic::policy::Scrubber`] (Phase 28 — Track H.5) so
    /// the host-side constructor cannot accidentally produce an
    /// unscrubbed / unbounded witness.  Every textual field
    /// (`env_snapshot` values, `cwd`, each `args_repr` entry) is routed
    /// through the scrubber before the witness is serialised, and the
    /// truncated `payload_bytes` slice is routed through the
    /// byte-aware [`crate::dynamic::policy::Scrubber::scrub_bytes`] so
    /// real-world payloads carrying credential tokens are replaced with
    /// a deterministic same-length placeholder while curated corpus
    /// payloads pass through unchanged.
    pub fn from_inputs<I, S>(
        env: I,
        cwd: impl Into<String>,
        payload: &[u8],
        callee: impl Into<String>,
        args_repr: Vec<String>,
    ) -> Self
    where
        I: IntoIterator<Item = (S, S)>,
        S: Into<String>,
    {
        let scrubber = policy::Scrubber::project_default();
        let env_snapshot: BTreeMap<String, String> = policy::scrub_env(env)
            .into_iter()
            .map(|(k, v)| (k, scrubber.scrub_string(&v)))
            .collect();
        let scrubbed_args: Vec<String> = args_repr
            .into_iter()
            .map(|s| scrubber.scrub_string(&s))
            .collect();
        let scrubbed_callee = scrubber.scrub_string(&callee.into());
        let scrubbed_cwd = scrubber.scrub_string(&cwd.into());
        let truncated = policy::truncate_payload_bytes(payload);
        let scrubbed_payload = scrubber.scrub_bytes(truncated);
        Self {
            env_snapshot,
            cwd: scrubbed_cwd,
            payload_bytes: scrubbed_payload,
            callee: scrubbed_callee,
            args_repr: scrubbed_args,
        }
    }
}

/// One structured observation written by the harness when the instrumented
/// sink fires.  Serialised as a single JSON object on its own line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkProbe {
    /// Fully-qualified or last-segment callee name of the fired sink
    /// (e.g. `"os.system"`, `"Runtime.exec"`).
    pub sink_callee: String,
    /// Captured positional arguments, left-to-right.  Empty when the sink
    /// takes no arguments or the shim could not introspect them.
    pub args: Vec<ProbeArg>,
    /// Monotonic-ish nanosecond timestamp captured at write time.  Used to
    /// order multiple probe entries from the same run; absolute value is
    /// not meaningful across runs.
    pub captured_at_ns: u64,
    /// Identifier of the payload in flight when the probe fired.
    pub payload_id: PayloadId,
    /// Phase 08: normal sink observation vs sink-site crash.  Defaults to
    /// `Normal` so probes written by the Phase 06 shims (no `kind` field
    /// on the wire) deserialise as normal observations.
    #[serde(default)]
    pub kind: ProbeKind,
    /// Phase 08: bounded forensic snapshot.  Empty when the shim did not
    /// capture one — the field stays `default` so older probe files
    /// round-trip unchanged.
    #[serde(default)]
    pub witness: ProbeWitness,
}

/// Per-run handle on a file-backed [`SinkProbe`] channel.
///
/// Construction creates / truncates the underlying file under `workdir`;
/// [`clear`](ProbeChannel::clear) re-truncates between payload runs;
/// [`drain`](ProbeChannel::drain) reads every record currently buffered.
#[derive(Debug)]
pub struct ProbeChannel {
    path: PathBuf,
    /// Serialises read / write / truncate operations against the underlying
    /// file from the host side.  The harness process writes from its own
    /// address space; this lock only protects host-side callers (test
    /// helpers, the runner).
    io_lock: Mutex<()>,
}

impl ProbeChannel {
    /// Construct a channel rooted at
    /// `<workdir>/__nyx_probes-pid{pid}.jsonl`.
    ///
    /// The filename is stamped with [`std::process::id`] so two test
    /// binaries running in parallel against the same deterministic
    /// `spec_hash` (and therefore the same `<workdir>`) do not race on
    /// the probe file — one process's [`clear`](ProbeChannel::clear)
    /// would otherwise truncate another process's freshly-written
    /// probe records and cause the runner's `vuln_fired` gate to
    /// evaluate false on an empty drain, silently dropping the benign
    /// control attempt.  Within a single process every call resolves
    /// to the same filename so the intra-run probe lifecycle
    /// (write → drain → clear → next payload) stays correct.
    ///
    /// Creates the file (truncating any previous contents) so a stale
    /// probe file left over from a prior workdir reuse cannot poison
    /// the next run's oracle.
    pub fn for_workdir(workdir: &Path) -> std::io::Result<Self> {
        let path = workdir.join(format!("__nyx_probes-pid{}.jsonl", std::process::id()));
        File::create(&path)?;
        Ok(Self {
            path,
            io_lock: Mutex::new(()),
        })
    }

    /// Construct a channel at an explicit path (test helper).  Mirrors
    /// [`for_workdir`](ProbeChannel::for_workdir) but does not assume any
    /// directory layout.
    pub fn at_path(path: PathBuf) -> std::io::Result<Self> {
        File::create(&path)?;
        Ok(Self {
            path,
            io_lock: Mutex::new(()),
        })
    }

    /// Absolute path of the probe file.  Forwarded to the harness process
    /// via the `NYX_PROBE_PATH` env var.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Truncate the channel between payload runs.  Cheap: a single
    /// `File::create` on the existing path.
    pub fn clear(&self) -> std::io::Result<()> {
        let _guard = self.io_lock.lock().ok();
        File::create(&self.path)?;
        Ok(())
    }

    /// Read every record currently buffered.  Malformed lines (truncated
    /// writes, partial flushes) are skipped silently — the oracle treats a
    /// missing probe as "sink did not fire" without distinguishing causes.
    pub fn drain(&self) -> Vec<SinkProbe> {
        let _guard = self.io_lock.lock().ok();
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(p) = serde_json::from_str::<SinkProbe>(trimmed) {
                out.push(p);
            }
        }
        out
    }

    /// Append a probe record from the host side.  Primarily a test helper:
    /// in production the harness process writes directly via its
    /// per-language shim, bypassing this entry point.
    pub fn write(&self, probe: &SinkProbe) -> std::io::Result<()> {
        let _guard = self.io_lock.lock().ok();
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        let line = serde_json::to_string(probe)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_probe(label: &str) -> SinkProbe {
        SinkProbe {
            sink_callee: "os.system".into(),
            args: vec![ProbeArg::String("ls; whoami".into())],
            captured_at_ns: 42,
            payload_id: label.into(),
            kind: ProbeKind::Normal,
            witness: ProbeWitness::empty(),
        }
    }

    #[test]
    fn channel_round_trip_writes_and_drains() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        ch.write(&sample_probe("cmdi-echo-marker")).unwrap();
        ch.write(&sample_probe("cmdi-echo-marker-2")).unwrap();
        let probes = ch.drain();
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0].payload_id, "cmdi-echo-marker");
        assert_eq!(probes[1].payload_id, "cmdi-echo-marker-2");
    }

    #[test]
    fn drain_after_clear_returns_empty() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        ch.write(&sample_probe("a")).unwrap();
        ch.clear().unwrap();
        assert!(ch.drain().is_empty());
    }

    #[test]
    fn drain_skips_malformed_lines() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        // Manually append a junk line, then a valid one.
        std::fs::write(ch.path(), "this is not json\n").unwrap();
        ch.write(&sample_probe("after-junk")).unwrap();
        let probes = ch.drain();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].payload_id, "after-junk");
    }

    #[test]
    fn probe_arg_views() {
        let s = ProbeArg::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));
        assert_eq!(s.as_bytes(), Some(&b"hello"[..]));
        assert_eq!(s.as_int(), None);

        let i = ProbeArg::Int(7);
        assert_eq!(i.as_str(), None);
        assert_eq!(i.as_bytes(), None);
        assert_eq!(i.as_int(), Some(7));

        let b = ProbeArg::Bytes(vec![b'h', b'i']);
        assert_eq!(b.as_str(), Some("hi"));
        assert_eq!(b.as_bytes(), Some(&[b'h', b'i'][..]));
    }

    #[test]
    fn empty_channel_drains_to_empty_vec() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        assert!(ch.drain().is_empty());
    }

    #[test]
    fn probe_kind_defaults_to_normal_when_field_omitted() {
        // Legacy probe-line shape (Phase 06) — no `kind` field on the wire.
        let line = r#"{"sink_callee":"os.system","args":[],"captured_at_ns":1,"payload_id":"p"}"#;
        let p: SinkProbe = serde_json::from_str(line).unwrap();
        assert_eq!(p.kind, ProbeKind::Normal);
        assert_eq!(p.witness, ProbeWitness::empty());
    }

    #[test]
    fn crash_probe_round_trips_through_channel() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        let mut p = sample_probe("crash-test");
        p.kind = ProbeKind::Crash {
            signal: Signal::Sigsegv,
        };
        ch.write(&p).unwrap();
        let drained = ch.drain();
        assert_eq!(drained.len(), 1);
        assert!(matches!(
            drained[0].kind,
            ProbeKind::Crash {
                signal: Signal::Sigsegv
            }
        ));
    }

    #[test]
    fn witness_from_inputs_hashes_pii_args() {
        let env: Vec<(String, String)> = vec![];
        let w = ProbeWitness::from_inputs(
            env,
            "/tmp/run",
            b"payload",
            "os.system",
            vec!["nyx-stub-secret-aaa-bbb-ccc".to_owned()],
        );
        // The args_repr entry contained a project-stub-secret literal and
        // must be hashed before the witness is serialised.
        assert_eq!(w.args_repr.len(), 1);
        assert!(
            w.args_repr[0].starts_with(policy::SCRUB_HASH_PREFIX),
            "args_repr value should be scrubbed; got {}",
            w.args_repr[0]
        );
        assert!(!w.args_repr[0].contains("aaa-bbb-ccc"));
    }

    #[test]
    fn probe_kind_header_wire_frame_round_trips_through_channel() {
        let dir = TempDir::new().unwrap();
        let ch = ProbeChannel::for_workdir(dir.path()).unwrap();
        let mut p = sample_probe("wire-smuggle");
        p.kind = ProbeKind::HeaderWireFrame {
            raw_bytes: b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nX-Injected: 1\r\n".to_vec(),
        };
        ch.write(&p).unwrap();
        let drained = ch.drain();
        assert_eq!(drained.len(), 1);
        match &drained[0].kind {
            ProbeKind::HeaderWireFrame { raw_bytes } => {
                assert!(raw_bytes.windows(11).any(|w| w == b"Set-Cookie:"));
                assert!(raw_bytes.windows(11).any(|w| w == b"X-Injected:"));
            }
            other => panic!("expected HeaderWireFrame, got {other:?}"),
        }
    }

    #[test]
    fn probe_kind_header_wire_frame_serdes_with_explicit_tag() {
        let p = SinkProbe {
            sink_callee: "wire".into(),
            args: vec![],
            captured_at_ns: 1,
            payload_id: "wire-1".into(),
            kind: ProbeKind::HeaderWireFrame {
                raw_bytes: b"Set-Cookie: a=1\r\nX-Injected: 1\r\n".to_vec(),
            },
            witness: ProbeWitness::empty(),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(r#""kind":"HeaderWireFrame""#));
        let round: SinkProbe = serde_json::from_str(&json).unwrap();
        assert!(matches!(round.kind, ProbeKind::HeaderWireFrame { .. }));
    }

    #[test]
    fn witness_from_inputs_redacts_and_truncates() {
        let huge_payload = vec![0xAB; policy::PAYLOAD_CAPTURE_LIMIT_BYTES * 2];
        let env = vec![
            ("PATH".to_owned(), "/bin".to_owned()),
            ("AWS_SECRET_ACCESS_KEY".to_owned(), "secret!!!".to_owned()),
        ];
        let w = ProbeWitness::from_inputs(
            env,
            "/tmp/run",
            &huge_payload,
            "os.system",
            vec!["ls; whoami".to_owned()],
        );
        assert_eq!(w.cwd, "/tmp/run");
        assert_eq!(w.payload_bytes.len(), policy::PAYLOAD_CAPTURE_LIMIT_BYTES);
        assert_eq!(w.env_snapshot.get("PATH").map(String::as_str), Some("/bin"));
        assert_eq!(
            w.env_snapshot
                .get("AWS_SECRET_ACCESS_KEY")
                .map(String::as_str),
            Some(policy::REDACTED_VALUE)
        );
        assert_eq!(w.args_repr, vec!["ls; whoami".to_owned()]);
        assert_eq!(w.callee, "os.system");
    }
}
