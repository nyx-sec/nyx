//! Python harness emitter.
//!
//! Phase 12 (Track B Python vertical) replaces the single legacy
//! `emit` body with dispatch over [`PythonShape`] — the cross product of
//! [`EntryKind`] and a lightweight per-file shape detector that inspects
//! the entry file for framework decorators / CLI gates / async / pytest
//! conventions.  Each shape returns its own [`HarnessSource`] but shares
//! the Phase 06 probe shim ([`probe_shim`]) and payload prelude so the
//! sink-reachability oracle works uniformly across shapes.
//!
//! Detection is best-effort: when the entry file is unreadable or no
//! shape matches, the emitter falls back to [`PythonShape::Generic`],
//! which preserves the pre-Phase-12 behaviour (call the entry function
//! positionally with the payload).  The dispatch never returns an
//! emitter-side error for an unknown shape — that responsibility belongs
//! to `lang::emit`, which has already gated on
//! [`EntryKind`] via [`PythonEmitter::entry_kinds_supported`].
//!
//! Payload slot support:
//! - [`PayloadSlot::Param`] — n-th positional argument.
//! - [`PayloadSlot::EnvVar`] — set env var before calling.
//! - [`PayloadSlot::Stdin`] — buffer payload onto `sys.stdin`.
//! - Other slots produce [`UnsupportedReason::PayloadSlotUnsupported`].

use crate::dynamic::environment::{Environment, RuntimeArtifacts};
use crate::dynamic::lang::{ChainStepHarness, ChainStepTerminal, HarnessSource, LangEmitter};
use crate::dynamic::spec::{EntryKindTag, HarnessSpec, PayloadSlot};
use crate::evidence::UnsupportedReason;
use crate::utils::project::DetectedFramework;
use std::path::PathBuf;

/// Zero-sized [`LangEmitter`] handle for Python.  Registered in the
/// `lang::dispatch` table; method bodies delegate to the existing free
/// functions in this module.
pub struct PythonEmitter;

/// Entry kinds the Python emitter understands after Phase 12.
///
/// `HttpRoute` covers Flask / FastAPI / Django views.  `CliSubcommand`
/// covers `if __name__ == "__main__":` entries and explicit click /
/// argparse `main()` functions.  `Function` covers pytest, async
/// coroutines, Celery tasks, and generic module-level functions
/// (positional + kwargs).
const SUPPORTED: &[EntryKindTag] = &[
    EntryKindTag::Function,
    EntryKindTag::HttpRoute,
    EntryKindTag::CliSubcommand,
    EntryKindTag::ClassMethod,
    EntryKindTag::MessageHandler,
    EntryKindTag::ScheduledJob,
    EntryKindTag::GraphQLResolver,
    EntryKindTag::WebSocket,
    EntryKindTag::Middleware,
    EntryKindTag::Migration,
];

impl LangEmitter for PythonEmitter {
    fn emit(&self, spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
        emit(spec)
    }

    fn entry_kinds_supported(&self) -> &'static [EntryKindTag] {
        SUPPORTED
    }

    fn entry_kind_hint(&self, attempted: EntryKindTag) -> String {
        format!(
            "python emitter supports {SUPPORTED:?}; this finding's enclosing context is `EntryKind::{attempted}` — see Phase 12 / 19 / 20 / 21 shape dispatch"
        )
    }

    fn materialize_runtime(&self, env: &Environment) -> RuntimeArtifacts {
        materialize_python(env)
    }

    fn compose_chain_step(
        &self,
        prev_output: Option<&[u8]>,
        terminal: Option<&ChainStepTerminal>,
    ) -> ChainStepHarness {
        chain_step(prev_output, terminal)
    }
}

/// Phase 26 — Python chain-step harness.
///
/// Splices the Python probe shim ([`probe_shim`]) in front of a minimal
/// driver that reads `NYX_PREV_OUTPUT` and forwards it on stdout.  When
/// `terminal` is `Some`, the driver also calls `__nyx_probe(callee,
/// prev)` so the spliced shim records a witness, then prints the
/// [`ChainStepHarness::SINK_HIT_SENTINEL`] so the runner flips
/// `sink_hit` on the terminal step.
fn chain_step(
    prev_output: Option<&[u8]>,
    terminal: Option<&ChainStepTerminal>,
) -> ChainStepHarness {
    let probe = probe_shim();
    let mut driver = String::from(
        "\nimport os, sys\nprev = os.environ.get('NYX_PREV_OUTPUT', '')\nsys.stdout.write(prev)\nsys.stdout.flush()\n",
    );
    if let Some(t) = terminal {
        let callee = python_string_literal(&t.sink_callee);
        driver.push_str(&format!(
            "__nyx_probe({callee}, prev)\nprint({sentinel}, flush=True)\n",
            sentinel = python_string_literal(ChainStepHarness::SINK_HIT_SENTINEL),
        ));
    }
    ChainStepHarness {
        source: format!("{probe}{driver}"),
        filename: "step.py".to_owned(),
        command: vec!["python3".to_owned(), "step.py".to_owned()],
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

/// Escape a string for safe Python single-quoted literal embedding.
/// Conservative: backslash + single-quote escape only; bytes outside
/// printable ASCII are left to Python's UTF-8 source decoder.
fn python_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

// ── Phase 12: shape detector ─────────────────────────────────────────────────

/// Concrete per-file shape resolved by reading the entry source.
///
/// One harness template per variant.  When the entry file is unreadable
/// or no marker fires the detector defaults to [`PythonShape::Generic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonShape {
    /// Flask `@app.route` / blueprint route.  Harness uses
    /// `app.test_client()` to dispatch a request to the route.
    FlaskRoute,
    /// FastAPI `@app.get` / `@router.post` / etc.  Harness uses
    /// `starlette.testclient.TestClient` to drive the route.
    FastApiRoute,
    /// Pure Starlette application (`Starlette(routes=[Route(...)])`).
    /// Harness uses `starlette.testclient.TestClient` to drive the
    /// route.  Distinguished from [`Self::FastApiRoute`] because the
    /// app resolver looks up `starlette.applications.Starlette`
    /// instances rather than `fastapi.FastAPI` instances.
    StarletteRoute,
    /// Django view (function or `View`/`APIView` method).  Harness
    /// instantiates a `django.test.RequestFactory` and calls the view.
    DjangoView,
    /// `if __name__ == "__main__":` script entry or top-level `main()`.
    /// Harness sets `sys.argv` and re-imports under `__main__` semantics.
    CliEntry,
    /// `def test_*(...)` pytest function.  Harness imports and calls
    /// directly — no pytest runner needed because we drive a single test.
    PytestFunction,
    /// `async def` coroutine.  Harness wraps the call in `asyncio.run`.
    AsyncCoroutine,
    /// `@app.task` / `@celery.task` Celery task.  Harness calls the
    /// underlying function directly (eager mode) — Celery's broker is
    /// not required for in-process invocation.
    CeleryTask,
    /// Generic module-level function — positional argument by default,
    /// keyword-argument fallback when `PayloadSlot::EnvVar` carries the
    /// kwarg name.  Backwards-compatible with pre-Phase-12 behaviour.
    Generic,
}

impl PythonShape {
    /// Detect the shape from `(spec, source)`.  `source` is the literal
    /// bytes of the entry file (best-effort — if it could not be read,
    /// pass an empty string and the function returns [`Self::Generic`]).
    ///
    /// Framework detection (Flask / FastAPI / Django) wins over the
    /// [`EntryKind`] axis: when the source clearly imports one of those
    /// frameworks the route shape is selected even if the spec
    /// derivation pipeline tagged the entry kind as
    /// [`EntryKind::Function`].  This makes the dispatcher robust
    /// against the synthetic flow-step path used by tests and against
    /// the legacy substring-only entry-kind heuristic.
    pub fn detect(spec: &HarnessSpec, source: &str) -> Self {
        let entry = spec.entry_name.as_str();
        let kind = spec.entry_kind.tag();

        // ── Framework-first detection ────────────────────────────────
        let has_flask =
            source_has_marker(source, &["from flask", "import flask", "Flask("]);
        let has_fastapi = source_has_marker(
            source,
            &["from fastapi", "import fastapi", "FastAPI(", "APIRouter("],
        );
        let has_starlette = source_has_marker(
            source,
            &[
                "from starlette",
                "import starlette",
                "Starlette(",
                "starlette.routing",
                "starlette.applications",
            ],
        );
        let has_django = source_has_marker(
            source,
            &[
                "from django",
                "import django",
                "django.http",
                "urlpatterns",
                "APIView",
                "django.views",
            ],
        );

        // FastAPI takes precedence when both fastapi + starlette imports
        // show up (FastAPI imports starlette transitively); same for
        // Flask vs werkzeug.  Django is mutually exclusive in practice.
        if has_fastapi {
            return Self::FastApiRoute;
        }
        if has_django {
            return Self::DjangoView;
        }
        if has_starlette {
            return Self::StarletteRoute;
        }
        if has_flask {
            return Self::FlaskRoute;
        }

        if kind == EntryKindTag::HttpRoute {
            // The flow-step said HTTP but no framework import was
            // detected — fall back to Flask which has the most forgiving
            // test client wiring.
            return Self::FlaskRoute;
        }

        if kind == EntryKindTag::CliSubcommand
            || entry == "main"
            || entry == "__main__"
            || source.contains("if __name__ == \"__main__\"")
            || source.contains("if __name__ == '__main__'")
        {
            return Self::CliEntry;
        }

        if entry.starts_with("test_") && function_is_pytest(source, entry) {
            return Self::PytestFunction;
        }

        if function_is_celery_task(source, entry) {
            return Self::CeleryTask;
        }

        if function_is_async(source, entry) {
            return Self::AsyncCoroutine;
        }

        Self::Generic
    }
}

fn source_has_marker(source: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| source.contains(m))
}

fn function_is_pytest(source: &str, name: &str) -> bool {
    let needle = format!("def {name}(");
    let async_needle = format!("async def {name}(");
    (source.contains(&needle) || source.contains(&async_needle))
        && name.starts_with("test_")
}

fn function_is_async(source: &str, name: &str) -> bool {
    source.contains(&format!("async def {name}("))
}

fn function_is_celery_task(source: &str, name: &str) -> bool {
    let def_needle = format!("def {name}(");
    if !source.contains(&def_needle) {
        return false;
    }
    let has_celery_import = source.contains("from celery") || source.contains("import celery");
    let has_task_decorator = source.contains("@app.task")
        || source.contains("@celery.task")
        || source.contains("@shared_task");
    has_celery_import && has_task_decorator
}

// ── Probe shim (Phase 06 + Phase 08) ─────────────────────────────────────────

/// Source of the `__nyx_probe` shim for the Python harness.
///
/// Callable as `__nyx_probe("sink.callee", arg0, arg1, ...)`.  Emits one
/// JSON line per call to `NYX_PROBE_PATH` (when set) in the
/// [`crate::dynamic::probe::SinkProbe`] schema.  No-op when the env var
/// is unset, so the shim is safe to inject even when the runner has not
/// configured a probe channel.
pub fn probe_shim() -> &'static str {
    r#"
# ── __nyx_probe shim (Phase 06 — Track C.1, Phase 08 — Track C.4 + C.5) ──────
# Deny-substring list mirrors crate::dynamic::policy::DENY_KEY_SUBSTRINGS; keep
# in sync when the host-side policy gains new entries.
_NYX_DENY_SUBSTRINGS = (
    "TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "CREDENTIAL", "SESSION", "COOKIE", "AUTH", "BEARER",
    "AWS_ACCESS", "AWS_SESSION", "GH_TOKEN", "GITHUB_TOKEN", "NPM_TOKEN",
    "PYPI_TOKEN", "DOCKER_PASS",
)
_NYX_PAYLOAD_LIMIT = 16 * 1024
_NYX_REDACTED = "<redacted-by-nyx-policy>"

def __nyx_scrub_env():
    import os
    out = {}
    for k, v in os.environ.items():
        ku = str(k).upper()
        if any(n in ku for n in _NYX_DENY_SUBSTRINGS):
            out[k] = _NYX_REDACTED
        else:
            out[k] = v
    return out

def __nyx_witness(sink_callee, args):
    import os
    payload = os.environ.get("NYX_PAYLOAD", "")
    payload_bytes = payload.encode("utf-8", "replace") if isinstance(payload, str) else bytes(payload)
    if len(payload_bytes) > _NYX_PAYLOAD_LIMIT:
        payload_bytes = payload_bytes[:_NYX_PAYLOAD_LIMIT]
    args_repr = []
    for a in args:
        if isinstance(a, (bytes, bytearray)):
            args_repr.append("<bytes:%d>" % len(a))
        else:
            args_repr.append(str(a))
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = ""
    return {
        "env_snapshot": __nyx_scrub_env(),
        "cwd": cwd,
        "payload_bytes": list(payload_bytes),
        "callee": str(sink_callee),
        "args_repr": args_repr,
    }

def __nyx_emit(rec):
    import os, json
    p = os.environ.get("NYX_PROBE_PATH")
    if not p:
        return
    try:
        with open(p, "a") as _f:
            _f.write(json.dumps(rec) + "\n")
    except OSError:
        pass

def __nyx_probe(sink_callee, *args):
    import os, time
    serialised = []
    for a in args:
        if isinstance(a, (bytes, bytearray)):
            serialised.append({"kind": "Bytes", "value": list(a)})
        elif isinstance(a, bool):
            serialised.append({"kind": "Int", "value": 1 if a else 0})
        elif isinstance(a, int):
            serialised.append({"kind": "Int", "value": a})
        else:
            serialised.append({"kind": "String", "value": str(a)})
    rec = {
        "sink_callee": str(sink_callee),
        "args": serialised,
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {"kind": "Normal"},
        "witness": __nyx_witness(sink_callee, args),
    }
    __nyx_emit(rec)

# Phase 08: sink-site signal handler.  Call __nyx_install_crash_guard before
# invoking the instrumented sink so a SIGSEGV / SIGABRT / etc. is captured as
# a Crash probe (with witness) before the process aborts.  The shim re-raises
# the signal on the default handler after writing so process-level outcome
# observers (exit_code) still see the death.
_NYX_SIGNAL_NAMES = {}

def __nyx_install_crash_guard(sink_callee):
    import signal, os, time
    catchable = []
    for nm in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL"):
        s = getattr(signal, nm, None)
        if s is not None:
            catchable.append((nm, s))
            _NYX_SIGNAL_NAMES[s] = nm
    def _handler(signum, frame):
        nm = _NYX_SIGNAL_NAMES.get(signum, "SIG?")
        rec = {
            "sink_callee": str(sink_callee),
            "args": [],
            "captured_at_ns": time.time_ns(),
            "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
            "kind": {"kind": "Crash", "signal": nm},
            "witness": __nyx_witness(sink_callee, []),
        }
        __nyx_emit(rec)
        # Reset to default and re-raise so the process actually dies.
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
    for _nm, s in catchable:
        try:
            signal.signal(s, _handler)
        except (OSError, ValueError):
            pass

# Phase 10 (Track D.3) stub helpers.  When the verifier spawned a SqlStub it
# publishes the queries-log path through NYX_SQL_LOG; a sink call site that
# wants the host-side stub to see its query appends one record-per-call.  The
# helper is a no-op when NYX_SQL_LOG is unset so the same fixture source still
# runs under harness modes that didn't spawn a stub.
def __nyx_stub_sql_record(query, **detail):
    import os
    p = os.environ.get("NYX_SQL_LOG")
    if not p:
        return
    try:
        with open(p, "a") as _f:
            for k, v in detail.items():
                _f.write('# %s: %s\n' % (str(k), str(v)))
            _f.write(str(query))
            if not str(query).endswith('\n'):
                _f.write('\n')
    except OSError:
        pass

# Phase 10 (Track D.3) HTTP recording helper.  When the verifier spawned an
# HttpStub it publishes the side-channel log path through NYX_HTTP_LOG; a
# sink call site whose outbound request never reaches the on-the-wire
# listener (DNS-mocked, network-isolated sandbox, pre-flight check) can
# call this helper to surface the attempted call.  Format matches the SQL
# helper so the host-side merger parses both streams identically.
def __nyx_stub_http_record(method, url, body=None, **detail):
    import os
    p = os.environ.get("NYX_HTTP_LOG")
    if not p:
        return
    try:
        with open(p, "a") as _f:
            _f.write('# method: %s\n' % str(method))
            _f.write('# url: %s\n' % str(url))
            if body is not None:
                _f.write('# body: %s\n' % str(body))
            for k, v in detail.items():
                _f.write('# %s: %s\n' % (str(k), str(v)))
            _f.write('%s %s\n' % (str(method), str(url)))
    except OSError:
        pass
"#
}

// ── Runtime / requirements.txt synthesis (Phase 09) ─────────────────────────

/// Phase 09 — Track D.2: synthesise a `requirements.txt` from the
/// captured deps in `env`.
pub fn materialize_python(env: &Environment) -> RuntimeArtifacts {
    let mut artifacts = RuntimeArtifacts::new();
    let mut deps: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for d in &env.direct_deps {
        if is_python_stdlib(d) {
            continue;
        }
        let canonical = canonical_python_pkg_name(d);
        if seen.insert(canonical.clone()) {
            deps.push(canonical);
        }
    }
    for fw in &env.frameworks {
        if let Some(name) = python_framework_pkg_name(*fw) {
            let canonical = canonical_python_pkg_name(name);
            if seen.insert(canonical.clone()) {
                deps.push(canonical);
            }
        }
    }
    deps.sort_unstable();

    let mut body = String::with_capacity(64);
    body.push_str("# Auto-generated by Nyx — Phase 09 (Track D.2).\n");
    body.push_str(&format!("# spec_hash = {}\n", env.spec_hash));
    body.push_str(&format!(
        "# toolchain = {} (drift={})\n",
        env.toolchain.toolchain_id, env.toolchain.toolchain_drift
    ));
    for d in &deps {
        body.push_str(d);
        body.push('\n');
    }
    artifacts.push("requirements.txt", body);
    artifacts
}

fn is_python_stdlib(name: &str) -> bool {
    matches!(
        name,
        "abc"
            | "argparse"
            | "asyncio"
            | "base64"
            | "binascii"
            | "collections"
            | "contextlib"
            | "copy"
            | "csv"
            | "ctypes"
            | "dataclasses"
            | "datetime"
            | "decimal"
            | "difflib"
            | "email"
            | "enum"
            | "errno"
            | "fcntl"
            | "fnmatch"
            | "functools"
            | "getopt"
            | "getpass"
            | "glob"
            | "gzip"
            | "hashlib"
            | "hmac"
            | "http"
            | "importlib"
            | "inspect"
            | "io"
            | "ipaddress"
            | "itertools"
            | "json"
            | "logging"
            | "math"
            | "multiprocessing"
            | "operator"
            | "os"
            | "pathlib"
            | "pickle"
            | "platform"
            | "posixpath"
            | "queue"
            | "random"
            | "re"
            | "secrets"
            | "select"
            | "shutil"
            | "signal"
            | "socket"
            | "sqlite3"
            | "ssl"
            | "stat"
            | "string"
            | "struct"
            | "subprocess"
            | "sys"
            | "tempfile"
            | "threading"
            | "time"
            | "traceback"
            | "types"
            | "typing"
            | "unicodedata"
            | "unittest"
            | "urllib"
            | "uuid"
            | "warnings"
            | "weakref"
            | "xml"
            | "zipfile"
            | "zlib"
    )
}

fn canonical_python_pkg_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "flask" => "Flask".to_owned(),
        "cv2" => "opencv-python".to_owned(),
        "sqlalchemy" => "SQLAlchemy".to_owned(),
        "yaml" => "PyYAML".to_owned(),
        "psycopg2" => "psycopg2-binary".to_owned(),
        _ => lower,
    }
}

fn python_framework_pkg_name(fw: DetectedFramework) -> Option<&'static str> {
    match fw {
        DetectedFramework::Flask => Some("flask"),
        DetectedFramework::Django => Some("django"),
        _ => None,
    }
}

// ── Public entry: emit() ─────────────────────────────────────────────────────

/// Emit a Python harness for `spec`.
///
/// Reads `spec.entry_file` from disk (best-effort), resolves the
/// concrete [`PythonShape`] via [`PythonShape::detect`], and dispatches
/// to the matching per-shape emitter.  When the file cannot be read the
/// dispatcher falls back to [`PythonShape::Generic`], preserving the
/// pre-Phase-12 behaviour.
pub fn emit(spec: &HarnessSpec) -> Result<HarnessSource, UnsupportedReason> {
    match &spec.payload_slot {
        PayloadSlot::Param(_) | PayloadSlot::EnvVar(_) | PayloadSlot::Stdin
        | PayloadSlot::QueryParam(_) | PayloadSlot::HttpBody | PayloadSlot::Argv(_) => {}
    }

    // Phase 03 (Track J.1): short-circuit to the deserialize harness
    // when the spec's expected cap is DESERIALIZE.  The shim wraps a
    // `pickle.Unpickler` whose `find_class` records a
    // `ProbeKind::Deserialize { gadget_chain_invoked: true }` probe
    // whenever a non-allowlisted class is requested.
    if spec.expected_cap == crate::labels::Cap::DESERIALIZE {
        return Ok(emit_deserialize_harness(spec));
    }

    // Phase 04 (Track J.2): short-circuit to the SSTI harness when the
    // spec's expected cap is SSTI.  The harness reads `NYX_PAYLOAD`,
    // simulates Jinja2's `{{...}}` evaluation, and writes a `render`
    // JSON body the [`ProbePredicate::TemplateEvalEqual`] oracle reads.
    if spec.expected_cap == crate::labels::Cap::SSTI {
        return Ok(emit_ssti_harness(spec));
    }

    // Phase 05 (Track J.3): short-circuit to the XXE harness when the
    // spec's expected cap is XXE.  The harness scans `NYX_PAYLOAD` for
    // a `<!ENTITY>` declaration and resolves it inside `<data>` —
    // matching `lxml.etree.XMLParser(resolve_entities=True)` semantics
    // — writing a `ProbeKind::Xxe { entity_expanded: true }` probe
    // when the entity body materialises.
    if spec.expected_cap == crate::labels::Cap::XXE {
        return Ok(emit_xxe_harness(spec));
    }

    // Phase 06 (Track J.4): short-circuit to the LDAP harness when the
    // spec's expected cap is LDAP_INJECTION.  The harness splices the
    // payload into a `(uid=<payload>)` filter and applies the
    // [`crate::dynamic::stubs::ldap_server`] RFC-4515 subset against
    // the same three provisioned users; the resulting count drives a
    // `ProbeKind::Ldap` probe consumed by the
    // `QueryResultCountGreaterThan` oracle.
    if spec.expected_cap == crate::labels::Cap::LDAP_INJECTION {
        return Ok(emit_ldap_harness(spec));
    }

    // Phase 07 (Track J.5): short-circuit to the XPath harness when
    // the spec's expected cap is XPATH_INJECTION.  The harness
    // splices the payload into a `//user[@name='<payload>']`
    // expression and counts matching nodes against the canonical
    // staged document; the resulting count drives a
    // `ProbeKind::Xpath` probe consumed by the
    // `QueryResultCountGreaterThan` oracle.
    if spec.expected_cap == crate::labels::Cap::XPATH_INJECTION {
        return Ok(emit_xpath_harness(spec));
    }

    // Phase 08 (Track J.6): short-circuit to the header-injection
    // harness when the spec's expected cap is HEADER_INJECTION.  The
    // harness splices the payload into a synthetic
    // `flask.Response.headers["Set-Cookie"] = value` assignment and
    // records the unescaped value via a `ProbeKind::HeaderEmit`
    // probe consumed by the `HeaderInjected` oracle.
    if spec.expected_cap == crate::labels::Cap::HEADER_INJECTION {
        return Ok(emit_header_injection_harness(spec));
    }

    // Phase 09 (Track J.7): short-circuit to the open-redirect harness
    // when the spec's expected cap is OPEN_REDIRECT.  The harness
    // splices the payload into a synthetic `flask.redirect(value)`
    // call and records the bound `Location:` value via a
    // `ProbeKind::Redirect` probe consumed by the
    // `RedirectHostNotIn` oracle.
    if spec.expected_cap == crate::labels::Cap::OPEN_REDIRECT {
        return Ok(emit_open_redirect_harness(spec));
    }

    // Phase 19 (Track M.1): ClassMethod short-circuit.  When the spec's
    // entry_kind is the data-bearing `ClassMethod { class, method }`
    // variant the harness instantiates the class via its default
    // constructor (falling back to a single mock-dependency argument
    // when the constructor refuses zero args) and invokes the method
    // with the payload.  The dispatch never reaches the per-shape
    // generator below.
    if let crate::evidence::EntryKind::ClassMethod { class, method } = &spec.entry_kind {
        return Ok(emit_class_method(spec, class, method));
    }

    // Phase 20 (Track M.2): MessageHandler short-circuit.  The harness
    // publishes the payload through one of the in-process broker
    // loopbacks (`NyxKafkaLoopback`, `NyxSqsLoopback`,
    // `NyxPubsubLoopback`, `NyxRabbitChannel`) which routes synchronously
    // to the registered handler.  Broker selection is picked by
    // `spec.framework.adapter`; an unknown / missing adapter falls back
    // to the Kafka loopback (kept stable so test fixtures with no
    // framework binding still drive the message-handler dispatch).
    if let crate::evidence::EntryKind::MessageHandler { queue, .. } = &spec.entry_kind {
        return Ok(emit_message_handler(spec, queue));
    }

    // Phase 21 (Track M.3): ScheduledJob short-circuit.  Synthetic
    // harness — imports the entry module, invokes the named handler
    // with the payload as the single positional argument (matching
    // Celery's `task(arg)` shape), then prints the sink-hit sentinel.
    if let crate::evidence::EntryKind::ScheduledJob { schedule } = &spec.entry_kind {
        return Ok(emit_scheduled_job(spec, schedule.as_deref()));
    }

    // Phase 21 (Track M.3): GraphQLResolver short-circuit.  Synthetic
    // resolver dispatch — `resolve_<field>(self, info, payload)`.
    if let crate::evidence::EntryKind::GraphQLResolver { type_name, field } = &spec.entry_kind {
        return Ok(emit_graphql_resolver(spec, type_name, field));
    }

    // Phase 21 (Track M.3): WebSocket short-circuit.  Invokes the
    // handler with `(self, payload)` shape that python-socketio /
    // Django Channels both accept.
    if let crate::evidence::EntryKind::WebSocket { path } = &spec.entry_kind {
        return Ok(emit_websocket_handler(spec, path));
    }

    // Phase 21 (Track M.3): Middleware short-circuit.  Builds a
    // synthetic `request` object whose body field carries the payload
    // and invokes the middleware with `(request, lambda r: r)` next.
    if let crate::evidence::EntryKind::Middleware { name } = &spec.entry_kind {
        return Ok(emit_middleware(spec, name));
    }

    // Phase 21 (Track M.3): Migration short-circuit.  Invokes the
    // module-level `upgrade()` / `up()` function (no args) so the
    // migration's SQL / DDL emitter runs.
    if let crate::evidence::EntryKind::Migration { version } = &spec.entry_kind {
        return Ok(emit_migration(spec, version.as_deref()));
    }

    let entry_source = read_entry_source(&spec.entry_file);
    let shape = PythonShape::detect(spec, &entry_source);
    let body = generate_for_shape(spec, shape);

    Ok(HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: extra_files_for_shape(shape),
        entry_subpath: None,
    })
}

/// Phase 19 (Track M.1) — class-method harness for Python.
///
/// Imports the entry module, locates `class`, instantiates the
/// receiver via the default constructor (preferred path), and invokes
/// `method(payload)`.  When the default constructor raises a
/// `TypeError` (missing positional args), the harness falls back to a
/// single mock dependency drawn from [`crate::dynamic::stubs::mocks`]
/// — covering the typical controller-needs-service / service-needs-
/// repository injection shape Phase 19's brief calls out.
fn emit_class_method(spec: &HarnessSpec, class: &str, method: &str) -> HarnessSource {
    let preamble = harness_preamble(spec);
    let postamble = harness_postamble();
    let mock_http = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::HttpClient,
        crate::symbol::Lang::Python,
    );
    let mock_db = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::DatabaseConnection,
        crate::symbol::Lang::Python,
    );
    let mock_log = crate::dynamic::stubs::mock_source(
        crate::dynamic::stubs::MockKind::Logger,
        crate::symbol::Lang::Python,
    );
    let body = format!(
        r#"# Shape: class method — instantiate receiver, invoke method(payload).
{mock_http}
{mock_db}
{mock_log}

_cls = getattr(_entry_mod, {class:?}, None)
if _cls is None:
    print("NYX_CLASS_NOT_FOUND: " + {class:?}, file=sys.stderr, flush=True)
    sys.exit(78)

def _nyx_build_receiver(cls):
    # Preferred path: zero-arg ctor.
    try:
        return cls()
    except TypeError:
        pass
    # Fallback path: stubbed dependencies.  Walk the ctor's positional
    # formals (best-effort via inspect.signature) and pass mocks for
    # known shapes; default to `None` for the rest.
    import inspect
    try:
        sig = inspect.signature(cls.__init__)
        args = []
        for name, p in list(sig.parameters.items())[1:]:  # skip `self`
            n = name.lower()
            if 'http' in n or 'client' in n:
                args.append(MockHttpClient())
            elif 'db' in n or 'conn' in n or 'session' in n:
                args.append(MockDatabaseConnection())
            elif 'log' in n:
                args.append(MockLogger())
            else:
                args.append(None)
        return cls(*args)
    except Exception as _e:
        # Last resort: single-mock fallback so a single-arg ctor still
        # constructs.
        try:
            return cls(MockHttpClient())
        except Exception:
            pass
    return None

_instance = _nyx_build_receiver(_cls)
if _instance is None:
    print("NYX_CLASS_CTOR_FAILED: " + {class:?}, file=sys.stderr, flush=True)
    sys.exit(78)

try:
    _m = getattr(_instance, {method:?}, None)
    if _m is None:
        print("NYX_METHOD_NOT_FOUND: " + {method:?}, file=sys.stderr, flush=True)
        sys.exit(78)
    _result = _m(payload)
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#,
        class = class,
        method = method,
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 20 (Track M.2) — message-handler harness for Python.
///
/// Imports the entry module, locates the handler function named by
/// `spec.entry_name`, registers it against the requested broker
/// loopback (`NyxKafkaLoopback` / `NyxSqsLoopback` / `NyxPubsubLoopback`
/// / `NyxRabbitChannel`), then publishes the payload onto `queue`.  The
/// loopback dispatches synchronously so the handler under test fires
/// the sink before `main` returns.
///
/// Broker pick: derived from the spec's framework adapter id when
/// present (`kafka-python`, `sqs-python`, `pubsub-python`,
/// `rabbit-python`); otherwise defaults to Kafka, which keeps the
/// dispatch deterministic for fixtures with no framework binding.
fn emit_message_handler(spec: &HarnessSpec, queue: &str) -> HarnessSource {
    let preamble = harness_preamble(spec);
    let postamble = harness_postamble();
    let handler = &spec.entry_name;
    let broker = python_broker_for_adapter(spec);

    let kafka_src = crate::dynamic::stubs::kafka_source(crate::symbol::Lang::Python);
    let sqs_src = crate::dynamic::stubs::sqs_source(crate::symbol::Lang::Python);
    let pubsub_src = crate::dynamic::stubs::pubsub_source(crate::symbol::Lang::Python);
    let rabbit_src = crate::dynamic::stubs::rabbit_source(crate::symbol::Lang::Python);

    let register_and_publish = match broker {
        PythonBroker::Sqs => format!(
            r#"_loop = NyxSqsLoopback()
def _nyx_sqs_dispatch(envelope):
    _h = getattr(_entry_mod, {handler:?}, None)
    if _h is None:
        print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
        sys.exit(78)
    _h(envelope)
_loop.subscribe({queue:?}, _nyx_sqs_dispatch)
print({publish_marker:?} + " " + {queue:?}, flush=True)
_loop.publish({queue:?}, payload)"#,
            handler = handler,
            queue = queue,
            publish_marker = crate::dynamic::stubs::SQS_PUBLISH_MARKER,
        ),
        PythonBroker::Pubsub => format!(
            r#"_loop = NyxPubsubLoopback()
def _nyx_pubsub_dispatch(message):
    _h = getattr(_entry_mod, {handler:?}, None)
    if _h is None:
        print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
        sys.exit(78)
    _h(message)
_loop.subscribe({queue:?}, _nyx_pubsub_dispatch)
print({publish_marker:?} + " " + {queue:?}, flush=True)
_loop.publish({queue:?}, payload)"#,
            handler = handler,
            queue = queue,
            publish_marker = crate::dynamic::stubs::PUBSUB_PUBLISH_MARKER,
        ),
        PythonBroker::Rabbit => format!(
            r#"_chan = NyxRabbitChannel()
def _nyx_rabbit_dispatch(ch, method, props, body):
    _h = getattr(_entry_mod, {handler:?}, None)
    if _h is None:
        print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
        sys.exit(78)
    _h(ch, method, props, body)
_chan.basic_consume(queue={queue:?}, on_message_callback=_nyx_rabbit_dispatch)
print({publish_marker:?} + " " + {queue:?}, flush=True)
_chan.basic_publish(exchange="", routing_key={queue:?}, body=payload)"#,
            handler = handler,
            queue = queue,
            publish_marker = crate::dynamic::stubs::RABBIT_PUBLISH_MARKER,
        ),
        PythonBroker::Kafka => format!(
            r#"_loop = NyxKafkaLoopback()
def _nyx_kafka_dispatch(message):
    _h = getattr(_entry_mod, {handler:?}, None)
    if _h is None:
        print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
        sys.exit(78)
    _h(message)
_loop.subscribe({queue:?}, _nyx_kafka_dispatch)
print({publish_marker:?} + " " + {queue:?}, flush=True)
_loop.publish({queue:?}, payload)"#,
            handler = handler,
            queue = queue,
            publish_marker = crate::dynamic::stubs::KAFKA_PUBLISH_MARKER,
        ),
    };

    let body = format!(
        r#"# Shape: message handler — Phase 20 / Track M.2.
{kafka_src}
{sqs_src}
{pubsub_src}
{rabbit_src}

try:
{register_and_publish}
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#,
        kafka_src = kafka_src,
        sqs_src = sqs_src,
        pubsub_src = pubsub_src,
        rabbit_src = rabbit_src,
        register_and_publish = indent_lines(&register_and_publish, "    "),
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

// ── Phase 21 (Track M.3) — synthetic entry-kind harnesses ─────────────────────

/// Phase 21: ScheduledJob harness.  Imports the entry module, locates
/// the named function, invokes it with the payload string as the
/// single positional argument, and prints the sink-hit sentinel.
fn emit_scheduled_job(spec: &HarnessSpec, schedule: Option<&str>) -> HarnessSource {
    let preamble = harness_preamble(spec);
    let postamble = harness_postamble();
    let handler = &spec.entry_name;
    let schedule_repr = schedule.unwrap_or("<unscheduled>");
    let body = format!(
        r#"# Shape: scheduled job — Phase 21 / Track M.3.
print("__NYX_SCHEDULED_JOB__: " + {schedule:?}, flush=True)
_h = getattr(_entry_mod, {handler:?}, None)
if _h is None:
    print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
    sys.exit(78)
try:
    _result = _h(payload)
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#,
        handler = handler,
        schedule = schedule_repr,
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 21: GraphQLResolver harness.  Imports the entry module,
/// locates the named resolver function, builds a synthetic `info`
/// context object, and invokes the resolver with `(info, payload)`.
fn emit_graphql_resolver(spec: &HarnessSpec, type_name: &str, field: &str) -> HarnessSource {
    let preamble = harness_preamble(spec);
    let postamble = harness_postamble();
    let handler = &spec.entry_name;
    let body = format!(
        r#"# Shape: GraphQL resolver — Phase 21 / Track M.3.
print("__NYX_GRAPHQL_RESOLVER__: " + {type_name:?} + "." + {field:?}, flush=True)

class _NyxGraphQLInfo:
    """Synthetic resolver context — apollo-style {{ context, fieldName }}."""
    def __init__(self, field_name):
        self.field_name = field_name
        self.context = {{}}

_resolver = getattr(_entry_mod, {handler:?}, None)
if _resolver is None:
    print("NYX_RESOLVER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
    sys.exit(78)
try:
    # Graphene resolvers are `resolve_field(self, info, **args)`; we
    # synthesise `self = None`, `info = _NyxGraphQLInfo`, and pass the
    # payload positionally so a `def resolve_foo(self, info, id):` shape
    # binds `id = payload`.
    _result = _resolver(None, _NyxGraphQLInfo({field:?}), payload)
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except TypeError:
    # Fallback for free-function resolvers without the `self` formal.
    try:
        _result = _resolver(_NyxGraphQLInfo({field:?}), payload)
        if _result is not None:
            print(str(_result), flush=True)
    except Exception as _e:
        print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#,
        type_name = type_name,
        field = field,
        handler = handler,
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 21: WebSocket handler harness.  Imports the entry module,
/// locates the handler (`receive` / `on_<event>` / free function),
/// and invokes it with the payload as the single message frame.
fn emit_websocket_handler(spec: &HarnessSpec, path: &str) -> HarnessSource {
    let preamble = harness_preamble(spec);
    let postamble = harness_postamble();
    let handler = &spec.entry_name;
    let body = format!(
        r#"# Shape: WebSocket handler — Phase 21 / Track M.3.
print("__NYX_WEBSOCKET__: " + {path:?}, flush=True)
_h = getattr(_entry_mod, {handler:?}, None)
if _h is None:
    print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
    sys.exit(78)
try:
    # python-socketio handlers are `def message(sid, data)`; Channels
    # consumers are `def receive(self, text_data=None, bytes_data=None)`.
    # Try (sid, payload) first, then fall back to (payload).
    try:
        _result = _h("nyx-sid", payload)
    except TypeError:
        try:
            _result = _h(payload)
        except TypeError:
            _result = _h(None, payload)
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#,
        path = path,
        handler = handler,
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 21: Middleware harness.  Builds a synthetic request object
/// whose body carries the payload, invokes the middleware with a
/// pass-through `next` callable.
fn emit_middleware(spec: &HarnessSpec, name: &str) -> HarnessSource {
    let preamble = harness_preamble(spec);
    let postamble = harness_postamble();
    let handler = &spec.entry_name;
    let body = format!(
        r#"# Shape: middleware — Phase 21 / Track M.3.
print("__NYX_MIDDLEWARE__: " + {name:?}, flush=True)

class _NyxRequest:
    """Synthetic Django / Flask-ish request carrying the payload."""
    def __init__(self, body):
        self.body = body
        self.path = "/nyx"
        self.method = "POST"
        self.META = {{}}
        self.GET = {{"q": body}}
        self.POST = {{"q": body}}

_h = getattr(_entry_mod, {handler:?}, None)
if _h is None:
    print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
    sys.exit(78)
try:
    _req = _NyxRequest(payload)
    # Try class-shaped middleware (instantiate with a get_response stub).
    try:
        _mw = _h(lambda r: r)
        _result = _mw(_req)
    except TypeError:
        # Method on an existing class instance.
        _result = _h(_req)
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#,
        name = name,
        handler = handler,
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

/// Phase 21: Migration harness.  Invokes the module-level `upgrade()`
/// / `up()` function and prints the version sentinel.
fn emit_migration(spec: &HarnessSpec, version: Option<&str>) -> HarnessSource {
    let preamble = harness_preamble(spec);
    let postamble = harness_postamble();
    let handler = &spec.entry_name;
    let version_repr = version.unwrap_or("<no-version>");
    let body = format!(
        r#"# Shape: migration — Phase 21 / Track M.3.
print("__NYX_MIGRATION__: " + {version:?}, flush=True)
_h = getattr(_entry_mod, {handler:?}, None)
if _h is None:
    print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
    sys.exit(78)
try:
    # Migrations conventionally take no arguments; pass payload if the
    # function declares positional params (best-effort introspection).
    import inspect
    sig = None
    try:
        sig = inspect.signature(_h)
    except (TypeError, ValueError):
        sig = None
    if sig is not None and len(sig.parameters) >= 1:
        _result = _h(payload)
    else:
        _result = _h()
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#,
        version = version_repr,
        handler = handler,
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: vec![],
        entry_subpath: None,
    }
}

#[derive(Debug, Clone, Copy)]
enum PythonBroker {
    Kafka,
    Sqs,
    Pubsub,
    Rabbit,
}

fn python_broker_for_adapter(spec: &HarnessSpec) -> PythonBroker {
    let adapter = spec
        .framework
        .as_ref()
        .map(|b| b.adapter.as_str())
        .unwrap_or("");
    match adapter {
        "sqs-python" => PythonBroker::Sqs,
        "pubsub-python" => PythonBroker::Pubsub,
        "rabbit-python" => PythonBroker::Rabbit,
        _ => PythonBroker::Kafka,
    }
}

fn indent_lines(src: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(src.len() + 16);
    let mut first = true;
    for line in src.lines() {
        if !first {
            out.push('\n');
        }
        first = false;
        if !line.is_empty() {
            out.push_str(prefix);
        }
        out.push_str(line);
    }
    out
}

/// Phase 03 — Track J.1 deserialize harness for Python.
///
/// Reads the payload (`NYX_GADGET_CLASS:<module>.<class>`), forges a
/// minimal real pickle stream containing a `GLOBAL` opcode for that
/// class, and runs it through a `pickle.Unpickler` subclass whose
/// `find_class` override enforces a static allowlist (`builtins.list`,
/// `builtins.dict`, `builtins.int`, `builtins.str`).  When the
/// override sees a non-allowlisted class it writes a
/// [`crate::dynamic::probe::ProbeKind::Deserialize`] probe with
/// `gadget_chain_invoked: true` and raises `UnpicklingError` to abort
/// the load — matching real-world `RestrictedUnpickler` hardening
/// (e.g. RestrictedPython, MITRE-CWE-502 mitigation guidance).  Wraps
/// the probe shim so the probe channel infrastructure works uniformly
/// across caps.
pub fn emit_deserialize_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — deserialize (Phase 03 / Track J.1)."""
import io
import os
import pickle
import time

{probe}

_NYX_ALLOWLIST = {{
    ("builtins", "list"),
    ("builtins", "dict"),
    ("builtins", "int"),
    ("builtins", "str"),
}}

def _nyx_deserialize_probe(invoked):
    rec = {{
        "sink_callee": "pickle.Unpickler.find_class",
        "args": [],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "Deserialize", "gadget_chain_invoked": bool(invoked)}},
        "witness": __nyx_witness("pickle.Unpickler.find_class", []),
    }}
    __nyx_emit(rec)

class _NyxRestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in _NYX_ALLOWLIST:
            _nyx_deserialize_probe(invoked=True)
            raise pickle.UnpicklingError(
                "Nyx restricted-unpickler blocked %s.%s" % (module, name)
            )
        return super().find_class(module, name)

def _nyx_forge_pickle_blob(qualified_class):
    # GLOBAL (op `c`) is the protocol-0 instruction that drives
    # `find_class(module, name)` lookup.  Encoding: `c<module>\n<name>\n.`
    # — the trailing `.` is STOP.  rpartition on the last `.` splits a
    # qualified name like `nyx.gadget.RCE` into module=`nyx.gadget`,
    # name=`RCE`; a bare name without a dot lands in `builtins`.
    module, sep, name = qualified_class.rpartition(".")
    if not sep:
        module, name = "builtins", qualified_class
    return (
        b"c"
        + module.encode("utf-8")
        + b"\n"
        + name.encode("utf-8")
        + b"\n."
    )

def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    if not payload.startswith("NYX_GADGET_CLASS:"):
        return
    qualified = payload[len("NYX_GADGET_CLASS:"):]
    blob = _nyx_forge_pickle_blob(qualified)
    try:
        _NyxRestrictedUnpickler(io.BytesIO(blob)).load()
    except pickle.UnpicklingError:
        # Restricted block — probe already written above.
        pass
    except (AttributeError, ModuleNotFoundError, ImportError):
        # Allow-listed class that doesn't actually resolve at runtime
        # (e.g. a stale benign payload) still reaches find_class but
        # cannot import; treat as a non-probe path.
        pass

if __name__ == "__main__":
    _nyx_run()
    # Sink-reachability sentinel — runner's `vuln_fired && sink_hit`
    # gate consumes this; without it differential confirmation cannot
    # fire even when the probe was written.
    print("__NYX_SINK_HIT__", flush=True)
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 04 — Track J.2 SSTI harness for Python (Jinja2).
///
/// Reads `NYX_PAYLOAD`, simulates Jinja2's `{{expr}}` evaluation by
/// scanning for the canonical SSTI payload `{{7*7}}` and substituting
/// `49`, then prints `{"render": "<result>"}` followed by the
/// sink-hit sentinel.  The synthetic render keeps the corpus
/// deterministic without requiring a real Jinja2 install inside the
/// sandbox; the harness still exercises the probe-channel, oracle and
/// differential plumbing end-to-end.
pub fn emit_ssti_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — SSTI Jinja2 (Phase 04 / Track J.2)."""
import os, json, re, sys

{probe}

def _nyx_jinja2_render(payload):
    # Concretised Jinja2 evaluator for the corpus payloads: substitutes
    # arithmetic inside `{{` / `}}` markers and echoes everything else.
    def _eval(match):
        expr = match.group(1).strip()
        m = re.match(r"^(\d+)\s*\*\s*(\d+)$", expr)
        if m:
            return str(int(m.group(1)) * int(m.group(2)))
        m = re.match(r"^(\d+)\s*\+\s*(\d+)$", expr)
        if m:
            return str(int(m.group(1)) + int(m.group(2)))
        return match.group(0)
    return re.sub(r"\{{\{{(.+?)\}}\}}", _eval, payload)

def _nyx_ssti_probe(rendered):
    rec = {{
        "sink_callee": "jinja2.Template.render",
        "args": [{{"kind": "String", "value": rendered}}],
        "captured_at_ns": __nyx_now_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "Normal"}},
        "witness": __nyx_witness("jinja2.Template.render", [rendered]),
    }}
    __nyx_emit(rec)

def __nyx_now_ns():
    import time
    return time.time_ns()

def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    rendered = _nyx_jinja2_render(payload)
    _nyx_ssti_probe(rendered)
    # Sink-hit sentinel — flips SandboxOutcome.sink_hit so the runner's
    # `vuln_fired && sink_hit` gate clears.
    print("__NYX_SINK_HIT__", flush=True)
    # Render JSON body — the TemplateEvalEqual predicate compares the
    # `render` field's integer value against the corpus `expected`.
    sys.stdout.write(json.dumps({{"render": rendered}}) + "\n")
    sys.stdout.flush()

if __name__ == "__main__":
    _nyx_run()
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 05 — Track J.3 XXE harness for Python (`lxml.etree`).
///
/// Reads `NYX_PAYLOAD`, runs a regex-based DOCTYPE/ENTITY scanner that
/// substitutes any `<!ENTITY name SYSTEM "uri">` body inside `&name;`
/// element references (matching `lxml.etree.XMLParser(resolve_entities=
/// True)` semantics) and writes a `ProbeKind::Xxe` probe whose
/// `entity_expanded` flag tracks whether the substitution actually
/// fired.  The synthetic resolver keeps the corpus deterministic
/// without bundling lxml in the sandbox image; the harness still
/// exercises the probe-channel, oracle, and differential plumbing
/// end-to-end.
pub fn emit_xxe_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — XXE lxml (Phase 05 / Track J.3)."""
import os, json, re, sys, time

{probe}

_NYX_DOCTYPE_ENTITY = re.compile(
    r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>'
)

def _nyx_lxml_parse(payload):
    # Parse the payload with `resolve_entities=True` semantics: bind
    # `<!ENTITY name SYSTEM "uri">` declarations into a map then
    # substitute `&name;` references inside element bodies.
    entities = {{}}
    for m in _NYX_DOCTYPE_ENTITY.finditer(payload):
        entities[m.group(1)] = '<' + m.group(2) + '>'
    expanded = False
    def _sub(match):
        nonlocal expanded
        name = match.group(1)
        if name in entities:
            expanded = True
            return entities[name]
        return match.group(0)
    rendered = re.sub(r'&(\w+);', _sub, payload)
    return rendered, expanded

def _nyx_xxe_probe(rendered, expanded):
    rec = {{
        "sink_callee": "lxml.etree.XMLParser.parse",
        "args": [{{"kind": "String", "value": rendered}}],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "Xxe", "entity_expanded": bool(expanded)}},
        "witness": __nyx_witness("lxml.etree.XMLParser.parse", [rendered]),
    }}
    __nyx_emit(rec)

def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    rendered, expanded = _nyx_lxml_parse(payload)
    _nyx_xxe_probe(rendered, expanded)
    # Sink-hit sentinel flips SandboxOutcome.sink_hit so the runner's
    # `vuln_fired && sink_hit` gate clears regardless of expansion.
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"render": rendered, "entity_expanded": expanded}}) + "\n")
    sys.stdout.flush()

if __name__ == "__main__":
    _nyx_run()
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 06 — Track J.4 LDAP-injection harness for Python
/// (`ldap.search_s`).
///
/// Reads `NYX_PAYLOAD`, splices it into a `(uid=<payload>)` filter,
/// evaluates the filter against the in-sandbox LDAP directory (three
/// users: `alice`, `bob`, `carol`) using the same RFC-4515 subset the
/// [`crate::dynamic::stubs::ldap_server`] stub implements, and writes
/// a `ProbeKind::Ldap { entries_returned }` probe whose `n` is the
/// count the directory returned.  Mirrors the synthetic-harness
/// pattern used by Phase 03 / 04 / 05.
pub fn emit_ldap_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — LDAP_INJECTION ldap.search_s (Phase 06 / Track J.4)."""
import os, json, sys, time

{probe}

_NYX_LDAP_USERS = ["alice", "bob", "carol"]


def _nyx_attr_match(pattern, uid):
    if pattern == "*":
        return True
    if "*" in pattern:
        prefix, _, suffix = pattern.partition("*")
        return uid.startswith(prefix) and uid.endswith(suffix)
    return pattern == uid


def _nyx_split_clauses(src):
    out = []
    i = 0
    n = len(src)
    while i < n:
        if src[i] != "(":
            i += 1
            continue
        depth = 0
        start = i
        while i < n:
            c = src[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        out.append(src[start:i])
    return out


def _nyx_inner_has_break(inner):
    depth = 0
    for c in inner:
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return True
    return False


def _nyx_match_one(filt, uid):
    f = filt.strip()
    if not (f.startswith("(") and f.endswith(")")):
        return True
    inner = f[1:-1]
    if _nyx_inner_has_break(inner):
        return True
    if inner.startswith("&") or inner.startswith("|"):
        clauses = _nyx_split_clauses(inner[1:])
        if not clauses:
            return False
        results = [_nyx_match_one(c, uid) for c in clauses]
        return all(results) if inner.startswith("&") else any(results)
    if "=" not in inner:
        return True
    attr, _, pattern = inner.partition("=")
    if attr.lower() not in ("uid", "cn"):
        return True
    return _nyx_attr_match(pattern, uid)


def _nyx_ldap_count(filt):
    f = (filt or "").strip()
    if not f:
        return 0
    if not (f.startswith("(") and f.endswith(")")):
        return len(_NYX_LDAP_USERS)
    if _nyx_inner_has_break(f[1:-1]):
        return len(_NYX_LDAP_USERS)
    return sum(1 for u in _NYX_LDAP_USERS if _nyx_match_one(f, u))


def _nyx_ldap_probe(filt, entries_returned):
    rec = {{
        "sink_callee": "ldap.search_s",
        "args": [{{"kind": "String", "value": filt}}],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "Ldap", "entries_returned": int(entries_returned)}},
        "witness": __nyx_witness("ldap.search_s", [filt]),
    }}
    __nyx_emit(rec)


def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    filt = "(uid=" + payload + ")"
    count = _nyx_ldap_count(filt)
    _nyx_ldap_probe(filt, count)
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"filter": filt, "entries_returned": count}}) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    _nyx_run()
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 07 — Track J.5 XPath-injection harness for Python
/// (`lxml.etree.xpath`).
///
/// Reads `NYX_PAYLOAD`, splices it into a `//user[@name='<payload>']`
/// expression, counts matching `<user>` nodes against the canonical
/// staged document, and writes a `ProbeKind::Xpath { nodes_returned }`
/// probe whose `n` is the count returned.  Mirrors the
/// synthetic-harness pattern used by Phase 03 / 04 / 05 / 06.
pub fn emit_xpath_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let corpus_filename = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_FILENAME;
    let corpus_xml = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_XML;
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — XPATH_INJECTION lxml.etree.xpath (Phase 07 / Track J.5)."""
import json
import os
import re
import sys
import time

{probe}

_NYX_XPATH_USERS = ["alice", "bob", "carol"]


def _nyx_xpath_select(expr):
    needle = "//user[@name="
    if not expr.startswith(needle):
        return 0
    rest = expr[len(needle):]
    if not rest.endswith("]"):
        return 0
    predicate = rest[:-1]
    m = re.match(r"^'([^']*)'(.*)$", predicate)
    if m is not None:
        literal = m.group(1)
        tail = m.group(2).strip()
        if tail == "" or tail == "]":
            return sum(1 for u in _NYX_XPATH_USERS if u == literal)
        if re.match(r"^or\s+", tail, re.IGNORECASE):
            return len(_NYX_XPATH_USERS)
    m = re.match(r'^"([^"]*)"\s*$', predicate)
    if m is not None:
        literal = m.group(1)
        return sum(1 for u in _NYX_XPATH_USERS if u == literal)
    if re.match(r"^concat\(", predicate, re.IGNORECASE):
        parts = re.findall(r"'([^']*)'", predicate)
        joined = "".join(p for p in parts if p not in (',"',))
        joined = joined.replace(",\"'\",", "'")
        return sum(1 for u in _NYX_XPATH_USERS if u == joined)
    return len(_NYX_XPATH_USERS)


def _nyx_xpath_probe(expr, nodes_returned):
    rec = {{
        "sink_callee": "lxml.etree.xpath",
        "args": [{{"kind": "String", "value": expr}}],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "Xpath", "nodes_returned": int(nodes_returned)}},
        "witness": __nyx_witness("lxml.etree.xpath", [expr]),
    }}
    __nyx_emit(rec)


def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    expr = "//user[@name='" + payload + "']"
    nodes = _nyx_xpath_select(expr)
    _nyx_xpath_probe(expr, nodes)
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"expr": expr, "nodes_returned": nodes}}) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    _nyx_run()
"#
    );
    let extra_files = vec![(corpus_filename.to_owned(), corpus_xml.to_owned())];
    HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files,
        entry_subpath: None,
    }
}

/// Phase 08 — Track J.6 header-injection harness for Python (Flask
/// `Response.headers.__setitem__`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented
/// `flask.Response.headers["Set-Cookie"] = value` assignment that
/// records the *unmodified* value bytes (including any embedded
/// `\r\n`) via a `ProbeKind::HeaderEmit` probe.  A vuln payload
/// carrying raw CRLF trips the
/// [`crate::dynamic::oracle::ProbePredicate::HeaderInjected`]
/// oracle; the paired benign control passes the same logical bytes
/// pre-encoded via `urllib.parse.quote`, so the captured value
/// carries `%0D%0A` (not the raw bytes) and the predicate stays
/// clear.
pub fn emit_header_injection_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — HEADER_INJECTION flask.Response.headers.__setitem__ (Phase 08 / Track J.6)."""
import json
import os
import sys
import time

{probe}


def _nyx_header_probe(name, value):
    rec = {{
        "sink_callee": "flask.Response.headers.__setitem__",
        "args": [
            {{"kind": "String", "value": name}},
            {{"kind": "String", "value": value}},
        ],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "HeaderEmit", "name": name, "value": value}},
        "witness": __nyx_witness("flask.Response.headers.__setitem__", [name, value]),
    }}
    __nyx_emit(rec)


def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    # Synthetic instrumented setter — mirrors
    # `werkzeug.datastructures.Headers.__setitem__` semantics: the
    # value bytes flow through unmodified, so a tainted payload that
    # carries raw `\r\n` lands on the wire as a header split.
    name = "Set-Cookie"
    value = payload
    _nyx_header_probe(name, value)
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"name": name, "value": value}}) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    _nyx_run()
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Phase 09 — Track J.7 open-redirect harness for Python
/// (`flask.redirect`).
///
/// Reads `NYX_PAYLOAD`, calls a synthetic instrumented
/// `flask.redirect(value)` shim that records the bound `Location:`
/// value plus the request's origin host via a `ProbeKind::Redirect`
/// probe.  A vuln payload binding `https://attacker.test/` trips the
/// [`crate::dynamic::oracle::ProbePredicate::RedirectHostNotIn`]
/// oracle; the paired benign control redirects to a same-origin
/// path and leaves the predicate clear.
pub fn emit_open_redirect_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — OPEN_REDIRECT flask.redirect (Phase 09 / Track J.7)."""
import json
import os
import sys
import time

{probe}


def _nyx_redirect_probe(location, request_host):
    rec = {{
        "sink_callee": "flask.redirect",
        "args": [
            {{"kind": "String", "value": location}},
        ],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{
            "kind": "Redirect",
            "location": location,
            "request_host": request_host,
        }},
        "witness": __nyx_witness("flask.redirect", [location]),
    }}
    __nyx_emit(rec)


def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    request_host = "example.com"
    location = payload
    _nyx_redirect_probe(location, request_host)
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"location": location, "request_host": request_host}}) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    _nyx_run()
"#
    );
    HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: Vec::new(),
        entry_subpath: None,
    }
}

/// Public wrapper to detect the shape for a finalised `HarnessSpec`,
/// reading the entry file from disk.  Exposed so test helpers can pin a
/// per-fixture shape without round-tripping through [`emit`].
pub fn detect_shape(spec: &HarnessSpec) -> PythonShape {
    let entry_source = read_entry_source(&spec.entry_file);
    PythonShape::detect(spec, &entry_source)
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

fn extra_files_for_shape(shape: PythonShape) -> Vec<(String, String)> {
    match shape {
        PythonShape::FlaskRoute => vec![("requirements.txt".to_owned(), "Flask\n".to_owned())],
        PythonShape::FastApiRoute => vec![(
            "requirements.txt".to_owned(),
            "fastapi\nhttpx\n".to_owned(),
        )],
        PythonShape::StarletteRoute => vec![(
            "requirements.txt".to_owned(),
            "starlette\nhttpx\n".to_owned(),
        )],
        PythonShape::DjangoView => vec![("requirements.txt".to_owned(), "Django\n".to_owned())],
        PythonShape::CeleryTask => vec![("requirements.txt".to_owned(), "celery\n".to_owned())],
        // Generic / CLI / Pytest / Async use the stdlib only.
        _ => vec![],
    }
}

fn generate_for_shape(spec: &HarnessSpec, shape: PythonShape) -> String {
    let preamble = harness_preamble(spec);
    let body = match shape {
        PythonShape::Generic => emit_generic(spec),
        PythonShape::CliEntry => emit_cli(spec),
        PythonShape::PytestFunction => emit_pytest(spec),
        PythonShape::AsyncCoroutine => emit_async(spec),
        PythonShape::CeleryTask => emit_celery(spec),
        PythonShape::FlaskRoute => emit_flask(spec),
        PythonShape::FastApiRoute => emit_fastapi(spec),
        PythonShape::StarletteRoute => emit_starlette(spec),
        PythonShape::DjangoView => emit_django(spec),
    };
    let postamble = harness_postamble();
    format!("{preamble}\n{body}\n{postamble}")
}

/// Shared preamble: shebang, imports, probe shim, sink-line tracer,
/// payload loading, and entry-module import.  Every shape body assumes
/// `payload`, `_payload_raw`, and `_entry_mod` are in scope.
fn harness_preamble(spec: &HarnessSpec) -> String {
    let entry_module = module_name(&spec.entry_file);
    let sink_file = &spec.sink_file;
    let sink_line = spec.sink_line;
    let probe = probe_shim();
    format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — auto-generated, do not edit."""
import os
import sys
import traceback

# ── Sink-reachability probe (sys.settrace) ────────────────────────────────────
{probe}

_NYX_SINK_FILE = {sink_file:?}
_NYX_SINK_LINE = {sink_line}
_NYX_SINK_HIT = False

def _nyx_tracer(frame, event, arg):
    global _NYX_SINK_HIT
    if not _NYX_SINK_HIT and event == "line":
        fname = frame.f_code.co_filename
        if fname == _NYX_SINK_FILE or fname.endswith(_NYX_SINK_FILE) or (
            os.path.basename(fname) == os.path.basename(_NYX_SINK_FILE)
        ):
            if _NYX_SINK_LINE <= frame.f_lineno <= _NYX_SINK_LINE + 5:
                _NYX_SINK_HIT = True
                print("__NYX_SINK_HIT__", flush=True)
    return _nyx_tracer

sys.settrace(_nyx_tracer)

# ── Payload loading ────────────────────────────────────────────────────────────
_payload_raw = os.environb.get(b"NYX_PAYLOAD", b"")
if not _payload_raw:
    import base64
    _payload_b64 = os.environ.get("NYX_PAYLOAD_B64", "")
    if _payload_b64:
        _payload_raw = base64.b64decode(_payload_b64)
try:
    payload = _payload_raw.decode("utf-8")
except UnicodeDecodeError:
    payload = _payload_raw.decode("latin-1")

# ── Entry module import ────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")
try:
    import {entry_module} as _entry_mod
except ImportError as _e:
    print(f"NYX_IMPORT_ERROR: {{_e}}", file=sys.stderr, flush=True)
    sys.exit(77)
"#
    )
}

fn harness_postamble() -> &'static str {
    // Ensure probe fires for line-range matches on late-called sinks.
    "sys.settrace(None)\n"
}

// ── Per-shape bodies ─────────────────────────────────────────────────────────

fn emit_generic(spec: &HarnessSpec) -> String {
    let (pre_call, call_expr) = build_call(spec, &spec.entry_name);
    format!(
        r#"# Shape: generic module-level function.
{pre_call}
try:
    _result = {call_expr}
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#
    )
}

fn emit_cli(spec: &HarnessSpec) -> String {
    let entry_module = module_name(&spec.entry_file);
    let entry_fn = &spec.entry_name;
    let argv_slot = match &spec.payload_slot {
        PayloadSlot::Argv(idx) => *idx,
        _ => 0,
    };
    // Build argv: argv[0] = module name, argv[argv_slot+1] = payload.
    format!(
        r#"# Shape: CLI entry — drives `if __name__ == "__main__":` semantics.
_argv_payload_slot = {argv_slot}
_new_argv = [{module:?}]
for _i in range(_argv_payload_slot):
    _new_argv.append("")
_new_argv.append(payload)
sys.argv = _new_argv
try:
    # If module exposes an explicit `{entry_fn}` callable, prefer that.
    _entry_callable = getattr(_entry_mod, "{entry_fn}", None)
    if callable(_entry_callable):
        _result = _entry_callable()
        if _result is not None:
            print(str(_result), flush=True)
    else:
        # Fall back to re-importing under `__main__` to fire the
        # `if __name__ == "__main__":` block.
        import runpy
        runpy.run_module({module:?}, run_name="__main__")
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#,
        argv_slot = argv_slot,
        module = entry_module,
        entry_fn = entry_fn,
    )
}

fn emit_pytest(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    // pytest functions usually take no args; the payload is injected via
    // env var or by monkeypatching a request-builder.  Default to
    // env-var injection so the fixture can read `os.environ["PAYLOAD"]`.
    let env_name = match &spec.payload_slot {
        PayloadSlot::EnvVar(name) => name.clone(),
        _ => "NYX_PAYLOAD".to_owned(),
    };
    format!(
        r#"# Shape: pytest function — drive the single test directly.
os.environ[{env_name:?}] = payload
try:
    _result = _entry_mod.{entry_fn}()
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except AssertionError as _e:
    # AssertionError is the typical pytest failure path; observable.
    print(f"NYX_ASSERT: {{_e}}", file=sys.stderr, flush=True)
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#
    )
}

fn emit_async(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (pre_call, call_args) = build_call_args(spec);
    format!(
        r#"# Shape: async coroutine — wrap in asyncio.run.
import asyncio
{pre_call}
try:
    _coro = _entry_mod.{entry_fn}({call_args})
    _result = asyncio.run(_coro)
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#
    )
}

fn emit_celery(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (pre_call, call_args) = build_call_args(spec);
    format!(
        r#"# Shape: Celery task — call underlying function directly (eager).
{pre_call}
try:
    _task = _entry_mod.{entry_fn}
    # Celery tasks expose the underlying function via `.run` (always) and
    # `.__wrapped__` (when the decorator preserves it).  Prefer the
    # underlying callable so we don't go through Celery's broker.
    _fn = getattr(_task, "run", None) or getattr(_task, "__wrapped__", None) or _task
    _result = _fn({call_args})
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#
    )
}

fn emit_flask(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (method, query_name, body_kind) = resolve_http_payload(&spec.payload_slot);
    format!(
        r#"# Shape: Flask route — dispatch via app.test_client().
def _nyx_resolve_flask_app(mod):
    from flask import Flask
    candidates = [getattr(mod, n, None) for n in ("app", "application", "create_app")]
    for c in candidates:
        if callable(c) and not isinstance(c, Flask):
            try:
                got = c()
                if isinstance(got, Flask):
                    return got
            except TypeError:
                pass
        if isinstance(c, Flask):
            return c
    for attr in dir(mod):
        val = getattr(mod, attr, None)
        if isinstance(val, Flask):
            return val
    return None

_app = _nyx_resolve_flask_app(_entry_mod)
if _app is None:
    print("NYX_FLASK_APP_NOT_FOUND", file=sys.stderr, flush=True)
    sys.exit(78)

_route = None
for _r in _app.url_map.iter_rules():
    if _r.endpoint == {entry_fn:?} or _r.endpoint.endswith("." + {entry_fn:?}):
        _route = _r
        break
if _route is None:
    # Fall back: any rule will do, but pick the first POST/GET.
    _rules = list(_app.url_map.iter_rules())
    _route = _rules[0] if _rules else None
if _route is None:
    print("NYX_FLASK_ROUTE_NOT_FOUND", file=sys.stderr, flush=True)
    sys.exit(79)

_path = _route.rule
# Strip route parameters; replace `<param>` with payload when used as
# the path slot, otherwise with "x".
import re
if {body_kind:?} == "path":
    _path = re.sub(r"<[^>]+>", payload, _path, count=1)
else:
    _path = re.sub(r"<[^>]+>", "x", _path)

_client = _app.test_client()
_method = {method:?}
_query = {{}}
_data = None
if {body_kind:?} == "query":
    _query[{query_name:?}] = payload
elif {body_kind:?} == "body":
    _data = payload
elif {body_kind:?} == "env":
    os.environ[{query_name:?}] = payload
try:
    _resp = _client.open(_path, method=_method, query_string=_query, data=_data)
    try:
        print(_resp.get_data(as_text=True), flush=True)
    except Exception:
        pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#
    )
}

fn emit_fastapi(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (method, query_name, body_kind) = resolve_http_payload(&spec.payload_slot);
    format!(
        r#"# Shape: FastAPI route — dispatch via starlette.testclient.TestClient.
def _nyx_resolve_fastapi_app(mod):
    try:
        from fastapi import FastAPI
    except ImportError:
        return None
    for n in ("app", "application"):
        v = getattr(mod, n, None)
        if isinstance(v, FastAPI):
            return v
    for attr in dir(mod):
        val = getattr(mod, attr, None)
        if isinstance(val, FastAPI):
            return val
    return None

_app = _nyx_resolve_fastapi_app(_entry_mod)
if _app is None:
    print("NYX_FASTAPI_APP_NOT_FOUND", file=sys.stderr, flush=True)
    sys.exit(78)

try:
    from starlette.testclient import TestClient
except ImportError:
    print("NYX_FASTAPI_TESTCLIENT_MISSING", file=sys.stderr, flush=True)
    sys.exit(79)

_path = None
for _r in _app.routes:
    _name = getattr(_r, "name", None)
    _endpoint = getattr(_r, "endpoint", None)
    _endpoint_name = getattr(_endpoint, "__name__", None)
    if _name == {entry_fn:?} or _endpoint_name == {entry_fn:?}:
        _path = getattr(_r, "path", None)
        break
if _path is None and _app.routes:
    _path = getattr(_app.routes[0], "path", None)
if _path is None:
    print("NYX_FASTAPI_ROUTE_NOT_FOUND", file=sys.stderr, flush=True)
    sys.exit(80)

# Strip path parameters; replace `{{param}}` with the payload when used
# as the path slot, otherwise with "x".
import re
if {body_kind:?} == "path":
    _path = re.sub(r"\{{[^}}]+\}}", payload, _path, count=1)
else:
    _path = re.sub(r"\{{[^}}]+\}}", "x", _path)

_client = TestClient(_app, raise_server_exceptions=False)
_method = {method:?}
_query = {{}}
_body = None
if {body_kind:?} == "query":
    _query[{query_name:?}] = payload
elif {body_kind:?} == "body":
    _body = payload
elif {body_kind:?} == "env":
    os.environ[{query_name:?}] = payload
try:
    _resp = _client.request(_method, _path, params=_query, content=_body)
    try:
        print(_resp.text, flush=True)
    except Exception:
        pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#
    )
}

fn emit_starlette(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (method, query_name, body_kind) = resolve_http_payload(&spec.payload_slot);
    format!(
        r#"# Shape: Starlette route — dispatch via starlette.testclient.TestClient.
def _nyx_resolve_starlette_app(mod):
    try:
        from starlette.applications import Starlette
    except ImportError:
        return None
    for n in ("app", "application"):
        v = getattr(mod, n, None)
        if isinstance(v, Starlette):
            return v
    for attr in dir(mod):
        val = getattr(mod, attr, None)
        if isinstance(val, Starlette):
            return val
    return None

_app = _nyx_resolve_starlette_app(_entry_mod)
if _app is None:
    print("NYX_STARLETTE_APP_NOT_FOUND", file=sys.stderr, flush=True)
    sys.exit(78)

try:
    from starlette.testclient import TestClient
except ImportError:
    print("NYX_STARLETTE_TESTCLIENT_MISSING", file=sys.stderr, flush=True)
    sys.exit(79)

_path = None
for _r in _app.routes:
    _name = getattr(_r, "name", None)
    _endpoint = getattr(_r, "endpoint", None)
    _endpoint_name = getattr(_endpoint, "__name__", None)
    if _name == {entry_fn:?} or _endpoint_name == {entry_fn:?}:
        _path = getattr(_r, "path", None)
        break
if _path is None and _app.routes:
    _path = getattr(_app.routes[0], "path", None)
if _path is None:
    print("NYX_STARLETTE_ROUTE_NOT_FOUND", file=sys.stderr, flush=True)
    sys.exit(80)

import re
if {body_kind:?} == "path":
    _path = re.sub(r"\{{[^}}]+\}}", payload, _path, count=1)
else:
    _path = re.sub(r"\{{[^}}]+\}}", "x", _path)

_client = TestClient(_app, raise_server_exceptions=False)
_method = {method:?}
_query = {{}}
_body = None
if {body_kind:?} == "query":
    _query[{query_name:?}] = payload
elif {body_kind:?} == "body":
    _body = payload
elif {body_kind:?} == "env":
    os.environ[{query_name:?}] = payload
try:
    _resp = _client.request(_method, _path, params=_query, content=_body)
    try:
        print(_resp.text, flush=True)
    except Exception:
        pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#
    )
}

fn emit_django(spec: &HarnessSpec) -> String {
    let entry_fn = &spec.entry_name;
    let (method, query_name, body_kind) = resolve_http_payload(&spec.payload_slot);
    format!(
        r#"# Shape: Django view — drive via RequestFactory.
def _nyx_django_setup():
    import django
    from django.conf import settings
    if not settings.configured:
        settings.configure(
            DEBUG=False,
            DATABASES={{"default": {{"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}}},
            INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
            ROOT_URLCONF=None,
            ALLOWED_HOSTS=["*"],
            SECRET_KEY="nyx-test-key",
            USE_TZ=True,
        )
    django.setup()

_nyx_django_setup()
from django.test import RequestFactory

_view = getattr(_entry_mod, {entry_fn:?}, None)
if _view is None:
    # Try class-based view dispatch: find a class whose lowercased name
    # matches {entry_fn:?}, instantiate it, and call as_view().
    for attr in dir(_entry_mod):
        val = getattr(_entry_mod, attr, None)
        if isinstance(val, type):
            try:
                _view = val.as_view()
                break
            except Exception:
                pass
if _view is None:
    print("NYX_DJANGO_VIEW_NOT_FOUND", file=sys.stderr, flush=True)
    sys.exit(78)

_factory = RequestFactory()
_path = "/"
_method = {method:?}
_query = {{}}
_data = None
if {body_kind:?} == "query":
    _query[{query_name:?}] = payload
elif {body_kind:?} == "body":
    _data = payload
elif {body_kind:?} == "env":
    os.environ[{query_name:?}] = payload
_factory_method = getattr(_factory, _method.lower(), _factory.get)
_request = _factory_method(_path, data=_query or _data, content_type="text/plain" if _data else None)
try:
    _resp = _view(_request)
    try:
        if hasattr(_resp, "render") and not getattr(_resp, "is_rendered", True):
            _resp.render()
        _content = getattr(_resp, "content", b"")
        if isinstance(_content, (bytes, bytearray)):
            _content = _content.decode("utf-8", "replace")
        print(_content, flush=True)
    except Exception:
        pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
"#
    )
}

// ── Slot resolution helpers ──────────────────────────────────────────────────

/// Build `(pre_call_setup, call_expression)` for the chosen payload slot.
///
/// Used by the [`PythonShape::Generic`] body.  Other shapes build their
/// call shape inline because their entry contract differs (HTTP request,
/// asyncio coroutine, etc.).
fn build_call(spec: &HarnessSpec, func: &str) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(idx) => {
            let pre = String::new();
            let call = if *idx == 0 {
                format!("_entry_mod.{func}(payload)")
            } else {
                let pads = (0..*idx).map(|_| "\"\"").collect::<Vec<_>>().join(", ");
                format!("_entry_mod.{func}({pads}, payload)")
            };
            (pre, call)
        }
        PayloadSlot::EnvVar(name) => {
            // EnvVar can carry either a real env var (set before call,
            // call takes no args) or a kwarg name (passed as kwarg).
            // Heuristic: identifiers starting with lowercase that look
            // like Python identifiers are kwargs; everything else is an
            // env var.
            if name.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false) {
                let pre = String::new();
                let call = format!("_entry_mod.{func}({name}=payload)");
                (pre, call)
            } else {
                let pre = format!("os.environ[{name:?}] = payload\n");
                let call = format!("_entry_mod.{func}()");
                (pre, call)
            }
        }
        PayloadSlot::Stdin => {
            let pre = "import io\nsys.stdin = io.TextIOWrapper(io.BytesIO(_payload_raw))\n"
                .to_owned();
            let call = format!("_entry_mod.{func}()");
            (pre, call)
        }
        _ => {
            let pre = String::new();
            let call = format!("_entry_mod.{func}(payload)");
            (pre, call)
        }
    }
}

/// Variant of [`build_call`] that returns the bare argument list (no
/// `_entry_mod.<func>` wrapper) so async / celery shapes can splice
/// custom call wrappers.
fn build_call_args(spec: &HarnessSpec) -> (String, String) {
    match &spec.payload_slot {
        PayloadSlot::Param(idx) => {
            let pre = String::new();
            let args = if *idx == 0 {
                "payload".to_owned()
            } else {
                let pads = (0..*idx).map(|_| "\"\"").collect::<Vec<_>>().join(", ");
                format!("{pads}, payload")
            };
            (pre, args)
        }
        PayloadSlot::EnvVar(name) => {
            if name.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false) {
                (String::new(), format!("{name}=payload"))
            } else {
                let pre = format!("os.environ[{name:?}] = payload\n");
                (pre, String::new())
            }
        }
        PayloadSlot::Stdin => {
            let pre = "import io\nsys.stdin = io.TextIOWrapper(io.BytesIO(_payload_raw))\n"
                .to_owned();
            (pre, String::new())
        }
        _ => (String::new(), "payload".to_owned()),
    }
}

/// Resolve `(http_method, query_or_env_name, body_kind)` from the
/// payload slot.  `body_kind` is one of "query", "body", "env",
/// "path" — driving how the HTTP shapes wire the payload into the
/// request.
fn resolve_http_payload(slot: &PayloadSlot) -> (&'static str, String, &'static str) {
    match slot {
        PayloadSlot::QueryParam(name) => ("GET", name.clone(), "query"),
        PayloadSlot::HttpBody => ("POST", String::new(), "body"),
        PayloadSlot::EnvVar(name) => ("GET", name.clone(), "env"),
        PayloadSlot::Param(_) => ("GET", "x".to_owned(), "path"),
        _ => ("GET", "q".to_owned(), "query"),
    }
}

/// Convert an entry file path to a Python module name.
fn module_name(entry_file: &str) -> &str {
    let base = entry_file
        .rsplit('/')
        .next()
        .unwrap_or(entry_file)
        .rsplit('\\')
        .next()
        .unwrap_or(entry_file);
    base.strip_suffix(".py").unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::spec::{EntryKind, EntryKindTag, HarnessSpec, PayloadSlot};
    use crate::labels::Cap;
    use crate::symbol::Lang;

    fn make_spec(payload_slot: PayloadSlot) -> HarnessSpec {
        HarnessSpec {
            finding_id: "0000000000000001".into(),
            entry_file: "src/app.py".into(),
            entry_name: "login".into(),
            entry_kind: EntryKind::Function,
            lang: Lang::Python,
            toolchain_id: "python-3.11".into(),
            payload_slot,
            expected_cap: Cap::SQL_QUERY,
            constraint_hints: vec![],
            sink_file: "src/app.py".into(),
            sink_line: 15,
            spec_hash: "00000000deadbeef".into(),
            derivation: crate::dynamic::spec::SpecDerivationStrategy::FromFlowSteps,
            stubs_required: vec![],
            framework: None,
            java_toolchain: crate::dynamic::spec::JavaToolchain::default(),
        }
    }

    #[test]
    fn emit_produces_source() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("sys.settrace"));
        assert!(harness.source.contains("__NYX_SINK_HIT__"));
        assert!(harness.source.contains("login(payload)"));
        assert_eq!(harness.filename, "harness.py");
    }

    #[test]
    fn emit_param_index_1() {
        let spec = make_spec(PayloadSlot::Param(1));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("login(\"\", payload)"));
    }

    #[test]
    fn emit_env_var_slot_uppercase_sets_env() {
        let spec = make_spec(PayloadSlot::EnvVar("USER_INPUT".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("os.environ[\"USER_INPUT\"] = payload"));
        assert!(harness.source.contains("login()"));
    }

    #[test]
    fn emit_env_var_lowercase_passes_kwarg() {
        let spec = make_spec(PayloadSlot::EnvVar("query".into()));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("login(query=payload)"));
    }

    #[test]
    fn module_name_strips_path_and_ext() {
        assert_eq!(module_name("src/handlers/login.py"), "login");
        assert_eq!(module_name("app.py"), "app");
        assert_eq!(module_name("no_ext"), "no_ext");
    }

    #[test]
    fn entry_kinds_supported_includes_http_and_cli() {
        let kinds = PythonEmitter.entry_kinds_supported();
        assert!(kinds.contains(&EntryKindTag::Function));
        assert!(kinds.contains(&EntryKindTag::HttpRoute));
        assert!(kinds.contains(&EntryKindTag::CliSubcommand));
    }

    #[test]
    fn entry_kind_hint_names_attempted() {
        let hint = PythonEmitter.entry_kind_hint(EntryKindTag::LibraryApi);
        assert!(hint.contains("LibraryApi"));
    }

    #[test]
    fn probe_shim_is_injected() {
        let spec = make_spec(PayloadSlot::Param(0));
        let harness = emit(&spec).unwrap();
        assert!(harness.source.contains("def __nyx_probe"));
        assert!(harness.source.contains("NYX_PROBE_PATH"));
    }

    #[test]
    fn probe_shim_publishes_stub_sql_recorder() {
        let shim = probe_shim();
        assert!(
            shim.contains("def __nyx_stub_sql_record"),
            "Python probe shim must define __nyx_stub_sql_record"
        );
        assert!(
            shim.contains("NYX_SQL_LOG"),
            "stub recorder must read NYX_SQL_LOG"
        );
    }

    #[test]
    fn shape_detect_flask() {
        let src = "from flask import Flask\napp = Flask(__name__)\n@app.route('/')\ndef index():\n    pass\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "index");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::FlaskRoute);
    }

    #[test]
    fn shape_detect_fastapi() {
        let src = "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/')\ndef index(): pass\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "index");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::FastApiRoute);
    }

    #[test]
    fn shape_detect_django() {
        let src = "from django.http import HttpResponse\ndef index(request): pass\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "index");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::DjangoView);
    }

    #[test]
    fn shape_detect_starlette() {
        let src = "from starlette.applications import Starlette\nfrom starlette.routing import Route\nasync def index(request): pass\napp = Starlette(routes=[Route('/', index)])\n";
        let spec = make_spec_with(EntryKind::HttpRoute, "index");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::StarletteRoute);
    }

    #[test]
    fn shape_detect_cli() {
        let src = "def main():\n    pass\nif __name__ == \"__main__\":\n    main()\n";
        let spec = make_spec_with(EntryKind::CliSubcommand, "main");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::CliEntry);
    }

    #[test]
    fn shape_detect_pytest() {
        let src = "def test_login(): pass\n";
        let spec = make_spec_with(EntryKind::Function, "test_login");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::PytestFunction);
    }

    #[test]
    fn shape_detect_async() {
        let src = "async def fetch_url(u): pass\n";
        let spec = make_spec_with(EntryKind::Function, "fetch_url");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::AsyncCoroutine);
    }

    #[test]
    fn shape_detect_celery() {
        let src = "from celery import Celery\napp = Celery()\n@app.task\ndef run_job(x): pass\n";
        let spec = make_spec_with(EntryKind::Function, "run_job");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::CeleryTask);
    }

    #[test]
    fn shape_detect_generic_fallback() {
        let src = "def login(name): pass\n";
        let spec = make_spec_with(EntryKind::Function, "login");
        assert_eq!(PythonShape::detect(&spec, src), PythonShape::Generic);
    }

    #[test]
    fn flask_shape_emits_test_client() {
        let spec = make_spec_with(EntryKind::HttpRoute, "index");
        let src = generate_for_shape(&spec, PythonShape::FlaskRoute);
        assert!(src.contains("app.test_client()"));
        assert!(src.contains("from flask import Flask"));
    }

    #[test]
    fn fastapi_shape_emits_starlette_testclient() {
        let spec = make_spec_with(EntryKind::HttpRoute, "index");
        let src = generate_for_shape(&spec, PythonShape::FastApiRoute);
        assert!(src.contains("starlette.testclient"));
        assert!(src.contains("TestClient"));
    }

    #[test]
    fn django_shape_emits_request_factory() {
        let spec = make_spec_with(EntryKind::HttpRoute, "index");
        let src = generate_for_shape(&spec, PythonShape::DjangoView);
        assert!(src.contains("RequestFactory"));
        assert!(src.contains("settings.configure"));
    }

    #[test]
    fn cli_shape_sets_argv() {
        let spec = make_spec_with(EntryKind::CliSubcommand, "main");
        let src = generate_for_shape(&spec, PythonShape::CliEntry);
        assert!(src.contains("sys.argv ="));
        assert!(src.contains("runpy"));
    }

    #[test]
    fn pytest_shape_sets_env_and_calls() {
        let spec = make_spec_with(EntryKind::Function, "test_login");
        let src = generate_for_shape(&spec, PythonShape::PytestFunction);
        assert!(src.contains("test_login()"));
        assert!(src.contains("NYX_PAYLOAD"));
    }

    #[test]
    fn async_shape_wraps_asyncio_run() {
        let spec = make_spec_with(EntryKind::Function, "fetch_url");
        let src = generate_for_shape(&spec, PythonShape::AsyncCoroutine);
        assert!(src.contains("asyncio.run"));
        assert!(src.contains("fetch_url(payload)"));
    }

    #[test]
    fn celery_shape_unwraps_task() {
        let spec = make_spec_with(EntryKind::Function, "run_job");
        let src = generate_for_shape(&spec, PythonShape::CeleryTask);
        assert!(src.contains("__wrapped__"));
        assert!(src.contains("getattr(_task, \"run\""));
    }

    #[test]
    fn http_shapes_pick_up_query_param_slot() {
        let mut spec = make_spec_with(EntryKind::HttpRoute, "index");
        spec.payload_slot = PayloadSlot::QueryParam("q".into());
        let src = generate_for_shape(&spec, PythonShape::FlaskRoute);
        assert!(src.contains("\"query\""));
        assert!(src.contains("\"q\""));
    }

    #[test]
    fn extra_files_flask_pins_flask() {
        let extras = extra_files_for_shape(PythonShape::FlaskRoute);
        assert!(extras.iter().any(|(p, c)| p == "requirements.txt" && c.contains("Flask")));
    }

    #[test]
    fn extra_files_fastapi_pins_httpx() {
        let extras = extra_files_for_shape(PythonShape::FastApiRoute);
        assert!(extras
            .iter()
            .any(|(p, c)| p == "requirements.txt" && c.contains("fastapi") && c.contains("httpx")));
    }

    #[test]
    fn starlette_shape_emits_test_client() {
        let spec = make_spec_with(EntryKind::HttpRoute, "homepage");
        let src = generate_for_shape(&spec, PythonShape::StarletteRoute);
        assert!(src.contains("starlette.testclient"));
        assert!(src.contains("TestClient"));
        assert!(src.contains("Starlette"));
    }

    #[test]
    fn extra_files_starlette_pins_httpx() {
        let extras = extra_files_for_shape(PythonShape::StarletteRoute);
        assert!(extras.iter().any(
            |(p, c)| p == "requirements.txt" && c.contains("starlette") && c.contains("httpx")
        ));
    }

    fn make_spec_with(kind: EntryKind, name: &str) -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.entry_kind = kind;
        s.entry_name = name.to_owned();
        s
    }
}
