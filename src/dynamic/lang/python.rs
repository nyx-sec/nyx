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
        let has_flask = source_has_marker(source, &["from flask", "import flask", "Flask("]);
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
    (source.contains(&needle) || source.contains(&async_needle)) && name.starts_with("test_")
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

    if let Some(adapter) = env.framework_adapter.as_deref() {
        for d in crate::dynamic::framework::runtime_deps::deps_for_adapter(adapter).python_packages
        {
            let canonical = canonical_python_pkg_name(d);
            if seen.insert(canonical.clone()) {
                deps.push(canonical);
            }
        }
    }
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
        PayloadSlot::Param(_)
        | PayloadSlot::EnvVar(_)
        | PayloadSlot::Stdin
        | PayloadSlot::QueryParam(_)
        | PayloadSlot::HttpBody
        | PayloadSlot::Argv(_) => {}
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

    // Phase 11 (Track J.9): short-circuit to the CRYPTO harness when
    // the spec's expected cap is CRYPTO.  The harness imports the
    // fixture, invokes the entry function with the payload, and
    // converts the returned key into a `ProbeKind::WeakKey { key_int }`
    // record (int returns flow through verbatim; byte / bytearray
    // returns get truncated to the leading 8 bytes via
    // `int.from_bytes`, so a 32-byte CSPRNG key produces a `key_int`
    // whose magnitude trivially exceeds any 16-bit budget).
    if spec.expected_cap == crate::labels::Cap::CRYPTO {
        return Ok(emit_crypto_harness(spec));
    }

    // JSON_PARSE uses a dedicated depth-counting harness.
    if spec.expected_cap == crate::labels::Cap::JSON_PARSE {
        return Ok(emit_json_parse_harness(spec));
    }

    // Phase 11 (Track J.9): UNAUTHORIZED_ID harness.  Imports the
    // fixture, invokes the entry with the payload as the requested
    // owner_id, and emits a `ProbeKind::IdorAccess { caller_id, owner_id }`
    // whenever the fixture materialises a non-None record.  The
    // `IdorBoundaryCrossed` predicate fires when `caller_id != owner_id`.
    if spec.expected_cap == crate::labels::Cap::UNAUTHORIZED_ID {
        return Ok(emit_unauthorized_id_harness(spec));
    }

    // Phase 11 (Track J.9): DATA_EXFIL harness.  Monkey-patches
    // `urllib.request.urlopen` (and `urlopen` re-exported from
    // `urllib.request` modules) so the outbound URL's host is recorded
    // via a `ProbeKind::OutboundNetwork { host }` probe before the
    // request is short-circuited (no real network egress).  The
    // `OutboundHostNotIn` predicate fires when the captured host is
    // outside the configured loopback allowlist.
    if spec.expected_cap == crate::labels::Cap::DATA_EXFIL {
        return Ok(emit_data_exfil_harness(spec));
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

def _nyx_known_mock_for(name):
    n = name.lower()
    if 'http' in n or 'client' in n:
        return MockHttpClient()
    if 'db' in n or 'conn' in n or 'session' in n:
        return MockDatabaseConnection()
    if 'log' in n:
        return MockLogger()
    return None

def _nyx_resolve_annotation(ann):
    if ann is None:
        return None
    try:
        if isinstance(ann, str):
            return getattr(_entry_mod, ann, None)
        if getattr(ann, "__module__", None) == getattr(_entry_mod, "__name__", None):
            return ann
    except Exception:
        return None
    return None

def _nyx_build_receiver(cls, depth=3, seen=None):
    if seen is None:
        seen = set()
    if cls in seen:
        return None
    seen.add(cls)
    # Preferred path: zero-arg ctor.
    try:
        return cls()
    except TypeError:
        pass
    # Fallback path: recursively build in-file typed dependencies up to
    # depth 3, then use known boundary mocks by constructor-name shape.
    import inspect
    try:
        sig = inspect.signature(cls.__init__)
        args = []
        for name, p in list(sig.parameters.items())[1:]:  # skip `self`
            dep = None
            if depth > 0:
                dep_cls = _nyx_resolve_annotation(getattr(p, "annotation", None))
                if dep_cls is not None and dep_cls is not cls:
                    dep = _nyx_build_receiver(dep_cls, depth - 1, set(seen))
            if dep is None:
                dep = _nyx_known_mock_for(name)
            args.append(dep)
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
    print("__NYX_SINK_HIT__", flush=True)
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
        extra_files: framework_dependency_files(spec),
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
            r#"if not _nyx_try_real_sqs({queue:?}, payload, {handler:?}):
    _loop = NyxSqsLoopback()
    def _nyx_sqs_dispatch(envelope):
        _h = getattr(_entry_mod, {handler:?}, None)
        if _h is None:
            print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
            sys.exit(78)
        _h(envelope)
    _loop.subscribe({queue:?}, _nyx_sqs_dispatch)
    print({publish_marker:?} + " " + {queue:?}, flush=True)
    _nyx_record_broker_publish("NYX_SQS_LOG", {queue:?}, payload)
    _loop.publish({queue:?}, payload)
    for _env in _loop.receive_message({queue:?}, max_number=1):
        _nyx_record_broker_event("NYX_SQS_LOG", "deliver", {queue:?}, _env.get("Body", ""))
        _nyx_sqs_dispatch(_env)
        if _loop.delete_message({queue:?}, _env.get("ReceiptHandle", "")):
            _nyx_record_broker_event("NYX_SQS_LOG", "ack", {queue:?}, _env.get("ReceiptHandle", ""))"#,
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
    _nyx_record_broker_event("NYX_PUBSUB_LOG", "deliver", {queue:?}, getattr(message, "data", message))
    _h(message)
    if hasattr(message, "ack"):
        message.ack()
    _nyx_record_broker_event("NYX_PUBSUB_LOG", "ack", {queue:?}, getattr(message, "message_id", ""))
_loop.subscribe({queue:?}, _nyx_pubsub_dispatch)
print({publish_marker:?} + " " + {queue:?}, flush=True)
_nyx_record_broker_publish("NYX_PUBSUB_LOG", {queue:?}, payload)
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
    _nyx_record_broker_event("NYX_RABBIT_LOG", "deliver", {queue:?}, body)
    _h(ch, method, props, body)
    _nyx_record_broker_event("NYX_RABBIT_LOG", "ack", {queue:?}, getattr(method, "delivery_tag", ""))
_chan.basic_consume(queue={queue:?}, on_message_callback=_nyx_rabbit_dispatch)
print({publish_marker:?} + " " + {queue:?}, flush=True)
_nyx_record_broker_publish("NYX_RABBIT_LOG", {queue:?}, payload)
_chan.basic_publish(exchange="", routing_key={queue:?}, body=payload)"#,
            handler = handler,
            queue = queue,
            publish_marker = crate::dynamic::stubs::RABBIT_PUBLISH_MARKER,
        ),
        PythonBroker::Kafka => format!(
            r#"if not _nyx_try_kafka_http({queue:?}, payload, {handler:?}):
    _loop = NyxKafkaLoopback()
    def _nyx_kafka_dispatch(message):
        _h = getattr(_entry_mod, {handler:?}, None)
        if _h is None:
            print("NYX_HANDLER_NOT_FOUND: " + {handler:?}, file=sys.stderr, flush=True)
            sys.exit(78)
        _h(message)
    _loop.subscribe({queue:?}, _nyx_kafka_dispatch)
    print({publish_marker:?} + " " + {queue:?}, flush=True)
    _nyx_record_broker_publish("NYX_KAFKA_LOG", {queue:?}, payload)
    _loop.publish({queue:?}, payload)
    for _record in _loop.poll({queue:?}, max_records=1):
        _nyx_record_broker_event("NYX_KAFKA_LOG", "deliver", {queue:?}, _record.value)
        _nyx_kafka_dispatch(_record.value)
        _loop.commit(_record)
        _nyx_record_broker_event("NYX_KAFKA_LOG", "ack", {queue:?}, str(_record.offset))"#,
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

def _nyx_record_broker_event(env_name, action, destination, body):
    path = os.environ.get(env_name, "")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(
                str(action).replace("\t", " ") + "\t" +
                str(destination).replace("\t", " ") + "\t" +
                str(body) + "\n"
            )
    except Exception:
        pass

def _nyx_record_broker_publish(env_name, destination, body):
    _nyx_record_broker_event(env_name, "publish", destination, body)

def _nyx_try_kafka_http(topic, body, handler_name):
    endpoint = os.environ.get("NYX_KAFKA_ENDPOINT", "")
    if not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        return False
    _h = getattr(_entry_mod, handler_name, None)
    if _h is None:
        print("NYX_HANDLER_NOT_FOUND: " + handler_name, file=sys.stderr, flush=True)
        sys.exit(78)
    try:
        import json
        import urllib.parse
        import urllib.request
        base = endpoint.rstrip("/")
        topic_path = urllib.parse.quote(str(topic), safe="")
        print({kafka_publish_marker:?} + " " + str(topic), flush=True)
        _send = urllib.request.Request(
            base + "/topics/" + topic_path + "/messages",
            data=str(body).encode("utf-8"),
            method="POST",
        )
        urllib.request.urlopen(_send, timeout=2).read()
        _records_raw = urllib.request.urlopen(
            base + "/topics/" + topic_path + "/records?max=1",
            timeout=2,
        ).read()
        _records = json.loads(_records_raw.decode("utf-8") or "{{}}").get("records", [])
        if not _records:
            return False
        for _rec in _records:
            _h(_rec.get("value", ""))
            _offset = str(_rec.get("offset", "0"))
            _commit = urllib.request.Request(
                base + "/topics/" + topic_path + "/commit",
                data=urllib.parse.urlencode({{"offset": _offset}}).encode("utf-8"),
                method="POST",
            )
            urllib.request.urlopen(_commit, timeout=2).read()
        return True
    except SystemExit:
        raise
    except Exception as _e:
        print(f"NYX_KAFKA_HTTP_FALLBACK: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
        return False

def _nyx_try_real_sqs(queue, body, handler_name):
    endpoint = os.environ.get("NYX_SQS_ENDPOINT", "")
    if not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        return False
    try:
        import boto3
        try:
            from botocore.config import Config
            _cfg = Config(
                retries={{"max_attempts": 0}},
                connect_timeout=1,
                read_timeout=2,
            )
        except Exception:
            _cfg = None
    except Exception:
        return False
    _h = getattr(_entry_mod, handler_name, None)
    if _h is None:
        print("NYX_HANDLER_NOT_FOUND: " + handler_name, file=sys.stderr, flush=True)
        sys.exit(78)
    try:
        _kwargs = {{
            "endpoint_url": endpoint,
            "region_name": "us-east-1",
            "aws_access_key_id": "nyx",
            "aws_secret_access_key": "nyx",
        }}
        if _cfg is not None:
            _kwargs["config"] = _cfg
        _client = boto3.client("sqs", **_kwargs)
        _queue_url = endpoint.rstrip("/") + "/" + str(queue).strip("/")
        print({sqs_publish_marker:?} + " " + str(queue), flush=True)
        _client.send_message(QueueUrl=_queue_url, MessageBody=str(body))
        _resp = _client.receive_message(
            QueueUrl=_queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=0,
            AttributeNames=["ApproximateReceiveCount"],
        )
        _messages = _resp.get("Messages", [])
        if not _messages:
            return False
        for _msg in _messages:
            _h(_msg)
            _receipt = _msg.get("ReceiptHandle", "")
            if _receipt:
                _client.delete_message(QueueUrl=_queue_url, ReceiptHandle=_receipt)
        return True
    except SystemExit:
        raise
    except Exception as _e:
        print(f"NYX_REAL_SQS_FALLBACK: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
        return False

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
        kafka_publish_marker = crate::dynamic::stubs::KAFKA_PUBLISH_MARKER,
        sqs_publish_marker = crate::dynamic::stubs::SQS_PUBLISH_MARKER,
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: message_handler_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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
        extra_files: framework_dependency_files(spec),
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

def _nyx_migration_sql_record(sql, driver):
    text = str(sql)
    upper = text.upper()
    if not any(k in upper for k in ("SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP")):
        return
    __nyx_stub_sql_record(text, driver=driver, source="migration")
    endpoint = os.environ.get("NYX_SQL_ENDPOINT", "")
    if endpoint:
        try:
            import sqlite3
            conn = sqlite3.connect(endpoint)
            try:
                conn.execute(text)
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass

class _NyxMigrationOpProxy:
    def __init__(self, inner=None):
        self._inner = inner
    def execute(self, sql, *args, **kwargs):
        _nyx_migration_sql_record(sql, "alembic")
        if self._inner is not None and self._inner is not self and hasattr(self._inner, "execute"):
            return self._inner.execute(sql, *args, **kwargs)
        return None
    def __getattr__(self, name):
        if self._inner is not None and self._inner is not self:
            return getattr(self._inner, name)
        raise AttributeError(name)

_nyx_migration_cleanup = None

def _nyx_real_alembic_operations():
    endpoint = os.environ.get("NYX_SQL_ENDPOINT", "")
    url = "sqlite:///" + endpoint if endpoint else "sqlite:///:memory:"
    try:
        from sqlalchemy import create_engine
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        engine = create_engine(url)
        conn = engine.connect()
        ctx = MigrationContext.configure(conn)
        ops = Operations(ctx)
        def _cleanup():
            try:
                conn.close()
            finally:
                engine.dispose()
        return ops, _cleanup
    except Exception:
        return None, None

def _nyx_install_migration_sql_hooks():
    global _nyx_migration_cleanup
    if hasattr(_entry_mod, "op"):
        try:
            real_ops, cleanup = _nyx_real_alembic_operations()
            _nyx_migration_cleanup = cleanup
            _entry_mod.op = _NyxMigrationOpProxy(real_ops or getattr(_entry_mod, "op"))
        except Exception:
            pass

def _nyx_record_migration_result(result):
    if result is None:
        return
    sql = getattr(result, "sql", None)
    if sql is not None:
        _nyx_migration_sql_record(sql, "django")
    elif isinstance(result, str):
        _nyx_migration_sql_record(result, "migration")
    elif hasattr(result, "database_forwards"):
        sql = getattr(result, "sql", None)
        if sql is not None:
            _nyx_migration_sql_record(sql, "django")
        try:
            from django.conf import settings
            if not settings.configured:
                endpoint = os.environ.get("NYX_SQL_ENDPOINT", ":memory:")
                settings.configure(
                    INSTALLED_APPS=[],
                    DATABASES={{"default": {{"ENGINE": "django.db.backends.sqlite3", "NAME": endpoint}}}},
                    SECRET_KEY="nyx-dynamic-harness",
                )
            import django
            django.setup()
            from django.db import connection
            with connection.schema_editor() as schema_editor:
                result.database_forwards("nyx_dynamic", schema_editor, None, None)
        except Exception:
            pass

try:
    _nyx_install_migration_sql_hooks()
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
    _nyx_record_migration_result(_result)
    if _result is not None:
        try:
            print(str(_result), flush=True)
        except Exception:
            pass
    if _nyx_migration_cleanup is not None:
        _nyx_migration_cleanup()
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {{type(_e).__name__}}: {{_e}}", file=sys.stderr, flush=True)
    if _nyx_migration_cleanup is not None:
        _nyx_migration_cleanup()
"#,
        version = version_repr,
        handler = handler,
    );
    HarnessSource {
        source: format!("{preamble}\n{body}\n{postamble}"),
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files: framework_dependency_files(spec),
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
"""Nyx dynamic harness — SSTI Jinja2 (Phase 04 / Track J.2).

Routes `NYX_PAYLOAD` through the real `jinja2.Template(...).render()`
call.  The corpus vuln payload `{{{{7*7}}}}` reaches Jinja2's
expression evaluator and renders as `49`; the benign control `7*7`
has no `{{{{` / `}}}}` markers so the engine echoes it verbatim.
"""
import os, json, sys

{probe}

import jinja2

def _nyx_jinja2_render(payload):
    template = jinja2.Template(payload)
    return template.render()

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
    try:
        rendered = _nyx_jinja2_render(payload)
    except jinja2.TemplateError as exc:
        rendered = "<jinja2-error:{{}}>".format(type(exc).__name__)
    _nyx_ssti_probe(rendered)
    print("__NYX_SINK_HIT__", flush=True)
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
        extra_files: vec![("requirements.txt".to_owned(), "Jinja2\n".to_owned())],
        entry_subpath: None,
    }
}

/// Phase 05 — Track J.3 XXE harness for Python (`lxml.etree`).
///
/// Reads `NYX_PAYLOAD`, parses it with `xml.parsers.expat` (the stdlib
/// XML parser backing `xml.etree.ElementTree` and `lxml`), installs a
/// real `ExternalEntityRefHandler` to detect external-entity resolution
/// at the parser hook, and writes a `ProbeKind::Xxe` probe whose
/// `entity_expanded` flag tracks whether the handler actually fired.
/// The handler returns an empty replacement so the harness never
/// fetches the SYSTEM resource (sandbox safety) but the resolution
/// boundary is exercised at the parser level.
pub fn emit_xxe_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — XXE xml.parsers.expat (Phase 05 / Track J.3)."""
import os, json, sys, time
import urllib.request as _nyx_urlreq
import xml.parsers.expat as _nyx_expat

{probe}

# Build the XML document fed into expat.  Two shapes:
#   - URL-form NYX_PAYLOAD (`http://...` or `https://...`): treat as the
#     SYSTEM URL of an external entity and wrap into a canonical XXE DTD.
#     The OOB-nonce payload variant emits a loopback URL here so the
#     external-ref hook performs a real HTTP GET that the OOB listener
#     observes (Phase 05 OOB closure, 2026-05-21).
#   - Anything else: treat NYX_PAYLOAD as the full XML document
#     (existing Phase 05 shape).
def _nyx_xxe_document(payload):
    p = payload if isinstance(payload, str) else payload.decode("utf-8", "replace")
    if p.startswith("http://") or p.startswith("https://"):
        url = p.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
        return (
            "<?xml version=\"1.0\"?>\n"
            "<!DOCTYPE data [\n"
            "  <!ENTITY xxe SYSTEM \"" + url + "\">\n"
            "]>\n"
            "<data>&xxe;</data>"
        )
    return p

def _nyx_xxe_parse(payload):
    expanded = [False]
    parser = _nyx_expat.ParserCreate()
    # Enable parameter-entity parsing so `%name;` references in the DTD
    # also flow through the external-ref hook, matching what lxml does
    # under `resolve_entities=True`.
    try:
        parser.SetParamEntityParsing(_nyx_expat.XML_PARAM_ENTITY_PARSING_ALWAYS)
    except Exception:
        pass

    def _external_ref(context, base, system_id, public_id):
        # Real parser hook: fired by expat for every `<!ENTITY x SYSTEM "...">`
        # reference inside element bodies / DTD.  Mark expanded.  When the
        # SYSTEM URL points at loopback HTTP, perform a real GET so the OOB
        # listener can observe the callback (Phase 05 OOB closure).  Any
        # other scheme returns an empty replacement (no fetch).
        expanded[0] = True
        if system_id and (system_id.startswith("http://127.0.0.1")
                          or system_id.startswith("http://host-gateway")
                          or system_id.startswith("http://localhost")):
            try:
                _nyx_urlreq.urlopen(system_id, timeout=2).read()
            except Exception:
                pass
        sub = parser.ExternalEntityParserCreate(context, "utf-8")
        try:
            sub.Parse("", 1)
        except _nyx_expat.ExpatError:
            pass
        return 1

    parser.ExternalEntityRefHandler = _external_ref
    doc = _nyx_xxe_document(payload)
    try:
        parser.Parse(doc.encode("utf-8", "replace"), 1)
    except _nyx_expat.ExpatError:
        # Malformed XML still counts as a parser invocation; expanded
        # flag reflects whatever the hook saw before the error.
        pass
    return expanded[0]

def _nyx_xxe_probe(payload, expanded):
    rec = {{
        "sink_callee": "lxml.etree.XMLParser.parse",
        "args": [{{"kind": "String", "value": payload}}],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "Xxe", "entity_expanded": bool(expanded)}},
        "witness": __nyx_witness("lxml.etree.XMLParser.parse", [payload]),
    }}
    __nyx_emit(rec)

def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    expanded = _nyx_xxe_parse(payload)
    _nyx_xxe_probe(payload, expanded)
    # Sink-hit sentinel flips SandboxOutcome.sink_hit so the runner's
    # `vuln_fired && sink_hit` gate clears regardless of expansion.
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"entity_expanded": bool(expanded)}}) + "\n")
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
/// and — when `NYX_LDAP_ENDPOINT` is set — routes the search through
/// the in-sandbox LDAP stub over the real LDAPv3 BER wire (the stub's
/// accept loop at [`crate::dynamic::stubs::ldap_server::accept_loop`]
/// auto-detects the `0x30 SEQUENCE` lead byte and routes through the
/// reader/writer at [`crate::dynamic::stubs::ldap_ber`]).  Falls back
/// to an in-process RFC 4515 subset matcher against three canonical
/// users (`alice`, `bob`, `carol`) when the env var is unset, the
/// filter does not parse as a supported RFC 4515 shape, or the socket
/// exchange errors, so the harness still produces a verdict on hosts
/// that exercise it outside the stub-backed corpus.  Writes a
/// `ProbeKind::Ldap { entries_returned }` probe whose `n` is the
/// count the directory returned.  The BER client is pure-stdlib (just
/// `socket`) so no extra pip dep is required.
pub fn emit_ldap_harness(_spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — LDAP_INJECTION ldap.search_s (Phase 06 / Track J.4)."""
import os, json, socket, sys, time

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


# --- LDAPv3 BER client (zero-dep, pure stdlib) ----------------------------
# Tags this client emits / consumes.  Mirrors `src/dynamic/stubs/ldap_ber.rs`.
_NYX_BER_BOOLEAN = 0x01
_NYX_BER_INTEGER = 0x02
_NYX_BER_OCTET_STRING = 0x04
_NYX_BER_ENUMERATED = 0x0A
_NYX_BER_SEQUENCE = 0x30
_NYX_BER_BIND_REQUEST = 0x60
_NYX_BER_BIND_RESPONSE = 0x61
_NYX_BER_SEARCH_REQUEST = 0x63
_NYX_BER_SEARCH_RESULT_ENTRY = 0x64
_NYX_BER_SEARCH_RESULT_DONE = 0x65
_NYX_BER_AUTH_SIMPLE = 0x80
_NYX_BER_FILTER_AND = 0xA0
_NYX_BER_FILTER_OR = 0xA1
_NYX_BER_FILTER_EQUALITY = 0xA3
_NYX_BER_FILTER_SUBSTRINGS = 0xA4
_NYX_BER_FILTER_PRESENT = 0x87
_NYX_BER_SUBSTR_INITIAL = 0x80
_NYX_BER_SUBSTR_ANY = 0x81
_NYX_BER_SUBSTR_FINAL = 0x82


def _nyx_ber_length(n):
    if n < 0x80:
        return bytes([n])
    tmp = []
    while n:
        tmp.append(n & 0xFF)
        n >>= 8
    tmp.reverse()
    return bytes([0x80 | len(tmp)]) + bytes(tmp)


def _nyx_ber_tlv(tag, body):
    return bytes([tag]) + _nyx_ber_length(len(body)) + body


def _nyx_ber_int(n):
    if n < 0:
        return None
    if n == 0:
        body = b"\x00"
    else:
        tmp = []
        x = n
        while x > 0:
            tmp.append(x & 0xFF)
            x >>= 8
        tmp.reverse()
        body = bytes(tmp)
        if body[0] & 0x80:
            body = b"\x00" + body
    return _nyx_ber_tlv(_NYX_BER_INTEGER, body)


def _nyx_ber_enum(n):
    return _nyx_ber_tlv(_NYX_BER_ENUMERATED, bytes([n & 0xFF]))


def _nyx_ber_octstr(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return _nyx_ber_tlv(_NYX_BER_OCTET_STRING, s)


def _nyx_ber_bool(b):
    return _nyx_ber_tlv(_NYX_BER_BOOLEAN, b"\xFF" if b else b"\x00")


def _nyx_ber_seq(body):
    return _nyx_ber_tlv(_NYX_BER_SEQUENCE, body)


def _nyx_valid_attr(a):
    if not a:
        return False
    for ch in a:
        if not (ch.isalnum() or ch in "-_."):
            return False
    return True


def _nyx_split_paren_children(s):
    """Split a string of concatenated `(...)(...)` groups into a list."""
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] != "(":
            return None
        depth = 0
        start = i
        while i < n:
            c = s[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        if depth != 0:
            return None
        out.append(s[start:i])
    return out


def _nyx_encode_filter(filt):
    """RFC 4515 (subset) -> BER bytes.  Returns ``None`` for invalid /
    unsupported filter shapes; caller falls back to the local matcher."""
    s = filt.strip()
    if not s.startswith("(") or not s.endswith(")"):
        return None
    depth = 0
    for i, c in enumerate(s):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return None
            if depth == 0 and i != len(s) - 1:
                return None
    if depth != 0:
        return None
    inner = s[1:-1]
    if not inner:
        return None
    head = inner[0]
    if head in ("&", "|"):
        children = _nyx_split_paren_children(inner[1:])
        if not children:
            return None
        parts = b""
        for c in children:
            sub = _nyx_encode_filter(c)
            if sub is None:
                return None
            parts += sub
        tag = _NYX_BER_FILTER_AND if head == "&" else _NYX_BER_FILTER_OR
        return _nyx_ber_tlv(tag, parts)
    if "=" not in inner:
        return None
    attr, _, val = inner.partition("=")
    if not _nyx_valid_attr(attr):
        return None
    if val == "*":
        return _nyx_ber_tlv(_NYX_BER_FILTER_PRESENT, attr.encode("utf-8"))
    if "*" in val:
        parts = val.split("*")
        seq = b""
        if parts[0]:
            seq += _nyx_ber_tlv(_NYX_BER_SUBSTR_INITIAL, parts[0].encode("utf-8"))
        for p in parts[1:-1]:
            if p:
                seq += _nyx_ber_tlv(_NYX_BER_SUBSTR_ANY, p.encode("utf-8"))
        if parts[-1]:
            seq += _nyx_ber_tlv(_NYX_BER_SUBSTR_FINAL, parts[-1].encode("utf-8"))
        body = _nyx_ber_octstr(attr) + _nyx_ber_seq(seq)
        return _nyx_ber_tlv(_NYX_BER_FILTER_SUBSTRINGS, body)
    body = _nyx_ber_octstr(attr) + _nyx_ber_octstr(val)
    return _nyx_ber_tlv(_NYX_BER_FILTER_EQUALITY, body)


def _nyx_read_n(sock, n):
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            return None
        out += chunk
    return out


def _nyx_read_ber_message(sock):
    head = _nyx_read_n(sock, 2)
    if head is None or head[0] != _NYX_BER_SEQUENCE:
        return None
    if head[1] & 0x80 == 0:
        body_len = head[1]
        length_bytes = b""
    else:
        nl = head[1] & 0x7F
        if nl == 0 or nl > 4:
            return None
        length_bytes = _nyx_read_n(sock, nl)
        if length_bytes is None:
            return None
        body_len = 0
        for b in length_bytes:
            body_len = (body_len << 8) | b
    if body_len > 64 * 1024:
        return None
    body = _nyx_read_n(sock, body_len)
    if body is None:
        return None
    return head + length_bytes + body


def _nyx_decode_tlv(buf, offset):
    if offset + 2 > len(buf):
        return None
    tag = buf[offset]
    first_len = buf[offset + 1]
    if first_len & 0x80 == 0:
        body_len = first_len
        body_start = offset + 2
    else:
        nl = first_len & 0x7F
        if nl == 0 or nl > 4 or offset + 2 + nl > len(buf):
            return None
        body_len = 0
        for b in buf[offset + 2:offset + 2 + nl]:
            body_len = (body_len << 8) | b
        body_start = offset + 2 + nl
    body_end = body_start + body_len
    if body_end > len(buf):
        return None
    return (tag, buf[body_start:body_end], body_end)


def _nyx_decode_ldap_op(msg):
    """Return ``(op_tag, op_body)`` for an LDAPMessage byte slice."""
    outer = _nyx_decode_tlv(msg, 0)
    if outer is None or outer[0] != _NYX_BER_SEQUENCE:
        return None
    inner = outer[1]
    msg_id_tlv = _nyx_decode_tlv(inner, 0)
    if msg_id_tlv is None or msg_id_tlv[0] != _NYX_BER_INTEGER:
        return None
    op_tlv = _nyx_decode_tlv(inner, msg_id_tlv[2])
    if op_tlv is None:
        return None
    return (op_tlv[0], op_tlv[1])


def _nyx_ldap_count_via_ber(filt):
    """Route through the in-sandbox LDAP stub via real LDAPv3 BER when
    `NYX_LDAP_ENDPOINT` is set.  Returns the entry count on success, or
    ``None`` when the env var is unset, the filter is not a supported
    RFC 4515 shape, the address fails to parse, the bind fails, or the
    socket exchange errors — caller falls back to the in-process matcher.
    """
    ep = os.environ.get("NYX_LDAP_ENDPOINT", "")
    if not ep:
        return None
    sep = ep.rfind(":")
    if sep <= 0 or sep >= len(ep) - 1:
        return None
    host = ep[:sep]
    try:
        port = int(ep[sep + 1:])
    except ValueError:
        return None
    filter_bytes = _nyx_encode_filter(filt)
    if filter_bytes is None:
        return None
    try:
        with socket.create_connection((host, port), timeout=2.0) as sock:
            sock.settimeout(2.0)
            bind_body = (
                _nyx_ber_int(3)
                + _nyx_ber_octstr(b"")
                + _nyx_ber_tlv(_NYX_BER_AUTH_SIMPLE, b"")
            )
            bind_msg = _nyx_ber_seq(
                _nyx_ber_int(1) + _nyx_ber_tlv(_NYX_BER_BIND_REQUEST, bind_body)
            )
            sock.sendall(bind_msg)
            resp = _nyx_read_ber_message(sock)
            if resp is None:
                return None
            decoded = _nyx_decode_ldap_op(resp)
            if decoded is None or decoded[0] != _NYX_BER_BIND_RESPONSE:
                return None
            search_body = (
                _nyx_ber_octstr(b"")
                + _nyx_ber_enum(2)
                + _nyx_ber_enum(0)
                + _nyx_ber_int(0)
                + _nyx_ber_int(2)
                + _nyx_ber_bool(False)
                + filter_bytes
                + _nyx_ber_seq(b"")
            )
            search_msg = _nyx_ber_seq(
                _nyx_ber_int(2) + _nyx_ber_tlv(_NYX_BER_SEARCH_REQUEST, search_body)
            )
            sock.sendall(search_msg)
            count = 0
            while True:
                resp = _nyx_read_ber_message(sock)
                if resp is None:
                    return None
                decoded = _nyx_decode_ldap_op(resp)
                if decoded is None:
                    return None
                op_tag = decoded[0]
                if op_tag == _NYX_BER_SEARCH_RESULT_ENTRY:
                    count += 1
                elif op_tag == _NYX_BER_SEARCH_RESULT_DONE:
                    return count
                else:
                    return count
    except (OSError, socket.timeout):
        return None


def _nyx_ldap_count_local(filt):
    f = (filt or "").strip()
    if not f:
        return 0
    if not (f.startswith("(") and f.endswith(")")):
        return len(_NYX_LDAP_USERS)
    if _nyx_inner_has_break(f[1:-1]):
        return len(_NYX_LDAP_USERS)
    return sum(1 for u in _NYX_LDAP_USERS if _nyx_match_one(f, u))


def _nyx_ldap_count(filt):
    via_ber = _nyx_ldap_count_via_ber(filt)
    if via_ber is not None:
        return via_ber
    return _nyx_ldap_count_local(filt)


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
pub fn emit_xpath_harness(spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let corpus_filename = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_FILENAME;
    let corpus_xml = crate::dynamic::stubs::xpath_document::XPATH_CORPUS_XML;
    let module_name = derive_module_name(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — XPATH_INJECTION lxml.etree.xpath (Phase 07 / Track J.5)."""
import importlib
import json
import os
import sys
import time

{probe}


def _nyx_xpath_via_fixture(payload):
    # Phase 07 tier-(a): import the fixture and call its
    # `{entry_name}` so the real `lxml.etree.xpath` runs against the
    # staged corpus document.  A missing `lxml` host install is the
    # only structural reason the import fails; in that case we emit
    # the conventional `NYX_IMPORT_ERROR:` stderr marker plus
    # `sys.exit(77)` so the runner maps the outcome to
    # `RunError::BuildFailed` and the e2e SKIP branch fires.
    sys.path.insert(0, ".")
    try:
        mod = importlib.import_module("{module_name}")
    except ImportError as _e:
        print(f"NYX_IMPORT_ERROR: {{_e}}", file=sys.stderr, flush=True)
        sys.exit(77)
    fn = getattr(mod, "{entry_name}", None)
    if fn is None:
        raise RuntimeError(
            "Phase 07 XPath harness: entry function '{entry_name}' not found in fixture module '{module_name}'"
        )
    try:
        result = fn(payload)
    except Exception:
        # Malformed XPath / parse error / etc. — treat as a 0-node
        # return so a benign fixture that rejects the payload stays
        # NotConfirmed.
        return 0
    try:
        return len(result)
    except TypeError:
        return 0


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
    nodes = _nyx_xpath_via_fixture(payload)
    print("__NYX_XPATH_TIER_A__", flush=True)
    _nyx_xpath_probe(expr, nodes)
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"expr": expr, "nodes_returned": nodes}}) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    _nyx_run()
"#
    );
    let extra_files = vec![
        (corpus_filename.to_owned(), corpus_xml.to_owned()),
        ("requirements.txt".to_owned(), "lxml\n".to_owned()),
    ];
    HarnessSource {
        source: body,
        filename: "harness.py".to_owned(),
        command: vec!["python3".to_owned(), "harness.py".to_owned()],
        extra_files,
        entry_subpath: None,
    }
}

/// Map an entry file path like `tests/.../vuln.py` to the Python
/// module name `vuln` the harness will `importlib.import_module(...)`.
/// Falls back to `vuln` when the path is unusable so the harness still
/// attempts an import (the fallback inline matcher fires when the
/// import fails).
fn derive_module_name(entry_file: &str) -> String {
    PathBuf::from(entry_file)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| "vuln".to_owned())
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
pub fn emit_header_injection_harness(spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let module_name = derive_module_name(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_flask = entry_source.contains("from flask")
        || entry_source.contains("import flask")
        || entry_source.contains("werkzeug.wrappers");
    // Phase 08 tier-(b): a fixture that subclasses
    // `BaseHTTPRequestHandler` writes bytes straight to the response
    // socket via `self.wfile.write`, bypassing every framework-level
    // CRLF validator (werkzeug / Flask / axum / Tomcat all strip CRLF
    // before write).  The harness boots the handler on a loopback
    // port and captures the raw response-header block as a
    // `ProbeKind::HeaderWireFrame` probe.
    let uses_raw_socket = entry_source.contains("BaseHTTPRequestHandler");
    let wire_frame_via_fixture = if uses_raw_socket {
        format!(
            r#"def _nyx_wire_frame_via_fixture(payload):
    # Phase 08 tier-(b): boot the fixture's BaseHTTPRequestHandler on
    # 127.0.0.1:0, issue one raw-socket GET, read the bytes the handler
    # wrote to the response socket up to the CRLF-CRLF boundary.
    # Returns the captured header-block bytes on success, or None on
    # import / boot failure so the caller can fall back to the inline
    # synthetic probe.
    import http.server
    import socket
    import threading
    sys.path.insert(0, ".")
    try:
        mod = importlib.import_module("{module_name}")
    except Exception:
        return None
    Handler = getattr(mod, "VulnHandler", None)
    if Handler is None:
        return None
    try:
        if isinstance(payload, str):
            Handler.cookie_value = payload.encode("utf-8")
        else:
            Handler.cookie_value = bytes(payload)
    except Exception:
        return None
    try:
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    except Exception:
        return _nyx_fallback_wire_frame(payload)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    raw = b""
    try:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        except Exception:
            return _nyx_fallback_wire_frame(payload)
        try:
            sock.settimeout(2.0)
            sock.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            while len(raw) < 65536:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw += chunk
                if b"\r\n\r\n" in raw:
                    break
        finally:
            try:
                sock.close()
            except Exception:
                pass
    finally:
        try:
            server.shutdown()
        except Exception:
            pass
        try:
            server.server_close()
        except Exception:
            pass
    if not raw:
        return _nyx_fallback_wire_frame(payload)
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return raw
    return raw[:sep]


def _nyx_fallback_wire_frame(payload):
    cookie = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    body = b"ok\n"
    return (
        b"HTTP/1.0 200 OK\r\n"
        + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        + b"Set-Cookie: "
        + cookie
    )


def _nyx_wire_frame_probe(raw_bytes):
    rec = {{
        "sink_callee": "http.server.wfile.write",
        "args": [],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "HeaderWireFrame", "raw_bytes": list(raw_bytes)}},
        "witness": __nyx_witness("http.server.wfile.write", []),
    }}
    __nyx_emit(rec)


"#
        )
    } else {
        String::new()
    };
    let invoke_via_wire_frame = if uses_raw_socket {
        r#"    raw_bytes = _nyx_wire_frame_via_fixture(payload)
    if raw_bytes is not None:
        _nyx_wire_frame_probe(raw_bytes)
        # Also emit a HeaderEmit record per Set-Cookie line so the
        # tier-(a) HeaderInjected predicate fires on the same payload
        # that trips HeaderSmuggledInWire.  The wire-frame branch is
        # the source of truth; the HeaderEmit records are derived from
        # the same captured bytes.
        for line in raw_bytes.split(b"\r\n"):
            sep = line.find(b": ")
            if sep < 0:
                continue
            name = line[:sep].decode("ascii", "replace")
            if name.lower() != "set-cookie":
                continue
            value = line[sep + 2:].decode("utf-8", "replace")
            _nyx_header_probe(name, value)
        print("__NYX_SINK_HIT__", flush=True)
        sys.stdout.write(json.dumps({"wire_frame_len": len(raw_bytes)}) + "\n")
        sys.stdout.flush()
        return
"#
    } else {
        ""
    };
    let via_fixture = if uses_flask {
        format!(
            r#"def _nyx_header_via_fixture(payload):
    # Phase 08 tier-(a): import the fixture, monkey-patch
    # `werkzeug.datastructures.Headers.__setitem__` to capture every
    # name/value pair the fixture writes *before* werkzeug's strict
    # CRLF validator runs.  This mirrors the Java permissive servlet
    # stub at `src/dynamic/lang/java_servlet_stubs.rs::http_servlet_response`,
    # so a vuln payload with raw `\r\n` is recorded verbatim and a
    # benign control whose bytes are URL-encoded is recorded
    # URL-encoded.  Returns `None` when werkzeug is missing or the
    # fixture cannot be imported so the caller can fall back to the
    # inline synthetic probe.
    try:
        import werkzeug.datastructures as _wzd
    except Exception:
        return None
    captured = []
    _orig_setitem = _wzd.Headers.__setitem__
    def _nyx_setitem(self, key, value):
        try:
            captured.append((str(key), str(value)))
        except Exception:
            pass
        try:
            _orig_setitem(self, key, value)
        except Exception:
            # werkzeug>=2.x rejects CRLF in header values.  Swallow
            # the validator's exception so the captor still records
            # the would-have-been-written bytes.
            pass
    _wzd.Headers.__setitem__ = _nyx_setitem
    sys.path.insert(0, ".")
    try:
        try:
            mod = importlib.import_module("{module_name}")
        except Exception:
            return None
        fn = getattr(mod, "{entry_name}", None)
        if fn is None:
            return None
        try:
            fn(payload)
        except Exception:
            # Fixture itself raised (validator path, missing dep, etc.)
            # — return whatever the captor recorded before the throw.
            pass
        return captured
    finally:
        _wzd.Headers.__setitem__ = _orig_setitem


"#
        )
    } else {
        String::new()
    };
    let invoke_via_fixture = if uses_flask {
        r#"    captured = _nyx_header_via_fixture(payload)
    if captured:
        for name, value in captured:
            _nyx_header_probe(name, value)
        print("__NYX_SINK_HIT__", flush=True)
        sys.stdout.write(json.dumps({"headers": [list(p) for p in captured]}) + "\n")
        sys.stdout.flush()
        return
"#
    } else {
        ""
    };
    let importlib_import = if uses_flask || uses_raw_socket {
        "import importlib\n"
    } else {
        ""
    };
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — HEADER_INJECTION flask.Response.headers.__setitem__ + raw-socket wire-frame (Phase 08 / Track J.6)."""
{importlib_import}import json
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
        "kind": {{"kind": "HeaderEmit", "name": name, "value": value, "protocol": "in-process"}},
        "witness": __nyx_witness("flask.Response.headers.__setitem__", [name, value]),
    }}
    __nyx_emit(rec)


{wire_frame_via_fixture}{via_fixture}def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
{invoke_via_wire_frame}{invoke_via_fixture}    # Synthetic fallback — mirrors
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
pub fn emit_open_redirect_harness(spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let entry_source = read_entry_source(&spec.entry_file);
    let module_name = derive_module_name(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let uses_flask = entry_source.contains("from flask") || entry_source.contains("import flask");
    let via_fixture = if uses_flask {
        format!(
            r#"def _nyx_redirect_via_fixture(payload):
    # Phase 09 tier-(a): import the fixture, call its `{entry_name}` so
    # the real `flask.redirect` runs, then read the bound `Location:`
    # header off the returned response.  Returns `(location, request_host)`
    # on success, or `None` when the import / call fails so the caller
    # can fall back to the inline synthetic probe.
    sys.path.insert(0, ".")
    try:
        mod = importlib.import_module("{module_name}")
    except Exception:
        return None
    fn = getattr(mod, "{entry_name}", None)
    if fn is None:
        return None
    try:
        response = fn(payload)
    except Exception:
        # Fixture raised (validator path, missing dep, etc.) — drop
        # tier-(a) and let the caller fall back.
        return None
    try:
        location = response.headers.get("Location", "")
    except Exception:
        return None
    if not isinstance(location, str):
        try:
            location = str(location)
        except Exception:
            return None
    return (location, "example.com")


"#
        )
    } else {
        String::new()
    };
    let invoke_via_fixture = if uses_flask {
        r#"    captured = _nyx_redirect_via_fixture(payload)
    if captured is not None:
        location, request_host = captured
        _nyx_redirect_probe(location, request_host)
        _nyx_follow_location(location)
        print("__NYX_SINK_HIT__", flush=True)
        sys.stdout.write(json.dumps({"location": location, "request_host": request_host}) + "\n")
        sys.stdout.flush()
        return
"#
    } else {
        ""
    };
    let importlib_import = if uses_flask { "import importlib\n" } else { "" };
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — OPEN_REDIRECT flask.redirect (Phase 09 / Track J.7)."""
{importlib_import}import json
import os
import sys
import time
import urllib.request

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


# Phase 09 OOB closure: when the captured Location is a fully-qualified
# loopback URL, follow it with a real GET so the OOB listener records
# the per-finding nonce.  Skips non-loopback hosts (no real network egress)
# and any non-HTTP scheme.  Best-effort: failures do not propagate, the
# listener may still have observed the connect before the read errored.
def _nyx_follow_location(location):
    if not location:
        return
    lower = location.lower()
    if not (
        lower.startswith("http://127.0.0.1")
        or lower.startswith("http://localhost")
        or lower.startswith("http://host-gateway")
    ):
        return
    try:
        with urllib.request.urlopen(location, timeout=2.0) as resp:
            resp.read(1)
    except Exception:
        # best-effort OOB fetch
        pass


{via_fixture}def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
{invoke_via_fixture}    request_host = "example.com"
    location = payload
    _nyx_redirect_probe(location, request_host)
    _nyx_follow_location(location)
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

/// Phase 11 (Track J.9) CRYPTO harness for Python.
///
/// Reads `NYX_PAYLOAD`, imports the entry module, invokes the named
/// entry function with the payload, then emits a
/// [`crate::dynamic::probe::ProbeKind::WeakKey`] probe carrying the
/// integer view of the produced key.  Integer returns flow through
/// verbatim (truncated to a `u64`); `bytes`/`bytearray` returns get
/// reduced via `int.from_bytes(<bytes>[:8], "big")` so a CSPRNG-strong
/// benign key trivially exceeds any plausible 16-bit budget while a
/// weak `random.randint(0, 0xFFFF)` value lands well inside it.  When
/// the fixture cannot be imported or raises during invocation the
/// harness falls back to emitting a `key_int` derived from the raw
/// payload bytes so the universal sink-hit path still fires.
pub fn emit_crypto_harness(spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let module_name = derive_module_name(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — CRYPTO weak-RNG key entropy (Phase 11 / Track J.9)."""
import importlib
import json
import os
import sys
import time

{probe}


def _nyx_weak_key_probe(key_int):
    rec = {{
        "sink_callee": "__nyx_weak_key",
        "args": [
            {{"kind": "Int", "value": int(key_int)}},
        ],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "WeakKey", "key_int": int(key_int)}},
        "witness": __nyx_witness("__nyx_weak_key", [int(key_int)]),
    }}
    __nyx_emit(rec)


def _nyx_key_to_int(value):
    # int → truncate to u64 magnitude
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value & 0xFFFFFFFFFFFFFFFF
    if isinstance(value, (bytes, bytearray)):
        head = bytes(value)[:8]
        if not head:
            return 0
        return int.from_bytes(head, "big")
    # Unknown type — fall back to its string repr's first 8 bytes so
    # the predicate still has something deterministic to score
    try:
        encoded = str(value).encode("utf-8", "replace")[:8]
    except Exception:
        return 0
    if not encoded:
        return 0
    return int.from_bytes(encoded, "big")


def _nyx_crypto_via_fixture(payload):
    sys.path.insert(0, ".")
    try:
        mod = importlib.import_module("{module_name}")
    except Exception:
        return None
    fn = getattr(mod, "{entry_name}", None)
    if fn is None:
        return None
    try:
        return fn(payload)
    except Exception:
        return None


def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    produced = _nyx_crypto_via_fixture(payload)
    if produced is None:
        # Fixture path failed.  Fall back to the payload-derived key
        # so the universal sink-hit path still fires for outcome
        # reporting; the WeakKeyEntropy predicate will reflect the
        # payload's own entropy.
        produced = payload.encode("utf-8", "replace") if isinstance(payload, str) else payload
    key_int = _nyx_key_to_int(produced)
    _nyx_weak_key_probe(key_int)
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"key_int": key_int}}) + "\n")
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

/// JSON_PARSE depth-bomb harness for Python.
///
/// The harness wraps `json.loads`, records the maximum nested list / dict
/// depth, then calls the fixture entry with `NYX_PAYLOAD`. It treats parser
/// recursion errors as excessive depth so the oracle sees the failure mode.
pub fn emit_json_parse_harness(spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let module_name = derive_module_name(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness for JSON_PARSE depth checks."""
import importlib
import json
import os
import sys
import time

{probe}

_NYX_MAX_WALK = 4096


def _nyx_count_depth(parsed):
    max_depth = 0
    stack = [(parsed, 1)]
    visited = 0
    while stack:
        cur, depth = stack.pop()
        visited += 1
        if visited > _NYX_MAX_WALK:
            break
        if depth > max_depth:
            max_depth = depth
        if isinstance(cur, dict):
            for value in cur.values():
                stack.append((value, depth + 1))
        elif isinstance(cur, list):
            for value in cur:
                stack.append((value, depth + 1))
    return max_depth


def _nyx_json_parse_probe(depth, excessive):
    rec = {{
        "sink_callee": "json.loads",
        "args": [{{"kind": "Int", "value": int(depth)}}],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{
            "kind": "JsonParse",
            "depth": int(depth),
            "excessive_depth": bool(excessive),
        }},
        "witness": __nyx_witness("json.loads", [int(depth)]),
    }}
    __nyx_emit(rec)


_nyx_orig_json_loads = json.loads


def _nyx_json_loads_with_depth(s, *args, **kwargs):
    try:
        parsed = _nyx_orig_json_loads(s, *args, **kwargs)
    except RecursionError:
        _nyx_json_parse_probe(0, True)
        raise
    depth = _nyx_count_depth(parsed)
    _nyx_json_parse_probe(depth, depth > 64)
    return parsed


json.loads = _nyx_json_loads_with_depth


def _nyx_json_parse_via_fixture(payload):
    sys.path.insert(0, ".")
    try:
        mod = importlib.import_module("{module_name}")
    except Exception:
        return False
    fn = getattr(mod, "{entry_name}", None)
    if fn is None:
        return False
    try:
        fn(payload)
    except Exception:
        return True
    return True


def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    _nyx_json_parse_via_fixture(payload)
    print("__NYX_SINK_HIT__", flush=True)


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

/// UNAUTHORIZED_ID IDOR harness for Python.
///
/// Reads `NYX_PAYLOAD` as the requested `owner_id`, imports the fixture
/// module, and invokes the named entry function with it.  When the
/// fixture returns a non-`None` record (i.e. the data store materialised
/// the row without an authorization check) the harness emits a
/// [`crate::dynamic::probe::ProbeKind::IdorAccess`] probe carrying the
/// hard-coded `caller_id = "alice"` and the payload as `owner_id`.  The
/// [`crate::dynamic::oracle::ProbePredicate::IdorBoundaryCrossed`]
/// predicate fires whenever `caller_id != owner_id`, so a vuln payload
/// (`bob`) materialises the probe and a benign payload (`alice`) clears
/// the predicate even though both fixtures return a record.
pub fn emit_unauthorized_id_harness(spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let module_name = derive_module_name(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — UNAUTHORIZED_ID IDOR boundary (Phase 11 / Track J.9)."""
import importlib
import json
import os
import sys
import time

{probe}

_NYX_CALLER_ID = "alice"


def _nyx_idor_probe(caller_id, owner_id):
    rec = {{
        "sink_callee": "__nyx_idor_lookup",
        "args": [
            {{"kind": "String", "value": str(caller_id)}},
            {{"kind": "String", "value": str(owner_id)}},
        ],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{
            "kind": "IdorAccess",
            "caller_id": str(caller_id),
            "owner_id": str(owner_id),
        }},
        "witness": __nyx_witness("__nyx_idor_lookup", [str(caller_id), str(owner_id)]),
    }}
    __nyx_emit(rec)


def _nyx_idor_via_fixture(payload):
    sys.path.insert(0, ".")
    try:
        mod = importlib.import_module("{module_name}")
    except Exception:
        return None
    fn = getattr(mod, "{entry_name}", None)
    if fn is None:
        return None
    try:
        return fn(payload)
    except Exception:
        return None


def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    record = _nyx_idor_via_fixture(payload)
    if record is not None:
        _nyx_idor_probe(_NYX_CALLER_ID, payload)
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"materialised": record is not None}}) + "\n")
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

/// DATA_EXFIL outbound-network harness for Python.
///
/// Monkey-patches `urllib.request.urlopen` so any outbound HTTP request
/// the fixture initiates is intercepted before the wire I/O: the URL's
/// host is parsed via `urllib.parse.urlparse`, a
/// [`crate::dynamic::probe::ProbeKind::OutboundNetwork`] probe is
/// emitted, and the call returns a benign in-memory stand-in so the
/// fixture's caller never blocks on the network.  The
/// [`crate::dynamic::oracle::ProbePredicate::OutboundHostNotIn`]
/// predicate fires when the captured host falls outside the loopback
/// allowlist, so the `attacker.test` vuln payload materialises a probe
/// the predicate matches while the `127.0.0.1` benign control stays
/// clear even though both fixtures call through the same intercepted
/// API.
pub fn emit_data_exfil_harness(spec: &HarnessSpec) -> HarnessSource {
    let probe = probe_shim();
    let module_name = derive_module_name(&spec.entry_file);
    let entry_name = if spec.entry_name.is_empty() {
        "run".to_owned()
    } else {
        spec.entry_name.clone()
    };
    let body = format!(
        r#"#!/usr/bin/env python3
"""Nyx dynamic harness — DATA_EXFIL outbound-host (Phase 11 / Track J.9)."""
import importlib
import io
import json
import os
import sys
import time
import urllib.parse
import urllib.request

{probe}


def _nyx_outbound_probe(host):
    rec = {{
        "sink_callee": "__nyx_mock_http",
        "args": [{{"kind": "String", "value": str(host)}}],
        "captured_at_ns": time.time_ns(),
        "payload_id": os.environ.get("NYX_PAYLOAD_ID", ""),
        "kind": {{"kind": "OutboundNetwork", "host": str(host)}},
        "witness": __nyx_witness("__nyx_mock_http", [str(host)]),
    }}
    __nyx_emit(rec)


def _nyx_extract_host(target):
    # Accepts either a urllib.request.Request instance or a raw URL str.
    raw = None
    if hasattr(target, "full_url"):
        raw = target.full_url
    elif hasattr(target, "get_full_url"):
        try:
            raw = target.get_full_url()
        except Exception:
            raw = None
    if raw is None:
        raw = target
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8", "replace")
        except Exception:
            raw = ""
    if not isinstance(raw, str):
        raw = str(raw)
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return ""
    host = parsed.hostname
    return host if host is not None else ""


class _NyxFakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def getcode(self):
        return 200

    def info(self):
        return {{}}


def _nyx_urlopen(url, data=None, timeout=None, *args, **kwargs):
    host = _nyx_extract_host(url)
    _nyx_outbound_probe(host)
    return _NyxFakeResponse(b"")


urllib.request.urlopen = _nyx_urlopen


def _nyx_data_exfil_via_fixture(payload):
    sys.path.insert(0, ".")
    try:
        mod = importlib.import_module("{module_name}")
    except Exception:
        return False
    fn = getattr(mod, "{entry_name}", None)
    if fn is None:
        return False
    try:
        fn(payload)
    except Exception:
        return True
    return True


def _nyx_run():
    payload = os.environ.get("NYX_PAYLOAD", "")
    _nyx_data_exfil_via_fixture(payload)
    print("__NYX_SINK_HIT__", flush=True)
    sys.stdout.write(json.dumps({{"payload": payload}}) + "\n")
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

fn message_handler_dependency_files(spec: &HarnessSpec) -> Vec<(String, String)> {
    if spec.expected_cap != crate::labels::Cap::CODE_EXEC {
        return Vec::new();
    }
    let source = read_entry_source(&spec.entry_file);
    let mut deps = python_message_handler_deps(&source);
    if let Some(adapter) = spec.framework.as_ref().map(|b| b.adapter.as_str()) {
        for &dep in
            crate::dynamic::framework::runtime_deps::deps_for_adapter(adapter).python_packages
        {
            if !deps.contains(&dep) {
                deps.push(dep);
            }
        }
    }
    if deps.is_empty() {
        return Vec::new();
    }
    deps.sort_unstable();
    let mut body = String::new();
    for dep in deps {
        body.push_str(dep);
        body.push('\n');
    }
    vec![("requirements.txt".to_owned(), body)]
}

fn framework_dependency_files(spec: &HarnessSpec) -> Vec<(String, String)> {
    if spec.expected_cap != crate::labels::Cap::CODE_EXEC {
        return Vec::new();
    }
    let Some(adapter) = spec.framework.as_ref().map(|b| b.adapter.as_str()) else {
        return Vec::new();
    };
    let mut deps: Vec<&'static str> =
        crate::dynamic::framework::runtime_deps::deps_for_adapter(adapter)
            .python_packages
            .to_vec();
    if deps.is_empty() {
        return Vec::new();
    }
    deps.sort_unstable();
    deps.dedup();
    let mut body = String::new();
    for dep in deps {
        body.push_str(dep);
        body.push('\n');
    }
    vec![("requirements.txt".to_owned(), body)]
}

fn python_message_handler_deps(source: &str) -> Vec<&'static str> {
    let mut deps = Vec::new();
    for raw_line in source.lines() {
        let line = raw_line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        if (line.starts_with("from kafka import") || line.starts_with("import kafka"))
            && !deps.contains(&"kafka-python")
        {
            deps.push("kafka-python");
        }
        if (line.starts_with("import boto3") || line.starts_with("from boto3 import"))
            && !deps.contains(&"boto3")
        {
            deps.push("boto3");
        }
        if (line.starts_with("from google.cloud import pubsub")
            || line.starts_with("import google.cloud.pubsub"))
            && !deps.contains(&"google-cloud-pubsub")
        {
            deps.push("google-cloud-pubsub");
        }
        if (line.starts_with("import pika") || line.starts_with("from pika import"))
            && !deps.contains(&"pika")
        {
            deps.push("pika");
        }
    }
    deps
}

fn extra_files_for_shape(shape: PythonShape) -> Vec<(String, String)> {
    match shape {
        PythonShape::FlaskRoute => vec![("requirements.txt".to_owned(), "Flask\n".to_owned())],
        PythonShape::FastApiRoute => {
            vec![("requirements.txt".to_owned(), "fastapi\nhttpx\n".to_owned())]
        }
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
            if name
                .chars()
                .next()
                .map(|c| c.is_ascii_lowercase())
                .unwrap_or(false)
            {
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
            let pre =
                "import io\nsys.stdin = io.TextIOWrapper(io.BytesIO(_payload_raw))\n".to_owned();
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
            if name
                .chars()
                .next()
                .map(|c| c.is_ascii_lowercase())
                .unwrap_or(false)
            {
                (String::new(), format!("{name}=payload"))
            } else {
                let pre = format!("os.environ[{name:?}] = payload\n");
                (pre, String::new())
            }
        }
        PayloadSlot::Stdin => {
            let pre =
                "import io\nsys.stdin = io.TextIOWrapper(io.BytesIO(_payload_raw))\n".to_owned();
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
        assert!(
            harness
                .source
                .contains("os.environ[\"USER_INPUT\"] = payload")
        );
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
        let src =
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/')\ndef index(): pass\n";
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
        assert!(
            extras
                .iter()
                .any(|(p, c)| p == "requirements.txt" && c.contains("Flask"))
        );
    }

    #[test]
    fn extra_files_fastapi_pins_httpx() {
        let extras = extra_files_for_shape(PythonShape::FastApiRoute);
        assert!(
            extras.iter().any(|(p, c)| p == "requirements.txt"
                && c.contains("fastapi")
                && c.contains("httpx"))
        );
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
        assert!(extras.iter().any(|(p, c)| p == "requirements.txt"
            && c.contains("starlette")
            && c.contains("httpx")));
    }

    #[test]
    fn message_handler_deps_ignore_string_markers() {
        let src = r#"
_NYX_ADAPTER_MARKER = "from kafka import KafkaConsumer"
_OTHER = "boto3.client('sqs')"
"#;
        assert!(python_message_handler_deps(src).is_empty());
    }

    #[test]
    fn message_handler_deps_detect_real_python_broker_imports() {
        let src = r#"
from kafka import KafkaConsumer
import boto3
from google.cloud import pubsub_v1
import pika
"#;
        assert_eq!(
            python_message_handler_deps(src),
            vec!["kafka-python", "boto3", "google-cloud-pubsub", "pika"]
        );
    }

    #[test]
    fn emit_message_handler_stages_requirements_for_hard_imports() {
        let dir = std::env::temp_dir().join("nyx_message_handler_python_deps");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("entry.py");
        std::fs::write(
            &entry,
            "from kafka import KafkaConsumer\n\
             def handler(message):\n\
                 return str(message)\n",
        )
        .unwrap();

        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.entry_file = entry.to_string_lossy().into_owned();
        spec.entry_name = "handler".to_owned();
        spec.entry_kind = EntryKind::MessageHandler {
            queue: "orders".to_owned(),
            message_schema: None,
        };
        spec.expected_cap = Cap::CODE_EXEC;

        let h = emit(&spec).unwrap();
        assert!(
            h.extra_files
                .iter()
                .any(|(p, c)| { p == "requirements.txt" && c.contains("kafka-python") })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_spec_with(kind: EntryKind, name: &str) -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.entry_kind = kind;
        s.entry_name = name.to_owned();
        s
    }

    fn make_ldap_spec() -> HarnessSpec {
        let mut s = make_spec(PayloadSlot::Param(0));
        s.expected_cap = Cap::LDAP_INJECTION;
        s.entry_name = "run".into();
        s
    }

    #[test]
    fn emit_ldap_harness_routes_through_stub_when_endpoint_set() {
        let h = emit_ldap_harness(&make_ldap_spec());
        assert!(
            h.source.contains("NYX_LDAP_ENDPOINT"),
            "Python LDAP harness must read NYX_LDAP_ENDPOINT to route through the stub",
        );
        assert!(
            h.source.contains("socket.create_connection"),
            "Python LDAP harness must open a TCP socket against the stub endpoint",
        );
        assert!(
            h.source.contains("_NYX_BER_BIND_REQUEST = 0x60"),
            "Python LDAP harness must compose an LDAPv3 BindRequest (BER tag 0x60)",
        );
        assert!(
            h.source.contains("_NYX_BER_SEARCH_REQUEST = 0x63"),
            "Python LDAP harness must compose an LDAPv3 SearchRequest (BER tag 0x63)",
        );
        assert!(
            h.source.contains("_nyx_encode_filter"),
            "Python LDAP harness must encode the RFC 4515 filter string into BER bytes",
        );
        assert!(
            !h.source.contains("\"SEARCH \""),
            "Python LDAP harness must no longer write the plaintext SEARCH <filter> tier-(a) framing",
        );
    }

    #[test]
    fn emit_ldap_harness_retains_local_matcher_fallback() {
        let h = emit_ldap_harness(&make_ldap_spec());
        assert!(
            h.source.contains("_nyx_ldap_count_local"),
            "Python LDAP harness must keep the in-process matcher as a fallback for hosts without the stub",
        );
        assert!(
            h.source.contains("_nyx_ldap_count_via_ber"),
            "Python LDAP harness must dispatch through the BER stub-route helper",
        );
    }

    fn make_xpath_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::XPATH_INJECTION;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_xpath_harness_routes_through_fixture_import() {
        let h = emit_xpath_harness(&make_xpath_spec(
            "tests/dynamic_fixtures/xpath_injection/python/vuln.py",
            "run",
        ));
        assert_eq!(h.extra_files.len(), 2);
        assert_eq!(h.extra_files[0].0, "xpath_corpus.xml");
        assert_eq!(
            h.extra_files[1].0, "requirements.txt",
            "Python XPath harness must stage requirements.txt so prepare_python pip-installs lxml",
        );
        assert_eq!(
            h.extra_files[1].1, "lxml\n",
            "Python XPath harness requirements.txt must pin lxml so tier-(a) imports succeed",
        );
        assert!(
            h.source.contains("def _nyx_xpath_via_fixture(payload):"),
            "Python XPath harness must define the fixture-routing helper",
        );
        assert!(
            h.source.contains("importlib.import_module(\"vuln\")"),
            "Python XPath harness must import the entry module by its file stem",
        );
        assert!(
            h.source.contains("getattr(mod, \"run\", None)"),
            "Python XPath harness must look up the entry function by name",
        );
        assert!(
            h.source.contains("nodes = _nyx_xpath_via_fixture(payload)"),
            "Python XPath harness main must call the fixture-routing helper",
        );
    }

    #[test]
    fn emit_xpath_harness_drops_inline_matcher_fallback() {
        let h = emit_xpath_harness(&make_xpath_spec(
            "tests/dynamic_fixtures/xpath_injection/python/vuln.py",
            "run",
        ));
        assert!(
            !h.source.contains("_nyx_xpath_select"),
            "Python XPath harness must no longer carry the inline `_nyx_xpath_select` matcher fallback",
        );
        assert!(
            h.source.contains("NYX_IMPORT_ERROR:"),
            "Python XPath harness must emit the conventional NYX_IMPORT_ERROR stderr marker so the runner SKIPs hosts without lxml installed",
        );
        assert!(
            h.source.contains("sys.exit(77)"),
            "Python XPath harness must exit 77 on ImportError so RunError::BuildFailed fires",
        );
        assert!(
            h.source.contains("__NYX_XPATH_TIER_A__"),
            "Python XPath harness must print the tier-(a) stdout marker after a successful fixture call so e2e assertions can pin tier-(a) execution",
        );
    }

    #[test]
    fn emit_xpath_harness_derives_module_name_from_entry_file() {
        let h = emit_xpath_harness(&make_xpath_spec("/abs/path/benign.py", "run"));
        assert!(
            h.source.contains("importlib.import_module(\"benign\")"),
            "module name must come from the entry-file stem, not a hard-coded literal",
        );
    }

    fn make_header_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::HEADER_INJECTION;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_header_injection_harness_routes_through_fixture_when_flask_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_py_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.py");
        std::fs::write(
            &entry,
            "from flask import Response\n\
             def run(value):\n    response = Response('ok')\n    response.headers['Set-Cookie'] = value\n    return response\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("def _nyx_header_via_fixture(payload):"),
            "tier-(a) harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source.contains("import werkzeug.datastructures"),
            "tier-(a) harness must monkey-patch werkzeug Headers: {}",
            h.source
        );
        assert!(
            h.source.contains("_wzd.Headers.__setitem__ = _nyx_setitem"),
            "tier-(a) harness must install the permissive captor: {}",
            h.source
        );
        assert!(
            h.source.contains("importlib.import_module(\"vuln\")"),
            "tier-(a) harness must import the fixture by its file stem: {}",
            h.source
        );
        assert!(
            h.source.contains("getattr(mod, \"run\", None)"),
            "tier-(a) harness must look up the named entry function: {}",
            h.source
        );
        assert!(
            h.source
                .contains("captured = _nyx_header_via_fixture(payload)"),
            "harness main must call the fixture-routing helper first: {}",
            h.source
        );
        assert!(
            h.source
                .contains("_nyx_header_probe(\"Set-Cookie\", payload)")
                || h.source
                    .contains("value = payload\n    _nyx_header_probe(name, value)"),
            "fallback path must still emit a synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_falls_back_when_flask_not_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_py_test_no_flask");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.py");
        std::fs::write(&entry, "def run(value):\n    return value\n").unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("import werkzeug.datastructures"),
            "fallback path must not import werkzeug: {}",
            h.source
        );
        assert!(
            !h.source.contains("def _nyx_header_via_fixture"),
            "fallback path must not define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source
                .contains("value = payload\n    _nyx_header_probe(name, value)"),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_derives_module_name_from_entry_file() {
        let dir = std::env::temp_dir().join("nyx_phase08_py_test_module_derive");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("benign.py");
        std::fs::write(
            &entry,
            "from flask import Response\n\
             def run(v):\n    return Response('ok')\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("importlib.import_module(\"benign\")"),
            "module name must come from the entry-file stem: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_routes_through_wire_frame_when_base_http_request_handler_imported()
     {
        let dir = std::env::temp_dir().join("nyx_phase08_py_test_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.py");
        std::fs::write(
            &entry,
            "from http.server import BaseHTTPRequestHandler\n\
             class VulnHandler(BaseHTTPRequestHandler):\n    cookie_value = b''\n    def do_GET(self):\n        self.wfile.write(b'HTTP/1.0 200 OK\\r\\nSet-Cookie: ' + self.__class__.cookie_value + b'\\r\\n\\r\\nok')\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source
                .contains("def _nyx_wire_frame_via_fixture(payload):"),
            "tier-(b) harness must define the wire-frame helper: {}",
            h.source
        );
        assert!(
            h.source
                .contains("http.server.HTTPServer((\"127.0.0.1\", 0)"),
            "tier-(b) harness must boot HTTPServer on loopback ephemeral port: {}",
            h.source
        );
        assert!(
            h.source.contains("getattr(mod, \"VulnHandler\", None)"),
            "tier-(b) harness must look up the VulnHandler class: {}",
            h.source
        );
        assert!(
            h.source
                .contains("raw_bytes = _nyx_wire_frame_via_fixture(payload)"),
            "harness main must call the wire-frame helper first when raw-socket fixture detected: {}",
            h.source
        );
        assert!(
            h.source
                .contains(r#""kind": {"kind": "HeaderWireFrame", "raw_bytes": list(raw_bytes)}"#),
            "tier-(b) harness must emit a HeaderWireFrame probe carrying the raw header-block bytes: {}",
            h.source
        );
        // Wire-frame branch also derives HeaderEmit records from the
        // captured Set-Cookie lines so the tier-(a) HeaderInjected
        // predicate fires on the same payload.
        assert!(
            h.source.contains("_nyx_header_probe(name, value)"),
            "wire-frame branch must also emit derived HeaderEmit probes: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_header_injection_harness_drops_wire_frame_branch_when_only_flask_imported() {
        let dir = std::env::temp_dir().join("nyx_phase08_py_test_no_wire_frame");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.py");
        std::fs::write(
            &entry,
            "from flask import Response\n\
             def run(value):\n    response = Response('ok')\n    response.headers['Set-Cookie'] = value\n    return response\n",
        )
        .unwrap();
        let h = emit_header_injection_harness(&make_header_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("def _nyx_wire_frame_via_fixture"),
            "flask-only fixture must not pull in the wire-frame helper: {}",
            h.source
        );
        assert!(
            !h.source.contains("HeaderWireFrame"),
            "flask-only harness must not emit the HeaderWireFrame probe shape: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_redirect_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::OPEN_REDIRECT;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_open_redirect_harness_routes_through_fixture_when_flask_imported() {
        let dir = std::env::temp_dir().join("nyx_phase09_py_test_drive_fixture");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.py");
        std::fs::write(
            &entry,
            "from flask import redirect\ndef run(value):\n    return redirect(value)\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("def _nyx_redirect_via_fixture(payload):"),
            "tier-(a) harness must define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            h.source.contains("importlib.import_module(\"vuln\")"),
            "tier-(a) harness must import the fixture by its file stem: {}",
            h.source
        );
        assert!(
            h.source
                .contains("response.headers.get(\"Location\", \"\")"),
            "tier-(a) harness must read the Location header off the returned response: {}",
            h.source
        );
        assert!(
            h.source
                .contains("captured = _nyx_redirect_via_fixture(payload)"),
            "harness main must call the fixture-routing helper first: {}",
            h.source
        );
        assert!(
            h.source
                .contains("location = payload\n    _nyx_redirect_probe(location, request_host)"),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_falls_back_when_flask_not_imported() {
        let dir = std::env::temp_dir().join("nyx_phase09_py_test_no_flask");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.py");
        std::fs::write(&entry, "def run(value):\n    return value\n").unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            !h.source.contains("def _nyx_redirect_via_fixture"),
            "fallback path must not define the fixture-routing helper: {}",
            h.source
        );
        assert!(
            !h.source.contains("importlib.import_module"),
            "fallback path must not import the fixture: {}",
            h.source
        );
        assert!(
            h.source
                .contains("location = payload\n    _nyx_redirect_probe(location, request_host)"),
            "fallback path must keep the synthetic probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_ships_follow_location_helper() {
        let dir = std::env::temp_dir().join("nyx_phase09_py_test_follow_location");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.py");
        std::fs::write(
            &entry,
            "from flask import redirect\ndef run(value):\n    return redirect(value)\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("def _nyx_follow_location(location):"),
            "OPEN_REDIRECT harness must declare the _nyx_follow_location helper: {}",
            h.source
        );
        assert!(
            h.source.contains("import urllib.request"),
            "OPEN_REDIRECT harness must import urllib.request for the loopback follow: {}",
            h.source
        );
        assert!(
            h.source
                .contains("urllib.request.urlopen(location, timeout=2.0)"),
            "follow-location helper must call urllib.request.urlopen with a 2-second timeout: {}",
            h.source
        );
        assert!(
            h.source.contains("startswith(\"http://127.0.0.1\")")
                && h.source.contains("startswith(\"http://localhost\")")
                && h.source.contains("startswith(\"http://host-gateway\")"),
            "follow-location helper must gate on loopback host prefixes: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_open_redirect_harness_follows_captured_location_in_tier_a() {
        let dir = std::env::temp_dir().join("nyx_phase09_py_test_follow_captured");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entry = dir.join("vuln.py");
        std::fs::write(
            &entry,
            "from flask import redirect\ndef run(value):\n    return redirect(value)\n",
        )
        .unwrap();
        let h = emit_open_redirect_harness(&make_redirect_spec(entry.to_str().unwrap(), "run"));
        assert!(
            h.source.contains("_nyx_redirect_probe(location, request_host)\n        _nyx_follow_location(location)"),
            "tier-(a) must follow the captured Location after emitting the probe: {}",
            h.source
        );
        assert!(
            h.source.contains(
                "_nyx_redirect_probe(location, request_host)\n    _nyx_follow_location(location)"
            ),
            "tier-(b) fallback must also follow the synthetic location after the probe: {}",
            h.source
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_crypto_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::CRYPTO;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_crypto_harness_when_cap_is_crypto() {
        let h = emit(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/python/vuln.py",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("_nyx_weak_key_probe"),
            "dispatcher must short-circuit Cap::CRYPTO into emit_crypto_harness so the weak-key probe shim is present: {}",
            h.source
        );
        assert!(
            h.source.contains("\"kind\": \"WeakKey\""),
            "crypto harness must record probes with `kind: WeakKey` so the WeakKeyEntropy predicate fires",
        );
    }

    #[test]
    fn emit_crypto_harness_routes_through_fixture_import() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/python/vuln.py",
            "run",
        ));
        assert!(
            h.source.contains("def _nyx_crypto_via_fixture(payload):"),
            "Python CRYPTO harness must define the fixture-routing helper",
        );
        assert!(
            h.source.contains("importlib.import_module(\"vuln\")"),
            "Python CRYPTO harness must import the entry module by its file stem",
        );
        assert!(
            h.source.contains("getattr(mod, \"run\", None)"),
            "Python CRYPTO harness must look up the entry function by name",
        );
        assert!(
            h.source
                .contains("produced = _nyx_crypto_via_fixture(payload)"),
            "Python CRYPTO harness main must call the fixture-routing helper",
        );
        assert_eq!(
            h.filename, "harness.py",
            "Python CRYPTO harness must emit a harness.py file",
        );
        assert!(
            h.extra_files.is_empty(),
            "Python CRYPTO harness must not require per-spec deps — random + secrets are stdlib",
        );
    }

    #[test]
    fn emit_crypto_harness_emits_weak_key_probe_kind() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/python/vuln.py",
            "run",
        ));
        assert!(
            h.source.contains("\"kind\": \"WeakKey\", \"key_int\":"),
            "Python CRYPTO harness must emit ProbeKind::WeakKey records carrying a key_int field so the WeakKeyEntropy predicate fires: {}",
            h.source
        );
        assert!(
            h.source.contains("__NYX_SINK_HIT__"),
            "Python CRYPTO harness must print the universal sink-hit sentinel",
        );
    }

    #[test]
    fn emit_crypto_harness_converts_bytes_returns_via_from_bytes() {
        let h = emit_crypto_harness(&make_crypto_spec(
            "tests/dynamic_fixtures/crypto/python/benign.py",
            "run",
        ));
        assert!(
            h.source.contains("int.from_bytes("),
            "Python CRYPTO harness must reduce bytes/bytearray returns via int.from_bytes so a 32-byte CSPRNG key produces a key_int whose magnitude exceeds any 16-bit budget",
        );
        assert!(
            h.source.contains("isinstance(value, int):"),
            "Python CRYPTO harness must keep int returns flowing through verbatim",
        );
    }

    #[test]
    fn emit_crypto_harness_derives_module_name_from_entry_file() {
        let h = emit_crypto_harness(&make_crypto_spec("/abs/path/benign.py", "run"));
        assert!(
            h.source.contains("importlib.import_module(\"benign\")"),
            "module name must come from the entry-file stem, not a hard-coded literal",
        );
    }

    fn make_json_parse_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::JSON_PARSE;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_json_parse_harness_when_cap_is_json_parse() {
        let h = emit(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/python/vuln.py",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("_nyx_json_loads_with_depth"),
            "dispatcher must select the JSON_PARSE depth harness: {}",
            h.source
        );
        assert!(
            h.source.contains("\"kind\": \"JsonParse\""),
            "JSON_PARSE harness must emit JsonParse probes",
        );
    }

    #[test]
    fn emit_json_parse_harness_monkey_patches_json_loads() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/python/vuln.py",
            "run",
        ));
        assert!(h.source.contains("_nyx_orig_json_loads = json.loads"));
        assert!(h.source.contains("json.loads = _nyx_json_loads_with_depth"));
        assert!(h.source.contains("def _nyx_count_depth(parsed):"));
    }

    #[test]
    fn emit_json_parse_harness_emits_depth_fields() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/python/vuln.py",
            "run",
        ));
        assert!(h.source.contains("\"depth\": int(depth)"));
        assert!(h.source.contains("\"excessive_depth\": bool(excessive)"));
        assert!(h.source.contains("depth > 64"));
        assert!(h.source.contains("__NYX_SINK_HIT__"));
    }

    #[test]
    fn emit_json_parse_harness_handles_parser_recursion_error() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/python/vuln.py",
            "run",
        ));
        assert!(h.source.contains("except RecursionError:"));
        assert!(h.source.contains("_nyx_json_parse_probe(0, True)"));
    }

    #[test]
    fn emit_json_parse_harness_routes_through_fixture_import() {
        let h = emit_json_parse_harness(&make_json_parse_spec(
            "tests/dynamic_fixtures/json_parse_depth/python/vuln.py",
            "run",
        ));
        assert!(
            h.source
                .contains("def _nyx_json_parse_via_fixture(payload):")
        );
        assert!(h.source.contains("importlib.import_module(\"vuln\")"));
        assert!(h.source.contains("getattr(mod, \"run\", None)"));
        assert_eq!(h.filename, "harness.py");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_json_parse_harness_derives_module_name_from_entry_file() {
        let h = emit_json_parse_harness(&make_json_parse_spec("/abs/path/benign.py", "run"));
        assert!(h.source.contains("importlib.import_module(\"benign\")"));
    }

    fn make_unauthorized_id_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::UNAUTHORIZED_ID;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_unauthorized_id_harness_when_cap_is_unauthorized_id() {
        let h = emit(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/python/vuln.py",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("_nyx_idor_probe"),
            "dispatcher must short-circuit Cap::UNAUTHORIZED_ID into emit_unauthorized_id_harness: {}",
            h.source
        );
        assert!(
            h.source.contains("\"kind\": \"IdorAccess\""),
            "UNAUTHORIZED_ID harness must emit ProbeKind::IdorAccess records",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_pins_caller_id() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/python/vuln.py",
            "run",
        ));
        assert!(
            h.source.contains("_NYX_CALLER_ID = \"alice\""),
            "harness must hard-code caller_id=alice so the predicate fires only when payload ≠ alice",
        );
        assert!(
            h.source
                .contains("_nyx_idor_probe(_NYX_CALLER_ID, payload)"),
            "harness must emit the IDOR probe with the hard-coded caller and the payload owner_id",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_skips_probe_when_record_is_none() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/python/benign.py",
            "run",
        ));
        assert!(
            h.source.contains("if record is not None:"),
            "harness must only emit the probe when the fixture materialised a record so the benign fixture (which returns None on boundary cross) does not flip the predicate",
        );
    }

    #[test]
    fn emit_unauthorized_id_harness_routes_through_fixture_import() {
        let h = emit_unauthorized_id_harness(&make_unauthorized_id_spec(
            "tests/dynamic_fixtures/unauthorized_id/python/vuln.py",
            "run",
        ));
        assert!(
            h.source.contains("def _nyx_idor_via_fixture(payload):"),
            "Python UNAUTHORIZED_ID harness must define the fixture-routing helper",
        );
        assert!(h.source.contains("importlib.import_module(\"vuln\")"));
        assert!(h.source.contains("getattr(mod, \"run\", None)"));
        assert_eq!(h.filename, "harness.py");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_unauthorized_id_harness_derives_module_name_from_entry_file() {
        let h =
            emit_unauthorized_id_harness(&make_unauthorized_id_spec("/abs/path/benign.py", "run"));
        assert!(h.source.contains("importlib.import_module(\"benign\")"));
    }

    fn make_data_exfil_spec(entry_file: &str, entry_name: &str) -> HarnessSpec {
        let mut spec = make_spec(PayloadSlot::Param(0));
        spec.expected_cap = Cap::DATA_EXFIL;
        spec.entry_file = entry_file.to_owned();
        spec.entry_name = entry_name.to_owned();
        spec
    }

    #[test]
    fn emit_dispatches_to_data_exfil_harness_when_cap_is_data_exfil() {
        let h = emit(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/python/vuln.py",
            "run",
        ))
        .unwrap();
        assert!(
            h.source.contains("urllib.request.urlopen = _nyx_urlopen"),
            "dispatcher must short-circuit Cap::DATA_EXFIL into emit_data_exfil_harness: {}",
            h.source
        );
        assert!(
            h.source.contains("\"kind\": \"OutboundNetwork\""),
            "DATA_EXFIL harness must emit ProbeKind::OutboundNetwork records",
        );
    }

    #[test]
    fn emit_data_exfil_harness_monkey_patches_urlopen() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/python/vuln.py",
            "run",
        ));
        assert!(h.source.contains("urllib.request.urlopen = _nyx_urlopen"));
        assert!(
            h.source
                .contains("def _nyx_urlopen(url, data=None, timeout=None, *args, **kwargs):")
        );
        assert!(
            h.source.contains("class _NyxFakeResponse(io.BytesIO):"),
            "harness must return a fake response so the fixture does not block on real network egress",
        );
    }

    #[test]
    fn emit_data_exfil_harness_parses_host_via_urlparse() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/python/vuln.py",
            "run",
        ));
        assert!(h.source.contains("urllib.parse.urlparse(raw)"));
        assert!(h.source.contains("host = parsed.hostname"));
    }

    #[test]
    fn emit_data_exfil_harness_handles_request_instance_via_full_url() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/python/vuln.py",
            "run",
        ));
        assert!(
            h.source.contains("hasattr(target, \"full_url\")"),
            "harness must accept a urllib.request.Request instance too (not only bare URL strings)",
        );
    }

    #[test]
    fn emit_data_exfil_harness_routes_through_fixture_import() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec(
            "tests/dynamic_fixtures/data_exfil/python/vuln.py",
            "run",
        ));
        assert!(
            h.source
                .contains("def _nyx_data_exfil_via_fixture(payload):"),
            "Python DATA_EXFIL harness must define the fixture-routing helper",
        );
        assert!(h.source.contains("importlib.import_module(\"vuln\")"));
        assert!(h.source.contains("getattr(mod, \"run\", None)"));
        assert_eq!(h.filename, "harness.py");
        assert!(h.extra_files.is_empty());
    }

    #[test]
    fn emit_data_exfil_harness_derives_module_name_from_entry_file() {
        let h = emit_data_exfil_harness(&make_data_exfil_spec("/abs/path/benign.py", "run"));
        assert!(h.source.contains("importlib.import_module(\"benign\")"));
    }
}
