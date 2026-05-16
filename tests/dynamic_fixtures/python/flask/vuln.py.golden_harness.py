#!/usr/bin/env python3
"""Nyx dynamic harness — auto-generated, do not edit."""
import os
import sys
import traceback

# ── Sink-reachability probe (sys.settrace) ────────────────────────────────────

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


_NYX_SINK_FILE = "<TMPDIR>/<ENTRY_FILE>"
_NYX_SINK_LINE = 18
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
    import vuln as _entry_mod
except ImportError as _e:
    print(f"NYX_IMPORT_ERROR: {_e}", file=sys.stderr, flush=True)
    sys.exit(77)

# Shape: Flask route — dispatch via app.test_client().
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
    if _r.endpoint == "ping" or _r.endpoint.endswith("." + "ping"):
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
if "query" == "path":
    _path = re.sub(r"<[^>]+>", payload, _path, count=1)
else:
    _path = re.sub(r"<[^>]+>", "x", _path)

_client = _app.test_client()
_method = "GET"
_query = {}
_data = None
if "query" == "query":
    _query["host"] = payload
elif "query" == "body":
    _data = payload
elif "query" == "env":
    os.environ["host"] = payload
try:
    _resp = _client.open(_path, method=_method, query_string=_query, data=_data)
    try:
        print(_resp.get_data(as_text=True), flush=True)
    except Exception:
        pass
except SystemExit as _e:
    sys.exit(_e.code)
except Exception as _e:
    print(f"NYX_EXCEPTION: {type(_e).__name__}: {_e}", file=sys.stderr, flush=True)

sys.settrace(None)
