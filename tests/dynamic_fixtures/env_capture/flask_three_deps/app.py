# Phase 09 fixture: Flask app with three deps.  The static engine
# resolves the sink to `_execute` (helper) and the callgraph rewrite
# resolves the entry to the Flask route handler `run_command`.
# Phase 09's environment capture pass must:
#   1. Resolve toolchain via .python-version / pyproject.toml.
#   2. Extract flask + requests + jinja2 as direct deps.
#   3. Detect Flask via the manifest in requirements.txt.
#   4. Stage every file in the source closure of `_execute`.

from flask import Flask, request
import requests
import jinja2

app = Flask(__name__)


def _execute(cmd):
    import os
    os.system(cmd)  # sink: command injection


def _enrich(cmd):
    # Cross-file helper consumer: forces the source closure walk to copy
    # at least one extra file beyond `app.py` even when this fixture is
    # collapsed into a single-file directory.
    template = jinja2.Template("echo {{ value }}")
    return template.render(value=cmd)


@app.route("/run", methods=["POST"])
def run_command():
    raw = request.form.get("cmd", "")
    cmd = _enrich(raw)
    _execute(cmd)
    return "ok"
