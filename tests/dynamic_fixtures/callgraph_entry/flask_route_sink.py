# Phase 04 fixture: sink in a helper function called only from a Flask
# route handler. The callgraph-aware spec-derivation path must rewrite
# the harness entry to the route handler `run_command` (entry-point
# ancestor with `entry_kind = FlaskRoute`), not the helper `_execute`
# where the sink physically lives.

from flask import Flask, request

app = Flask(__name__)


def _execute(cmd):
    import os
    os.system(cmd)  # sink: command injection


@app.route("/run", methods=["POST"])
def run_command():
    cmd = request.form.get("cmd", "")
    _execute(cmd)
    return "ok"
