"""End-to-end chain composer fixture.

A single-file Flask app where an unauthenticated POST handler reads
`cmd` straight off the request body and passes it to `eval()`.  The
ingredients line up for the chain composer:

- SurfaceMap gains one `EntryPoint` (Flask `/run` POST, `auth_required: false`).
- SurfaceMap gains one `DangerousLocal` (the route function itself
  consumes `Cap::CODE_EXEC` via the `eval` call site).
- A `taint-unsanitised-flow` finding ties `flask.request.json` to `eval`.

`nyx scan --format json` against this directory should emit at least one
entry in the top-level `chains` array.  The chain's `implied_impact` is
`rce` (CODE_EXEC lattice fall-through) and its `severity` reaches
`critical` via the score path.
"""

import flask

app = flask.Flask(__name__)


@app.route("/run", methods=["POST"])
def run():
    cmd = flask.request.json.get("cmd")
    return {"out": eval(cmd)}
