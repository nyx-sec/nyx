# Phase 16 Python entry-kind seeding precision.  The `@app.route(...)`
# decorator binds `cmd` as a path capture; the entry-point seeding pass
# paints `cmd` as `Source(UserInput)`, producing `taint-unsanitised-flow`
# at the `os.system` sink.  Without per-formal route-capture gating the
# engine fell back to `cfg-unguarded-sink` for Python handlers.
from flask import Flask
import os

app = Flask(__name__)


@app.route("/run/<cmd>", methods=["POST"])
def run(cmd):
    os.system(cmd)
    return "ok"
