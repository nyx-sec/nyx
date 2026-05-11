# Flask path-capture with a converter prefix (`<path:slug>`).  The route
# binds `slug` as the path capture; only the inner name after the
# converter colon participates in the gate.  Slug flows to
# `subprocess.check_output(shell=True)` producing
# `taint-unsanitised-flow`.
from flask import Flask
import subprocess

app = Flask(__name__)


@app.route("/exec/<path:slug>")
def exec_slug(slug):
    subprocess.check_output("echo " + slug, shell=True)
    return "ok"
