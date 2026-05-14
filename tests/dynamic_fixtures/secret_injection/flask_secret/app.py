# Phase 11 fixture: Flask app that reads FLASK_SECRET at import time via
# the bare-index `os.environ["FLASK_SECRET"]` form (the canonical KeyError
# trap).  The harness must populate the env *before* the module is
# imported or app.secret_key resolution raises.
#
# Phase 11 — Track D.4 acceptance bullet:
#   "A Flask fixture with `app.secret_key = os.environ["FLASK_SECRET"]`
#    boots without raising `KeyError`."

import os
from flask import Flask

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]

API_TOKEN = os.environ.get("API_TOKEN", "default-token")


@app.route("/")
def index():
    return "ok"
