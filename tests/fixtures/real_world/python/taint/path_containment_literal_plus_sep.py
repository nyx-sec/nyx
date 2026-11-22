"""A root built as a literal plus a separator is a directory prefix."""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/literal-plus-sep")
def literal_plus_sep():
    name = request.args.get("f", "")
    p = os.path.realpath(os.path.join("/srv/data", name))
    if not p.startswith("/srv/data" + os.sep):
        return ""
    with open(p) as fh:
        return fh.read()  # @safe separator appended at the test


@app.route("/bare-literal")
def bare_literal():
    p = os.path.realpath(request.args.get("f"))
    if not p.startswith("/srv/data"):
        return ""
    return open(p).read()  # @vuln sibling directory shares the prefix
