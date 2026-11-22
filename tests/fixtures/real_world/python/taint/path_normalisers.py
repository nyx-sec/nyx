import os
from pathlib import Path
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE = "/srv/files"


# Vulnerable: realpath returns an absolute path but does not confine it.
@app.route("/realpath")
def v_realpath():
    name = request.args.get("name")
    p = os.path.realpath(os.path.join(BASE, name))
    return send_file(p)


# Safe: realpath, then a containment check against the root.
@app.route("/realpath-checked")
def s_realpath():
    name = request.args.get("name")
    p = os.path.realpath(os.path.join(BASE, name))
    if not p.startswith(BASE + os.sep):
        abort(403)
    return send_file(p)


# Vulnerable: normpath keeps a leading `..`, and `/etc/passwd` joins to itself.
@app.route("/normpath")
def v_normpath():
    name = request.args.get("name")
    p = os.path.normpath(os.path.join(BASE, name))
    return send_file(p)


# Vulnerable: normpath, reject absolute, then join under the root. `../../etc`
# survives normpath and the absolute check.
@app.route("/normpath-isabs")
def v_normpath_isabs():
    name = request.args.get("name")
    p = os.path.normpath(name)
    if os.path.isabs(p):
        abort(400)
    return send_file(os.path.join(BASE, p))


# Safe: a normalized path that does not start with `..` or `/` is relative and
# stays under the root it is joined to.
@app.route("/normpath-rejected")
def s_normpath_rejected():
    name = request.args.get("name")
    p = os.path.normpath(name)
    if p.startswith("..") or p.startswith("/"):
        abort(400)
    return send_file(os.path.join(BASE, p))


# Safe: normpath, then a containment check.
@app.route("/normpath-checked")
def s_normpath_checked():
    name = request.args.get("name")
    p = os.path.normpath(os.path.join(BASE, name))
    if not p.startswith(BASE + os.sep):
        abort(403)
    return send_file(p)


# Vulnerable: abspath makes the path absolute but does not confine it.
@app.route("/abspath")
def v_abspath():
    name = request.args.get("name")
    p = os.path.abspath(os.path.join(BASE, name))
    return send_file(p)


# Safe: abspath, then a containment check.
@app.route("/abspath-checked")
def s_abspath():
    name = request.args.get("name")
    p = os.path.abspath(os.path.join(BASE, name))
    if not p.startswith(BASE + os.sep):
        abort(403)
    return send_file(p)


# Vulnerable: Path.resolve does not confine either.
@app.route("/resolve")
def v_resolve():
    name = request.args.get("name")
    p = Path(BASE, name).resolve()
    return send_file(p)


# Safe: resolve, then is_relative_to.
@app.route("/resolve-checked")
def s_resolve():
    name = request.args.get("name")
    p = (Path(BASE) / name).resolve()
    if not p.is_relative_to(BASE):
        abort(403)
    return send_file(p)


# Safe: basename keeps only the final component.
@app.route("/basename")
def s_basename():
    name = request.args.get("name")
    leaf = os.path.basename(name)
    return send_file(os.path.join(BASE, leaf))
