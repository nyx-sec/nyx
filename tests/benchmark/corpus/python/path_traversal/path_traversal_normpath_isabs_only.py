import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name")
    clean = os.path.normpath(name)
    # Rejecting only the absolute path lets `../../etc/passwd` through.
    if os.path.isabs(clean):
        abort(400)
    return send_file(os.path.join(BASE, clean))
