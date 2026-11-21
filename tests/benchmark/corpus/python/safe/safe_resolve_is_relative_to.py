from pathlib import Path
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name")
    path = (Path(BASE) / name).resolve()
    if not path.is_relative_to(BASE):
        abort(403)
    return send_file(path)
