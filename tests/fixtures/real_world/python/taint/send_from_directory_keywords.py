from flask import Flask, request, send_from_directory

app = Flask(__name__)


@app.route("/dl")
def download_positional():
    # Vulnerable: the directory comes from the request.
    d = request.args.get("d")
    return send_from_directory(d, "index.html")


@app.route("/dl-kw")
def download_keyword():
    # Vulnerable: the directory is passed as the `directory=` keyword.
    d = request.args.get("d")
    return send_from_directory(directory=d, path="index.html")


@app.route("/files/<name>")
def download_name(name):
    # Safe: werkzeug's safe_join rejects `..` and absolute names in `path`.
    return send_from_directory("/srv/files", request.args.get("name"))


@app.route("/files-kw")
def download_name_kw():
    # Safe: constant directory, tainted `path=` keyword.
    return send_from_directory(directory="/srv/files", path=request.args.get("name"))
