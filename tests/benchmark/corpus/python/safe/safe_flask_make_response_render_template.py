from flask import Flask, jsonify, make_response, render_template, request

app = Flask(__name__)


@app.route("/search")
def search_page():
    q = request.args.get("q")
    resp = make_response(render_template("search.html", q=q))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/search")
def search_api():
    q = request.args.get("q")
    return make_response(jsonify({"q": q}), 200)
