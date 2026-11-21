from flask import Flask, request

from .db import Post, db

app = Flask(__name__)


@app.route("/posts", methods=["POST"])
def create_post():
    title = request.json.get("title")
    post = Post(title=title)
    db.session.add(post)
    db.session.commit()
    return {"ok": True}
