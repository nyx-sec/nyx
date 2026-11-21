"""`request.json.get(..)` reads a dictionary, not an invitation token.

The handler writes a new row built from the request body.  No id from the URL
or the body picks an existing row, so neither the ownership rule nor the token
rule has anything to report.
"""

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
