from flask import Flask, request
from .db import get_db

app = Flask(__name__)


@app.route("/items")
def items():
    db = get_db()
    q = "SELECT id FROM items"
    match request.args.get("mode"):
        case "search":
            q = "SELECT id FROM items WHERE name = '" + request.args.get("name") + "'"
            app.logger.info("search is disabled")
        case _:
            db.execute(q)
    return "ok"
