# Phase 15 — Python SQLAlchemy `text(f"…")` interpolation SQLi positive.
# `sqlalchemy.text` is a flat SQL_QUERY sink; the f-string interpolates
# `request.args.get('name')` directly into the SQL fragment with no
# parameterisation.  Receiver-typing on `Session()` resolves
# `session.execute(...)` to `SqlAlchemySession.execute` for the
# downstream call, but the sink fires at the `text(...)` site itself.
from flask import Flask, request
from sqlalchemy import text
from sqlalchemy.orm import Session

app = Flask(__name__)


@app.route("/users")
def lookup():
    name = request.args.get("name")
    session = Session()
    rows = session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
    return list(rows)
