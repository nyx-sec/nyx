# Phase 15 deferred-fix negative — Python parameterised cursor.execute
# with TAINTED bind values.  The SQL string at arg 0 is constant; the
# user-controlled `name` is passed via the `%s` placeholder bind tuple
# at arg 1.  The DB-API driver escapes bind values, so this is safe.
#
# Without payload-arg gating on `cursor.execute` (Phase 15 deferred fix
# in `labels/python.rs::GATED_SINKS`), the flat `cursor.execute` rule
# would fire SQLi on `name`'s flow into the bind tuple.  The Destination
# gate restricts `sink_payload_args` to `&[0]`, silencing taint at arg 1+.
import psycopg2
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def lookup():
    name = request.args.get("name")
    conn = psycopg2.connect("dbname=app")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    return cursor.fetchall()
