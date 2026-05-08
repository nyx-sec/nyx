# Phase 15 negative — Python parameterised cursor.execute.
# The SQL string is a literal with `%s` placeholder; the bind tuple is
# entirely constant, so no taint flows into either argument and the
# flat `cursor.execute` sink stays silent.  Mirrors phase 07's
# `sqli_typeorm_safe_parameterized.ts` shape: the negative fixture
# documents the parameterised API form, not parameterised-with-tainted-
# bind-args (which would require payload-arg gating).
import psycopg2
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def lookup():
    _name = request.args.get("name")
    conn = psycopg2.connect("dbname=app")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (1,))
    return cursor.fetchall()
