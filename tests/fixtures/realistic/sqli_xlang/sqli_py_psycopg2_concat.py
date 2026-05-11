# Phase 15 — Python psycopg2 raw-string concat SQLi positive.
# `cursor.execute` is a flat SQL_QUERY sink in `labels/python.rs`;
# concatenated user input (`request.args.get('name')`) flows directly
# into the SQL string without parameterisation.
import psycopg2
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def lookup():
    name = request.args.get("name")
    conn = psycopg2.connect("dbname=app")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchall()
