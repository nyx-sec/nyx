# Negative: a plain `int` query parameter is validated by the framework, so
# it cannot carry SQL and is not painted as attacker input.
import sqlite3

from fastapi import FastAPI

app = FastAPI()


@app.get("/page")
def page(limit: int):
    conn = sqlite3.connect("items.db")
    return conn.execute(f"SELECT * FROM items LIMIT {limit}").fetchall()
