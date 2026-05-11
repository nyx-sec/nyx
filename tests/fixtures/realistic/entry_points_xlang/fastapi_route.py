# Phase 16 fixture: FastAPI route handler.  The `@app.get("/items/{item_id}")`
# decorator marks `read_item` as a `FastApiRoute { method: GET }` entry
# point.  Every formal is seeded as `Source(Cap::all())`; the unsanitised
# `item_id` value is concatenated into a SQL statement and forwarded to
# `cursor.execute` (flat SQL_QUERY sink).
from fastapi import FastAPI
import sqlite3

app = FastAPI()


@app.get("/items/{item_id}")
async def read_item(item_id: str):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE id = '" + item_id + "'")
    return cursor.fetchall()
