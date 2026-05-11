# Positive: FastAPI route with a brace-segment path capture.
# `@app.get("/items/{item_id}")` binds `item_id` as a path capture;
# `extract_route_path_captures` populates `BodyMeta.param_route_capture`
# from the new FastAPI brace-segment parser, and the entry-point seeding
# pass paints `item_id` as `Source(UserInput)`. The unsanitised value
# concatenated into the SQL string fires `taint-unsanitised-flow` at
# `cursor.execute`.
from fastapi import FastAPI
import sqlite3

app = FastAPI()


@app.get("/items/{item_id}")
def read_item(item_id: str):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE id = '" + item_id + "'")
    return cursor.fetchall()
