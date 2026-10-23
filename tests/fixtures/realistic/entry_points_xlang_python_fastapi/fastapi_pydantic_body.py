# Positive: a same-file Pydantic model annotation is the request body.  Its
# fields are as attacker-controlled as the model itself.
import os
import sqlite3

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Item(BaseModel):
    name: str
    cmd: str


@app.post("/items")
def create_item(item: Item):
    conn = sqlite3.connect("items.db")
    conn.execute(f"INSERT INTO items VALUES ('{item.name}')")
    os.system("echo " + item.cmd)
    return item
