import sqlite3

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Item(BaseModel):
    name: str


@app.post("/items")
def create_item(item: Item):
    conn = sqlite3.connect("items.db")
    conn.execute(f"INSERT INTO items VALUES ('{item.name}')")
    return item
