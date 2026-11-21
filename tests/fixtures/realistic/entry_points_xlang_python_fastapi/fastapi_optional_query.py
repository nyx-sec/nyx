# Positive: `Optional[str] = None` and `str | None = None` are optional
# query parameters.
from typing import Optional

import requests
from fastapi import FastAPI

app = FastAPI()


@app.get("/proxy")
def proxy(target: Optional[str] = None):
    return requests.get(target).text


@app.get("/proxy2")
def proxy2(target: str | None = None):
    return requests.get(target).text
