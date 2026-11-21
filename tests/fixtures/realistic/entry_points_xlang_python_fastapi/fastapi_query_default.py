# Positive: the pre-`Annotated` marker form `q: str = Query(None)`.  The
# `Query(..)` default alone says the value comes from the query string.
from fastapi import FastAPI, Query

app = FastAPI()


@app.get("/read")
def read(path: str = Query(None)):
    return open(path).read()
