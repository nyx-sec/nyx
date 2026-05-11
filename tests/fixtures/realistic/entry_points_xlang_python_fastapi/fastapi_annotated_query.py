# Positive: FastAPI route with an Annotated typed extractor.  No path
# capture, but `q: Annotated[str, Query()]` matches the FastAPI marker
# `Query(`, so `classify_param_type_python` returns
# `Some(TypeKind::String)` and the seed gate paints `q` as
# `Source(UserInput)`.  Forwarding the unsanitised value to
# `subprocess.run(shell=True)` fires `taint-unsanitised-flow`.
from fastapi import FastAPI
from typing import Annotated
from fastapi import Query
import subprocess

app = FastAPI()


@app.get("/search")
def search(q: Annotated[str, Query()]):
    subprocess.run("echo " + q, shell=True)
    return "ok"
