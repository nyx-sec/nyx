# Positive: a plain scalar annotation on a FastAPI route is a query
# parameter, so `q` is request-bound even without `Query()` or a path
# capture.  Forwarding it to a shell fires `taint-unsanitised-flow`.
import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/search")
def search(q: str):
    subprocess.run("echo " + q, shell=True)
    return "ok"
