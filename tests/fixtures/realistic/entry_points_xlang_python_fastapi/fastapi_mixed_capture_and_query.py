# Positive: a path capture and a query parameter on the same route.  The
# query parameter is request-bound too.
import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/m/{name}")
def m(name: str, q: str):
    subprocess.run("echo " + q, shell=True)
    return name
