import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    return subprocess.run("ping -c 1 " + host, shell=True)
