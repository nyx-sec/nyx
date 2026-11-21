# Negative: framework-injected handles are not request input.  `Request`
# and `BackgroundTasks` arrive from the framework, not the query string.
import subprocess

from fastapi import BackgroundTasks, FastAPI, Request

app = FastAPI()


@app.get("/hook")
def hook(request: Request, background_tasks: BackgroundTasks):
    subprocess.run("echo " + str(request.scope), shell=True)
    background_tasks.add_task(subprocess.run, "echo done", shell=True)
    return "ok"
