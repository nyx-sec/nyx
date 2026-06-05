"""Phase 12 (Track L.10) — FastAPI CMDI vuln fixture.

`GET /run?cmd=<...>` forwards the `cmd` query parameter straight into
`os.system`.  Adapter binding: `@app.get("/run")` with `cmd` flowing
through the function formal.
"""
import os
from fastapi import FastAPI

app = FastAPI()


@app.get("/run")
def run_cmd(cmd: str = ""):
    os.system(cmd)
    return {"ok": True}
