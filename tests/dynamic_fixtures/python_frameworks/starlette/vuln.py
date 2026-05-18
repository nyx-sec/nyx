"""Phase 12 (Track L.10) — Starlette CMDI vuln fixture.

`run_cmd(request)` reads the `cmd` query parameter and pipes it
straight to `os.system`.  Adapter binding: `Route("/run", endpoint=run_cmd)`
registration with `cmd` flowing through `request.query_params`.
"""
import os
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route


async def run_cmd(request):
    cmd = request.query_params.get("cmd", "")
    os.system(cmd)
    return PlainTextResponse("ok")


app = Starlette(routes=[Route("/run", endpoint=run_cmd)])
