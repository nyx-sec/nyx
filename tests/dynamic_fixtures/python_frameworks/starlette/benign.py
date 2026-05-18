"""Phase 12 (Track L.10) — Starlette CMDI benign fixture.

`run_cmd(request)` reads the `cmd` query parameter but rejects anything
outside an allowlist before invoking `subprocess.run` with a fixed
argv, so the sink call is unreachable for attacker-controlled values.
"""
import subprocess
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

_ALLOW = {"status", "uptime", "version"}


async def run_cmd(request):
    cmd = request.query_params.get("cmd", "")
    if cmd not in _ALLOW:
        return PlainTextResponse("rejected", status_code=400)
    subprocess.run(["/usr/bin/echo", cmd], check=False)
    return PlainTextResponse("ok")


app = Starlette(routes=[Route("/run", endpoint=run_cmd)])
