"""Phase 12 (Track L.10) — Django CMDI benign fixture.

`run_cmd(request)` reads `request.GET["cmd"]` but rejects anything
outside an allowlist before invoking `subprocess.run` with a fixed
argv, so the sink call is unreachable for attacker-controlled values.
"""
import subprocess
from django.http import HttpResponse
from django.urls import path

_ALLOW = {"status", "uptime", "version"}


def run_cmd(request):
    cmd = request.GET.get("cmd", "")
    if cmd not in _ALLOW:
        return HttpResponse("rejected", status=400)
    subprocess.run(["/usr/bin/echo", cmd], check=False)
    return HttpResponse("ok")


urlpatterns = [path("run/", run_cmd)]
