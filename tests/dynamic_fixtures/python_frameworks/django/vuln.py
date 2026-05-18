"""Phase 12 (Track L.10) — Django CMDI vuln fixture.

`run_cmd(request)` reads `request.GET["cmd"]` and pipes it straight to
`os.system`.  Adapter binding: `path("run/", run_cmd)` registration with
`cmd` flowing through `request.GET`.
"""
import os
from django.http import HttpResponse
from django.urls import path


def run_cmd(request):
    cmd = request.GET.get("cmd", "")
    os.system(cmd)
    return HttpResponse("ok")


urlpatterns = [path("run/", run_cmd)]
