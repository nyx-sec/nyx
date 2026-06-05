"""Phase 12 — Django view, benign."""
import re
import subprocess

from django.http import HttpResponse

_VALID_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def ping(request):
    host = request.GET.get("host", "")
    if not _VALID_HOST.fullmatch(host):
        return HttpResponse("invalid host")
    result = subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return HttpResponse(result.stdout + result.stderr)
