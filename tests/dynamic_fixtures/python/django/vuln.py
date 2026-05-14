"""Phase 12 — Django view, vulnerable.

Function-based view driven via `django.test.RequestFactory`.  The
harness configures a minimal Django settings module at runtime so the
view can be called without a project layout.
"""
import subprocess

from django.http import HttpResponse


def ping(request):
    """Vulnerable: query parameter flows to subprocess(shell=True)."""
    host = request.GET.get("host", "")
    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return HttpResponse(result.stdout + result.stderr)
