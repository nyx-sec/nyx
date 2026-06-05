"""Phase 21 (Track M.3) — Django middleware vuln fixture.

`AuditMiddleware.__call__(request)` splices `request.body` into a shell
command via `os.system`.
"""
import os

_NYX_ADAPTER_MARKER = "from django.utils.deprecation import MiddlewareMixin"


class AuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # SINK: tainted request body concatenated into shell command.
        os.system("echo " + str(request.body))
        return self.get_response(request)


# Module-level alias for the harness to resolve `audit` directly.
def audit(get_response):
    return AuditMiddleware(get_response)
