"""Phase 21 — Django middleware benign control."""
import os
import shlex

_NYX_ADAPTER_MARKER = "from django.utils.deprecation import MiddlewareMixin"


class AuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        os.system("echo " + shlex.quote(str(request.body)))
        return self.get_response(request)


def audit(get_response):
    return AuditMiddleware(get_response)
