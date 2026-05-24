from django.utils.deprecation import MiddlewareMixin


class AuditMiddleware(MiddlewareMixin):
    def process_request(self, request):
        return None


def normalize_request(request):
    return request
