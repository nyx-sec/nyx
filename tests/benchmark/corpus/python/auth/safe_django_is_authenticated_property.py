"""An early return on `request.user.is_authenticated` guards the rest of the view."""

from django.http import HttpResponse


def handle_export(request):
    if not request.user.is_authenticated:
        return HttpResponse("login required", status=401)
    with open("/srv/export/report.csv") as report:
        return HttpResponse(report.read())
