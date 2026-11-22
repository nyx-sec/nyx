# Safe: a boolean helper named for redirect safety guards the redirect target.
from django.shortcuts import redirect
from django.urls import reverse

from util import safe_for_redirect


def export(request):
    q = request.GET.copy()
    q.pop("export")
    redirect_url = f"{request.path}?{q.urlencode()}"
    if safe_for_redirect(redirect_url):
        return redirect(redirect_url)
    return redirect(reverse("list"))
