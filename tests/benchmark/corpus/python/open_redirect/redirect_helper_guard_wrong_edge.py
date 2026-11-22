# Positive: the redirect runs on the edge where the safety helper rejected
# the target, so the helper vouches for nothing.
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse

from util import safe_for_redirect


def login(request):
    redirect_url = request.GET.get("next")
    if not safe_for_redirect(redirect_url):
        return HttpResponseRedirect(redirect_url)
    return redirect(reverse("home"))
