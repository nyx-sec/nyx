from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse

from util import safe_for_redirect


def login(request):
    redirect_url = request.POST.get("next") or request.GET.get("next")
    if redirect_url and safe_for_redirect(redirect_url):
        print("ok")
    else:
        redirect_url = reverse("home")
    return HttpResponseRedirect(redirect_url)  # @safe only a vetted target survives


def export(request):
    q = request.GET.copy()
    q.pop("export")
    redirect_url = f"{request.path}?{q.urlencode()}"
    if safe_for_redirect(redirect_url):
        return redirect(redirect_url)  # @safe guarded by the predicate
    return redirect(reverse("list"))


def unguarded(request):
    redirect_url = request.GET.get("next")
    return HttpResponseRedirect(redirect_url)  # @vuln


def wrong_edge(request):
    redirect_url = request.GET.get("next")
    if not safe_for_redirect(redirect_url):
        return HttpResponseRedirect(redirect_url)  # @vuln runs for rejected targets
    return redirect(reverse("home"))
