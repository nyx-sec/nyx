from django.db import connection
from django.shortcuts import redirect
from django.urls import reverse

from util import safe_for_redirect


def lookup(request):
    name = request.GET.get("name")
    if safe_for_redirect(name):
        with connection.cursor() as cur:
            cur.execute("SELECT * FROM t WHERE n = '%s'" % name)  # @vuln redirect predicate does not vouch for SQL
    return redirect(reverse("home"))
