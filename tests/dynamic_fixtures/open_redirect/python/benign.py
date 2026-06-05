# Phase 09 (Track J.7) — Python OPEN_REDIRECT benign control fixture.
#
# The function ignores the attacker-supplied value and redirects to a
# same-origin path, so the captured `Location:` header carries no
# off-origin authority.
from flask import redirect


def run(value):
    return redirect("/dashboard")
