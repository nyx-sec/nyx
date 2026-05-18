# Phase 09 (Track J.7) — Python OPEN_REDIRECT vuln fixture.
#
# The function passes `value` straight into `flask.redirect` without
# host validation.  A payload carrying `https://attacker.test/` sends
# the response's `Location:` header off-origin.
from flask import redirect


def run(value):
    return redirect(value)
