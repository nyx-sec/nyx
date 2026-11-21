# Phase 14 fixture (Python negative) — `urllib.parse.urljoin(base, path)`
# with a literal base and a path that starts with a fixed `v1/` segment.  The
# head makes the path a relative reference, which keeps the base host, so the
# origin-locked StringFact prefix suppresses the SSRF sink even though the
# tail of the path is attacker-controlled.  (A bare attacker path does not
# lock: `urljoin(base, "//evil/x")` is `//evil/x`; see
# `ssrf_py_urljoin_attacker_path.py`.)
import requests
from urllib.parse import urljoin
from flask import request


def proxy():
    body = request.get_json()
    path = body["path"]
    url = urljoin("https://api.example.com", "v1/" + path)
    requests.get(url)
    return ""
