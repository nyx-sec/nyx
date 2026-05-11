# Phase 14 fixture (Python negative) — `urllib.parse.urljoin(base, path)`
# with a literal base anchors an origin-locked StringFact prefix that
# `is_string_safe_for_ssrf` honours, suppressing the SSRF sink even
# though the path component is attacker-controlled.
import requests
from urllib.parse import urljoin
from flask import request


def proxy():
    body = request.get_json()
    path = body["path"]
    url = urljoin("https://api.example.com", path)
    requests.get(url)
    return ""
