# Phase 14 fixture (Python positive) — attacker-controlled URL flows
# directly into `requests.get`. The `requests.get` flat SSRF rule fires
# at the call site without any URL-builder support: the SSA value
# carries `Cap::all()` source taint from `request.json()` which the
# SSRF gate intersects against `Cap::SSRF`.
import requests
from flask import request


def proxy():
    body = request.get_json()
    target = body["url"]
    requests.get(target)
    return ""
