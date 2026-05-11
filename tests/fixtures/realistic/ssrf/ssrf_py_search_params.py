# Phase 14 fixture (Python search-params positive) — attacker-controlled
# URL passed positionally to `requests.request(method, url, ...)`. The
# `params={...}` kwarg carries a benign dict; the SSRF flow comes from
# the URL position (arg 1 for `requests.request`).
import requests
from flask import request


def proxy():
    body = request.get_json()
    target = body["target"]
    requests.request("GET", target, params={"q": body["q"]})
    return ""
