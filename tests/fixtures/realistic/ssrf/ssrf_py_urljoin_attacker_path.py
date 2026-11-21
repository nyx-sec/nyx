# `urljoin(base, path)` resolves `path` as a reference against `base`, so an
# attacker-controlled path can be absolute (`https://evil/`) or
# protocol-relative (`//evil/`) and replace the literal base's host.
import requests
from urllib.parse import urljoin
from flask import request


def proxy():
    body = request.get_json()
    path = body["path"]
    url = urljoin("https://api.example.com", path)
    requests.get(url)
    return ""
