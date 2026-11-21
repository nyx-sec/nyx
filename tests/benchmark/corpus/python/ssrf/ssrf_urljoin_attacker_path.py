import requests
from urllib.parse import urljoin
from flask import request


def proxy():
    path = request.args.get("path")
    # urljoin resolves the path as a reference: "//evil/x" replaces the host.
    url = urljoin("https://api.example.com/", path)
    requests.get(url)
    return "ok"
