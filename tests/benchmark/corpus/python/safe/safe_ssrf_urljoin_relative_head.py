import requests
from urllib.parse import urljoin
from flask import request


def proxy():
    item = request.args.get("id")
    # A fixed `v1/` head makes the path a relative reference under the base.
    url = urljoin("https://api.example.com/", "v1/items/" + item)
    requests.get(url)
    return "ok"
