import requests
from urllib.parse import urljoin
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    # Vulnerable: `urljoin("https://api/", "//evil/x")` is `https://evil/x`.
    path = request.args.get("path")
    url = urljoin("https://api.example.com/", path)
    requests.get(url)
    return "ok"


@app.route("/items")
def items():
    # Safe: a fixed `v1/` head is a relative reference under the base.
    item = request.args.get("id")
    url = urljoin("https://api.example.com/", "v1/items/" + item)
    requests.get(url)
    return "ok"


@app.route("/exact")
def exact():
    # Safe: the reference is a literal.
    request.args.get("id")
    url = urljoin("https://api.example.com/", "v1/status")
    requests.get(url)
    return "ok"


@app.route("/weather")
def weather():
    # Safe: constant host, tainted query parameter.
    city = request.args.get("city")
    requests.get("https://api.example.com/v1/weather", params={"city": city})
    return "ok"


@app.route("/city")
def city_path():
    # Safe: f-string with a fixed `scheme://host/` head.
    city = request.args.get("city")
    url = f"https://api.example.com/v1/city/{city}"
    requests.get(url)
    return "ok"


@app.route("/raw")
def raw():
    # Vulnerable: the whole URL is attacker-controlled.
    url = request.args.get("url")
    requests.get(url)
    return "ok"


@app.route("/kw")
def kw():
    # Vulnerable: the URL passed as the `url=` keyword.
    target = request.args.get("url")
    requests.get(url=target)
    return "ok"


@app.route("/kw-params")
def kw_params():
    # Safe: constant `url=` endpoint, tainted query parameter.
    q = request.args.get("q")
    requests.get(url="https://api.example.com/v1/search", params={"q": q})
    return "ok"
