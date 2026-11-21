import requests
from flask import Flask, request

app = Flask(__name__)
API = "https://api.weather.example.com/v1/"


@app.route("/city")
def city():
    name = request.args.get("name")
    url = f"https://api.weather.example.com/v1/city/{name}"
    requests.get(url)
    return "ok"


@app.route("/forecast")
def forecast():
    days = request.args.get("days")
    # Constant endpoint, tainted query parameter.
    requests.get(API + "forecast", params={"days": days})
    return "ok"


@app.route("/module")
def module_const():
    name = request.args.get("name")
    requests.get(API + name)
    return "ok"
