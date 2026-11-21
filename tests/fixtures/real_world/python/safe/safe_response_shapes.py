import html
import json

from django.http import HttpResponse
from django.template.loader import render_to_string
from flask import Flask, jsonify, make_response, render_template, request

app = Flask(__name__)


@app.route("/search")
def search_page():
    q = request.args.get("q")
    resp = make_response(render_template("search.html", q=q))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/echo")
def echo_json():
    q = request.args.get("q")
    return make_response(jsonify({"q": q}), 200)


def django_json(request):
    q = request.GET.get("q")
    return HttpResponse(json.dumps({"q": q}), content_type="application/json")


def django_plain(request):
    q = request.GET.get("q")
    return HttpResponse(q, content_type="text/plain; charset=utf-8")


def django_template(request):
    q = request.GET.get("q")
    return HttpResponse(render_to_string("page.html", {"q": q}))


def django_escaped(request):
    q = request.GET.get("q")
    return HttpResponse(html.escape(q), status=200)


def django_json_default_type(request):
    q = request.GET.get("q")
    return HttpResponse(json.dumps({"q": q}))


def django_html_type(request):
    q = request.GET.get("q")
    return HttpResponse(q, content_type="text/html")


def django_dynamic_type(request, content_type):
    q = request.GET.get("q")
    return HttpResponse(q, content_type=content_type)


@app.route("/hello")
def hello():
    q = request.args.get("q")
    return make_response("<h1>Hello " + q + "</h1>")
