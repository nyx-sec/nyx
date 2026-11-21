from html import escape
from pickle import loads
from shlex import quote
from subprocess import check_output

from django.http import HttpResponse
from flask import request
from os import system


def run_listing():
    d = request.args.get("d")
    return check_output("ls " + d, shell=True)


def run_listing_inline():
    return check_output("ls " + request.args.get("d"), shell=True)


def run_system():
    d = request.args.get("d")
    system("ls " + d)


def load_blob():
    return loads(request.data)


def run_quoted_listing():
    d = quote(request.args.get("d"))
    return check_output("ls " + d, shell=True)


def greet(req):
    name = req.GET.get("name", "")
    safe = escape(name)
    return HttpResponse("<p>Hello " + safe + "</p>")
