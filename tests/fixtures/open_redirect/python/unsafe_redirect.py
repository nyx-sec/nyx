# Unsafe: Flask `redirect(url)` receives the user-controlled `next` query
# argument directly.
from flask import request, redirect


def handler():
    target = request.args.get("next")
    return redirect(target)
