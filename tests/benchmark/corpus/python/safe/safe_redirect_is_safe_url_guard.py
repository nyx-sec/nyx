from flask import redirect, request


def go():
    u = request.args.get("next")
    if is_safe_url(u):
        return redirect(u)
    return redirect("/")
