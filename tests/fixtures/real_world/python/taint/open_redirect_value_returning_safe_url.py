from flask import redirect, request


def quoted():
    u = request.args.get("next")
    if url_safe_quote(u):
        return redirect(u)  # @vuln an encoder is truthy for any input
    return redirect("/")


def confined():
    u = request.args.get("next")
    if safe_url(u):
        return redirect(u)  # @vuln a value-returning helper validates nothing
    return redirect("/")


def predicate():
    u = request.args.get("next")
    if is_safe_url(u):
        return redirect(u)  # @safe named boolean predicate
    return redirect("/")
