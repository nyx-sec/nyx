# Unsafe: jinja2 Environment.compile_expression accepts an arbitrary
# expression source; tainted input compiles into an executable callable.
from jinja2 import Environment
from flask import request


def handler():
    env = Environment()
    expr_src = request.form["expr"]
    expr = env.compile_expression(expr_src)
    return str(expr({}))
