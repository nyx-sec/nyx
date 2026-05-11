# Unsafe: tainted JSON body merged into target dict via the
# `dict.update(target, src)` class-method form, the canonical Python
# prototype-pollution attack shape (real-world CVE pattern: configuration
# / namespace dicts that thread user input through framework merges).
# Opt-in via NYX_PYTHON_PROTO_POLLUTION=1.
import json
from flask import request


def handler():
    body = json.loads(request.get_data())
    target = {}
    dict.update(target, body)
    return target


def handler_obj_dict():
    # Instance-attribute pollution via `__dict__.update(src)`.
    body = json.loads(request.get_data())

    class Cfg:
        pass

    obj = Cfg()
    obj.__dict__.update(body)
    return obj
