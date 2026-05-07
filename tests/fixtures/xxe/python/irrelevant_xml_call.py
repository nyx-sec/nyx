# Baseline: tainted body flows through a non-parser string operation.
# No XML parser entry point, no XXE label classification.
from flask import request


def handle():
    body = request.args.get("xml")
    return "<wrap>" + body + "</wrap>"
