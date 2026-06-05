# Phase 11 (Track J.9) — Python JSON_PARSE benign control fixture.
#
# json.loads then merge into a fresh `dict` rather than mutating the
# shared sentinel, so the canary trap on `_SHARED` cannot fire.
import json


def run(value):
    parsed = json.loads(value)
    return dict(parsed)
