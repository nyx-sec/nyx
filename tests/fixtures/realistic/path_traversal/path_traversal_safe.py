# Phase 13 path-traversal sanitized (Python).  `Path(name).resolve(strict=True)`
# canonicalises the path and raises if it doesn't exist; the canonical
# value is returned as a string, never reaching a FILE_IO sink.  Pairs
# the new `Path.resolve` Sanitizer(FILE_IO) recogniser with a no-sink
# control-flow shape so the fixture stays silent regardless of guard
# heuristics.
from flask import request
from pathlib import Path


def safe_handler():
    name = request.args.get("name")
    candidate = Path(name).resolve(strict=True)
    return str(candidate)
