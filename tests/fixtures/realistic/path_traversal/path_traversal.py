# Phase 13 path-traversal positive (Python).  Flask handler reads
# `request.args.get("name")` (Source) and feeds the value into
# `Path(name).read_text()`.  After paren-strip the chain text becomes
# `Path.read_text`, which matches the new pathlib FILE_IO rule in
# `src/labels/python.rs`.
from flask import request
from pathlib import Path


def handler():
    name = request.args.get("name")
    return Path(name).read_text()
