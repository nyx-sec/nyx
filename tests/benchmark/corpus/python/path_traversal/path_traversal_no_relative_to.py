# py-path-traversal-no-relative-to: regression guard companion to
# safe_relative_to_validator.py.  Same source/sink shape but without
# the `filepath.relative_to(base)` validator — taint must propagate.
from pathlib import Path

from flask import request, send_file


def download() -> None:
    base = Path("/var/www/static")
    rel_url = request.args.get("path")
    filepath = base.joinpath(rel_url).resolve()
    send_file(str(filepath))
