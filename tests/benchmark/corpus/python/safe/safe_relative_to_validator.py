# py-safe-relative-to: pathlib `relative_to(base)` raise-on-escape
# pattern recognised as a receiver-side FILE_IO validator.  Captures
# the canonical Python path-containment idiom — the receiver is proven
# contained in `base` if execution reaches the next statement.
# Motivated by CVE-2024-23334 patched fixture.
from pathlib import Path

from flask import request, send_file


def download() -> None:
    base = Path("/var/www/static")
    rel_url = request.args.get("path")
    filepath = base.joinpath(rel_url).resolve()
    try:
        filepath.relative_to(base)
    except ValueError:
        return
    send_file(str(filepath))
