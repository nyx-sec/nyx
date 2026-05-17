"""Phase 03 (Track J.1) — Python deserialize vuln fixture.

`pickle.loads` accepts arbitrary classes; a gadget chain inside the
payload runs straight through `__reduce__` without bumping into any
allowlist.
"""
import pickle


def run(blob: bytes):
    return pickle.loads(blob)
