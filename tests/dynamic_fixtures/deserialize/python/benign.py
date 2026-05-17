"""Phase 03 (Track J.1) — Python deserialize benign fixture.

Wraps `pickle.Unpickler` with a `find_class` override that hard-codes
a tiny allowlist.  A gadget chain in the payload trips
`UnpicklingError` before any code runs, so no Deserialize probe
fires.
"""
import io
import pickle

ALLOWED = {("builtins", "list"), ("builtins", "dict"), ("builtins", "int")}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str):
        if (module, name) not in ALLOWED:
            raise pickle.UnpicklingError(f"blocked: {module}.{name}")
        return super().find_class(module, name)


def run(blob: bytes):
    return RestrictedUnpickler(io.BytesIO(blob)).load()
