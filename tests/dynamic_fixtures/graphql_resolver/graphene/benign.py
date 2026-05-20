"""Phase 21 — Graphene resolver benign control."""
import re

_NYX_ADAPTER_MARKER = "import graphene"


def resolve_user(self, info, id):
    safe = re.sub(r"[^A-Za-z0-9_-]", "", str(id))
    return "user-" + safe
