"""Phase 21 — Graphene resolver benign control."""

_NYX_ADAPTER_MARKER = "import graphene"


def resolve_user(self, info, id):
    _ = (self, info, id)
    return "user-safe"
