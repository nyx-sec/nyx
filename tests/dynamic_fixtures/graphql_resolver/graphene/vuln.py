"""Phase 21 (Track M.3) — Graphene resolver vuln fixture.

`resolve_user(self, info, id)` is a Graphene query resolver that
splices the tainted `id` into a shell command via `os.system`.
"""
import os

_NYX_ADAPTER_MARKER = "import graphene"
_NYX_OBJECT_TYPE_MARKER = "class Query(graphene.ObjectType):"


def resolve_user(self, info, id):
    # SINK: tainted id concatenated into shell command.
    os.system("echo lookup-" + str(id))
    return "user-" + str(id)
