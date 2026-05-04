"""
Vulnerable counterpart to safe_fastapi_route_dependencies_auth.py: same
FastAPI route shape but with NO `dependencies=[Depends(...)]` keyword
arg on the route decorator.  The ownership-check rule must still fire
— the dependency-injection recogniser must not blanket-suppress every
FastAPI route, only those with an actual dependency-injected auth
check.

Sink uses a qualified Django-style ORM call so the post-fix
classifier still recognises it (`receiver_is_simple_chain` requires a
non-chained receiver dot).
"""
from fastapi import FastAPI

router = FastAPI()


class Connection:
    objects = None


@router.delete("/{connection_id}")
def delete_connection(connection_id: str):
    """No auth — must still fire missing_ownership_check."""
    Connection.objects.filter(id=connection_id).delete()
    return {"ok": True}
