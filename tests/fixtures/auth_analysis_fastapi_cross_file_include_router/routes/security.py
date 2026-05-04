"""Stub for the auth dependency callable referenced by the parent router."""
from typing import Annotated


def require_auth():
    """Validates a bearer JWT, raises HTTPException(401) on failure.

    Real airflow uses a more elaborate version that talks to a JWT
    validator and the token-recipient table; for this fixture the
    declaration-only stub is enough — the auth analysis cares about
    the route-level wrapper, not the body.
    """
    return None
