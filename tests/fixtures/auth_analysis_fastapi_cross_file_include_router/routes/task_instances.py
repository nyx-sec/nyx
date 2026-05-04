"""Bare child router — auth comes from `__init__.py` via include_router.

Pre-fix: every `@router.<verb>(...)` route in this file fired
`missing_ownership_check` because `router = VersionedAPIRouter()`
declares no inline `dependencies=[...]`.  The auth declaration lives
on `__init__.py`'s `authenticated_router = VersionedAPIRouter(
dependencies=[Security(require_auth)])` and is lifted onto this file
via `authenticated_router.include_router(task_instances.router)`.

Post-fix: cross-file router-fact resolution at pass 2 entry detects
the include_router edge targeting this file's `router` var, looks up
`authenticated_router`'s deps in the parent's `local_router_deps`
map, and folds them into this file's per-route auth attribution.
The route below must NOT fire `missing_ownership_check` /
`token_override_without_validation`."""
from typing import Annotated

from fastapi import Body
from cadwyn import VersionedAPIRouter

from .security import require_auth as _require_auth_unused  # noqa: F401  (parity with airflow)

router = VersionedAPIRouter()


@router.patch("/{task_instance_id}/state")
def patch_task_instance_state(
    task_instance_id: str,
    body: Annotated[dict, Body()],
):
    """Bare-child route — relies on parent router's Security(require_auth).

    Operations: writes a row keyed by user-supplied `task_instance_id`.
    Without cross-file router-dep resolution this is the canonical FP
    shape — the auth check lives in `__init__.py`, the sink lives here.
    """
    new_state = body.get("state", "")
    # Simulated session.add — write keyed by an id-like param the route
    # accepted from the URL path.  A bare in-file scan would mark this
    # as missing_ownership_check on the assumption that `task_instance_id`
    # is unauthorized user input.
    session = _get_session()
    session.add(
        TaskInstanceRow(
            task_instance_id=task_instance_id,
            state=new_state,
        )
    )
    session.commit()


def _get_session():
    """Stub — supplies the session object for the write below."""
    raise NotImplementedError


class TaskInstanceRow:
    def __init__(self, task_instance_id: str, state: str) -> None:
        self.task_instance_id = task_instance_id
        self.state = state
