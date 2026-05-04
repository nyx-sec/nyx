"""Recall guard for the Phase 1 caller-scope IPA fix.

Same shape as `safe_caller_scope_helper_under_authorized_route.py`, but
the router carries no route-level auth dep (`router = APIRouter()`).
The helper's `session.add` is reached from a route handler with no
authorization, so the engine MUST still fire
`missing_ownership_check` (and `token_override_without_validation`)
on the helper's sink.

Triggers `apply_caller_scope_propagation`'s soundness rule: a helper's
caller list must contain at least one caller with route-level non-Login
auth checks.  When no caller is authorized, no propagation happens and
the helper's sinks fire as expected.
"""
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Body


# Bare router — no Security dep at the boundary.
ti_id_router = APIRouter()


def _create_state_update(
    *,
    task_instance_id: UUID,
    payload: dict,
    session,
) -> None:
    if payload.get("kind") == "reschedule":
        session.add({"id": task_instance_id, "data": payload})


@ti_id_router.patch("/{task_instance_id}/state")
def ti_update_state(
    task_instance_id: UUID,
    payload: Annotated[dict, Body()],
    session,
) -> None:
    _create_state_update(
        task_instance_id=task_instance_id,
        payload=payload,
        session=session,
    )
