"""Distilled from airflow
`airflow-core/src/airflow/api_fastapi/execution_api/routes/task_instances.py:516-628`:
The route handler `ti_update_state` is route-level authorized via the
`ti_id_router = VersionedAPIRouter(dependencies=[Security(require_auth,
scopes=["ti:self"])])` declaration (closed by the session-0010 fix).
The handler then delegates the actual `session.add(TaskReschedule(...))`
sink to a private helper `_create_ti_state_update_query_and_update_state`
that has no inline auth check of its own.

Pre-fix the helper fired `missing_ownership_check` +
`token_override_without_validation` at the helper's body sink because
`check_ownership_gaps` is scoped per AnalysisUnit — the caller's
route-level auth check did not propagate to the callee.

The Phase 1 caller-scope IPA fix (`apply_caller_scope_propagation` in
`src/auth_analysis/mod.rs`) walks the call graph DOWN: when every
in-file caller of a helper carries route-level non-Login auth
(Other / Membership / Ownership / AdminGuard), the helper inherits the
caller's checks via synthetic `is_route_level=true` AuthChecks.  This
lifts the airflow shape exactly, both findings cleared post-fix.

Precision guard: helper must NOT fire `missing_ownership_check` or
`token_override_without_validation` despite holding the auth-relevant
sinks (`session.add` with caller-passed scoped id).
"""
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Body, Security


def require_auth():
    pass


# Router-level Security carries the JWT scope check on every attached
# route at runtime.  Closes the prior session-0010 gap.
ti_id_router = APIRouter(
    dependencies=[Security(require_auth, scopes=["ti:self"])],
)


def _create_state_update(
    *,
    task_instance_id: UUID,
    payload: dict,
    session,
) -> None:
    """Helper: caller-scope IPA must propagate route-level auth into here."""
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
