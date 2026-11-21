"""Private helper reached only from the authorized `ti_update_state`
route in `routes/task_instances.py` (cross-file caller-scope — safe side).

The helper holds the caller-scoped `session.add` sink but has NO inline
auth check and NO in-file caller.  Phase 2 cross-file caller-scope IPA
must lift the route handler's route-level auth onto this helper, so
`missing_ownership_check` / `token_override_without_validation` must NOT
fire here.
"""

from uuid import UUID

from .models import Invitation


def persist_ti_state_change(*, task_instance_id: UUID, payload: dict, session) -> None:
    invitation = Invitation.objects.get(token=payload["token"])
    session.add({"id": task_instance_id, "data": invitation})
