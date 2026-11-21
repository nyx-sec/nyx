"""Private helper reached only from the UNauthorized `purge_dag_run` route
in `routes/dag_runs.py` (cross-file caller-scope — recall guard).

The helper's caller is not an authorized route handler, so the Phase 2
cross-file accumulator's `all_authorized` conjunction is false and the
lift is refused.  `missing_ownership_check` and
`token_override_without_validation` MUST still fire on the token lookup and
the caller-scoped `session.add` sink.
"""

from uuid import UUID

from .models import Invitation


def delete_dag_run_row(*, dag_run_id: UUID, payload: dict, session) -> None:
    invitation = Invitation.objects.get(token=payload["token"])
    session.add({"id": dag_run_id, "data": invitation})
