"""Distilled from airflow
`airflow-core/src/airflow/api_fastapi/execution_api/routes/task_instances.py:89-318`:
FastAPI declares its auth dependency once at the router constructor —
`ti_id_router = VersionedAPIRouter(dependencies=[Security(require_auth,
scopes=["ti:self"])])` — and every per-task route attaches via
`@ti_id_router.<verb>(...)` with no inline deps.  FastAPI propagates
router-level dependencies to every attached route at runtime, so the
JWT-validated scope check guards every `session.add` / row-update sink
the handler body reaches.

Pre-fix the FastAPI dep extractor only walked the per-route decorator's
`dependencies=[...]` kwarg; router-constructor `dependencies=` was
dropped, so every `@ti_id_router.<verb>` route without inline deps fired
`missing_ownership_check` + `token_override_without_validation` despite
being authorized.

The fix walks module-level `<router> = APIRouter(...)` /
`VersionedAPIRouter(...)` / `FastAPI(...)` assignments, captures the
router's `dependencies=[...]` into a per-router map, and merges them
into the per-route middleware list when the decorator's prefix matches.
A scoped Security wrapper synthesises matching TokenExpiry +
TokenRecipient checks (the JWT-validation semantics) so the
token-override rule recognises the route too.

Precision guard: route must NOT fire `missing_ownership_check` /
`token_override_without_validation` even though the handler writes
through an id-targeted state update.
"""
from fastapi import Security
from cadwyn import VersionedAPIRouter


def require_auth(scopes):
    pass


# Router-level Security with non-empty scopes.  Every route attached to
# this router inherits the dep; no inline declaration needed.
ti_id_router = VersionedAPIRouter(
    dependencies=[
        Security(require_auth, scopes=["ti:self"]),
    ],
)


class Log:
    pass


class TaskInstance:
    pass


@ti_id_router.patch("/{task_instance_id}/state")
def ti_update_state(task_instance_id: str, session):
    session.add(
        Log(
            task_instance_id=task_instance_id,
            event="state_update",
        )
    )
