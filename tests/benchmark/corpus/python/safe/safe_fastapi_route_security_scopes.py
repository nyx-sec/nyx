"""Distilled from airflow
`airflow-core/src/airflow/api_fastapi/execution_api/routes/task_instances.py:101-117`:
FastAPI route declares its auth dependency as
`dependencies=[Security(require_auth, scopes=["token:execution"])]`.
`Security(...)` is FastAPI's OAuth2-scope-checked variant of `Depends(...)`
— the JWT must carry one of the listed scopes, so the route is fully
authorized at the boundary.

Pre-fix `is_depends_callee` only matched `Depends`; `Security(...)` was
ignored, leaving the route as if no auth dep were declared.  Even after
recognising the marker, `require_auth` is a registered login-guard, and a
`LoginGuard` AuthCheckKind would have been filtered by
`has_prior_subject_auth` — the route would still fire
`missing_ownership_check`.  The deeper fix promotes a scoped Security
wrapper to `AuthCheckKind::Other` so the route counts as authorized for
ownership / membership checks at any sink the handler reaches.

Precision guard: route must NOT fire `missing_ownership_check` even
though the handler does an id-targeted ORM filter.
"""
from fastapi import FastAPI, Security


def require_auth(scopes):
    pass


router = FastAPI()


class TaskInstance:
    pass


@router.patch(
    "/{task_instance_id}/run",
    dependencies=[Security(require_auth, scopes=["token:execution", "token:workload"])],
)
def ti_run(task_instance_id: str, session):
    return session.scalar(select(TaskInstance).filter_by(id=task_instance_id))


def select(_):
    pass
