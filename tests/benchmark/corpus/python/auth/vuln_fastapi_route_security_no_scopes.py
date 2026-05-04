"""Recall counterpart to safe_fastapi_route_security_scopes.py.

Precision guard for the Security-without-scopes path: a bare
`Security(callable)` with no `scopes=[...]` kwarg, or with an empty
`scopes=[]`, is NOT promoted from LoginGuard to AuthorizationCheck —
the OAuth2 scope semantic only fires when scopes is non-empty.  Without
scope enforcement the wrapper is functionally equivalent to
`Depends(callable)` plus a bare login check, so `missing_ownership_check`
must still fire on a downstream id-targeted ORM filter.

Recall guard: ownership-check rule must fire — Security with no scopes
is conservative (treated as login-only), so the route is not promoted
to authorized.
"""
from fastapi import FastAPI, Security


def require_auth():
    pass


router = FastAPI()


class TaskInstance:
    pass


@router.patch(
    "/{task_instance_id}/run",
    dependencies=[Security(require_auth, scopes=[])],
)
def ti_run(task_instance_id: str, session):
    return session.scalar(select(TaskInstance).filter_by(id=task_instance_id))


def select(_):
    pass
