# Distilled from airflow `airflow-core/src/airflow/api_fastapi/execution_api/routes/__init__.py`.
# Parent file declares an authorized router carrying scoped Security deps,
# then attaches every per-file child router via `include_router(...)`.
# FastAPI runtime lifts the parent's `dependencies=[...]` onto every route
# attached to the child router — including bare child routers declared
# without inline deps — so routes inside child files inherit the auth
# automatically.
#
# Pre-fix the per-file router-dep extractor only saw inline declarations;
# bare child routers fired `missing_ownership_check` /
# `token_override_without_validation` despite being authorized via the
# `include_router` parent.  The cross-file router-fact index resolves the
# parent-child lift at pass 2 entry.
from cadwyn import VersionedAPIRouter
from fastapi import APIRouter, Security

from . import task_instances, dag_runs, public_health
from .security import require_auth

execution_api_router = APIRouter()
execution_api_router.include_router(public_health.router, prefix="/health", tags=["Health"])

# All routes attached to this router are authenticated via Security(require_auth).
authenticated_router = VersionedAPIRouter(dependencies=[Security(require_auth)])
authenticated_router.include_router(
    task_instances.router, prefix="/task-instances", tags=["Task Instances"]
)
authenticated_router.include_router(dag_runs.router, prefix="/dag-runs", tags=["Dag Runs"])

execution_api_router.include_router(authenticated_router)
