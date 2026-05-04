"""Recall guard for the router-level Security-prop fix.  When a router
is declared with NO `dependencies=` kwarg (`router = APIRouter(...)`),
attached routes that don't supply inline deps are genuinely
unauthorized — the engine must still flag id-targeted writes as
`missing_ownership_check`.  Without the gate the router-level extractor
would over-fire by treating every router as auth-providing.

Distilled from airflow
`task_instances.py:1036-1082` where `router = VersionedAPIRouter()`
(bare, no deps) attaches `@router.get("/states", ...)` — the route is
auth-attached only via the cross-file `include_router` chain in
`routes/__init__.py`, which is a separate gap (see deep_engine_fixes.md).
For the per-file case where the router has no router-level deps
declared, the route is correctly an un-guarded ownership-check FN.
"""
from cadwyn import VersionedAPIRouter


# Bare router — no router-level dependencies declared.
router = VersionedAPIRouter()


class TaskInstance:
    pass


@router.get("/states/{run_id}/{task_id}")
def get_task_instance_states(run_id: str, task_id: str, session):
    rows = session.scalars(
        select(TaskInstance)
        .where(TaskInstance.run_id == run_id)
        .where(TaskInstance.task_id == task_id)
    ).all()
    [
        run_id_task_state_map[task.run_id].update(
            {task.task_id: task.state}
        )
        for task in rows
    ]


def select(_):
    pass


run_id_task_state_map = {}
