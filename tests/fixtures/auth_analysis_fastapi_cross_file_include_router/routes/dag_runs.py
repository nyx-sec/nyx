"""Second bare child router — same shape as task_instances.py."""
from typing import Annotated

from fastapi import Body
from cadwyn import VersionedAPIRouter

router = VersionedAPIRouter()


@router.put("/{dag_run_id}/clear")
def clear_dag_run(
    dag_run_id: str,
    body: Annotated[dict, Body()],
):
    """Bare-child route — auth via parent's include_router lift."""
    session = _get_session()
    session.add(
        DagRunRow(dag_run_id=dag_run_id, cleared=body.get("clear", False))
    )
    session.commit()


def _get_session():
    raise NotImplementedError


class DagRunRow:
    def __init__(self, dag_run_id: str, cleared: bool) -> None:
        self.dag_run_id = dag_run_id
        self.cleared = cleared
