"""SQLAlchemy variant of vuln_fastapi_route_no_dependencies.py: same FastAPI
route shape with NO `dependencies=[Depends(...)]` keyword arg, but the sink
is a real-world airflow-style SQLAlchemy queryset chain
`session.scalar(select(C).filter_by(conn_id=user_input))`.

Pre-fix the chain reduced to bare `["filter_by"]` and was suppressed by
`receiver_is_simple_chain`, blocking recall on this real-repo airflow shape.
The member_chain Python `function`-field traversal + `db_query_builder_roots`
extension restores recall.

Recall guard: ownership-check rule must fire on the chained query — the
caller has no auth check.
"""
from fastapi import FastAPI
from sqlalchemy import select

router = FastAPI()


class Connection:
    pass


@router.delete("/{connection_id}")
def delete_connection(connection_id: str, session):
    """No auth — must fire missing_ownership_check on the chained query."""
    return session.scalar(select(Connection).filter_by(conn_id=connection_id))
