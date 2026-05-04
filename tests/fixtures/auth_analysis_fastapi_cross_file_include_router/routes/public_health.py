"""Public router — NOT attached via authenticated_router, no auth lift.

The parent file declares
`execution_api_router.include_router(public_health.router, prefix="/health")`
where `execution_api_router = APIRouter()` has NO dependencies.  Every
route here is genuinely public — no inline auth, no cross-file lift.

The vulnerability counterpart in this fixture: the route below writes
a row keyed by an id-like path param, with no auth covering it.
The auth analysis must still fire `missing_ownership_check` here —
recall guard for the cross-file resolution.  If the cross-file lift
over-applies (e.g. blanket "any router covered by include_router gets
the parent's deps" without checking that the parent itself has deps),
this finding would silently disappear and we would lose the vuln
detection."""
from typing import Annotated

from fastapi import Body
from cadwyn import VersionedAPIRouter

router = VersionedAPIRouter()


@router.put("/{log_id}/payload")
def public_update_log(
    log_id: str,
    body: Annotated[dict, Body()],
):
    """Public route — no auth covers this id-targeted write.

    `log_id` is a path param the route accepted from the URL.  The
    write is keyed by that id with no ownership check — exactly the
    shape `py.auth.missing_ownership_check` is designed to flag.
    """
    session = _get_session()
    session.add(
        HealthLogRow(
            log_id=log_id,
            payload=body.get("payload", ""),
        )
    )
    session.commit()


def _get_session():
    raise NotImplementedError


class HealthLogRow:
    def __init__(self, log_id: str, payload: str) -> None:
        self.log_id = log_id
        self.payload = payload
