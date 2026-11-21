# Negative: dependency handles declared through `Annotated` aliases carry no
# `Depends(` text at the use site (`session: SessionDep`), so a plain class
# annotation on a route is not enough to call a formal request-bound.  The
# user object reaches the SQL string from the authenticated session, not the
# request, so no `taint-unsanitised-flow` is expected.
from typing import Annotated

from fastapi import Depends, FastAPI

app = FastAPI()


def get_db():
    return None


def get_user():
    return None


SessionDep = Annotated[object, Depends(get_db)]
CurrentUser = Annotated[object, Depends(get_user)]


@app.get("/me/items")
def my_items(session: SessionDep, current_user: CurrentUser):
    session.execute(f"SELECT * FROM items WHERE owner = {current_user.id}")
    return "ok"
