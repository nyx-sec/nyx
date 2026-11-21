from fastapi import Depends, FastAPI

from .auth import check_ownership
from .db import Doc, session

app = FastAPI()


# The project root also holds a UI `package.json` that lists only React, so
# the manifests name no Python server framework.  The FastAPI extractor still
# has to read the route dependency, which authorizes the whole handler.
@app.delete("/docs/{doc_id}", dependencies=[Depends(check_ownership)])
def delete_doc(doc_id: str):
    session.query(Doc).filter(Doc.id == doc_id).delete()
    return {"ok": True}
