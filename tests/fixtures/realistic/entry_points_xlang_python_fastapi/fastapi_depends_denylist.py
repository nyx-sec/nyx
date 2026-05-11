# Negative: FastAPI route with a `Depends(...)` DI handle.  `db: Session
# = Depends(get_db)` has type annotation `Session` which is NOT in the
# FastAPI Annotated marker list, so `classify_param_type_python` returns
# None and the seed gate skips `db`.  The handler executes a SQL string
# built from the DI handle (`db.execute("...")`); without seeding, this
# call carries no taint and produces no `taint-unsanitised-flow` finding.
# A structural `cfg-unguarded-sink` finding may still fire as the
# fallback (acceptable — the regression we guard against is over-seeding
# the DI handle as adversary input, which would produce a spurious
# `taint-unsanitised-flow`).
from fastapi import FastAPI, Depends

app = FastAPI()


def get_db():
    return None


@app.get("/health")
def health(db=Depends(get_db)):
    db.execute("SELECT 1")
    return "ok"
