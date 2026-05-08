# Phase 12 recall-gap fixture (Python).  FastAPI / starlette-shape async
# handler reads the request body via `await request.json()` and feeds it
# to a SQL sink.  Exercises the new Python `"await"` -> `Kind::AwaitForward`
# mapping in `src/labels/python.rs`: without it, the engine never models
# the await boundary as a 1:1 forward and `data` carries no Source taint.
async def handler(request):
    data = await request.json()
    cursor.execute("SELECT * FROM t WHERE id = " + data)
