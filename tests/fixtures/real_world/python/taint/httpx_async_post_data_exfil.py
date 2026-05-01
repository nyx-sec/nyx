import os
from fastapi import FastAPI, Request
import httpx

app = FastAPI()

# Async data-exfil path: an `httpx.AsyncClient` instance dispatches a POST
# whose `json` kwarg embeds an environment-config secret.  The chained-call
# normalization collapses `httpx.AsyncClient().post` to the gate matcher
# `httpx.AsyncClient.post` so the gated DATA_EXFIL fires.  Source is
# Sensitivity::Sensitive (EnvironmentConfig) so DATA_EXFIL MUST fire on the
# json kwarg; the destination URL is fixed so SSRF must NOT fire.
@app.post('/sync-async')
async def sync_async(req: Request):
    api_key = os.environ.get('UPSTREAM_API_KEY')
    await httpx.AsyncClient().post(
        'https://upstream.internal/ingest',
        json={'api_key': api_key},
    )
    return {'ok': True}
