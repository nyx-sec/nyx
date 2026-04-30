import os
import requests
from flask import Flask, request

app = Flask(__name__)


# Container-taint DATA_EXFIL: a dict accumulates env-config secrets across
# keys, then is forwarded as the JSON body of an outbound POST to a fixed
# URL.  The Python SSA heap model marks the dict's `Elements` slot tainted
# at every `payload[k] = ...` write; the sink-side
# `collect_tainted_sink_values` heap-loads the same slot when checking the
# `json` kwarg, so DATA_EXFIL must fire on the json field even though
# `payload` itself is not directly tainted by an Assign.  Pairs with
# `httpx_async_post_data_exfil.py` (single-key dict literal — no
# container-mutation step).
@app.route('/upload-config', methods=['POST'])
def upload_config():
    payload = {}
    payload['api_key'] = os.environ.get('UPSTREAM_API_KEY')
    payload['region'] = os.environ.get('UPSTREAM_REGION')
    requests.post('https://api.internal/ingest', json=payload)
    return 'ok'
