import os
import requests
from flask import Flask

app = Flask(__name__)


# DATA_EXFIL: env-config secrets accumulate into a dict, then flow as the
# json kwarg of requests.post() at a fixed destination URL.
@app.route('/upload-config', methods=['POST'])
def upload_config():
    payload = {}
    payload['api_key'] = os.environ.get('UPSTREAM_API_KEY')
    payload['region'] = os.environ.get('UPSTREAM_REGION')
    requests.post('https://api.internal/ingest', json=payload)
    return 'ok'
