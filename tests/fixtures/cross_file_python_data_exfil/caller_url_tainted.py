"""Tainted URL, fixed body: SSRF must fire on the URL flow.  DATA_EXFIL
must NOT fire — the body is a literal dict, not a sensitive source, and
the cap-vs-position split through the wrapper's summary keeps the URL's
taint from leaking onto the body's gate.
"""
from flask import Flask, request

from helper import forward

app = Flask(__name__)


@app.route('/proxy', methods=['POST'])
def proxy():
    tainted_url = request.args.get('url')
    forward(tainted_url, {'event': 'proxy_call'})
    return '', 204
