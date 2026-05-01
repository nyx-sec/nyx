"""Tainted body, fixed URL: DATA_EXFIL must fire on the body flow.  The
session cookie is a Sensitive-tier source, so taint carries the
DATA_EXFIL bit through to the wrapper's body-gate.  SSRF must NOT fire —
the URL is a hardcoded literal and the cap-vs-position split keeps the
body's taint from leaking onto the URL's gate.
"""
from flask import Flask, session

from helper import forward

app = Flask(__name__)


@app.route('/sync')
def sync():
    sid = session.get('user_token')
    forward('https://analytics.internal/track', {'session': sid})
    return '', 204
