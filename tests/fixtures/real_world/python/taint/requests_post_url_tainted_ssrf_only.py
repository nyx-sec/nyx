from flask import Flask, request
import requests

app = Flask(__name__)

# URL-only taint: the destination URL is attacker-controlled but the body is
# a fixed literal.  SSRF must fire on the URL flow.  DATA_EXFIL must NOT fire
# because no body kwarg carries taint (regression guard for per-cap
# attribution — the two classes share the callee but cap routing is per
# argument position).
@app.route('/proxy', methods=['POST'])
def proxy():
    target = request.args.get('target')
    requests.post(
        target,
        json={'event': 'proxy_call'},
    )
    return '', 204
