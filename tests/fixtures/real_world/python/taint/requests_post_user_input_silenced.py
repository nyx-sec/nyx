from flask import Flask, request
import requests

app = Flask(__name__)

# Plain user input echoed back into a fixed-URL request body.  The destination
# is hardcoded so SSRF must NOT fire.  DATA_EXFIL must NOT fire either: the
# source is Sensitivity::Plain (request.form is raw user input) and the
# source-sensitivity gate suppresses Plain-tier sources for Cap::DATA_EXFIL.
# Echoing the user's own data back to telemetry is not a cross-boundary
# disclosure — it is exactly what the API gateway pattern does.
@app.route('/forward', methods=['POST'])
def forward_message():
    payload = request.form.get('message')
    requests.post(
        'https://telemetry.internal/forward',
        data={'message': payload},
    )
    return '', 204
