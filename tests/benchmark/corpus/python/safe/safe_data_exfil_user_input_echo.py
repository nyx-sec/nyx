import requests
from flask import Flask, request

app = Flask(__name__)


# DATA_EXFIL safe: plain user input echoed into a fixed-destination
# requests.post body must not fire. Sensitivity-gate strips the cap
# because the source is Plain-tier (raw user input).
@app.route('/forward', methods=['POST'])
def forward():
    message = request.form.get('message')
    requests.post('https://telemetry.internal/forward', json={'message': message})
    return 'ok'
