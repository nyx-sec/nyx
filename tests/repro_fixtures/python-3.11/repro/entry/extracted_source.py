import flask

app = flask.Flask(__name__)


@app.route('/run', methods=['POST'])
def run():
    cmd = flask.request.json.get('cmd')
    return {'out': eval(cmd)}
