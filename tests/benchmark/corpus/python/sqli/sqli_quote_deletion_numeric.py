from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args["id"]
    uid = uid.replace("'", "")
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    return "ok"
