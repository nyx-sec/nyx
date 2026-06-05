from flask import Flask

app = Flask(__name__)


@app.get("/users")
def list_users():
    return "ok"
