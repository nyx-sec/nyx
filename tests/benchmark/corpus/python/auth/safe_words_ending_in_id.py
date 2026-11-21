from flask import Flask

app = Flask(__name__)


# `paid`, `android` and `valid` end in the letters "id" but are not ids.
@app.route("/orders")
def orders(paid):
    return Order.query.filter_by(paid=paid).all()


@app.route("/devices")
def devices(android):
    return Device.query.filter_by(android=android).all()
