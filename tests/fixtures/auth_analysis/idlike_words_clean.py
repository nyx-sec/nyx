# Ordinary words that end in the letters "id" (`paid`, `android`, `valid`) are
# not identifiers.  Filtering or creating by them is not a scoped-id lookup.
# Pinned in `auth_analysis_tests`.
from flask import Flask

app = Flask(__name__)


@app.route("/orders")
def orders(paid):
    return Order.query.filter_by(paid=paid).all()


@app.route("/devices")
def devices(android):
    return Device.query.filter_by(android=android).all()


@app.route("/submit")
def submit(valid):
    return Submission.create(valid=valid)
