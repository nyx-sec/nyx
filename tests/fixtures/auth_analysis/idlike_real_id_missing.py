# Recall guard for `idlike_words_clean.py`: a real `order_id` still fires.
# Pinned in `auth_analysis_tests`.
from flask import Flask

app = Flask(__name__)


@app.route("/orders/<order_id>")
def order_detail(order_id):
    return Order.query.filter_by(id=order_id).all()
