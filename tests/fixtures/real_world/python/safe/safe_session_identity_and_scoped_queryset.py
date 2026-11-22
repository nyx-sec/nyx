from flask import Flask, jsonify, session

from . import models

app = Flask(__name__)


@app.route("/me")
def me():
    u = models.User.query.get(session["user_id"])
    return jsonify(u)


@app.route("/orders")
def orders():
    uid = session["user_id"]
    return jsonify(models.Order.query.filter_by(user_id=uid).all())


def resolve_product(info, id, requestor):
    qs = models.Product.objects.visible_to_user(requestor)
    if id:
        return qs.filter(id=id).first()
    return None


def resolve_users(info, ids, requester):
    qs = models.User.objects.filter(id=requester.id)
    if ids:
        return qs.filter(id__in=ids)
    return qs
