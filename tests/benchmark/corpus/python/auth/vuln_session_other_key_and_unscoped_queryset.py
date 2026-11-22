from flask import Flask, jsonify, request, session

from . import models

app = Flask(__name__)


# Recall guards for safe_session_identity_and_scoped_queryset.py.
@app.route("/ws")
def workspace():
    w = models.Workspace.query.get(session["workspace_id"])
    return jsonify(w)


def resolve_product(info, id):
    qs = models.Product.objects.all()
    return qs.filter(id=id).first()


def resolve_other(info, id, requestor, flag):
    qs = models.Product.objects.visible_to_user(requestor)
    if flag:
        qs = models.Product.objects.all()
    return qs.filter(id=id).first()


def resolve_channel(info, id, channel):
    qs = models.Product.objects.visible_to_user(channel)
    return qs.filter(id=id).first()
