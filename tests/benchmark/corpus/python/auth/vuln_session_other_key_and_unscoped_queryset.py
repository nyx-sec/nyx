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


# The request id reaches the lookup through the branch that skips the session.
def note_conditional(request):
    uid = request.GET["id"]
    if request.GET.get("me"):
        uid = request.session["user_id"]
    return models.Note.objects.get(owner_id=uid)


# `.model.objects` leaves the scoped queryset for an unscoped manager.
def note_through_model(request, note_id):
    qs = models.Note.objects.filter(owner=request.user)
    qs = qs.model.objects.all()
    return qs.get(id=note_id)


# A local called `session` that holds request input is not a session store.
def note_fake_session(request):
    session = request.GET
    uid = session.get("user_id")
    return models.Note.objects.get(id=uid)
