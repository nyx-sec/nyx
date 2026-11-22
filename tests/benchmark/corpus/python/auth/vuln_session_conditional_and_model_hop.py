from django.http import JsonResponse

from . import models


def note_conditional(request):
    uid = request.GET["id"]
    if request.GET.get("me"):
        uid = request.session["user_id"]
    note = models.Note.objects.get(owner_id=uid)
    return JsonResponse({"body": note.body})


def note_through_model(request, note_id):
    qs = models.Note.objects.filter(owner=request.user)
    qs = qs.model.objects.all()
    note = qs.get(id=note_id)
    return JsonResponse({"body": note.body})


def note_fake_session(request):
    session = request.GET
    uid = session.get("user_id")
    note = models.Note.objects.get(id=uid)
    return JsonResponse({"body": note.body})
