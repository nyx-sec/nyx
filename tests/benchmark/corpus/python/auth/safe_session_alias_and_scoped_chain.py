from django.http import JsonResponse

from . import models


def note_session_only(request):
    uid = request.session["user_id"]
    note = models.Note.objects.get(owner_id=uid)
    return JsonResponse({"body": note.body})


def note_scoped_chain(request, note_id):
    qs = models.Note.objects.filter(owner=request.user)
    qs = qs.exclude(archived=True)
    note = qs.get(id=note_id)
    return JsonResponse({"body": note.body})


def note_real_session(request):
    session = request.session
    uid = session.get("user_id")
    note = models.Note.objects.get(owner_id=uid)
    return JsonResponse({"body": note.body})
