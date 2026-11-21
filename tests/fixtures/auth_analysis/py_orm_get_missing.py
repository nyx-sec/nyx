from django.http import JsonResponse

from .models import Document


def delete_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)
    doc.delete()
    return JsonResponse({"ok": True})
