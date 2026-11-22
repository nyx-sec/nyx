"""A Django view that deletes a document by the id in the URL.

`Document.objects.get(id=doc_id)` is an ORM read, not a token lookup, so the
missing owner check is reported as an ownership gap.
"""

from django.http import JsonResponse

from .models import Document


def delete_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)
    doc.delete()
    return JsonResponse({"ok": True})
