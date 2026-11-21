"""View decorators authorize the function wherever its route is registered.

The routes for these views live in a `urls.py` that this file does not
mention, which is the usual Django layout.
"""

from django.contrib.auth.decorators import permission_required, user_passes_test
from django.http import JsonResponse

from .models import Document


@permission_required("docs.delete_document")
def delete_document(request, doc_id):
    Document.objects.filter(id=doc_id).delete()
    return JsonResponse({"ok": True})


@user_passes_test(lambda u: u.is_staff)
def show_document(request, doc_id):
    doc = Document.objects.filter(id=doc_id).first()
    return JsonResponse({"title": doc.title})
