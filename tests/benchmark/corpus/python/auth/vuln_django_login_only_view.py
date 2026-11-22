"""`@login_required` proves who is calling, not that the document is theirs."""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

from .models import Document


@login_required
def show_document(request, doc_id):
    doc = Document.objects.filter(id=doc_id).first()
    return JsonResponse({"title": doc.title})
