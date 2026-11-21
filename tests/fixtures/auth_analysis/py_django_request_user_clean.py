from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

from .models import Document


@login_required
def show_owned_document(request, doc_id):
    doc = Document.objects.filter(owner=request.user, id=doc_id).first()
    return JsonResponse({"t": doc.title})


@login_required
def show_documents_of_user(request, doc_id):
    doc = request.user.documents.filter(id=doc_id).first()
    return JsonResponse({"t": doc.title})
