from django.contrib.auth.decorators import permission_required, user_passes_test
from django.http import JsonResponse
from django.utils.decorators import method_decorator

from .models import Document


@permission_required("docs.delete_permitted_document")
def delete_permitted_doc(request, doc_id):
    Document.objects.filter(id=doc_id).delete()
    return JsonResponse({"ok": True})


@user_passes_test(lambda u: u.is_staff)
def show_staff_doc(request, doc_id):
    doc = Document.objects.filter(id=doc_id).first()
    return JsonResponse({"t": doc.title})
