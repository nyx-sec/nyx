"""A DRF view class registered from another file, with no permission classes."""

from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Document


class DocumentDetail(APIView):
    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()
        return Response(status=204)
