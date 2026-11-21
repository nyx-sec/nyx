from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Document


class ApiViewDocumentDetail(APIView):
    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()
        return Response(status=204)


class ApiViewDocumentViewSet(viewsets.ViewSet):
    def destroy(self, request, pk=None):
        Document.objects.filter(pk=pk).delete()
        return Response(status=204)
