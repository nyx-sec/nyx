from rest_framework.permissions import DjangoObjectPermissions
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Document


class ObjectPermissionDocumentDetail(APIView):
    permission_classes = [DjangoObjectPermissions]

    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()
        return Response(status=204)
