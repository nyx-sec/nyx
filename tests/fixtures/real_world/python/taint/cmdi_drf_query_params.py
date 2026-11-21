import os

from rest_framework.views import APIView


class PingView(APIView):
    def get(self, request):
        host = request.query_params.get("host")
        os.system("ping -c 1 " + host)


async def ping(request):
    host = request.path_params["host"]
    os.system("ping -c 1 " + host)
