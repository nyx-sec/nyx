import os
from django.views import View
from django.http import HttpResponse

class RunView(View):
    def get(self, request):
        cmd = request.GET.get("cmd")
        os.system(cmd)
        return HttpResponse("ok")

class OtherView(View):
    def get(self, request):
        name = request.GET.get("name")
        d = {}
        d[name] = 1
        for k in d:
            os.system(k)
        return HttpResponse("ok")
