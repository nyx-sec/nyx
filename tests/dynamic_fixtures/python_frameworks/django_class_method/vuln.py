from django.views import View

import os


class UserCommandView(View):
    def get(self, payload):
        os.system(payload)
        return "ok"
