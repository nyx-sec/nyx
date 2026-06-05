from django.urls import path


def admin_view(request):
    return None


urlpatterns = [
    path("admin/", admin_view),
]
