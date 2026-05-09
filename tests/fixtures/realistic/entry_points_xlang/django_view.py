# Phase 16 fixture: Django class-based view.  `MyView` extends
# `django.views.View`; `get(self, request, name)` is recognised as a
# `DjangoView` entry point.  The seeding policy paints every formal
# (including `name`, the path-captured kwarg) as `Source(Cap::all())`,
# so flowing `name` into `cursor.execute` fires SQL_QUERY.
from django.db import connection
from django.views import View


class MyView(View):
    def get(self, request, name):
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
            return cursor.fetchall()
