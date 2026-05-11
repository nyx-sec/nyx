# Django ORM intermediate-binding SQLi positive.
# `qs = Model.objects.all()` binds a `QuerySet` to a local; `qs.raw(sql)`
# fires via the type-qualified `DjangoQuerySet.raw` sink rule.  The flat
# `objects.raw` matcher only covers the direct chained form
# `Model.objects.raw(sql)`, so this fixture pins the bound-receiver
# shape that requires the receiver-typed resolution path.
import os
from .models import User


def lookup():
    name = os.environ["NAME"]
    qs = User.objects.all()
    rows = qs.raw("SELECT * FROM users WHERE name = '" + name + "'")
    return list(rows)
