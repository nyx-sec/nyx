# Django ORM bare-projection SQLi positive.
# `qs = Model.objects` (no trailing `.all()` / `.filter(...)`) binds the
# manager projection itself to a local; `qs.raw(sql)` then dispatches via
# the type-qualified `DjangoQuerySet.raw` sink rule.  The chained shape
# `Model.objects.all()` already routes through the FieldProj decomposition
# and the existing field-receiver second-pass; this fixture pins the
# bare-manager binding which lowers as an `Assign` whose CFG node carries
# `member_field = Some("objects")`.
import os
from .models import User


def lookup():
    name = os.environ["NAME"]
    qs = User.objects
    rows = qs.raw("SELECT * FROM users WHERE name = '" + name + "'")
    return list(rows)
