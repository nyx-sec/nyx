# py-auth-vuln-002: helper takes a user-supplied id (`project_id`)
# and queries by it without any preceding ownership/membership check.
# This is the vulnerable counterpart to
# safe_django_orm_caller_scoped_entity.py — same Django ORM shape, but
# the param is an *id-like user input*, not a scope-entity object, so
# the caller-scope-entity exemption must not apply.
#
# Pinned to keep recall on the missing_ownership_check rule.


class Project:
    pass


def get_project(request, project_id):
    return Project.objects.filter(id=project_id).first()


def delete_project(request, project_id):
    Project.objects.filter(id=project_id).delete()
