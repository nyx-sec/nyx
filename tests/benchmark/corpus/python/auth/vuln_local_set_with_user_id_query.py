# py-auth-realrepo-XXX (vuln pair): same bare-`set()` / `dict()` /
# `defaultdict()` local collection shape as
# safe_local_set_update_no_orm.py, but the helper *also* runs an
# id-targeted ORM query whose filter argument is a user-supplied id
# (`team_id` in the function signature, no caller-scope-entity
# exemption applies).
#
# Recall guard: the bare-callee constructor recogniser must only
# suppress the InMemoryLocal `.update` / `.add` calls — the
# id-targeted ORM `.filter(id=team_id)` must still fire
# `py.auth.missing_ownership_check`.
class Team:
    pass


def get_team_with_history(request, team_id):
    seen_ids = set()
    audit = dict()
    seen_ids.add(team_id)
    audit["team"] = team_id

    return Team.objects.filter(id=team_id).first()


def archive_team(request, team_id):
    pending = set()
    pending.add(team_id)
    Team.objects.filter(id=team_id).delete()
