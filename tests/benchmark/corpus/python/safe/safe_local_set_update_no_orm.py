# py-auth-realrepo-XXX: bare-callee Python container constructors
# (`set()` / `dict()` / `defaultdict()`) bind a non-sink local
# collection.  Subsequent method calls on the bound var
# (`verified_ids.update(..)`, `cache[k] = v`, `requested_teams.add(..)`)
# are in-memory mutations, not ORM/DB writes, so the route handler
# must NOT fire `py.auth.missing_ownership_check`.
#
# Distilled from sentry `src/sentry/api/helpers/teams.py::get_teams`:
#
#     def get_teams(request, organization, teams=None):
#         requested_teams = set(request.GET.getlist("team", []) ...)
#         verified_ids: set[int] = set()
#         ...
#         verified_ids.update(myteams)        # <-- LOCAL set update
#         requested_teams.update(verified_ids)
#         teams_query = Team.objects.filter(
#             id__in=requested_teams, organization_id=organization.id
#         )
#
# Without the bare-callee constructor recogniser, `set()` / `dict()`
# go untracked, the bound vars miss `non_sink_vars`, and the
# `.update(..)` / `.add(..)` calls classify as `DbMutation` —
# triggering the false missing-ownership-check finding.  See
# `AuthAnalysisRules::is_non_sink_constructor_callee` and the
# `assignment` arm in `collect_unit_state`.
from collections import Counter, defaultdict
from collections.abc import Iterable


class Organization:
    pass


class Team:
    pass


def get_teams(request, organization: Organization, teams: Iterable[int] | None = None):
    requested_teams = set(request.GET.getlist("team", []) if teams is None else teams)
    verified_ids: set[int] = set()
    seen_counter = Counter()
    cache = defaultdict(list)
    metadata = dict()
    pending = list()

    if "myteams" in requested_teams:
        requested_teams.remove("myteams")
        myteams = request.access.team_ids_with_membership
        verified_ids.update(myteams)
        requested_teams.update(verified_ids)
        seen_counter.update(myteams)
        cache["my"].append(myteams)
        metadata["count"] = len(myteams)
        pending.append(myteams)

    return Team.objects.filter(
        id__in=requested_teams, organization_id=organization.id
    )
