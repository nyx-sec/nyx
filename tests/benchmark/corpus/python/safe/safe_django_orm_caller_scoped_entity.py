# py-auth-realrepo-008: caller-passed scope entity used as ownership
# constraint.  Distilled from sentry
# `src/sentry/api/helpers/environments.py::get_environments` (and the
# many sibling helpers in `api/endpoints/organization_releases.py`):
#
#     def get_environments(request, organization: Organization):
#         ...
#         return list(
#             Environment.objects.filter(
#                 organization_id=organization.id,
#                 name__in=requested_environments,
#             )
#         )
#
# `_filter_releases_by_query(queryset, organization, query, filter_params)`
# follows the same pattern with `queryset.filter_by_semver(organization.id, ...)`.
#
# Both helpers receive the already-authorised `organization` object
# from a route handler that resolved it via `OrganizationReleasesBaseEndpoint`
# membership middleware.  The query is *scoped by* `organization.id`
# — that IS the ownership boundary, not a user-controlled target.
#
# Without the caller-scope-entity exemption, every internal helper in a
# multi-tenant Django/Rails/Laravel codebase flags
# `missing_ownership_check` because the engine cannot tell "scoping
# arg" from "user-targeted arg".  The fix recognises that
# `<entity>.id` where `<entity>` is a unit parameter named after a
# scope-bearing domain entity (organization, project, team, workspace,
# tenant, account, ...) is a passed-in scope, not a target.
from typing import List


class Organization:
    pass


class Environment:
    pass


def get_environments(request, organization: Organization) -> List[Environment]:
    requested_environments = set(request.GET.getlist("environment"))
    if not requested_environments:
        return []
    return list(
        Environment.objects.filter(
            organization_id=organization.id, name__in=requested_environments
        )
    )


def _filter_releases_by_query(queryset, organization: Organization, query, filter_params):
    queryset = queryset.filter_by_semver(organization.id, query)
    queryset = queryset.filter_by_stage(organization.id, query)
    return queryset


def list_project_issues(request, project):
    return list(Issue.objects.filter(project_id=project.id, status="open"))


class Issue:
    pass
