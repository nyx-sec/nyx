# py-auth-realrepo-011: bare-identifier callees without a receiver dot
# are never DB / ORM operations.  Distilled from sentry
# `src/sentry/tasks/statistical_detectors.py` (line 743:
# `org_ids = list({p.organization_id for p in projects})`),
# `src/sentry/utils/query.py:90` (`events = list(method(...))`),
# `src/sentry/api/helpers/group_index/delete.py` (bare `delete_group_list`,
# `create_audit_entry`, `create_audit_entries` helper calls), and
# `src/sentry/seer/autofix/coding_agent.py` (bare `update_coding_agent_state`).
#
# Before the fix, the verb-name fallback in `classify_sink_class`
# matched bare callees `list`, `filter`, `update`, `create`, `add`,
# `delete` against the Python read/mutation indicator vocabulary and
# classified them as `DbCrossTenantRead` / `DbMutation`.  Combined with
# the user-input-evidence precondition (`request: Request` triggers it),
# every internal helper firing one of these builtins / locally-defined
# helpers produced a `py.auth.missing_ownership_check` finding.
#
# A real ORM / DB call always carries a receiver
# (`Model.objects.filter(...)`, `repo.find(id)`, `db.query(...)`); a
# bare-identifier callee is a Python builtin or a locally-defined
# helper, neither of which has the cross-tenant read / mutation
# semantics the rule is checking for.  The fix gates the verb fallback
# on `receiver_is_simple_chain(callee)` (callee contains a dot AND the
# receiver isn't itself a call expression).
from typing import Any, Iterable


def fetch_continuous_examples(raw_examples):
    # `list(...)` is a Python builtin — no DB op happens here.
    project_ids = list({pid for pid, _ in raw_examples.keys()})
    return project_ids


def detect_function_change_points(projects, start, transactions_per_project=None):
    # Bare `list({...})` set-comprehension materialisation; both args
    # come from internally-supplied `projects` collection iteration.
    org_ids = list({p.organization_id for p in projects})
    project_ids = list({p.id for p in projects})
    return org_ids, project_ids


def delete_group_list(request, project, group_list, delete_type):
    # Bare-name local helper invocation — `create_audit_entries` is a
    # function defined in the same module, not a DB write.  Used to
    # fire `py.auth.missing_ownership_check`.
    transaction_id = "tx"
    create_audit_entries(request, project, group_list, delete_type, transaction_id)


def create_audit_entries(request, project, group_list, delete_type, transaction_id):
    for group in group_list:
        # Bare `create_audit_entry` is a helper, not a DB INSERT.
        create_audit_entry(
            request=request,
            target_object=group.id,
            event="ISSUE_DELETE",
            data={"issue_id": group.id, "project_slug": project.slug},
        )


def create_audit_entry(**kwargs):
    pass


def update_coding_agent_state(state, action):
    # Bare `update_*` helper called inside an outer task — Python lets
    # you name local helpers freely, the verb prefix does not imply a
    # DB mutation.
    pass


def materialise_filter_chain(events: Iterable[Any]):
    # `filter(...)` is the Python builtin (`Iterable.filter`), and the
    # bare-name local helper pattern below is endemic in real-repo
    # Python code.
    return list(filter(lambda e: e is not None, events))
